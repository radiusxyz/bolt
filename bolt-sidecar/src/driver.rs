use std::{fmt, sync::Arc, time::Instant};

use alloy::{
    consensus::{TxType, Typed2718},
    rpc::types::beacon::events::HeadEvent,
    signers::local::PrivateKeySigner,
};
use ethereum_consensus::{
    clock::{self, SlotStream, SystemTimeProvider},
    phase0::mainnet::SLOTS_PER_EPOCH,
};
use eyre::Context;
use futures::StreamExt;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    api::{
        builder::{start_builder_proxy_server, BuilderProxyConfig},
        commitments::server::{spec::CommitmentError, CommitmentEvent, CommitmentsApiServer},
        firewall::receiver::CommitmentsReceiver,
        spec::ConstraintsApi,
    },
    builder::payload_fetcher::LocalPayloadFetcher,
    chain_io::BoltManager,
    client::{BeaconClient, ConstraintsClient},
    common::backoff::retry_with_backoff,
    config::{commitments::DEFAULT_RPC_PORT, Opts},
    crypto::{SignableBLS, SignerECDSA},
    primitives::{
        commitment::SignedCommitment, read_signed_delegations_from_file, CommitmentRequest,
        ConstraintsMessage, FetchPayloadRequest, SignedConstraints,
    },
    signer::{keystore::KeystoreSigner, local::LocalSigner, CommitBoostSigner, SignerBLS},
    state::{fetcher::StateFetcher, ConsensusState, ExecutionState, HeadTracker, StateClient},
    telemetry::ApiMetrics,
    LocalBuilder,
};

const API_EVENTS_BUFFER_SIZE: usize = 1024;

/// The driver for the sidecar, responsible for managing the main event loop.
///
/// The reponsibilities of the driver include:
/// - Handling incoming API events
/// - Updating the execution state based on new beacon chain heads
/// - Submitting constraints to the constraints service at the commitment deadline
/// - Building local payloads for the beacon chain
/// - Responding to requests to fetch a local payload
/// - Updating the consensus state based on the beacon chain clock
pub struct SidecarDriver<C, ECDSA> {
    /// Head tracker for monitoring the beacon chain clock
    head_tracker: HeadTracker,
    /// Execution state for tracking the current head and block templates
    execution: ExecutionState<C>,
    /// Consensus state for tracking the current slot and validator indexes
    consensus: ConsensusState,
    /// Signer for creating constraints
    constraint_signer: SignerBLS,
    /// Signer for creating commitment responses
    commitment_signer: ECDSA,
    /// Local block builder for creating local payloads
    local_builder: LocalBuilder,
    /// Client for interacting with the constraints service
    constraints_client: ConstraintsClient,
    /// Channel for receiving incoming API events
    api_events_rx: mpsc::Receiver<CommitmentEvent>,
    /// Channel for receiving requests to fetch a local payload
    payload_requests_rx: mpsc::Receiver<FetchPayloadRequest>,
    /// Stream of slots made from the consensus clock
    slot_stream: SlotStream<SystemTimeProvider>,
    /// Whether to skip consensus checks (should only be used for testing)
    unsafe_skip_consensus_checks: bool,
}

impl SidecarDriver<StateClient, PrivateKeySigner> {
    /// Create a new sidecar driver with the given [Opts] and private key signer.
    pub async fn with_local_signer(opts: &Opts) -> eyre::Result<Self> {
        // The default state client simply uses the execution API URL to fetch state updates.
        let state_client = StateClient::new(opts.execution_api_url.clone());

        // Constraints are signed with a BLS private key
        let constraint_signer = SignerBLS::Local(LocalSigner::new(
            opts.constraint_signing
                .constraint_private_key
                .clone()
                .expect("local constraint signing key")
                .0,
            opts.chain,
        ));

        // Commitment responses are signed with a regular Ethereum wallet private key.
        let commitment_key = opts.commitment_opts.operator_private_key.0.clone();
        let commitment_signer = PrivateKeySigner::from_signing_key(commitment_key);

        Self::from_components(opts, constraint_signer, commitment_signer, state_client)
            .await
            .wrap_err("Failed to initialize sidecar with local signer")
    }
}

impl SidecarDriver<StateClient, PrivateKeySigner> {
    /// Create a new sidecar driver with the given [Opts] and keystore signer.
    pub async fn with_keystore_signer(opts: &Opts) -> eyre::Result<Self> {
        // The default state client simply uses the execution API URL to fetch state updates.
        let state_client = StateClient::new(opts.execution_api_url.clone());

        let keystore = if let Some(psw) = opts.constraint_signing.keystore_password.as_ref() {
            KeystoreSigner::from_password(
                opts.constraint_signing.keystore_path.as_ref().expect("keystore path"),
                psw.as_ref(),
                opts.chain,
            )?
        } else {
            KeystoreSigner::from_secrets_directory(
                opts.constraint_signing.keystore_path.as_ref().expect("keystore path"),
                opts.constraint_signing.keystore_secrets_path.as_ref().expect("keystore secrets"),
                opts.chain,
            )?
        };

        let keystore_signer = SignerBLS::Keystore(keystore);

        // Commitment responses are signed with a regular Ethereum wallet private key.
        let commitment_key = opts.commitment_opts.operator_private_key.0.clone();
        let commitment_signer = PrivateKeySigner::from_signing_key(commitment_key);

        Self::from_components(opts, keystore_signer, commitment_signer, state_client)
            .await
            .wrap_err("Failed to initialize sidecar with keystore signer")
    }
}

impl SidecarDriver<StateClient, CommitBoostSigner> {
    /// Create a new sidecar driver with the given [Opts] and commit-boost signer.
    pub async fn with_commit_boost_signer(opts: &Opts) -> eyre::Result<Self> {
        // The default state client simply uses the execution API URL to fetch state updates.
        let state_client = StateClient::new(opts.execution_api_url.clone());

        let commit_boost_signer = CommitBoostSigner::new(
            opts.constraint_signing.commit_boost_signer_url.clone().expect("CommitBoost URL"),
            &opts.constraint_signing.commit_boost_jwt_hex.clone().expect("CommitBoost JWT"),
        )?;

        let cb_bls_signer = SignerBLS::CommitBoost(commit_boost_signer.clone());

        Self::from_components(opts, cb_bls_signer, commit_boost_signer, state_client)
            .await
            .wrap_err("Failed to initialize sidecar with commit-boost signer")
    }
}

impl<C: StateFetcher, ECDSA: SignerECDSA> SidecarDriver<C, ECDSA> {
    /// Create a new sidecar driver with the given components
    pub async fn from_components(
        opts: &Opts,
        constraint_signer: SignerBLS,
        commitment_signer: ECDSA,
        fetcher: C,
    ) -> eyre::Result<Self> {
        let mut constraints_client = ConstraintsClient::new(opts.constraints_api_url.clone());

        // read the delegations from disk if they exist and add them to the constraints client.
        let validator_pubkeys = if let Some(delegations_path) =
            &opts.constraint_signing.delegations_path
        {
            info!("Reading signed delegations from disk");
            let delegations = read_signed_delegations_from_file(delegations_path)?;
            let keys = delegations.iter().map(|d| d.validator_pubkey.clone()).collect::<Vec<_>>();
            constraints_client.add_delegations(delegations);
            keys
        } else {
            info!("No delegations provided, using public keys from the provided signer");
            Vec::from_iter(constraint_signer.available_pubkeys())
        };

        if opts.unsafe_disable_onchain_checks {
            warn!("Skipping validators and operator public keys verification: --unsafe-disable-onchain-checks is 'true'");
        } else if let Some(manager) =
            BoltManager::from_chain(opts.execution_api_url.clone(), *opts.chain)
        {
            info!(
                validator_pubkeys = %validator_pubkeys.len(),
                "Verifying validators and operator keys with BoltManager..."
            );

            manager
                .verify_validator_pubkeys(validator_pubkeys, commitment_signer.public_key())
                .await?;

            info!("Successfully verified validators and operator keys with BoltManager");
        } else {
            warn!(
                "BoltManager is not deployed on {}, skipping validators and operator public keys verification",
                opts.chain.name()
            );
        }

        let beacon_client = BeaconClient::new(opts.beacon_api_url.clone());
        let execution = ExecutionState::new(fetcher, opts.limits, opts.chain.gas_limit).await?;

        let genesis_time = beacon_client.get_genesis_details().await?.genesis_time;
        let slot_stream =
            clock::from_system_time(genesis_time, opts.chain.slot_time(), SLOTS_PER_EPOCH)
                .into_stream();

        let local_builder = LocalBuilder::new(opts, genesis_time);
        let head_tracker = HeadTracker::start(beacon_client.clone());

        let consensus = ConsensusState::new(
            beacon_client,
            opts.chain.commitment_deadline(),
            opts.chain.enable_unsafe_lookahead,
        );

        let (payload_requests_tx, payload_requests_rx) = mpsc::channel(16);
        let builder_proxy_cfg = BuilderProxyConfig {
            constraints_client: constraints_client.clone(),
            server_port: opts.constraints_proxy_port,
        };

        // start the builder api proxy server
        tokio::spawn(async move {
            let payload_fetcher = LocalPayloadFetcher::new(payload_requests_tx);
            if let Err(err) = start_builder_proxy_server(payload_fetcher, builder_proxy_cfg).await {
                error!(?err, "Builder API proxy server failed");
            }
        });

        let api_events_rx = if let Some(urls) = opts.commitment_opts.firewall_rpcs.clone() {
            CommitmentsReceiver::new(
                opts.commitment_opts.operator_private_key.clone(),
                opts.chain.chain,
                urls,
            )
            .run()
            .await
        } else {
            let port = opts.commitment_opts.port.unwrap_or(DEFAULT_RPC_PORT);
            // start the commitments api server
            let api_addr = format!("0.0.0.0:{}", port);
            let (api_events_tx, api_events_rx) = mpsc::channel(API_EVENTS_BUFFER_SIZE);
            CommitmentsApiServer::new(api_addr).run(api_events_tx, opts.limits).await;
            api_events_rx
        };

        let unsafe_skip_consensus_checks = opts.unsafe_disable_consensus_checks;

        Ok(Self {
            unsafe_skip_consensus_checks,
            head_tracker,
            execution,
            consensus,
            constraint_signer,
            commitment_signer,
            local_builder,
            constraints_client,
            api_events_rx,
            payload_requests_rx,
            slot_stream,
        })
    }

    /// Run the main event loop endlessly for the sidecar driver.
    ///
    /// Any errors encountered are contained to the specific `handler` in which
    /// they occurred, and the driver will continue to run as long as possible.
    pub async fn run_forever(mut self) -> ! {
        loop {
            tokio::select! {
                Some(api_event) = self.api_events_rx.recv() => {
                    self.handle_incoming_api_event(api_event).await;
                }
                Ok(head_event) = self.head_tracker.next_head() => {
                    self.handle_new_head_event(head_event).await;
                }
                Some(slot) = self.consensus.wait_commitment_deadline() => {
                    self.handle_commitment_deadline(slot).await;
                }
                Some(payload_request) = self.payload_requests_rx.recv() => {
                    self.handle_fetch_payload_request(payload_request);
                }
                Some(slot) = self.slot_stream.next() => {
                    if let Err(e) = self.consensus.update_slot(slot).await {
                        error!(err = ?e, "Failed to update consensus state slot");
                    }
                }
            }
        }
    }

    /// Handle an incoming API event, validating the request and responding with a commitment.
    async fn handle_incoming_api_event(&mut self, event: CommitmentEvent) {
        let CommitmentEvent { request, response } = event;

        info!("Received new commitment request: {:?}", request);
        ApiMetrics::increment_inclusion_commitments_received();

        let start = Instant::now();

        // When we'll add more commitment types, we'll need to match on the request type here.
        // For now, we only support inclusion requests so the flow is straightforward.
        let CommitmentRequest::Inclusion(mut inclusion_request) = request;
        let target_slot = inclusion_request.slot;

        let available_pubkeys = self.constraint_signer.available_pubkeys();

        // Determine the constraint signing public key for this request. Rationale:
        // - If we're skipping consensus checks, we can use any available pubkey in the keystore.
        // - On regular operation, we need to validate the request against the consensus state to
        //   determine if the sidecar is the proposer for the given slot. If so, we use the
        //   validator pubkey or any of its active delegatees to sign constraints.
        let signing_pubkey = if self.unsafe_skip_consensus_checks {
            available_pubkeys.iter().min().cloned().expect("at least one available pubkey")
        } else {
            let validator_pubkey = match self.consensus.validate_request(&inclusion_request) {
                Ok(pubkey) => pubkey,
                Err(err) => {
                    warn!(?err, "Consensus: failed to validate request");
                    let _ = response.send(Err(CommitmentError::Consensus(err)));
                    return;
                }
            };

            // Find a public key to sign new constraints with for this slot.
            // This can either be the validator pubkey or a delegatee (if one is available).
            let Some(signing_key) =
                self.constraints_client.find_signing_key(validator_pubkey, available_pubkeys)
            else {
                error!(%target_slot, "No available public key to sign constraints with");
                let _ = response.send(Err(CommitmentError::Internal));
                return;
            };

            signing_key
        };

        if let Err(err) = self.execution.validate_request(&mut inclusion_request).await {
            warn!(?err, "Execution: failed to validate request");
            ApiMetrics::increment_validation_errors(err.to_tag_str().to_owned());
            let _ = response.send(Err(CommitmentError::Validation(err)));
            return;
        }

        info!(
            target_slot,
            elapsed = ?start.elapsed(),
            "Validation against execution state passed"
        );

        // NOTE: we iterate over the transactions in the request and generate a signed constraint
        // for each one. This is because the transactions in the commitment request are not supposed
        // to be treated as a relative-ordering bundle, but a batch with no ordering guarantees.
        //
        // For more information, check out the constraints API docs:
        // https://docs.boltprotocol.xyz/technical-docs/api/builder#constraints
        for tx in &inclusion_request.txs {
            let tx_type = TxType::try_from(tx.ty()).expect("valid tx type");
            let message =
                ConstraintsMessage::from_tx(signing_pubkey.clone(), target_slot, tx.clone());
            let digest = message.digest();

            let signature_result = match &self.constraint_signer {
                SignerBLS::Local(signer) => signer.sign_commit_boost_root(digest),
                SignerBLS::CommitBoost(signer) => signer.sign_commit_boost_root(digest).await,
                SignerBLS::Keystore(signer) => {
                    signer.sign_commit_boost_root(digest, &signing_pubkey)
                }
            };

            let signed_constraints = match signature_result {
                Ok(signature) => SignedConstraints { message, signature },
                Err(e) => {
                    error!(?e, "Failed to sign constraints");
                    let _ = response.send(Err(CommitmentError::Internal));
                    return;
                }
            };

            ApiMetrics::increment_transactions_preconfirmed(tx_type);
            self.execution.add_constraint(target_slot, signed_constraints);
        }

        // Create a commitment by signing the request
        match inclusion_request.commit_and_sign(&self.commitment_signer).await {
            Ok(commitment) => {
                debug!(target_slot, elapsed = ?start.elapsed(), "Commitment signed and sent");
                response.send(Ok(SignedCommitment::Inclusion(commitment))).ok()
            }
            Err(err) => {
                error!(?err, "Failed to sign commitment");
                response.send(Err(CommitmentError::Internal)).ok()
            }
        };

        ApiMetrics::increment_inclusion_commitments_accepted();
    }

    /// Handle a new head event, updating the execution state.
    async fn handle_new_head_event(&mut self, head_event: HeadEvent) {
        let slot = head_event.slot;
        info!(slot, "Received new head event");

        // We use None to signal that we want to fetch the latest EL head
        if let Err(e) = self.execution.update_head(None, slot).await {
            error!(err = ?e, "Failed to update execution state head");
        }
    }

    /// Handle a commitment deadline event, submitting constraints to the Constraints client service
    /// and starting to build a local payload for the given target slot.
    async fn handle_commitment_deadline(&mut self, slot: u64) {
        let Some(template) = self.execution.get_block_template(slot) else {
            // Nothing to do then. Block templates are created only when constraints are added,
            // which means we haven't issued any commitment for this slot because we are
            // (probably) not the proposer for this block.
            return;
        };

        info!(slot, "Commitment deadline reached, building local block");

        if let Err(e) = self.local_builder.build_new_local_payload(slot, template).await {
            error!(err = ?e, "Error while building local payload at deadline for slot {slot}");
        };

        let constraints = Arc::new(template.signed_constraints_list.clone());
        let constraints_client = Arc::new(self.constraints_client.clone());

        // Submit constraints to the constraints service with an exponential retry mechanism.
        tokio::spawn(retry_with_backoff(10, move || {
            let constraints_client = Arc::clone(&constraints_client);
            let constraints = Arc::clone(&constraints);
            async move {
                match constraints_client.submit_constraints(constraints.as_ref()).await {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        error!(err = ?e, "Failed to submit constraints, retrying...");
                        Err(e)
                    }
                }
            }
        }));
    }

    /// Handle a fetch payload request, responding with the local payload if available.
    fn handle_fetch_payload_request(&mut self, request: FetchPayloadRequest) {
        info!(slot = request.slot, "Received local payload request");

        let Some(payload_and_bid) = self.local_builder.get_cached_payload() else {
            warn!(slot = request.slot, "No local payload found");
            let _ = request.response_tx.send(None);
            return;
        };

        if let Err(e) = request.response_tx.send(Some(payload_and_bid)) {
            error!(err = ?e, "Failed to send payload and bid in response channel");
        }
    }
}

impl fmt::Debug for SidecarDriver<StateClient, PrivateKeySigner> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SidecarDriver")
            .field("head_tracker", &self.head_tracker)
            .field("execution", &self.execution)
            .field("consensus", &self.consensus)
            .field("constraint_signer", &self.constraint_signer)
            .field("commitment_signer", &self.commitment_signer)
            .field("local_builder", &self.local_builder)
            .field("constraints_client", &self.constraints_client)
            .field("api_events_rx", &self.api_events_rx)
            .field("payload_requests_rx", &self.payload_requests_rx)
            .finish()
    }
}
