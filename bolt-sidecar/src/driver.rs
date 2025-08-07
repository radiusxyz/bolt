use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};

use alloy::{
    consensus::{Transaction, TxType, Typed2718},
    primitives::{Address, B256},
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
        commitments::{
            firewall::receiver::CommitmentsReceiver,
            server::{CommitmentEvent, CommitmentsApiServer},
            spec::CommitmentError,
        },
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
    state::{
        fetcher::StateFetcher, CommitmentDeadline, ConsensusState, ExecutionState, HeadTracker,
        StateClient,
    },
    telemetry::ApiMetrics,
    LocalBuilder,
};

const API_EVENTS_BUFFER_SIZE: usize = 1024;

/// Access list key for tracking used access list entries per slot
/// (Address, StorageKey) pair uniquely identifies an access list entry
pub type AccessListKey = (Address, B256);

/// State management for atomic exclusion request processing
/// Maps slot -> set of used access list keys to prevent conflicts
type SlotAccessLists = Arc<Mutex<HashMap<u64, HashSet<AccessListKey>>>>;

/// Exclusion constraint information for first inclusion validation
/// Tracks the original exclusion constraints to validate against first inclusion requests
#[derive(Debug, Clone)]
pub struct ExclusionConstraintInfo {
    /// The signer address that created the exclusion constraint
    pub signer: Address,
    /// The access list keys that were reserved in the exclusion constraint
    pub access_list_keys: Vec<AccessListKey>,
    /// The slot for which this exclusion constraint applies
    pub slot: u64,
}

/// Maps slot -> list of exclusion constraints for first inclusion validation
type SlotExclusionConstraints = Arc<Mutex<HashMap<u64, Vec<ExclusionConstraintInfo>>>>;

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
    /// Pending first inclusion requests awaiting processing 500ms after commitment deadline (slot -> (request, response_sender, start_time))
    pending_first_inclusion_requests: HashMap<
        u64,
        Vec<(
            crate::primitives::FirstInclusionRequest,
            tokio::sync::oneshot::Sender<
                Result<
                    crate::primitives::commitment::SignedCommitment,
                    crate::api::commitments::spec::CommitmentError,
                >,
            >,
            Instant,
        )>,
    >,
    /// Track when commitment deadlines occurred for each slot to schedule first inclusion processing
    commitment_deadline_timestamps: HashMap<u64, Instant>,
    /// Timer interval for checking pending first inclusion requests
    first_inclusion_timer_interval: std::time::Duration,
    /// First inclusion deadline for the current slot
    first_inclusion_deadline: Option<crate::state::CommitmentDeadline>,
    /// State management for atomic exclusion request processing
    /// Tracks used access list entries per slot to prevent conflicts
    slot_access_lists: SlotAccessLists,
    /// Tracks exclusion constraints for first inclusion validation
    /// Maps slot -> list of exclusion constraints with signer and access list info
    slot_exclusion_constraints: SlotExclusionConstraints,
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
    /// Extract access list keys from a transaction
    pub fn extract_access_list_keys(tx: &crate::primitives::FullTransaction) -> Vec<AccessListKey> {
        let mut keys = Vec::new();

        if let Some(access_list) = tx.access_list() {
            for item in &access_list.0 {
                for storage_key in &item.storage_keys {
                    keys.push((item.address, *storage_key));
                }
            }
        }

        keys
    }

    /// Check if an exclusion request has conflicting access lists with existing commitments
    /// Returns Ok(()) if no conflicts, Err(conflicting_keys) if conflicts detected
    fn validate_exclusion_request_atomic(
        &self,
        exclusion_request: &crate::primitives::ExclusionRequest,
    ) -> Result<Vec<AccessListKey>, Vec<AccessListKey>> {
        let target_slot = exclusion_request.slot;

        // Extract all access list keys from the exclusion request
        let mut request_keys = Vec::new();
        for tx in &exclusion_request.txs {
            request_keys.extend(Self::extract_access_list_keys(tx));
        }

        // If no access list entries, no conflicts possible
        if request_keys.is_empty() {
            return Ok(request_keys);
        }

        // Lock the slot access lists for atomic validation
        let slot_access_lists = self.slot_access_lists.lock().unwrap();

        // Get existing access list keys for this slot
        let existing_keys = slot_access_lists.get(&target_slot);

        // Check for conflicts
        let mut conflicting_keys = Vec::new();

        if let Some(existing) = existing_keys {
            for key in &request_keys {
                if existing.contains(key) {
                    conflicting_keys.push(*key);
                }
            }
        }

        if conflicting_keys.is_empty() {
            Ok(request_keys)
        } else {
            Err(conflicting_keys)
        }
    }

    /// Reserve access list keys for a slot (called after successful validation)
    /// This method assumes the caller has already validated the request atomically
    fn reserve_access_list_keys(&self, slot: u64, keys: Vec<AccessListKey>) {
        if keys.is_empty() {
            return;
        }

        let mut slot_access_lists = self.slot_access_lists.lock().unwrap();
        let slot_keys = slot_access_lists.entry(slot).or_insert_with(HashSet::new);

        for key in keys {
            slot_keys.insert(key);
        }
    }

    /// Clean up old slot access lists to prevent memory leaks
    /// Should be called periodically or when slots are finalized
    fn cleanup_old_access_lists(&self, current_slot: u64) {
        let mut slot_access_lists = self.slot_access_lists.lock().unwrap();

        // Keep only slots within a reasonable window (e.g., current slot + 100)
        let cutoff_slot = current_slot.saturating_sub(100);
        slot_access_lists.retain(|&slot, _| slot > cutoff_slot);
    }

    /// Store exclusion constraint information for first inclusion validation
    /// This allows us to validate that first inclusion requests match previous exclusion constraints
    fn store_exclusion_constraint_info(
        &self,
        slot: u64,
        signer: Address,
        access_list_keys: Vec<AccessListKey>,
    ) {
        let access_list_count = access_list_keys.len();
        let constraint_info = ExclusionConstraintInfo { signer, access_list_keys, slot };

        let mut slot_exclusion_constraints = self.slot_exclusion_constraints.lock().unwrap();
        slot_exclusion_constraints.entry(slot).or_insert_with(Vec::new).push(constraint_info);

        debug!(
            slot,
            ?signer,
            access_list_count,
            "📋 Stored exclusion constraint info for first inclusion validation"
        );
    }

    /// Validate a first inclusion request against previous exclusion constraints
    /// Returns Ok(()) if valid, Err(error_msg) if validation fails
    fn validate_first_inclusion_request(
        &self,
        request: &crate::primitives::FirstInclusionRequest,
    ) -> Result<(), String> {
        let slot = request.slot;

        // Check if request has signer information
        let request_signer = request
            .signer
            .ok_or_else(|| "First inclusion request must include signer information".to_string())?;

        // Get exclusion constraints for this slot
        let slot_exclusion_constraints = self.slot_exclusion_constraints.lock().unwrap();
        let exclusion_constraints = slot_exclusion_constraints
            .get(&slot)
            .ok_or_else(|| format!("No exclusion constraints found for slot {}", slot))?;

        // Find matching exclusion constraint by signer
        let matching_exclusion = exclusion_constraints
            .iter()
            .find(|constraint| constraint.signer == request_signer)
            .ok_or_else(|| {
                format!(
                    "No exclusion constraint found for signer {} in slot {}",
                    request_signer, slot
                )
            })?;

        // Extract access list keys from first inclusion request
        let mut request_access_keys = Vec::new();
        for tx in &request.txs {
            request_access_keys.extend(Self::extract_access_list_keys(tx));
        }

        // Validate that request access list is a subset of exclusion constraint access list
        for request_key in &request_access_keys {
            if !matching_exclusion.access_list_keys.contains(request_key) {
                return Err(format!(
                    "First inclusion access list key {}:{:#x} not found in exclusion constraint for signer {} in slot {}",
                    request_key.0, request_key.1, request_signer, slot
                ));
            }
        }

        debug!(
            slot,
            ?request_signer,
            exclusion_keys = matching_exclusion.access_list_keys.len(),
            request_keys = request_access_keys.len(),
            "✅ First inclusion validation: access list is subset of exclusion constraint"
        );

        Ok(())
    }

    /// Clean up old exclusion constraints to prevent memory leaks
    /// Should be called periodically along with access list cleanup
    fn cleanup_old_exclusion_constraints(&self, current_slot: u64) {
        let mut slot_exclusion_constraints = self.slot_exclusion_constraints.lock().unwrap();

        // Keep only slots within a reasonable window (same as access lists)
        let cutoff_slot = current_slot.saturating_sub(100);
        slot_exclusion_constraints.retain(|&slot, _| slot > cutoff_slot);
    }
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
                opts.limits,
                urls,
            )
            .run()
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
            pending_first_inclusion_requests: HashMap::new(),
            commitment_deadline_timestamps: HashMap::new(),
            first_inclusion_timer_interval: opts.chain.first_inclusion_timer_interval(),
            first_inclusion_deadline: None,
            slot_access_lists: Arc::new(Mutex::new(HashMap::new())),
            slot_exclusion_constraints: Arc::new(Mutex::new(HashMap::new())),
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

                    // 🧹 CLEANUP: Periodically clean up old state to prevent memory leaks
                    self.cleanup_old_access_lists(slot);
                    self.cleanup_old_exclusion_constraints(slot);
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

        // Handle different commitment types
        match request {
            CommitmentRequest::Inclusion(inclusion_request) => {
                self.handle_inclusion_request_legacy(inclusion_request, response, start).await;
            }
            CommitmentRequest::Exclusion(exclusion_request) => {
                self.handle_exclusion_request(exclusion_request, response, start).await;
            }
            CommitmentRequest::FirstInclusion(first_inclusion_request) => {
                self.handle_first_inclusion_request(first_inclusion_request, response, start).await;
            }
        }
    }

    /// Handle an inclusion request (legacy implementation)
    async fn handle_inclusion_request_legacy(
        &mut self,
        mut inclusion_request: crate::primitives::InclusionRequest,
        response: tokio::sync::oneshot::Sender<
            Result<
                crate::primitives::commitment::SignedCommitment,
                crate::api::commitments::spec::CommitmentError,
            >,
        >,
        start: Instant,
    ) {
        ApiMetrics::increment_inclusion_commitments_received();
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

    /// Handle an exclusion request by creating constraints for each transaction
    /// This method implements atomic validation to prevent access list conflicts
    async fn handle_exclusion_request(
        &mut self,
        exclusion_request: crate::primitives::ExclusionRequest,
        response: tokio::sync::oneshot::Sender<
            Result<
                crate::primitives::commitment::SignedCommitment,
                crate::api::commitments::spec::CommitmentError,
            >,
        >,
        start: Instant,
    ) {
        let target_slot = exclusion_request.slot;
        let signer = exclusion_request.signer;
        let tx_count = exclusion_request.txs.len();
        info!(
            target_slot,
            ?signer,
            tx_count,
            "🚫 SIDECAR: Received bolt_exclusionRequest from user - performing atomic validation"
        );

        // 🔒 ATOMIC VALIDATION: Check for access list conflicts before processing
        let access_list_keys = match self.validate_exclusion_request_atomic(&exclusion_request) {
            Ok(keys) => {
                info!(
                    target_slot,
                    access_list_entries = keys.len(),
                    "✅ ATOMIC VALIDATION: No access list conflicts detected"
                );
                keys
            }
            Err(conflicting_keys) => {
                warn!(
                    target_slot,
                    conflicting_entries = conflicting_keys.len(),
                    "❌ ATOMIC VALIDATION: Access list conflicts detected - rejecting request"
                );

                // Create detailed error response with conflicting access list information
                let error_details = format!(
                    "Access list conflict detected for slot {}. Conflicting entries: {}",
                    target_slot,
                    conflicting_keys
                        .iter()
                        .map(|(addr, key)| format!("{}:{:#x}", addr, key))
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                let _ = response.send(Err(CommitmentError::AccessListConflict(error_details)));
                return;
            }
        };

        // Perform consensus validation
        let available_pubkeys = self.constraint_signer.available_pubkeys();
        let signing_pubkey = if self.unsafe_skip_consensus_checks {
            available_pubkeys.iter().min().cloned().expect("at least one available pubkey")
        } else {
            let validator_pubkey =
                match self.consensus.validate_request(&crate::primitives::InclusionRequest {
                    slot: exclusion_request.slot,
                    txs: exclusion_request.txs.clone(),
                    signature: None,
                    signer: None,
                }) {
                    Ok(pubkey) => pubkey,
                    Err(err) => {
                        warn!(?err, "Consensus: failed to validate exclusion request");
                        let _ = response.send(Err(CommitmentError::Consensus(err)));
                        return;
                    }
                };

            let Some(signing_key) =
                self.constraints_client.find_signing_key(validator_pubkey, available_pubkeys)
            else {
                error!(target_slot, "No available public key to sign constraints with");
                let _ = response.send(Err(CommitmentError::Internal));
                return;
            };

            signing_key
        };

        // 🔒 ATOMIC OPERATION: Reserve access list keys before processing constraints
        // This ensures the entire exclusion request is processed atomically
        self.reserve_access_list_keys(target_slot, access_list_keys.clone());

        info!(
            target_slot,
            reserved_keys = access_list_keys.len(),
            "🔐 ATOMIC OPERATION: Reserved access list keys for exclusion request"
        );

        // Create constraints for exclusion request transactions
        // At this point, we have atomically validated and reserved access lists
        let mut signed_constraints_batch = Vec::new();

        for (i, tx) in exclusion_request.txs.iter().enumerate() {
            let message =
                ConstraintsMessage::from_tx(signing_pubkey.clone(), target_slot, tx.clone());
            let digest = message.digest();

            info!(
                target_slot,
                tx_index = i,
                tx_hash = %tx.hash(),
                top = %message.top,
                "🔐 SIDECAR: Created Exclusion constraint with top=false"
            );
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
                    error!(?e, "❌ Failed to sign exclusion constraints");

                    // ❌ ROLLBACK: Remove reserved access list keys on failure
                    // TODO: Implement proper rollback mechanism if needed
                    warn!(
                        target_slot,
                        "⚠️  Access list keys were reserved but constraint signing failed. Consider implementing rollback."
                    );

                    let _ = response.send(Err(CommitmentError::Internal));
                    return;
                }
            };

            signed_constraints_batch.push(signed_constraints);
        }

        // 📤 ATOMIC CONSTRAINT STORAGE: Store all constraints atomically
        for (i, signed_constraints) in signed_constraints_batch.into_iter().enumerate() {
            info!(
                target_slot,
                tx_index = i,
                "✅ SIDECAR: Successfully created BLS-signed constraint"
            );

            self.execution.add_constraint(target_slot, signed_constraints);
        }

        info!(
            target_slot,
            tx_count,
            elapsed = ?start.elapsed(),
            "🎯 ATOMIC SUCCESS: Exclusion request processed atomically with access list validation"
        );

        // 📋 EXCLUSION TRACKING: Store exclusion constraint info for first inclusion validation
        if let Some(request_signer) = signer {
            self.store_exclusion_constraint_info(
                target_slot,
                request_signer,
                access_list_keys.clone(),
            );
        }

        // Create the commitment response to user
        match exclusion_request.commit_and_sign(&self.commitment_signer).await {
            Ok(commitment) => {
                debug!(slot = target_slot, elapsed = ?start.elapsed(), "✅ Exclusion commitment signed and sent");
                response.send(Ok(SignedCommitment::Exclusion(commitment))).ok()
            }
            Err(err) => {
                error!(?err, "❌ Failed to sign exclusion commitment");
                response.send(Err(CommitmentError::Internal)).ok()
            }
        };
    }

    /// Handle a first inclusion request by adding it to the pending auction queue
    async fn handle_first_inclusion_request(
        &mut self,
        first_inclusion_request: crate::primitives::FirstInclusionRequest,
        response: tokio::sync::oneshot::Sender<
            Result<
                crate::primitives::commitment::SignedCommitment,
                crate::api::commitments::spec::CommitmentError,
            >,
        >,
        start: Instant,
    ) {
        let target_slot = first_inclusion_request.slot;
        info!(
            "Received first inclusion request for slot {}, adding to pending queue for processing after commitment deadline + 500ms",
            target_slot
        );

        // Add the request to the pending queue for processing after commitment deadline + 500ms
        self.pending_first_inclusion_requests.entry(target_slot).or_insert_with(Vec::new).push((
            first_inclusion_request,
            response,
            start,
        ));

        debug!(slot = target_slot, "Added first inclusion request to pending queue");
    }

    /// Schedule first inclusion processing after commitment deadline + first inclusion timer interval
    async fn schedule_first_inclusion_processing(&mut self, slot: u64) {
        // Create a new deadline for first inclusion processing
        self.first_inclusion_deadline =
            Some(CommitmentDeadline::new(slot, self.first_inclusion_timer_interval));
        debug!(slot, interval = ?self.first_inclusion_timer_interval, "Scheduled first inclusion processing");
    }

    /// Handle pending first inclusion requests after the commitment deadline + interval
    async fn handle_first_inclusion_deadline(&mut self, slot: u64) {
        // Clear the deadline as it has been reached
        self.first_inclusion_deadline = None;

        info!(slot, "First inclusion deadline reached, processing pending requests");

        // Process all pending first inclusion requests for this slot
        if let Some(requests) = self.pending_first_inclusion_requests.remove(&slot) {
            debug!(slot, num_requests = requests.len(), "Processing first inclusion requests");

            let mut batch_constraints: Vec<crate::primitives::SignedConstraints> = Vec::new();

            for (request, response, start) in requests {
                // Determine the constraint signing public key for this request
                let available_pubkeys = self.constraint_signer.available_pubkeys();
                let signing_pubkey = if self.unsafe_skip_consensus_checks {
                    available_pubkeys.iter().min().cloned().expect("at least one available pubkey")
                } else {
                    // 🕐 FIRST INCLUSION TIMING: Skip deadline validation since first inclusion
                    // is processed after commitment deadline by design (500ms delay)
                    let validator_pubkey = match self
                        .consensus
                        .find_validator_pubkey_for_slot(request.slot)
                    {
                        Ok(pubkey) => {
                            debug!(
                                slot = request.slot,
                                "✅ First inclusion: found validator pubkey for slot"
                            );
                            pubkey
                        }
                        Err(err) => {
                            warn!(?err, slot = request.slot, "Consensus: failed to find validator pubkey for first inclusion request");
                            let _ = response.send(Err(CommitmentError::Consensus(err)));
                            continue;
                        }
                    };

                    let Some(signing_key) = self
                        .constraints_client
                        .find_signing_key(validator_pubkey, available_pubkeys)
                    else {
                        error!(slot, "No available public key to sign constraints with");
                        let _ = response.send(Err(CommitmentError::Internal));
                        continue;
                    };

                    signing_key
                };

                // 🔍 FIRST INCLUSION VALIDATION: Verify signer and access list subset
                let validation_result = self.validate_first_inclusion_request(&request);
                match validation_result {
                    Ok(_) => {
                        debug!(slot, ?request.signer, "✅ First inclusion validation passed");
                    }
                    Err(error_msg) => {
                        warn!(slot, ?request.signer, error = %error_msg, "❌ First inclusion validation failed");
                        let _ = response.send(Err(CommitmentError::Internal));
                        continue;
                    }
                }

                // Create constraints for first inclusion request transactions
                let mut failed_signing = false;
                for tx in &request.txs {
                    let mut message =
                        ConstraintsMessage::from_tx(signing_pubkey.clone(), slot, tx.clone());
                    // 🔝 FIRST INCLUSION: Set top: true for first inclusion constraints
                    message.top = true;
                    info!(
                        slot,
                        tx_hash = %tx.hash(),
                        top = %message.top,
                        "🔝 SIDECAR: Created First Inclusion constraint with top=true"
                    );
                    let digest = message.digest();

                    let signature_result = match &self.constraint_signer {
                        crate::signer::SignerBLS::Local(signer) => {
                            signer.sign_commit_boost_root(digest)
                        }
                        crate::signer::SignerBLS::CommitBoost(signer) => {
                            signer.sign_commit_boost_root(digest).await
                        }
                        crate::signer::SignerBLS::Keystore(signer) => {
                            signer.sign_commit_boost_root(digest, &signing_pubkey)
                        }
                    };

                    let signed_constraints = match signature_result {
                        Ok(signature) => {
                            crate::primitives::SignedConstraints { message, signature }
                        }
                        Err(e) => {
                            error!(?e, "Failed to sign constraints for first inclusion request");
                            failed_signing = true;
                            break;
                        }
                    };

                    batch_constraints.push(signed_constraints);
                }

                // If signing failed, send error response and continue to next request
                if failed_signing {
                    let _ = response.send(Err(CommitmentError::Internal));
                    continue;
                }

                // Sign and commit the request
                match request.commit_and_sign(&self.commitment_signer).await {
                    Ok(commitment) => {
                        debug!(slot, elapsed = ?start.elapsed(), "First inclusion commitment signed and sent");
                        let _ = response.send(Ok(SignedCommitment::FirstInclusion(commitment)));
                    }
                    Err(err) => {
                        error!(?err, "Failed to sign first inclusion commitment");
                        let _ = response.send(Err(CommitmentError::Internal));
                    }
                }
            }

            // Submit first inclusion constraints to bolt-boost
            if !batch_constraints.is_empty() {
                let constraints_client = std::sync::Arc::new(self.constraints_client.clone());
                let constraints = std::sync::Arc::new(batch_constraints);

                debug!(
                    slot,
                    num_constraints = constraints.len(),
                    "Submitting first inclusion constraints to bolt-boost"
                );

                tokio::spawn(crate::common::backoff::retry_with_backoff(
                    Some(10),
                    None,
                    move || {
                        let constraints_client = std::sync::Arc::clone(&constraints_client);
                        let constraints = std::sync::Arc::clone(&constraints);
                        async move {
                            match constraints_client.submit_constraints(constraints.as_ref()).await
                            {
                                Ok(_) => {
                                    debug!("Successfully submitted first inclusion constraints");
                                    Ok(())
                                }
                                Err(e) => {
                                    error!(err = ?e, "Failed to submit first inclusion constraints, retrying...");
                                    Err(e)
                                }
                            }
                        }
                    },
                ));
            }
        } else {
            debug!(slot, "No pending first inclusion requests for this slot");
        }

        // Clean up old deadline timestamps
        let current_slot = self.consensus.latest_slot();
        self.commitment_deadline_timestamps.retain(|&s, _| s >= current_slot.saturating_sub(2));
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
        // Record the commitment deadline timestamp for first inclusion processing
        self.commitment_deadline_timestamps.insert(slot, Instant::now());

        let Some(template) = self.execution.get_block_template(slot) else {
            // Nothing to do then. Block templates are created only when constraints are added,
            // which means we haven't issued any commitment for this slot because we are
            // (probably) not the proposer for this block.

            return;
        };

        info!(
            slot,
            constraint_count = template.signed_constraints_list.len(),
            "⏰ SIDECAR: Commitment deadline reached, building local block and submitting constraints"
        );

        if let Err(e) = self.local_builder.build_new_local_payload(slot, template).await {
            error!(err = ?e, "Error while building local payload at deadline for slot {slot}");
        };

        let constraints = Arc::new(template.signed_constraints_list.clone());
        let constraints_client = Arc::new(self.constraints_client.clone());

        // Send constraints with BLS signatures to bolt-boost
        info!(
            slot,
            constraint_count = constraints.len(),
            "📡 SIDECAR: Sending submit_constraints to bolt-boost"
        );

        tokio::spawn(retry_with_backoff(Some(10), None, move || {
            let constraints_client = Arc::clone(&constraints_client);
            let constraints = Arc::clone(&constraints);

            info!("📡 SIDECAR: TEMP LOG Fix ExclusionCommitment processing, and then fix it");

            async move {
                match constraints_client.submit_constraints(constraints.as_ref()).await {
                    Ok(_) => {
                        info!(
                            constraint_count = constraints.len(),
                            "✅ SIDECAR: Successfully submitted constraints to bolt-boost"
                        );
                        Ok(())
                    }
                    Err(e) => {
                        error!(err = ?e, "❌ SIDECAR: Failed to submit constraints to bolt-boost, retrying...");
                        Err(e)
                    }
                }
            }
        }));

        // Wait 500ms before processing first inclusion requests
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Fix ExclusionCommitment processing, and then fix it
        // Schedule first inclusion processing after the additional interval
        self.handle_first_inclusion_deadline(slot).await;
        // self.schedule_first_inclusion_processing(slot).await;
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
            .field(
                "pending_first_inclusion_requests",
                &format!("{} slots", self.pending_first_inclusion_requests.len()),
            )
            .field(
                "commitment_deadline_timestamps",
                &format!("{} slots", self.commitment_deadline_timestamps.len()),
            )
            .field("first_inclusion_timer_interval", &self.first_inclusion_timer_interval)
            .field("first_inclusion_deadline", &self.first_inclusion_deadline.is_some())
            .finish()
    }
}
