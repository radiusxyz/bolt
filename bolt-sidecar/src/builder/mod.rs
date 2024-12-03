use alloy::primitives::U256;
use beacon_api_client::mainnet::Client as BeaconClient;
use ethereum_consensus::{
    crypto::{KzgCommitment, PublicKey},
    deneb::mainnet::ExecutionPayloadHeader,
    ssz::prelude::{List, MerkleizationError},
};

use crate::{
    common::secrets::BlsSecretKeyWrapper,
    config::{ChainConfig, Opts},
    primitives::{
        BuilderBid, GetPayloadResponse, PayloadAndBid, PayloadAndBlobs, SignedBuilderBid,
    },
};

/// Basic block template handler that can keep track of
/// the local commitments according to protocol validity rules.
///
/// The built template can be used as a fallback block in case of no valid
/// response from all relays.
pub mod template;
pub use template::BlockTemplate;

/// Builder payload signing utilities
pub mod signature;
use signature::sign_builder_message;

/// Fallback Payload builder agent that leverages the engine API's
/// `engine_newPayloadV3` response error to produce a valid payload.
pub mod payload_builder;
use payload_builder::FallbackPayloadBuilder;

/// Interface for fetching payloads from the beacon node.
pub mod payload_fetcher;
pub use payload_fetcher::{LocalPayloadFetcher, PayloadFetcher};

/// Compatibility types and utilities between Alloy, Reth,
/// Ethereum-consensus and other crates.
#[doc(hidden)]
mod compat;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum BuilderError {
    #[error("Failed to parse from integer: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Failed to de/serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Failed to decode hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Invalid JWT: {0}")]
    Jwt(#[from] alloy_rpc_types_engine::JwtError),
    #[error("Failed HTTP request: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed while fetching from RPC: {0}")]
    Transport(#[from] alloy::transports::TransportError),
    #[error("Failed in SSZ merkleization: {0}")]
    Merkleization(#[from] MerkleizationError),
    #[error("Failed while interacting with beacon client: {0}")]
    BeaconApi(#[from] beacon_api_client::Error),
    #[error("Failed to parse hint from engine response: {0}")]
    InvalidEngineHint(String),
    #[error("Failed to build payload: {0}")]
    Custom(String),
}

/// Local builder instance that can ingest a sealed header and
/// create the corresponding builder bid ready for the Builder API.
#[derive(Debug)]
pub struct LocalBuilder {
    /// BLS credentials for the local builder. We use this to sign the
    /// payload bid submissions built by the sidecar.
    secret_key: BlsSecretKeyWrapper,
    /// Chain configuration
    /// (necessary for signing messages with the correct domain)
    chain: ChainConfig,
    /// Async fallback payload builder to generate valid payloads with
    /// the engine API's `engine_newPayloadV3` response error.
    fallback_builder: FallbackPayloadBuilder,
    /// The last payload and bid that was built by the local builder.
    payload_and_bid: Option<PayloadAndBid>,
}

impl LocalBuilder {
    /// Create a new local builder with the given secret key.
    pub fn new(opts: &Opts, beacon_api_client: BeaconClient, genesis_time: u64) -> Self {
        Self {
            payload_and_bid: None,
            fallback_builder: FallbackPayloadBuilder::new(opts, beacon_api_client, genesis_time),
            secret_key: opts.builder_private_key.clone(),
            chain: opts.chain,
        }
    }

    /// Build a new payload with the given transactions. This method will
    /// cache the payload in the local builder instance, and make it available
    pub async fn build_new_local_payload(
        &mut self,
        slot: u64,
        template: &BlockTemplate,
    ) -> Result<(), BuilderError> {
        let transactions = template.as_signed_transactions();
        let blobs_bundle = template.as_blobs_bundle();
        let kzg_commitments = blobs_bundle.commitments.clone();

        // 1. build a fallback payload with the given transactions, on top of
        // the current head of the chain
        let block = self.fallback_builder.build_fallback_payload(slot, &transactions).await?;

        // NOTE: we use a big value for the bid to ensure it gets chosen by constraints client.
        // the client has no way to actually verify this, and we don't need to trust
        // an external relay as this block is self-built, so the fake bid value is fine.
        //
        // NOTE: we don't strictly need this. The validator & beacon nodes have options
        // to ALWAYS prefer PBS blocks. This is a safety measure that doesn't hurt to keep.
        let value = U256::from(100_000_000_000_000_000_000u128);

        let execution_payload = compat::to_consensus_execution_payload(&block);
        let payload_and_blobs = PayloadAndBlobs { execution_payload, blobs_bundle };

        // 2. create a builder bid with the sealed block header we just created
        let eth_header = compat::to_execution_payload_header(&block, transactions);

        // 3. sign the bid with the local builder's BLS key
        let signed_bid = self.create_signed_builder_bid(value, eth_header, kzg_commitments)?;

        // 4. prepare a get_payload response
        let get_payload_response = GetPayloadResponse::from(payload_and_blobs);

        // 5. cache the payload and bid in the local builder instance for it
        // to be fetched by the beacon node later
        self.payload_and_bid =
            Some(PayloadAndBid { bid: signed_bid, payload: get_payload_response });

        Ok(())
    }

    /// Get the cached payload and bid from the local builder, consuming the value.
    #[inline]
    pub fn get_cached_payload(&mut self) -> Option<PayloadAndBid> {
        self.payload_and_bid.take()
    }

    /// transform a sealed header into a signed builder bid using
    /// the local builder's BLS key.
    fn create_signed_builder_bid(
        &self,
        value: U256,
        header: ExecutionPayloadHeader,
        blob_kzg_commitments: Vec<KzgCommitment>,
    ) -> Result<SignedBuilderBid, BuilderError> {
        // compat: convert from blst to ethereum consensus types
        let pubkey = self.secret_key.sk_to_pk().to_bytes();
        let consensus_pubkey = PublicKey::try_from(pubkey.as_slice()).expect("valid pubkey bytes");
        let blob_kzg_commitments = List::try_from(blob_kzg_commitments).expect("valid list");

        let message =
            BuilderBid { header, blob_kzg_commitments, public_key: consensus_pubkey, value };

        let signature = sign_builder_message(&self.chain, &self.secret_key, &message)?;

        Ok(SignedBuilderBid { message, signature })
    }
}
