use alloy::{
    consensus::EMPTY_OMMER_ROOT_HASH,
    primitives::{Address, Bloom, Bytes, B256, B64, U256},
    rpc::types::{Block, Withdrawal, Withdrawals},
};
use alloy_rpc_types_engine::{ClientCode, ClientVersionV1, ExecutionPayload, JwtSecret};
use reqwest::Url;
use reth_primitives::{
    BlockBody, Header as RethHeader, SealedBlock, SealedHeader, TransactionSigned,
};

use crate::builder::{compat::to_alloy_execution_payload, BuilderError};

use super::{engine_hints::parse_hint_from_engine_response, secret_to_bearer_header};

/// The [EngineHinter] is responsible for gathering "hints" from the
/// engine API error responses to complete the sealed block.
///
/// Since error messages are not overly standardized across execution clients,
/// we need to know which execution client is being used to properly parse the hints.
///
/// This can be done automatically by querying the EL `eth_g`
#[derive(Debug)]
pub struct EngineHinter {
    client: reqwest::Client,
    jwt_hex: String,
    engine_rpc_url: Url,
}

impl EngineHinter {
    /// Create a new [EngineHinter] instance with the given JWT and engine RPC URL.
    pub fn new(jwt_hex: String, engine_rpc_url: Url) -> Self {
        Self { client: reqwest::Client::new(), jwt_hex, engine_rpc_url }
    }

    /// Collect hints from the engine API to complete the sealed block.
    /// This method will keep fetching hints until the payload is valid.
    pub async fn fetch_payload_from_hints(
        &self,
        mut ctx: EngineHinterContext,
    ) -> Result<SealedBlock, BuilderError> {
        let body = BlockBody {
            ommers: Vec::new(),
            transactions: ctx.transactions.clone(),
            withdrawals: Some(Withdrawals::new(ctx.withdrawals.clone())),
        };

        // Loop until we get a valid payload from the engine API. On each iteration,
        // we build a new block header with the hints from the context and fetch the next hint.
        let max_iterations = 20;
        let mut iterations = 0;
        loop {
            // Build a new block header using the hints from the context
            let header = ctx.build_block_header_with_hints();

            let sealed_hash = header.hash_slow();
            let sealed_header = SealedHeader::new(header, sealed_hash);
            let sealed_block = SealedBlock::new(sealed_header, body.clone());
            let block_hash = ctx.hints.block_hash.unwrap_or(sealed_block.hash());

            // build the new execution payload from the block header
            let exec_payload = to_alloy_execution_payload(&sealed_block, block_hash);

            // fetch the next hint from the engine API and add it to the context
            let hint = self.next_hint(&exec_payload, &ctx).await?;
            ctx.hints.populate_new(hint);

            if matches!(hint, EngineApiHint::ValidPayload) {
                return Ok(sealed_block);
            }

            iterations += 1;
            if iterations >= max_iterations {
                return Err(BuilderError::Custom(
                    "Failed to get a valid payload after 20 iterations".to_string(),
                ));
            }
        }
    }

    /// Yield the next hint from the engine API by calling `engine_newPayloadV3`
    /// and parsing the response to extract the hint.
    ///
    /// Returns Ok([EngineApiHint::ValidPayload]) if the payload is valid.
    async fn next_hint(
        &self,
        exec_payload: &ExecutionPayload,
        ctx: &EngineHinterContext,
    ) -> Result<EngineApiHint, BuilderError> {
        let raw_response = self
            .engine_new_payload(
                exec_payload,
                &ctx.blob_versioned_hashes,
                ctx.parent_beacon_block_root,
            )
            .await?;

        // Parse the hint from the engine API response, based on the EL client code
        let Some(hint) = parse_hint_from_engine_response(ctx.el_client_code, &raw_response)? else {
            // Short-circuit if the payload is valid
            if raw_response.contains("\"status\":\"VALID\"") {
                return Ok(EngineApiHint::ValidPayload);
            }

            return Err(BuilderError::Custom(
                "Unexpected: failed to parse any hint from engine response".to_string(),
            ));
        };

        Ok(hint)
    }

    /// Perform an engine API `newPayloadV3` request and return the stringified response.
    async fn engine_new_payload(
        &self,
        exec_payload: &ExecutionPayload,
        versioned_hashes: &[B256],
        parent_beacon_root: B256,
    ) -> Result<String, BuilderError> {
        let auth_jwt = secret_to_bearer_header(&JwtSecret::from_hex(&self.jwt_hex)?);

        let body = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"engine_newPayloadV3","params":[{}, {}, "{:?}"]}}"#,
            serde_json::to_string(&exec_payload)?,
            serde_json::to_string(&versioned_hashes)?,
            parent_beacon_root
        );

        Ok(self
            .client
            .post(self.engine_rpc_url.as_str())
            .header("Content-Type", "application/json")
            .header("Authorization", auth_jwt)
            .body(body)
            .send()
            .await?
            .text()
            .await?)
    }

    /// Fetch the client info from the engine API.
    pub async fn engine_client_info(&self) -> Result<Vec<ClientVersionV1>, BuilderError> {
        let auth_jwt = secret_to_bearer_header(&JwtSecret::from_hex(&self.jwt_hex)?);

        // When calling the `engine_getClientVersionV1` method, the `params` field must contain
        // a `ClientVersionV1` object containing the beacon client info to be shared with the EL.
        // Ref: <https://github.com/ethereum/execution-apis/blob/main/src/engine/identification.md#clientversionv1>
        // TODO: use accurate info from the CL connection instead of mocking this
        let cl_info = ClientVersionV1 {
            code: ClientCode::LH,
            name: "BoltSidecar".to_string(),
            version: format!("v{}", env!("CARGO_PKG_VERSION")),
            commit: "deadbeef".to_string(),
        };

        let body = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"engine_getClientVersionV1","params":[{}]}}"#,
            serde_json::to_string(&cl_info)?
        );

        Ok(self
            .client
            .post(self.engine_rpc_url.as_str())
            .header("Content-Type", "application/json")
            .header("Authorization", auth_jwt)
            .body(body)
            .send()
            .await?
            .json()
            .await?)
    }
}

/// Engine API hint values that can be fetched from the engine API
/// to complete the sealed block. These hints are used to fill in
/// missing values in the block header.
#[derive(Debug, Copy, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum EngineApiHint {
    BlockHash(B256),
    GasUsed(u64),
    StateRoot(B256),
    ReceiptsRoot(B256),
    LogsBloom(Bloom),
    ValidPayload,
}

/// The collection of hints that can be fetched from the engine API
/// via the [EngineHinter] to complete the sealed block.
///
/// When a field is `None`, we set it to its default value in the [ExecutionPayload]
/// and try to get the hint from the engine API response to fill its value.
#[derive(Debug, Default)]
pub struct Hints {
    pub gas_used: Option<u64>,
    pub receipts_root: Option<B256>,
    pub logs_bloom: Option<Bloom>,
    pub state_root: Option<B256>,
    pub block_hash: Option<B256>,
}

impl Hints {
    /// Populate the new hint value in the context.
    pub fn populate_new(&mut self, hint: EngineApiHint) {
        match hint {
            EngineApiHint::ValidPayload => { /* No-op */ }

            // If we receive a block hash hint, set it and keep it for the next one.
            // This should not happen, but in case it does, it doesn't break the flow.
            EngineApiHint::BlockHash(hash) => self.block_hash = Some(hash),

            // For regular hint types, set the value and reset the block hash
            EngineApiHint::GasUsed(gas) => {
                self.gas_used = Some(gas);
                self.block_hash = None;
            }
            EngineApiHint::StateRoot(hash) => {
                self.state_root = Some(hash);
                self.block_hash = None;
            }
            EngineApiHint::ReceiptsRoot(hash) => {
                self.receipts_root = Some(hash);
                self.block_hash = None;
            }
            EngineApiHint::LogsBloom(bloom) => {
                self.logs_bloom = Some(bloom);
                self.block_hash = None;
            }
        }
    }
}

/// Context holding the necessary values for
/// building a sealed block. Some of this data is fetched from the
/// beacon chain, while others are calculated locally or from the
/// transactions themselves.
#[derive(Debug)]
pub struct EngineHinterContext {
    pub extra_data: Bytes,
    pub base_fee: u64,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
    pub prev_randao: B256,
    pub fee_recipient: Address,
    pub transactions_root: B256,
    pub withdrawals_root: B256,
    pub parent_beacon_block_root: B256,
    pub blob_versioned_hashes: Vec<B256>,
    pub block_timestamp: u64,
    pub transactions: Vec<TransactionSigned>,
    pub withdrawals: Vec<Withdrawal>,
    pub head_block: Block,
    pub hints: Hints,
    pub el_client_code: ClientCode,
}

impl EngineHinterContext {
    /// Build a header using the info from the context.
    /// Use any hints available, and default to an empty value if not present.
    pub fn build_block_header_with_hints(&self) -> RethHeader {
        // Use the available hints, or default to an empty value if not present.
        let gas_used = self.hints.gas_used.unwrap_or_default();
        let receipts_root = self.hints.receipts_root.unwrap_or_default();
        let logs_bloom = self.hints.logs_bloom.unwrap_or_default();
        let state_root = self.hints.state_root.unwrap_or_default();

        RethHeader {
            parent_hash: self.head_block.header.hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: self.fee_recipient,
            state_root,
            transactions_root: self.transactions_root,
            receipts_root,
            withdrawals_root: Some(self.withdrawals_root),
            logs_bloom,
            difficulty: U256::ZERO,
            number: self.head_block.header.number + 1,
            gas_limit: self.head_block.header.gas_limit,
            gas_used,
            timestamp: self.block_timestamp,
            mix_hash: self.prev_randao,
            nonce: B64::ZERO,
            base_fee_per_gas: Some(self.base_fee),
            blob_gas_used: Some(self.blob_gas_used),
            excess_blob_gas: Some(self.excess_blob_gas),
            parent_beacon_block_root: Some(self.parent_beacon_block_root),
            extra_data: self.extra_data.clone(),
            // TODO: handle the Pectra-related fields
            requests_hash: None,
            target_blobs_per_block: None,
        }
    }
}
