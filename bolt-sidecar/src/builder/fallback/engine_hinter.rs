use alloy::{
    consensus::EMPTY_OMMER_ROOT_HASH,
    primitives::{Bloom, B256, B64, U256},
    rpc::types::Block,
};
use alloy_rpc_types_engine::{ClientCode, ClientVersionV1, ExecutionPayload, JwtSecret};
use hex::FromHex;
use reqwest::Url;
use reth_primitives::Header as RethHeader;
use tracing::trace;

use crate::builder::BuilderError;

use super::secret_to_bearer_header;

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

/// The collection of hints that can be fetched from the engine API
/// via the [EngineHinter] to complete the sealed block.
///
/// When a field is `None`, we set it to its default value in the [ExecutionPayload]
/// and try to get the hint from the engine API response to fill its value.
#[derive(Debug, Default)]
struct Hints {
    pub gas_used: Option<u64>,
    pub receipts_root: Option<B256>,
    pub logs_bloom: Option<Bloom>,
    pub state_root: Option<B256>,
    pub block_hash: Option<B256>,
}

/// Engine API hint values that can be fetched from the engine API
/// to complete the sealed block. These hints are used to fill in
/// missing values in the block header.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum EngineApiHint {
    BlockHash(B256),
    GasUsed(u64),
    StateRoot(B256),
    ReceiptsRoot(B256),
    LogsBloom(Bloom),
    ValidPayload,
}

impl EngineHinter {
    /// Create a new [EngineHinter] instance with the given JWT and engine RPC URL.
    pub fn new(jwt_hex: String, engine_rpc_url: Url) -> Self {
        Self { client: reqwest::Client::new(), jwt_hex, engine_rpc_url }
    }

    /// Yield the next hint from the engine API to complete the sealed block.
    ///
    /// Returns `Ok(None)` if the payload is valid and no more hints are needed.
    pub async fn next_hint(&self) -> Result<Option<EngineApiHint>, BuilderError> {
        // 1. Fetch the execution client info from the engine API
        let el_client_info = self.engine_client_info().await?;

        // 2. Fetch the next payload hint from the engine API's `newPayloadV3` method
        let raw_payload_response =
            self.engine_new_payload(exec_payload, versioned_hashes, parent_beacon_root).await?;

        // 3. Parse the hint from the engine API response, based on the client info
        parse_hint_from_engine_response(&el_client_info)
    }
}

impl EngineHinter {
    /// Fetch the next payload hint from the engine API to complete the sealed block.
    pub async fn fetch_next_payload_hint(
        &self,
        exec_payload: &ExecutionPayload,
        versioned_hashes: &[B256],
        parent_beacon_root: B256,
    ) -> Result<EngineApiHint, BuilderError> {
        let raw_payload_response =
            self.engine_new_payload(exec_payload, versioned_hashes, parent_beacon_root).await?;

        // let Some(hint_value) = parse_geth_response(&raw_hint) else {
        //     // If the hint is not found, it means that we likely got a VALID
        //     // payload response or an error message that we can't parse.
        //     if raw_hint.contains("\"status\":\"VALID\"") {
        //         return Ok(EngineApiHint::ValidPayload);
        //     }
        //     return Err(BuilderError::InvalidEngineHint(raw_hint));
        // };

        // trace!("engine hint: {:?}", raw_hint);

        // // Match the hint value to the corresponding header field and return it
        // if raw_hint.contains("blockhash mismatch") {
        //     return Ok(EngineApiHint::BlockHash(B256::from_hex(hint_value)?));
        // } else if raw_hint.contains("invalid gas used") {
        //     return Ok(EngineApiHint::GasUsed(hint_value.parse()?));
        // } else if raw_hint.contains("invalid merkle root") {
        //     return Ok(EngineApiHint::StateRoot(B256::from_hex(hint_value)?));
        // } else if raw_hint.contains("invalid receipt root hash") {
        //     return Ok(EngineApiHint::ReceiptsRoot(B256::from_hex(hint_value)?));
        // } else if raw_hint.contains("invalid bloom") {
        //     return Ok(EngineApiHint::LogsBloom(Bloom::from_hex(&hint_value)?));
        // };

        Err(BuilderError::Custom(
            "Unexpected: failed to parse any hint from engine response".to_string(),
        ))
    }

    /// Perform an engine API `newPayloadV3` request and return the stringified response.
    pub async fn engine_new_payload(
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

/// Build a header with the given hints and context values.
fn build_header_with_hints_and_context(
    latest_block: &Block,
    hints: &Hints,
    context: &Context,
) -> RethHeader {
    // Use the available hints, or default to an empty value if not present.
    let gas_used = hints.gas_used.unwrap_or_default();
    let receipts_root = hints.receipts_root.unwrap_or_default();
    let logs_bloom = hints.logs_bloom.unwrap_or_default();
    let state_root = hints.state_root.unwrap_or_default();

    RethHeader {
        parent_hash: latest_block.header.hash,
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: context.fee_recipient,
        state_root,
        transactions_root: context.transactions_root,
        receipts_root,
        withdrawals_root: Some(context.withdrawals_root),
        logs_bloom,
        difficulty: U256::ZERO,
        number: latest_block.header.number + 1,
        gas_limit: latest_block.header.gas_limit,
        gas_used,
        timestamp: context.block_timestamp,
        mix_hash: context.prev_randao,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(context.base_fee),
        blob_gas_used: Some(context.blob_gas_used),
        excess_blob_gas: Some(context.excess_blob_gas),
        parent_beacon_block_root: Some(context.parent_beacon_block_root),
        extra_data: context.extra_data.clone(),
        // TODO: handle the Pectra-related fields
        requests_hash: None,
        target_blobs_per_block: None,
    }
}
