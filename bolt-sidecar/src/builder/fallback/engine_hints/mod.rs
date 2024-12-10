use alloy_rpc_types_engine::ClientCode;
use tracing::error;

use crate::builder::BuilderError;

use super::engine_hinter::EngineApiHint;

/// Parse engine hints from Geth execution clients.
mod geth;

/// Parse engine hints from Nethermind execution clients.
mod nethermind;

/// Tries to parse engine hints from the given execution client and error response.
///
/// * Returns Ok(None) if no hint could be parsed.
/// * Returns an error if the execution client is not supported.
pub fn parse_hint_from_engine_response(
    client: ClientCode,
    error: &str,
) -> Result<Option<EngineApiHint>, BuilderError> {
    match client {
        ClientCode::GE => geth::parse_geth_engine_error_hint(error),
        // TODO: Add Nethermind engine hints parsing
        // ClientCode::NM => nethermind::parse_nethermind_engine_error_hint(error),
        _ => {
            error!("Unsupported fallback execution client: {}", client.client_name());
            Err(BuilderError::UnsupportedEngineClient(client))
        }
    }
}
