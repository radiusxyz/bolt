use alloy_rpc_types_engine::ClientCode;

/// Parse engine hints from Geth execution clients.
pub mod geth;

/// Parse engine hints from Nethermind execution clients.
pub mod nethermind;

/// Parse engine hints from the given execution client.
pub fn parse_hint_from_engine_response(client: ClientCode, error: &str) -> Option<String> {
    match client {
        ClientCode::GE => geth::parse_geth_engine_error_hint(error),
        ClientCode::NM => nethermind::parse_nethermind_engine_error_hint(error),
        _ => None,
    }
}
