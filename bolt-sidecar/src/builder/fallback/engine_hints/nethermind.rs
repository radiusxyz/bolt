use crate::builder::{fallback::engine_hinter::EngineApiHint, BuilderError};

/// Parse a hinted value from the engine response.
/// An example error message from the engine API looks like this:
///
/// ```json
/// {
///     "jsonrpc": "2.0",
///     "id": 1,
///     "error": {
///         "code":-32000,
///          "message": "local: blockhash mismatch: got 0x... expected 0x..."
///     }
/// }
/// ```
///
/// Nethermind Reference:
/// TODO
pub fn parse_nethermind_engine_error_hint(
    error: &str,
) -> Result<Option<EngineApiHint>, BuilderError> {
    dbg!(&error);

    Ok(None)
}
