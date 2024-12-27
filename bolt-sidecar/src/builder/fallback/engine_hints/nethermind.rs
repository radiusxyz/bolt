use alloy::primitives::{Bloom, B256};
use hex::FromHex;
use lazy_static::lazy_static;
use regex::Regex;

use crate::builder::{fallback::engine_hinter::EngineApiHint, BuilderError};

lazy_static! {
    /// Capture the "got" value from the error message
    static ref REGEX: Regex = Regex::new(r"got ([0-9a-zA-Z]+)").expect("valid regex");
}

/// Parse a hinted value from the engine response.
/// An example error message from the engine API looks like this:
///
/// ```json
/// {
///     "jsonrpc": "2.0",
///     "id": 1,
///     "error": {
///         "code":-32000,
///          "message": "HeaderGasUsedMismatch: Gas used in header does not match calculated. Expected 0, got 21000"
///     }
/// }
/// ```
pub fn parse_nethermind_engine_error_hint(
    error: &str,
) -> Result<Option<EngineApiHint>, BuilderError> {
    let raw_hint_value = match REGEX.captures(error).and_then(|cap| cap.get(1)) {
        Some(matched) => matched.as_str().to_string(),
        None => return Ok(None),
    };

    // Match the hint value to the corresponding hint type based on other parts of the error message
    if error.contains("InvalidHeaderHash") {
        return Ok(Some(EngineApiHint::BlockHash(B256::from_hex(raw_hint_value)?)));
    } else if error.contains("HeaderGasUsedMismatch") {
        return Ok(Some(EngineApiHint::GasUsed(raw_hint_value.parse()?)));
    } else if error.contains("InvalidStateRoot") {
        return Ok(Some(EngineApiHint::StateRoot(B256::from_hex(raw_hint_value)?)));
    } else if error.contains("InvalidReceiptsRoot") {
        return Ok(Some(EngineApiHint::ReceiptsRoot(B256::from_hex(raw_hint_value)?)));
    } else if error.contains("InvalidLogsBloom") {
        return Ok(Some(EngineApiHint::LogsBloom(Bloom::from_hex(&raw_hint_value)?)));
    };

    Ok(None)
}
