use regex::Regex;

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
/// Geth Reference:
/// - [ValidateState](<https://github.com/ethereum/go-ethereum/blob/9298d2db884c4e3f9474880e3dcfd080ef9eacfa/core/block_validator.go#L122-L151>)
/// - [Blockhash Mismatch](<https://github.com/ethereum/go-ethereum/blob/9298d2db884c4e3f9474880e3dcfd080ef9eacfa/beacon/engine/types.go#L253-L256>)
pub fn parse_geth_engine_error_hint(error: &str) -> Option<String> {
    // Capture either the "local" or "got" value from the error message
    let re = Regex::new(r"(?:local:|got) ([0-9a-zA-Z]+)").expect("valid regex");

    re.captures(error)
        .and_then(|capture| capture.get(1).map(|matched| matched.as_str().to_string()))
}
