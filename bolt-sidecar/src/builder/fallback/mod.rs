use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_rpc_types_engine::{Claims, JwtSecret};
use axum::http::HeaderValue;

pub mod payload_builder;
pub use payload_builder::FallbackPayloadBuilder;

mod engine_hinter;
pub use engine_hinter::EngineHinter;

mod engine_hints;

/// Extra-data payload field used for locally built blocks, decoded in UTF-8.
///
/// Corresponds to the string "Self-built with Bolt". It can be max 32 bytes
pub const DEFAULT_EXTRA_DATA: [u8; 20] = [
    0x53, 0x65, 0x6c, 0x66, 0x2d, 0x62, 0x75, 0x69, 0x6c, 0x74, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20,
    0x42, 0x6f, 0x6c, 0x74,
];

/// Helper function to convert a secret into a Bearer auth header value with claims according to
/// <https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md#jwt-claims>.
/// The token is valid for 60 seconds.
pub fn secret_to_bearer_header(secret: &JwtSecret) -> HeaderValue {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("time went backwards");
    let claims = Claims { iat: (now + Duration::from_secs(60)).as_secs(), exp: None };

    let token = secret.encode(&claims).expect("valid jwt token");
    format!("Bearer {}", token).parse().expect("valid header value")
}
