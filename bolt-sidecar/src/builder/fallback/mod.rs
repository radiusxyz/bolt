/// Fallback block builder for when the PBS stack doesn't yield a valid block.
pub mod payload_builder;
pub use payload_builder::FallbackPayloadBuilder;

/// Engine hinter for parsing hints from execution clients engine API responses.
mod engine_hinter;
pub use engine_hinter::EngineHinter;

/// Utilities for parsing engine hints from different execution clients types.
mod engine_hints;

/// Extra-data payload field used for locally built blocks, decoded in UTF-8.
///
/// Corresponds to the string "Self-built with Bolt". It can be max 32 bytes
pub const DEFAULT_EXTRA_DATA: [u8; 20] = [
    0x53, 0x65, 0x6c, 0x66, 0x2d, 0x62, 0x75, 0x69, 0x6c, 0x74, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20,
    0x42, 0x6f, 0x6c, 0x74,
];
