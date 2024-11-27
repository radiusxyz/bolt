/// Utilities for retrying a future with backoff.
pub mod backoff;
/// A hash map-like bounded data structure with an additional scoring mechanism.
pub mod score_cache;
/// Secret key types wrappers for BLS, ECDSA and JWT.
pub mod secrets;
/// Utility functions for working with transactions.
pub mod transactions;

/// The version of the Bolt sidecar binary.
pub const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
