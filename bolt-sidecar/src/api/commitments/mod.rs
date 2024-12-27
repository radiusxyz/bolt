/// The logic to accept commitments via firewall delegation, where a proposer specifies a list of
/// RPC URLs from which it will accept commitments via a websocket connection.
pub mod delegation;

/// The Commitments-API server implementation.
pub mod server;
