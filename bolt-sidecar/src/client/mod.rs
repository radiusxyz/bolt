/// Module for interacting with the Constraints client API via its Builder API interface.
/// The Bolt sidecar's main purpose is to sit between the beacon node and Constraints client,
/// so most requests are simply proxied to its API.
pub mod constraints_client;
pub use constraints_client::ConstraintsClient;

/// Module defining an RpcClient wrapper around the [`alloy::rpc::client::RpcClient`].
/// It provides a simple interface to interact with the Execution layer JSON-RPC API.
pub mod rpc;
pub use rpc::RpcClient;

// Re-export the beacon_api_client
pub use beacon_api_client::mainnet::Client as BeaconClient;
