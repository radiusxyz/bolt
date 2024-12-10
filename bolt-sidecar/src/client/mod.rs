/// Module for interacting with the Constraints client API via its Builder API interface.
/// The Bolt sidecar's main purpose is to sit between the beacon node and Constraints client,
/// so most requests are simply proxied to its API.
pub mod constraints;
pub use constraints::ConstraintsClient;

/// Module defining an execution layer client wrapper around [`alloy::rpc::client::RpcClient`]
/// for extending the [`alloy::providers::RootProvider`] with methods relevant to the Bolt state.
pub mod execution;
pub use execution::ExecutionClient;

/// Module defining a beacon chain client for fetching information from the beacon node API.
/// It extends the [`beacon_api_client::mainnet::Client`] with custom error handling and methods.
pub mod beacon;
pub use beacon::BeaconClient;

/// Module defining an Engine API client with a JWT authentication layer. Allows us to extend
/// the Alloy API with custom methods and error handling.
pub mod engine;
pub use engine::EngineClient;
