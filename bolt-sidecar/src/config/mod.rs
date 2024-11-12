use std::env;

use alloy::primitives::Address;
use clap::Parser;
use reqwest::Url;
use serde::Deserialize;

/// Chain configuration options.
pub mod chain;
pub use chain::ChainConfig;

/// Commitment and constraint signing related options.
pub mod constraint_signing;
pub use constraint_signing::ConstraintSigningOpts;

/// Telemetry and metrics related options.
pub mod telemetry;
use telemetry::TelemetryOpts;

/// Operating limits for commitments and constraints.
pub mod limits;
use limits::LimitsOpts;
use tracing::debug;

use crate::common::{BlsSecretKeyWrapper, EcdsaSecretKeyWrapper, JwtSecretConfig};

/// Default port for the JSON-RPC server exposed by the sidecar supporting the Commitments API.
///
/// 8017 -> BOLT :)
pub const DEFAULT_RPC_PORT: u16 = 8017;

/// Default port for the Constraints proxy server, binded to the default port used by MEV-Boost.
pub const DEFAULT_CONSTRAINTS_PROXY_PORT: u16 = 18550;

/// Command-line options for the Bolt sidecar
#[derive(Debug, Parser, Deserialize)]
pub struct Opts {
    /// Port to listen on for incoming JSON-RPC requests of the Commitments API.
    /// This port should be open on your firewall in order to receive external requests!
    #[clap(long, env = "BOLT_SIDECAR_PORT", default_value_t = DEFAULT_RPC_PORT)]
    pub port: u16,
    /// Execution client API URL
    #[clap(long, env = "BOLT_SIDECAR_EXECUTION_API_URL", default_value = "http://localhost:8545")]
    pub execution_api_url: Url,
    /// URL for the beacon client
    #[clap(long, env = "BOLT_SIDECAR_BEACON_API_URL", default_value = "http://localhost:5052")]
    pub beacon_api_url: Url,
    /// Execution client Engine API URL. This is needed for fallback block building and must be a
    /// synced Geth node.
    #[clap(long, env = "BOLT_SIDECAR_ENGINE_API_URL", default_value = "http://localhost:8551")]
    pub engine_api_url: Url,
    /// URL to forward the constraints produced by the Bolt sidecar to a server supporting the
    /// Constraints API, such as an MEV-Boost fork.
    #[clap(
        long,
        env = "BOLT_SIDECAR_CONSTRAINTS_API_URL",
        default_value = "http://localhost:18551"
    )]
    pub constraints_api_url: Url,
    /// The port from which the Bolt sidecar will receive Builder-API requests from the
    /// Beacon client
    #[clap(
        long,
        env = "BOLT_SIDECAR_CONSTRAINTS_PROXY_PORT",
        default_value_t = DEFAULT_CONSTRAINTS_PROXY_PORT
    )]
    pub constraints_proxy_port: u16,
    /// The JWT secret token to authenticate calls to the engine API.
    ///
    /// It can either be a hex-encoded string or a file path to a file
    /// containing the hex-encoded secret.
    #[clap(long, env = "BOLT_SIDECAR_ENGINE_JWT_HEX")]
    pub engine_jwt_hex: JwtSecretConfig,
    /// The fee recipient address for fallback blocks
    #[clap(long, env = "BOLT_SIDECAR_FEE_RECIPIENT")]
    pub fee_recipient: Address,
    /// Secret BLS key to sign fallback payloads with
    #[clap(long, env = "BOLT_SIDECAR_BUILDER_PRIVATE_KEY")]
    pub builder_private_key: BlsSecretKeyWrapper,
    /// Secret ECDSA key to sign commitment messages with. The public key associated to it must be
    /// then used when registering the operator in the `BoltManager` contract.
    #[clap(long, env = "BOLT_SIDECAR_COMMITMENT_PRIVATE_KEY")]
    pub commitment_private_key: EcdsaSecretKeyWrapper,
    /// Operating limits for the sidecar
    #[clap(flatten)]
    #[serde(default)]
    pub limits: LimitsOpts,
    /// Chain config for the chain on which the sidecar is running
    #[clap(flatten)]
    pub chain: ChainConfig,
    /// Constraint signing options
    #[clap(flatten)]
    pub constraint_signing: ConstraintSigningOpts,
    /// Telemetry options
    #[clap(flatten)]
    pub telemetry: TelemetryOpts,

    /// Additional unrecognized arguments. Useful for CI and testing
    /// to avoid issues on potential extra flags provided (e.g. "--exact" from cargo nextest).
    #[cfg(test)]
    #[clap(allow_hyphen_values = true, trailing_var_arg = true)]
    #[serde(default)]
    pub extra_args: Vec<String>,
}

/// It removes environment variables that are set as empty strings, i.e. like `MY_VAR=`. This is
/// useful to avoid unexpected edge cases and because we don't have options that make sense with an
/// empty string value.
pub fn remove_empty_envs() -> eyre::Result<()> {
    for item in env::vars() {
        let (key, val) = item;
        if val.trim().is_empty() {
            debug!("removing empty env var: {}", key);
            std::env::remove_var(key)
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use dotenvy::dotenv;

    use super::*;

    #[test]
    #[ignore = "Doesn't need to run in CI, only for local development"]
    fn test_remove_empty_envs() {
        let _ = dotenv().expect("to load .env file");
        remove_empty_envs().expect("to remove empty envs");
        let opts = Opts::parse();
        println!("{:#?}", opts);
    }

    #[test]
    fn test_validate_cli_flags() {
        use clap::CommandFactory;
        Opts::command().debug_assert();
    }

    #[test]
    fn test_parse_url() {
        let url = "http://0.0.0.0:3030";
        let parsed = url.parse::<Url>().unwrap();
        let socket_addr = parsed.socket_addrs(|| None).unwrap()[0];
        let localhost_socket = "0.0.0.0:3030".parse().unwrap();
        assert_eq!(socket_addr, localhost_socket);
    }
}
