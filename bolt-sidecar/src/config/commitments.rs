use clap::{ArgGroup, Args};
use reqwest::Url;
use serde::Deserialize;

use crate::common::secrets::EcdsaSecretKeyWrapper;

/// Default port for the JSON-RPC server exposed by the sidecar supporting the Commitments API.
///
/// 8017 -> BOLT :)
pub const DEFAULT_RPC_PORT: u16 = 8017;

/// Command-line options for signing constraint messages
#[derive(Args, Deserialize, Debug, Clone)]
#[clap(
    group = ArgGroup::new("commitments-opts").required(true)
        .args(&["commitments_port", "firewall_rpc"])
)]
pub struct CommitmentOpts {
    /// Port to listen on for incoming JSON-RPC requests of the Commitments API.
    /// This port should be open on your firewall in order to receive external requests!
    #[clap(long, env = "BOLT_SIDECAR_PORT", default_value = stringify!(DEFAULT_RPC_PORT))]
    pub port: Option<u16>,
    /// Comma-separated list of allowed RPC addresses to subscribe via websocket to receive
    /// incoming commitments requests.
    #[clap(long, env = "BOLT_SIDECAR_FIREWALL_RPC", conflicts_with("commitments_port"))]
    pub firewall_rpc_list: Option<Vec<Url>>,
    /// Secret ECDSA key used to sign commitment messages on behalf of your validators.
    /// This MUST be set to the private key of your operator address registered in a restaking protocol.
    #[clap(long, env = "BOLT_SIDECAR_COMMITMENT_PRIVATE_KEY")]
    pub operator_private_key: EcdsaSecretKeyWrapper,
}
