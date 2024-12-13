use clap::Args;
use reqwest::Url;
use serde::Deserialize;

use crate::common::secrets::EcdsaSecretKeyWrapper;

/// Default port for the JSON-RPC server exposed by the sidecar supporting the Commitments API.
///
/// 8017 -> BOLT :)
pub const DEFAULT_RPC_PORT: u16 = 8017;

/// Command-line options for signing constraint messages
#[derive(Args, Deserialize, Debug, Clone)]
pub struct CommitmentOpts {
    /// Port to listen on for incoming JSON-RPC requests of the Commitments API.
    /// This port should be open on your firewall in order to receive external requests!
    #[clap(long, env = "BOLT_SIDECAR_PORT")]
    pub port: Option<u16>,
    /// Comma-separated list of allowed RPC addresses to subscribe via websocket to receive
    /// incoming commitments requests.
    #[clap(
        long,
        env = "BOLT_SIDECAR_FIREWALL_RPCS",
        value_delimiter = ',',
        conflicts_with("port")
    )]
    pub firewall_rpcs: Option<Vec<Url>>,
    /// Secret ECDSA key used to sign commitment messages on behalf of your validators.
    /// This MUST be set to the private key of your operator address registered in a restaking protocol.
    #[clap(long, env = "BOLT_SIDECAR_COMMITMENT_PRIVATE_KEY")]
    pub operator_private_key: EcdsaSecretKeyWrapper,
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use reqwest::Url;

    #[derive(Parser)]
    struct TestCommitmentOpts {
        /// Matches [CommitmentOpts.firewall_rpc_list]
        #[clap(long, env = "RPC", value_delimiter = ',')]
        firewall_rpc_list: Option<Vec<Url>>,
        /// Captures extra arguments like the name of the test being run
        #[clap(allow_hyphen_values = true, trailing_var_arg = true)]
        pub extra_args: Option<Vec<String>>,
    }

    #[test]
    fn test_parse_rpc_urls() {
        let url_0 = "http://localhost:8080";
        let url_1 = "http://localhost:8081";
        let urls: Vec<Url> = [url_0, url_1].iter().map(|u| u.parse().expect("valid url")).collect();

        std::env::set_var("RPC", format!("{},{}", url_0, url_1));
        let opts = TestCommitmentOpts::parse();

        assert_eq!(opts.firewall_rpc_list, Some(urls));
    }
}
