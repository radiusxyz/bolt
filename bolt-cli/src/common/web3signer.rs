use std::fs;

use eyre::{Context, Result};
use reqwest::{Certificate, Identity, Url};
use serde::{Deserialize, Serialize};

use crate::cli::Web3SignerTlsCredentials;

/// Web3Signer remote server.
///
///  Functionality:
/// - List consensus accounts in the keystore.
/// - Sign roots over the consensus type.
///
/// Reference: https://docs.web3signer.consensys.io/reference
#[derive(Clone)]
pub struct Web3Signer {
    base_url: Url,
    client: reqwest::Client,
}

impl Web3Signer {
    /// Establish connection to a remote Web3Signer instance with TLS credentials.
    pub async fn connect(addr: String, credentials: Web3SignerTlsCredentials) -> Result<Self> {
        let base_url = addr.parse()?;
        let (cert, identity) = compose_credentials(credentials)?;

        let client = reqwest::Client::builder()
            .add_root_certificate(cert)
            .identity(identity)
            .use_rustls_tls()
            .build()?;

        Ok(Self { base_url, client })
    }

    /// List the consensus accounts of the keystore.
    ///
    /// Only the consensus keys are returned.
    /// This is due to signing only being over the consensus type.
    ///
    /// Reference: https://commit-boost.github.io/commit-boost-client/api/
    pub async fn list_accounts(&mut self) -> Result<Vec<String>> {
        let path = self.base_url.join("/signer/v1/get_pubkeys")?;
        let resp = self.client.get(path).send().await?.json::<CommitBoostKeys>().await?;

        let consensus_keys: Vec<String> =
            resp.keys.into_iter().map(|key_set| key_set.consensus).collect();

        Ok(consensus_keys)
    }

    /// Request a signature from the remote signer.
    ///
    /// This will sign an arbituary root over the consensus type.
    ///
    /// Reference: https://commit-boost.github.io/commit-boost-client/api/
    pub async fn request_signature(&mut self, pub_key: &str, object_root: &str) -> Result<String> {
        let path = self.base_url.join("/signer/v1/request_signature")?;
        let body = CommitBoostRequestSignature {
            type_: "consensus".to_string(),
            pubkey: pub_key.to_string(),
            object_root: object_root.to_string(),
        };

        let resp = self.client.post(path).json(&body).send().await?.json::<String>().await?;

        Ok(resp)
    }
}

/// Compose the TLS credentials for the Web3Signer.
///
/// Returns the CA certificate and the identity (combined PEM).
fn compose_credentials(credentials: Web3SignerTlsCredentials) -> Result<(Certificate, Identity)> {
    let ca_cert = fs::read(credentials.ca_cert_path).wrap_err("Failed to read CA cert")?;
    let ca_cert = Certificate::from_pem(&ca_cert)?;

    let identity = fs::read(credentials.combined_pem_path).wrap_err("Failed to read PEM")?;
    let identity = Identity::from_pem(&identity)?;

    Ok((ca_cert, identity))
}

#[derive(Serialize, Deserialize)]
struct Keys {
    /// The consensus keys stored in the Web3Signer.
    pub consensus: String,
    /// The two below proxy fields are here for deserialisation purposes.
    /// They are not used as signing is only over the consensus type.
    #[allow(unused)]
    pub proxy_bls: Vec<String>,
    #[allow(unused)]
    pub proxy_ecdsa: Vec<String>,
}

/// Outer container for response.
#[derive(Serialize, Deserialize)]
struct CommitBoostKeys {
    keys: Vec<Keys>,
}

/// Request signature from the Web3Signer.
#[derive(Serialize, Deserialize)]
struct CommitBoostRequestSignature {
    #[serde(rename = "type")]
    pub type_: String,
    pub pubkey: String,
    pub object_root: String,
}

#[cfg(test)]
pub mod test_util {
    use std::{
        process::{Child, Command},
        time::Duration,
    };

    use crate::cli::Web3SignerTlsCredentials;
    use eyre::{bail, Ok};

    /// Start a Web3Signer server for testing.
    ///
    /// This will start a Web3Signer server and return its URL, process handle, and TLS credentials.
    pub async fn start_web3signer_test_server(
    ) -> eyre::Result<(String, Child, Web3SignerTlsCredentials)> {
        let test_data_dir = env!("CARGO_MANIFEST_DIR").to_string() + "/test_data/web3signer";

        // Keystore test data.
        let keystore_dir = test_data_dir.clone() + "/keystore";

        // TLS test data.
        let tls_dir = test_data_dir.clone() + "/tls";
        let tls_keystore = tls_dir.clone() + "/key.p12";
        let tls_password = tls_dir.clone() + "/password.txt";
        let ca_cert_path = tls_dir.clone() + "/web3signer.crt";
        let combined_pem_path = tls_dir.clone() + "/combined.pem";

        // Check if web3signer is installed (in $PATH).
        if Command::new("web3signer").spawn().is_err() {
            bail!("Web3Signer is not installed in $PATH");
        }

        // Start the web3signer server.
        let web3signer_proc = Command::new("web3signer")
            .arg("--key-store-path")
            .arg(keystore_dir.clone())
            .arg("--tls-keystore-file")
            .arg(tls_keystore)
            .arg("--tls-allow-any-client")
            .arg("true")
            .arg("--tls-keystore-password-file")
            .arg(tls_password.clone())
            .arg("eth2")
            .arg("--network")
            .arg("mainnet")
            .arg("--slashing-protection-enabled")
            .arg("false")
            .arg("--commit-boost-api-enabled")
            .arg("true")
            .arg("--proxy-keystores-path")
            .arg(keystore_dir.clone())
            .arg("--proxy-keystores-password-file")
            .arg(tls_password)
            .spawn()?;

        // Allow the server to start up.
        tokio::time::sleep(Duration::from_secs(5)).await;

        let credentials = Web3SignerTlsCredentials { ca_cert_path, combined_pem_path };
        let url = "https://127.0.0.1:9000".to_string();

        Ok((url, web3signer_proc, credentials))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test for connecting to the Web3Signer and listing accounts.
    ///
    /// ```shell
    /// cargo test --package bolt --bin bolt -- common::web3signer::tests::test_web3signer_connection_e2e
    /// --exact --show-output --ignored
    /// ```
    #[tokio::test]
    #[ignore = "Requires Web3Signer to be installed on the system"]
    async fn test_web3signer_connection_e2e() -> eyre::Result<()> {
        let (url, mut web3signer_proc, creds) = test_util::start_web3signer_test_server().await?;
        let mut web3signer = Web3Signer::connect(url, creds).await?;

        let accounts = web3signer.list_accounts().await?;
        println!("Web3Signer Accounts: {:?}", accounts);

        web3signer_proc.kill()?;

        Ok(())
    }
}
