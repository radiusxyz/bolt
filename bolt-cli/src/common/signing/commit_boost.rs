use alloy::primitives::B256;
use ethereum_consensus::crypto::{bls::Signature as BlsSignature, PublicKey as BlsPublicKey};
use eyre::{bail, Result};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

/// The endpoint to get the available public keys from the CommitBoost signer.
pub const GET_PUBKEYS: &str = "/signer/v1/get_pubkeys";

/// The endpoint to request a signature from the CommitBoost signer.
pub const REQUEST_SIGNATURE: &str = "/signer/v1/request_signature";

/// A CommitBoost remote signer.
#[derive(Debug)]
pub struct CommitBoost {
    url: Url,
    client: Client,
}

impl CommitBoost {
    /// Create a new CommitBoost signer.
    pub fn new(url: Url) -> Self {
        CommitBoost { client: Client::new(), url }
    }

    /// Fetch the available public keys from the CommitBoost signer.
    pub async fn get_pubkeys(&self) -> Result<Vec<Keys>> {
        let res = self.client.get(self.url.join(GET_PUBKEYS)?).send().await?;

        match res.json::<APIResponse<GetPubkeysResponse>>().await {
            Ok(get_pubkeys_response) => match get_pubkeys_response {
                APIResponse::Success(res) => Ok(res.keys),
                APIResponse::Error { code, message } => {
                    bail!(format!("Failed to get pubkeys from CommitBoost: {}: {}", code, message))
                }
            },
            Err(err) => {
                bail!(format!("Failed to deserialize pubkeys response from CommitBoost: {}", err))
            }
        }
    }

    /// Request to sign a message using the CommitBoost signer.
    pub async fn request_signature(
        &self,
        pubkey: BlsPublicKey,
        hash: B256,
    ) -> Result<BlsSignature> {
        let req = SignatureRequestBody {
            typ: "consensus".to_string(),
            pubkey: pubkey.to_string(),
            object_root: hash,
        };

        let res = self.client.post(self.url.join(REQUEST_SIGNATURE)?).json(&req).send().await?;

        match res.json::<APIResponse<BlsSignature>>().await {
            Ok(res) => match res {
                APIResponse::Success(signature) => Ok(signature),
                APIResponse::Error { code, message } => {
                    bail!(format!(
                        "Failed to get signature from CommitBoost: {}: {}",
                        code, message
                    ))
                }
            },
            Err(err) => {
                bail!(format!("Failed to deserialize signature response from CommitBoost: {}", err))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum APIResponse<T> {
    Success(T),
    Error { code: u16, message: String },
}

#[derive(Debug, Deserialize)]
pub struct GetPubkeysResponse {
    keys: Vec<Keys>,
}

#[derive(Debug, Deserialize)]
pub struct Keys {
    consensus: String,
    proxy_bls: Vec<String>,
    proxy_ecdsa: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SignatureRequestBody {
    #[serde(rename = "type")]
    typ: String,
    pubkey: String,
    object_root: B256,
}
