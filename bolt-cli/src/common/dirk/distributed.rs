use alloy::primitives::B256;
use ethereum_consensus::crypto::{aggregate, PublicKey as BlsPublicKey, Signature as BlsSignature};
use eyre::{bail, Result};
use tracing::warn;

use crate::{
    cli::TlsCredentials,
    pb::eth2_signer_api::{self, Endpoint},
};

use super::Dirk;

#[derive(Debug)]
pub struct DistributedDirkAccount {
    credentials: TlsCredentials,
    participants: Vec<Endpoint>,
    threshold: usize,
    composite_public_key: BlsPublicKey,
}

impl DistributedDirkAccount {
    /// Create a new distributed account.
    pub fn new(
        acc: eth2_signer_api::DistributedAccount,
        credentials: TlsCredentials,
    ) -> Result<Self> {
        let composite_public_key = BlsPublicKey::try_from(acc.composite_public_key.as_ref())?;

        Ok(Self {
            credentials,
            composite_public_key,
            participants: acc.participants,
            threshold: acc.signing_threshold as usize,
        })
    }

    /// Obtain the composite public key of the distributed account.
    pub fn composite_public_key(&self) -> &BlsPublicKey {
        &self.composite_public_key
    }

    /// Obtain a threshold signature from the quorum of participants in the distributed account.
    pub async fn threshold_sign(
        &self,
        account_name: String,
        hash: B256,
        domain: B256,
    ) -> Result<BlsSignature> {
        let mut signatures = Vec::with_capacity(self.participants.len());

        for participant in &self.participants {
            if signatures.len() >= self.threshold {
                break;
            }

            let url = participant_url(participant);
            let mut conn = Dirk::connect(url.clone(), self.credentials.clone()).await?;

            // TODO: might have to unlock the account here

            // Every remote signer must sign the same message
            let signature = match conn.request_signature(account_name.clone(), hash, domain).await {
                Ok(signature) => signature,
                Err(err) => {
                    warn!(?err, "Failed to sign message with remote signer at {}", url);
                    continue;
                }
            };

            signatures.push(signature);
        }

        println!("Got {} signatures: {:?}", signatures.len(), signatures);

        if signatures.len() < self.threshold {
            bail!("Insufficient signatures: got {}, expected {}", signatures.len(), self.threshold);
        }

        let agg_signature = aggregate(&signatures)?;
        println!("Aggregated signature: {:?}", agg_signature);

        Ok(agg_signature)
    }
}

/// Build the participant URL for the given endpoint.
fn participant_url(endpoint: &Endpoint) -> String {
    // Note: the Dirk endpoint address must be parsed as "https://name:port".
    // Sauce: https://github.com/wealdtech/go-eth2-wallet-dirk/blob/263190301ef3352fbda43f91363145f175a12cf6/grpc.go#L1706
    format!("https://{}:{}", endpoint.name, endpoint.port)
}
