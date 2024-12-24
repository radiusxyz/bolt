use alloy::{
    primitives::keccak256,
    signers::{local::PrivateKeySigner, SignerSync},
};
use jsonwebtoken::encode;
use serde::{Deserialize, Serialize};

use crate::{
    common::time::current_timestamp,
    config::chain::Chain,
    primitives::signature::{AlloySignatureWrapper, ECDSASignatureExt},
};

/// A JWT claim for the proposer authentication.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProposerAuthClaims {
    /// The URL of the RPC server which the proposer will accept commitments from.
    rpc_url: String,
    /// The chain ID of the network the proposer is validating on.
    chain_id: u64,
    /// The expiry timestamp of the JWT, in seconds.
    #[serde(rename = "exp")]
    expiry: u64,
    /// The 0x-prefixed signature of over the digest `keccak256(rpc_url + chain_id + expiry)`,
    /// where `+` denotes concatenation. All values are encoded as UTF-8 strings.
    ///
    /// Example digest: `keccak256("http://localhost:8545" + 1 + 1734104048)`
    ///
    ///
    /// The signature must be performed with the operator private key.
    signature: String,
}

impl ProposerAuthClaims {
    /// Creates a new instance of the [ProposerAuthClaim] and creates a signature with
    /// the provided signer.
    ///
    /// If the expiry is not provided, it will default to 60 seconds from now.
    pub fn new_from_signer(
        rpc_url: String,
        chain: Chain,
        expiry: Option<u64>,
        signer: PrivateKeySigner,
    ) -> Self {
        let expiry = expiry.unwrap_or(current_timestamp() + 60);

        let digest = [rpc_url.clone(), chain.id().to_string(), expiry.to_string()].concat();
        let digest_hash = keccak256(digest);
        let signature = signer.sign_hash_sync(&digest_hash).expect("failed to sign the digest");
        let signature = AlloySignatureWrapper::try_from(signature.as_bytes().as_ref())
            .expect("failed to convert the signature");

        Self { rpc_url, chain_id: chain.id(), expiry, signature: signature.to_hex() }
    }

    /// Encodes the claims into a JWT, with default HS256 algorithm and empty secret key.
    /// That is because validation is performed by looking at the fields of the public payload.
    ///
    /// This is a much simpler implementation compared to sign the JWT using the ES256K algorithm
    /// with the operator private key.
    pub fn to_jwt(&self) -> Result<String, jsonwebtoken::errors::Error> {
        encode(&jsonwebtoken::Header::default(), self, &jsonwebtoken::EncodingKey::from_secret(&[]))
    }
}

#[cfg(test)]
mod tests {
    use alloy::signers::local::PrivateKeySigner;

    use crate::{
        api::commitments::delegation::jwt::ProposerAuthClaims, common::time::current_timestamp,
        config::chain::Chain,
    };

    #[test]
    fn test_encode_decode_proposer_auth_claim() {
        let rpc_url = "http://localhost:8545".to_string();
        let chain = Chain::Mainnet;
        let expiry = current_timestamp() + 60;
        let signer = PrivateKeySigner::random();

        let claim = ProposerAuthClaims::new_from_signer(rpc_url, chain, Some(expiry), signer);
        let jwt = claim.to_jwt().expect("failed to encode the claim");
        let decoded_claim = jsonwebtoken::decode::<ProposerAuthClaims>(
            &jwt,
            &jsonwebtoken::DecodingKey::from_secret(&[]),
            &jsonwebtoken::Validation::default(),
        )
        .expect("failed to decode the claim")
        .claims;
        assert_eq!(claim.rpc_url, decoded_claim.rpc_url);
        assert_eq!(claim.chain_id, decoded_claim.chain_id);
        assert_eq!(claim.expiry, decoded_claim.expiry);
        assert_eq!(claim.signature, decoded_claim.signature);
    }
}
