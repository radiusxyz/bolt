use alloy::{
    consensus::{Signed, TxEip4844Variant, TxEip4844WithSidecar, TxEnvelope},
    eips::eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    primitives::{keccak256, Bytes, TxHash, B256},
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
    signers::k256::sha2::{Digest, Sha256},
};
use axum::http::HeaderMap;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::ops::Deref;
use tracing::error;
use tree_hash::TreeHash;

use cb_common::{
    constants::COMMIT_BOOST_DOMAIN,
    pbs::{DenebSpec, EthSpec, SignedExecutionPayloadHeader, Transaction, VersionedResponse},
    signature::{compute_domain, compute_signing_root},
    signer::schemes::bls::verify_bls_signature,
    types::Chain,
};

/// A hash tree root.
pub type HashTreeRoot = tree_hash::Hash256;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct GetHeaderParams {
    pub slot: u64,
    pub parent_hash: B256,
    pub pubkey: BlsPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedConstraints {
    pub message: ConstraintsMessage,
    pub signature: BlsSignature,
}

impl SignedConstraints {
    /// Verifies the signature on this message against the provided BLS public key.
    /// The `chain` and `COMMIT_BOOST_DOMAIN` are used to compute the signing root.
    #[allow(unused)]
    pub fn verify_signature(&self, chain: Chain, pubkey: &BlsPublicKey) -> bool {
        let domain = compute_domain(chain, COMMIT_BOOST_DOMAIN);
        let digest = match self.message.digest() {
            Ok(digest) => digest,
            Err(e) => {
                error!(err = ?e, "Failed to compute digest");
                return false;
            }
        };

        let signing_root = compute_signing_root(digest, domain);
        verify_bls_signature(pubkey, &signing_root, &self.signature).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Eq, PartialEq, Deserialize, Encode, Decode)]
pub struct ConstraintsMessage {
    pub pubkey: BlsPublicKey,
    pub slot: u64,
    pub top: bool,
    pub transactions: Vec<Bytes>,
}

impl ConstraintsMessage {
    /// Returns the digest of this message.
    pub fn digest(&self) -> Eip2718Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(self.pubkey);
        hasher.update(self.slot.to_le_bytes());
        hasher.update((self.top as u8).to_le_bytes());

        for bytes in &self.transactions {
            let tx = TxEnvelope::decode_2718(&mut bytes.as_ref())?;
            hasher.update(tx.tx_hash());
        }

        Ok(hasher.finalize().into())
    }
}

#[derive(Debug)]
pub struct ConstraintsWithProofData {
    pub message: ConstraintsMessage,
    /// List of transaction hashes and corresponding hash tree roots. Same order
    /// as the transactions in the `message`.
    pub proof_data: Vec<(TxHash, HashTreeRoot)>,
}

impl TryFrom<ConstraintsMessage> for ConstraintsWithProofData {
    type Error = Eip2718Error;

    fn try_from(value: ConstraintsMessage) -> Result<Self, Self::Error> {
        let transactions = value
            .transactions
            .iter()
            .map(calculate_tx_proof_data)
            .collect::<Result<Vec<_>, Eip2718Error>>()?;

        Ok(Self { message: value, proof_data: transactions })
    }
}

/// Calculate the SSZ hash tree root of a transaction, starting from its enveloped form.
/// For type 3 transactions, the hash tree root of the inner transaction is taken (without blobs).
fn calculate_tx_proof_data(raw_tx: &Bytes) -> Result<(TxHash, HashTreeRoot), Eip2718Error> {
    let is_type_3 = raw_tx
        .first()
        .ok_or(Eip2718Error::RlpError(alloy_rlp::Error::Custom("empty RLP bytes")))?
        == &0x03;

    // For blob transactions (type 3), we need to make sure to strip out the blob sidecar when
    // calculating both the transaction hash and the hash tree root
    if !is_type_3 {
        let tx_hash = keccak256(raw_tx);
        return Ok((tx_hash, hash_tree_root_raw_tx(raw_tx.to_vec())));
    }

    let envelope = TxEnvelope::decode_2718(&mut raw_tx.as_ref())?;
    let TxEnvelope::Eip4844(signed_tx) = envelope else {
        unreachable!("we have already checked it is not a type 3 transaction")
    };
    let (tx, signature, tx_hash) = signed_tx.into_parts();
    match tx {
        TxEip4844Variant::TxEip4844(_) => {
            // We have the type 3 variant without sidecar, we can safely hash tree root the raw
            // RLP.
            Ok((tx_hash, hash_tree_root_raw_tx(raw_tx.to_vec())))
        }
        TxEip4844Variant::TxEip4844WithSidecar(TxEip4844WithSidecar { tx, .. }) => {
            // We strip out the sidecar and hash tree root the transaction
            let signed = Signed::new_unchecked(tx, signature, tx_hash);
            let new_envelope = TxEnvelope::from(signed);
            let mut buf = Vec::new();
            new_envelope.encode_2718(&mut buf);

            Ok((tx_hash, hash_tree_root_raw_tx(buf)))
        }
    }
}

fn hash_tree_root_raw_tx(raw_tx: Vec<u8>) -> HashTreeRoot {
    let tx = Transaction::<<DenebSpec as EthSpec>::MaxBytesPerTransaction>::from(raw_tx);
    TreeHash::tree_hash_root(&tx)
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedDelegation {
    pub message: DelegationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct DelegationMessage {
    action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedRevocation {
    pub message: RevocationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct RevocationMessage {
    action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

/// Reference: https://docs.boltprotocol.xyz/technical-docs/api/builder#get_header_with_proofs
pub type GetHeaderWithProofsResponse = VersionedResponse<SignedExecutionPayloadHeaderWithProofs>;

/// Reference: https://docs.boltprotocol.xyz/technical-docs/api/builder#get_header_with_proofs
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedExecutionPayloadHeaderWithProofs {
    #[serde(flatten)]
    pub header: SignedExecutionPayloadHeader,
    #[serde(default)]
    pub proofs: InclusionProofs,
}

/// Reference: https://docs.boltprotocol.xyz/technical-docs/api/builder#get_header_with_proofs
#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct InclusionProofs {
    /// The transaction hashes these inclusion proofs are for. The hash tree roots of
    /// these transactions are the leaves of the transactions tree.
    pub transaction_hashes: Vec<TxHash>,
    /// The generalized indexes of the nodes in the transactions tree.
    pub generalized_indexes: Vec<usize>,
    /// The proof hashes for the transactions tree.
    pub merkle_hashes: Vec<B256>,
}

impl InclusionProofs {
    /// Returns the total number of leaves in the tree.
    pub fn total_leaves(&self) -> usize {
        self.transaction_hashes.len()
    }
}

impl Deref for SignedExecutionPayloadHeaderWithProofs {
    type Target = SignedExecutionPayloadHeader;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

#[derive(Debug)]
pub struct RequestConfig {
    pub url: Url,
    pub timeout_ms: u64,
    pub headers: HeaderMap,
}
