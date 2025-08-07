use alloy::{
    consensus::{Signed, TxEip4844Variant, TxEip4844WithSidecar, TxEnvelope},
    eips::eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    primitives::{keccak256, Bytes, TxHash, B256},
    rpc::types::{
        beacon::{BlsPublicKey, BlsSignature},
        AccessList,
    },
    signers::k256::sha2::{Digest, Sha256},
};
use axum::http::HeaderMap;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode, SszDecoderBuilder};
use ssz_derive::{Decode, Encode};
use std::ops::Deref;
use tracing::error;
use tree_hash::TreeHash;

use cb_common::{
    constants::COMMIT_BOOST_DOMAIN,
    pbs::{DenebSpec, EthSpec, SignedExecutionPayloadHeader, Transaction, VersionedResponse},
    signature::{compute_domain, compute_signing_root},
    signer::verify_bls_signature,
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

#[derive(Debug, Clone, Serialize, Eq, PartialEq, Deserialize)]
pub struct ConstraintsMessage {
    pub pubkey: BlsPublicKey,
    pub slot: u64,
    pub top: bool,
    pub transactions: Vec<Bytes>,
    #[serde(default)]
    pub access_list: Option<AccessList>,
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

        if let Some(access_list) = &self.access_list {
            let access_list_bytes = serde_json::to_vec(access_list).unwrap_or_default();
            hasher.update(access_list_bytes);
        }

        Ok(hasher.finalize().into())
    }
}

impl SszEncode for ConstraintsMessage {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        self.pubkey.ssz_bytes_len()
            + self.slot.ssz_bytes_len()
            + self.top.ssz_bytes_len()
            + self.transactions.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.pubkey.ssz_append(buf);
        self.slot.ssz_append(buf);
        self.top.ssz_append(buf);
        self.transactions.ssz_append(buf);
    }
}

impl SszDecode for ConstraintsMessage {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_fixed_len() -> usize {
        0
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);

        builder.register_type::<BlsPublicKey>()?;
        builder.register_type::<u64>()?;
        builder.register_type::<bool>()?;
        builder.register_type::<Vec<Bytes>>()?;

        let mut decoder = builder.build()?;

        Ok(Self {
            pubkey: decoder.decode_next()?,
            slot: decoder.decode_next()?,
            top: decoder.decode_next()?,
            transactions: decoder.decode_next()?,
            access_list: None,
        })
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

/// Takes a raw EIP-2718 RLP-encoded transaction and calculates its proof data, consisting of its
/// hash and the hash tree root of the transaction. For type 3 transactions, the hash tree root of
/// the inner transaction is computed without blob sidecar.
fn calculate_tx_proof_data(raw_tx: &Bytes) -> Result<(TxHash, HashTreeRoot), Eip2718Error> {
    let Some(is_type_3) = raw_tx.first().map(|type_id| type_id == &0x03) else {
        return Err(Eip2718Error::RlpError(alloy_rlp::Error::Custom("empty RLP bytes")));
    };

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
            // We have the type 3 variant without sidecar, we can safely compute the hash tree root
            // of the transaction from the raw RLP bytes.
            Ok((tx_hash, hash_tree_root_raw_tx(raw_tx.to_vec())))
        }
        TxEip4844Variant::TxEip4844WithSidecar(TxEip4844WithSidecar { tx, .. }) => {
            // We strip out the sidecar and compute the hash tree root the transaction
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
