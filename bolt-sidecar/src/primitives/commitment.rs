use alloy::{
    consensus::Transaction,
    primitives::{keccak256, Address, PrimitiveSignature, B256},
    rpc::types::AccessList,
};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::SignerECDSA,
    state::{pricing::PricingError, InclusionPricer},
};

use super::{
    deserialize_txs,
    misc::{IntoSigned, Signed},
    serialize_txs,
    signature::{AlloySignatureWrapper, SignatureError},
    FullTransaction, TransactionExt,
};

/// Commitment requests sent by users or RPC proxies to the sidecar.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CommitmentRequest {
    /// Request of inclusion of a transaction at a specific slot.
    Inclusion(InclusionRequest),
    /// Request to exclude conflicting transactions from appearing above searcher's transaction.
    Exclusion(ExclusionRequest),
    /// Request for first access to previously registered states.
    FirstInclusion(FirstInclusionRequest),
}

/// A signed commitment with a generic signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignedCommitment {
    /// A signed inclusion commitment.
    Inclusion(InclusionCommitment),
    /// A signed exclusion commitment.
    Exclusion(ExclusionCommitment),
    /// A signed first access commitment.
    FirstInclusion(FirstInclusionCommitment),
}

/// An inclusion commitment with a generic signature.
pub type InclusionCommitment = Signed<InclusionRequest, AlloySignatureWrapper>;

/// An exclusion commitment with a generic signature.
pub type ExclusionCommitment = Signed<ExclusionRequest, AlloySignatureWrapper>;

/// A first access commitment with a generic signature.
pub type FirstInclusionCommitment = Signed<FirstInclusionRequest, AlloySignatureWrapper>;

impl From<SignedCommitment> for InclusionCommitment {
    fn from(commitment: SignedCommitment) -> Self {
        match commitment {
            SignedCommitment::Inclusion(inclusion) => inclusion,
            _ => panic!("Expected inclusion commitment"),
        }
    }
}

impl SignedCommitment {
    /// Returns the inner commitment if this is an inclusion commitment, otherwise `None`.
    pub fn into_inclusion_commitment(self) -> Option<InclusionCommitment> {
        match self {
            Self::Inclusion(inclusion) => Some(inclusion),
            _ => None,
        }
    }

    /// Returns the inner commitment if this is an exclusion commitment, otherwise `None`.
    pub fn into_exclusion_commitment(self) -> Option<ExclusionCommitment> {
        match self {
            Self::Exclusion(exclusion) => Some(exclusion),
            _ => None,
        }
    }

    /// Returns the inner commitment if this is a first access commitment, otherwise `None`.
    pub fn into_first_access_commitment(self) -> Option<FirstInclusionCommitment> {
        match self {
            Self::FirstInclusion(first_access) => Some(first_access),
            _ => None,
        }
    }
}

impl CommitmentRequest {
    /// Returns a reference to the inner request if this is an inclusion request, otherwise `None`.
    pub fn as_inclusion_request(&self) -> Option<&InclusionRequest> {
        match self {
            Self::Inclusion(req) => Some(req),
            _ => None,
        }
    }

    /// Returns a reference to the inner request if this is an exclusion request, otherwise `None`.
    pub fn as_exclusion_request(&self) -> Option<&ExclusionRequest> {
        match self {
            Self::Exclusion(req) => Some(req),
            _ => None,
        }
    }

    /// Returns a reference to the inner request if this is a first access request, otherwise `None`.
    pub fn as_first_inclusion_request(&self) -> Option<&FirstInclusionRequest> {
        match self {
            Self::FirstInclusion(req) => Some(req),
            _ => None,
        }
    }

    /// Commits and signs the request with the provided signer. Returns a [SignedCommitment].
    pub async fn commit_and_sign<S: SignerECDSA>(
        self,
        signer: &S,
    ) -> eyre::Result<SignedCommitment> {
        match self {
            Self::Inclusion(req) => {
                req.commit_and_sign(signer).await.map(SignedCommitment::Inclusion)
            }
            Self::Exclusion(req) => {
                req.commit_and_sign(signer).await.map(SignedCommitment::Exclusion)
            }
            Self::FirstInclusion(req) => {
                req.commit_and_sign(signer).await.map(SignedCommitment::FirstInclusion)
            }
        }
    }

    /// Returns the signature (if signed).
    pub fn signature(&self) -> Option<&AlloySignatureWrapper> {
        match self {
            Self::Inclusion(req) => req.signature.as_ref(),
            Self::Exclusion(req) => req.signature.as_ref(),
            Self::FirstInclusion(req) => req.signature.as_ref(),
        }
    }
}

/// Request to include a transaction at a specific slot.
#[cfg_attr(test, derive(Default))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionRequest {
    /// The consensus slot number at which the transaction should be included.
    pub slot: u64,
    /// The transaction to be included.
    #[serde(deserialize_with = "deserialize_txs", serialize_with = "serialize_txs")]
    pub txs: Vec<FullTransaction>,
    /// The signature over the "slot" and "tx" fields by the user.
    /// A valid signature is the only proof that the user actually requested
    /// this specific commitment to be included at the given slot.
    #[serde(skip)]
    pub signature: Option<AlloySignatureWrapper>,
    /// The signer of the request (if recovered).
    #[serde(skip)]
    pub signer: Option<Address>,
}

impl InclusionRequest {
    /// Commits and signs the request with the provided signer. Returns an [InclusionCommitment].
    pub async fn commit_and_sign<S: SignerECDSA>(
        self,
        signer: &S,
    ) -> eyre::Result<InclusionCommitment> {
        let digest = self.digest();
        let signature = signer.sign_hash(&digest).await?;
        let signature = PrimitiveSignature::try_from(signature.as_bytes().as_ref())?;
        let ic = self.into_signed(signature.into());
        Ok(ic)
    }

    /// Validates the transaction fees against a minimum basefee.
    /// Returns true if the fee is greater than or equal to the min, false otherwise.
    pub fn validate_basefee(&self, min: u128) -> bool {
        for tx in &self.txs {
            if tx.max_fee_per_gas() < min {
                return false;
            }
        }

        true
    }

    /// Validates the transaction chain id against the provided chain id.
    /// Returns true if the chain id matches, false otherwise. Will always return true
    /// for pre-EIP155 transactions.
    pub fn validate_chain_id(&self, chain_id: u64) -> bool {
        for tx in &self.txs {
            // Check if pre-EIP155 transaction
            if let Some(id) = tx.chain_id() {
                if id != chain_id {
                    return false;
                }
            }
        }

        true
    }

    /// Validates the tx size limit.
    pub fn validate_tx_size_limit(&self, limit: usize) -> bool {
        for tx in &self.txs {
            if tx.size() > limit {
                return false;
            }
        }

        true
    }

    /// Validates the init code limit.
    pub fn validate_init_code_limit(&self, limit: usize) -> bool {
        for tx in &self.txs {
            if tx.kind().is_create() && tx.input().len() > limit {
                return false;
            }
        }

        true
    }

    /// Validates the priority fee against the max fee per gas.
    /// Returns true if the fee is less than or equal to the max fee per gas, false otherwise.
    /// Ref: https://github.com/paradigmxyz/reth/blob/2d592125128c3742ff97b321884f93f9063abcb2/crates/transaction-pool/src/validate/eth.rs#L242
    pub fn validate_max_priority_fee(&self) -> bool {
        for tx in &self.txs {
            if tx.max_priority_fee_per_gas() > Some(tx.max_fee_per_gas()) {
                return false;
            }
        }

        true
    }

    /// Validates the priority fee against a minimum priority fee.
    /// Returns `true` if the "effective priority fee" is greater than or equal to the set minimum
    /// priority fee, `false` otherwise.
    /// Returns an error if min priority fee cannot be calculated.
    pub fn validate_min_priority_fee(
        &self,
        pricing: &InclusionPricer,
        preconfirmed_gas: u64,
        min_inclusion_profit: u64,
        max_base_fee: u128,
    ) -> Result<bool, PricingError> {
        // Each included tx will move the price up
        // So we need to calculate the minimum priority fee for each tx
        let mut local_preconfirmed_gas = preconfirmed_gas;
        for tx in &self.txs {
            // Calculate minimum required priority fee for this transaction
            let min_priority_fee = pricing
                .calculate_min_priority_fee(tx.gas_limit(), preconfirmed_gas)?
                + min_inclusion_profit;

            let tip = tx.effective_tip_per_gas(max_base_fee).unwrap_or_default();
            if tip < min_priority_fee as u128 {
                return Err(PricingError::TipTooLow {
                    tip,
                    min_priority_fee: min_priority_fee as u128,
                });
            }
            // Increment the preconfirmed gas for the next transaction in the bundle
            local_preconfirmed_gas = local_preconfirmed_gas.saturating_add(tx.gas_limit());
        }
        Ok(true)
    }

    /// Returns the total gas limit of all transactions in this request.
    pub fn gas_limit(&self) -> u64 {
        self.txs.iter().map(|tx| tx.gas_limit()).sum()
    }

    /// Returns the transaction signer.
    pub fn signer(&self) -> Option<Address> {
        self.signer
    }

    /// Sets the signature.
    pub fn set_signature(&mut self, signature: AlloySignatureWrapper) {
        self.signature = Some(signature);
    }

    /// Sets the signer.
    pub fn set_signer(&mut self, signer: Address) {
        self.signer = Some(signer);
    }

    /// Recovers the signer of all transactions in the request.
    pub fn recover_signers(&mut self) -> Result<(), SignatureError> {
        for tx in &mut self.txs {
            let signer = tx.recover_signer().map_err(|_| SignatureError)?;
            tx.sender = Some(signer);
        }

        Ok(())
    }
}

impl InclusionRequest {
    /// Returns the digest of the request.
    /// digest = keccak256(bytes(tx_hash1) | bytes(tx_hash2) | ... | le_bytes(target_slot))
    pub fn digest(&self) -> B256 {
        let mut data = Vec::new();
        // First field is the concatenation of all the transaction hashes
        data.extend_from_slice(
            &self.txs.iter().map(|tx| tx.hash().as_slice()).collect::<Vec<_>>().concat(),
        );

        // Second field is the little endian encoding of the target slot
        data.extend_from_slice(&self.slot.to_le_bytes());

        keccak256(&data)
    }
}

impl From<InclusionRequest> for CommitmentRequest {
    fn from(req: InclusionRequest) -> Self {
        Self::Inclusion(req)
    }
}

impl From<ExclusionRequest> for CommitmentRequest {
    fn from(req: ExclusionRequest) -> Self {
        Self::Exclusion(req)
    }
}

impl From<FirstInclusionRequest> for CommitmentRequest {
    fn from(req: FirstInclusionRequest) -> Self {
        Self::FirstInclusion(req)
    }
}

/// Request to exclude conflicting transactions from appearing above searcher's transaction.
#[cfg_attr(test, derive(Default))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExclusionRequest {
    /// The consensus slot number at which the exclusion should be enforced.
    pub slot: u64,
    /// The transactions that should be subject to exclusion constraints.
    #[serde(deserialize_with = "deserialize_txs", serialize_with = "serialize_txs")]
    pub txs: Vec<FullTransaction>,
    /// The access list of states that these transactions touch.
    pub access_list: AccessList,
    /// The signature over the request fields by the user.
    #[serde(skip)]
    pub signature: Option<AlloySignatureWrapper>,
    /// The signer of the request (if recovered).
    #[serde(skip)]
    pub signer: Option<Address>,
}

/// Request for first access to previously registered states.
#[cfg_attr(test, derive(Default))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirstInclusionRequest {
    /// The consensus slot number at which first access should be enforced.
    pub slot: u64,
    /// The transaction that should get first access.
    #[serde(deserialize_with = "deserialize_txs", serialize_with = "serialize_txs")]
    pub txs: Vec<FullTransaction>,
    /// The access list of states for which first access is requested.
    pub access_list: AccessList,
    /// The transaction representing the auction winner's bid. May be a one element vector.
    #[serde(deserialize_with = "deserialize_txs", serialize_with = "serialize_txs")]
    pub bid_transaction: Vec<FullTransaction>,
    /// The signature over the request fields by the user.
    #[serde(skip)]
    pub signature: Option<AlloySignatureWrapper>,
    /// The signer of the request (if recovered).
    #[serde(skip)]
    pub signer: Option<Address>,
}

impl ExclusionRequest {
    /// Commits and signs the request with the provided signer. Returns an [ExclusionCommitment].
    pub async fn commit_and_sign<S: SignerECDSA>(
        self,
        signer: &S,
    ) -> eyre::Result<ExclusionCommitment> {
        let digest = self.digest();
        let signature = signer.sign_hash(&digest).await?;
        let signature = PrimitiveSignature::try_from(signature.as_bytes().as_ref())?;
        let ec = self.into_signed(signature.into());
        Ok(ec)
    }

    /// Returns the digest of the request.
    pub fn digest(&self) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(
            &self.txs.iter().map(|tx| tx.hash().as_slice()).collect::<Vec<_>>().concat(),
        );
        data.extend_from_slice(&self.slot.to_le_bytes());
        let access_list_bytes = serde_json::to_vec(&self.access_list).unwrap_or_default();
        data.extend_from_slice(&keccak256(&access_list_bytes).as_slice());
        keccak256(&data)
    }

    /// Sets the signature.
    pub fn set_signature(&mut self, signature: AlloySignatureWrapper) {
        self.signature = Some(signature);
    }

    /// Sets the signer.
    pub fn set_signer(&mut self, signer: Address) {
        self.signer = Some(signer);
    }

    /// Returns the transaction signer.
    pub fn signer(&self) -> Option<Address> {
        self.signer
    }
}

impl FirstInclusionRequest {
    /// Commits and signs the request with the provided signer. Returns a [FirstInclusionCommitment].
    pub async fn commit_and_sign<S: SignerECDSA>(
        self,
        signer: &S,
    ) -> eyre::Result<FirstInclusionCommitment> {
        let digest = self.digest();
        let signature = signer.sign_hash(&digest).await?;
        let signature = PrimitiveSignature::try_from(signature.as_bytes().as_ref())?;
        let fac = self.into_signed(signature.into());
        Ok(fac)
    }

    /// Returns the digest of the request.
    pub fn digest(&self) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(
            &self.txs.iter().map(|tx| tx.hash().as_slice()).collect::<Vec<_>>().concat(),
        );
        data.extend_from_slice(&self.slot.to_le_bytes());
        let access_list_bytes = serde_json::to_vec(&self.access_list).unwrap_or_default();
        data.extend_from_slice(&keccak256(&access_list_bytes).as_slice());
        keccak256(&data)
    }

    /// Sets the signature.
    pub fn set_signature(&mut self, signature: AlloySignatureWrapper) {
        self.signature = Some(signature);
    }

    /// Sets the signer.
    pub fn set_signer(&mut self, signer: Address) {
        self.signer = Some(signer);
    }

    /// Returns the transaction signer.
    pub fn signer(&self) -> Option<Address> {
        self.signer
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::{
        hex,
        primitives::{Address, PrimitiveSignature as Signature},
    };

    use super::{CommitmentRequest, InclusionRequest};

    #[test]
    fn test_create_digest() {
        let json_req = r#"{
            "slot": 633067,
            "txs": ["0xf86b82016e84042343e0830f424094deaddeaddeaddeaddeaddeaddeaddeaddeaddead0780850344281a21a0e525fc31b5574722ff064bdd127c4441b0fc66de7dc44928e163cb68e9d807e5a00b3ec02fc1e34b0209f252369ad10b745cd5a51c88384a340f7a150d0e45e471"]
        }"#;

        let req: InclusionRequest = serde_json::from_str(json_req).unwrap();
        let digest = req.digest();
        assert_eq!(
            hex::encode(digest.as_slice()),
            "52ecc7832625c3d107aaba5b55d4509b48cd9f4f7ce375d6696d09bbf3310525"
        );

        // Verify signature over the digest
        let sig = Signature::from_str("0xcdd20b2abbd8cdfb77ec2608e1227f8ce0f66133b9d0ec0ea68102c2152b82193e3be0d6967b7c20b83e1a2530daa3a07713556541dc2aa16a46d922e6145a2b01").unwrap();
        let recovered = sig.recover_address_from_prehash(&digest).unwrap();
        assert_eq!(
            recovered,
            Address::from_str("0x27083ED52464625660f3e30Aa5B9C20A30D7E110").unwrap()
        );
    }

    #[test]
    fn test_deserialize_inclusion_request() {
        let json_req = r#"{
            "slot": 10,
            "txs": ["0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4"]
        }"#;

        let req: InclusionRequest = serde_json::from_str(json_req).unwrap();
        assert_eq!(req.slot, 10);

        let deser = serde_json::to_string(&req).unwrap();

        assert_eq!(
            deser.parse::<serde_json::Value>().unwrap(),
            json_req.parse::<serde_json::Value>().unwrap()
        );
    }

    #[test]
    fn test_deserialize_commitment_request() {
        let json_req = r#"{
            "slot": 10,
            "txs": ["0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4"]
        }"#;

        let req: CommitmentRequest = serde_json::from_str(json_req).unwrap();

        #[allow(irrefutable_let_patterns)]
        if let CommitmentRequest::Inclusion(req) = req {
            assert_eq!(req.slot, 10);
        } else {
            panic!("Expected Inclusion request");
        }
    }
}
