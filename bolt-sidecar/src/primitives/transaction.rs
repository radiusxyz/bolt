use std::{borrow::Cow, fmt};

use alloy::{
    consensus::BlobTransactionSidecar,
    eips::eip2718::{Decodable2718, Encodable2718},
    hex,
    primitives::{Address, Bytes, TxKind, U256},
};
use reth_primitives::{PooledTransactionsElement, TxType};
use serde::{de, ser::SerializeSeq};

/// Trait that exposes additional information on transaction types that don't already do it
/// by themselves (e.g. [`PooledTransactionsElement`]).
pub trait TransactionExt {
    /// Returns the gas limit of the transaction.
    fn gas_limit(&self) -> u64;

    /// Returns the value of the transaction.
    fn value(&self) -> U256;

    /// Returns the type of the transaction.
    fn tx_type(&self) -> TxType;

    /// Returns the kind of the transaction.
    fn tx_kind(&self) -> TxKind;

    /// Returns the input data of the transaction.
    fn input(&self) -> &Bytes;

    /// Returns the chain ID of the transaction.
    fn chain_id(&self) -> Option<u64>;

    /// Returns the blob sidecar of the transaction, if any.
    fn blob_sidecar(&self) -> Option<&BlobTransactionSidecar>;

    /// Returns the size of the transaction in bytes.
    fn size(&self) -> usize;
}

impl TransactionExt for PooledTransactionsElement {
    fn gas_limit(&self) -> u64 {
        match self {
            Self::Legacy { transaction, .. } => transaction.gas_limit,
            Self::Eip2930 { transaction, .. } => transaction.gas_limit,
            Self::Eip1559 { transaction, .. } => transaction.gas_limit,
            Self::BlobTransaction(blob_tx) => blob_tx.transaction.tx.gas_limit,
            _ => unimplemented!(),
        }
    }

    fn value(&self) -> U256 {
        match self {
            Self::Legacy { transaction, .. } => transaction.value,
            Self::Eip2930 { transaction, .. } => transaction.value,
            Self::Eip1559 { transaction, .. } => transaction.value,
            Self::BlobTransaction(blob_tx) => blob_tx.transaction.tx.value,
            _ => unimplemented!(),
        }
    }

    fn tx_type(&self) -> TxType {
        match self {
            Self::Legacy { .. } => TxType::Legacy,
            Self::Eip2930 { .. } => TxType::Eip2930,
            Self::Eip1559 { .. } => TxType::Eip1559,
            Self::BlobTransaction(_) => TxType::Eip4844,
            _ => unimplemented!(),
        }
    }

    fn tx_kind(&self) -> TxKind {
        match self {
            Self::Legacy { transaction, .. } => transaction.to,
            Self::Eip2930 { transaction, .. } => transaction.to,
            Self::Eip1559 { transaction, .. } => transaction.to,
            Self::BlobTransaction(blob_tx) => {
                TxKind::Call(blob_tx.transaction.tx.to)
            }
            _ => unimplemented!(),
        }
    }

    fn input(&self) -> &Bytes {
        match self {
            Self::Legacy { transaction, .. } => &transaction.input,
            Self::Eip2930 { transaction, .. } => &transaction.input,
            Self::Eip1559 { transaction, .. } => &transaction.input,
            Self::BlobTransaction(blob_tx) => &blob_tx.transaction.tx.input,
            _ => unimplemented!(),
        }
    }

    fn chain_id(&self) -> Option<u64> {
        match self {
            Self::Legacy { transaction, .. } => transaction.chain_id,
            Self::Eip2930 { transaction, .. } => Some(transaction.chain_id),
            Self::Eip1559 { transaction, .. } => Some(transaction.chain_id),
            Self::BlobTransaction(blob_tx) => {
                Some(blob_tx.transaction.tx.chain_id)
            }
            _ => unimplemented!(),
        }
    }

    fn blob_sidecar(&self) -> Option<&BlobTransactionSidecar> {
        match self {
            Self::BlobTransaction(blob_tx) => {
                Some(&blob_tx.transaction.sidecar)
            }
            _ => None,
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::Legacy { transaction, .. } => transaction.size(),
            Self::Eip2930 { transaction, .. } => transaction.size(),
            Self::Eip1559 { transaction, .. } => transaction.size(),
            Self::BlobTransaction(blob_tx) => blob_tx.transaction.tx.size(),
            _ => unimplemented!(),
        }
    }
}

/// Returns a string representation of the transaction type.
pub const fn tx_type_str(tx_type: TxType) -> &'static str {
    match tx_type {
        TxType::Legacy => "legacy",
        TxType::Eip2930 => "eip2930",
        TxType::Eip1559 => "eip1559",
        TxType::Eip4844 => "eip4844",
        TxType::Eip7702 => "eip7702",
    }
}

/// A wrapper type for a full, complete transaction (i.e. with blob sidecars attached).
#[derive(Clone, PartialEq, Eq)]
pub struct FullTransaction {
    /// The transaction itself.
    pub tx: PooledTransactionsElement,
    /// The sender of the transaction, if recovered.
    pub sender: Option<Address>,
}

impl From<PooledTransactionsElement> for FullTransaction {
    fn from(tx: PooledTransactionsElement) -> Self {
        Self { tx, sender: None }
    }
}

impl fmt::Debug for FullTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("FullTransaction");

        match &self.tx {
            PooledTransactionsElement::BlobTransaction(blob_tx) => {
                let shortened_blobs: Vec<String> =
                    // Use alternative `Display` to print trimmed blob
                    blob_tx.transaction.sidecar.blobs.iter().map(|blob| format!("{blob:#}")).collect();

                debug_struct.field("tx", &"BlobTransaction");
                debug_struct.field("hash", &blob_tx.hash);
                debug_struct.field("transaction", &blob_tx.transaction);
                debug_struct.field("signature", &blob_tx.signature);

                debug_struct.field("sidecar_blobs", &shortened_blobs);
                debug_struct.field("sidecar_commitments", &blob_tx.transaction.sidecar.commitments);
                debug_struct.field("sidecar_proofs", &blob_tx.transaction.sidecar.proofs);
            }
            other => {
                debug_struct.field("tx", other);
            }
        }

        debug_struct.field("sender", &self.sender);
        debug_struct.finish()
    }
}

impl std::ops::Deref for FullTransaction {
    type Target = PooledTransactionsElement;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl std::ops::DerefMut for FullTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

impl FullTransaction {
    /// Convenience method to parse a raw transaction into a `FullTransaction`.
    pub fn decode_enveloped(data: impl AsRef<[u8]>) -> eyre::Result<Self> {
        let tx = PooledTransactionsElement::decode_2718(&mut data.as_ref())?;
        Ok(Self { tx, sender: None })
    }

    /// Returns the inner transaction.
    pub fn into_inner(self) -> PooledTransactionsElement {
        self.tx
    }

    /// Returns the sender of the transaction, if recovered.
    pub fn sender(&self) -> Option<&Address> {
        self.sender.as_ref()
    }

    /// Returns the effective miner gas tip cap (`gasTipCap`) for the given base fee:
    /// `min(maxFeePerGas - baseFee, maxPriorityFeePerGas)`
    ///
    /// Returns `None` if the basefee is higher than the [`Transaction::max_fee_per_gas`].
    /// Ref: https://github.com/paradigmxyz/reth/blob/2d592125128c3742ff97b321884f93f9063abcb2/crates/primitives/src/transaction/mod.rs#L444
    pub fn effective_tip_per_gas(&self, base_fee: u128) -> Option<u128> {
        let max_fee_per_gas = self.max_fee_per_gas();

        if max_fee_per_gas < base_fee {
            return None;
        }

        // Calculate the difference between max_fee_per_gas and base_fee
        let fee = max_fee_per_gas - base_fee;

        // Compare the fee with max_priority_fee_per_gas (or gas price for non-EIP1559 transactions)
        if let Some(priority_fee) = self.max_priority_fee_per_gas() {
            Some(fee.min(priority_fee))
        } else {
            Some(fee)
        }
    }
}

/// Serialize a list of transactions into a sequence of hex-encoded strings.
pub fn serialize_txs<S: serde::Serializer>(
    txs: &[FullTransaction],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_seq(Some(txs.len()))?;
    for tx in txs {
        let encoded = tx.tx.encoded_2718();
        seq.serialize_element(&hex::encode_prefixed(encoded))?;
    }
    seq.end()
}

/// Deserialize a list of transactions from a sequence of hex-encoded strings.
pub fn deserialize_txs<'de, D>(deserializer: D) -> Result<Vec<FullTransaction>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_strings = <Vec<Cow<'_, str>> as de::Deserialize>::deserialize(deserializer)?;
    let mut txs = Vec::with_capacity(hex_strings.len());

    for s in hex_strings {
        let data = hex::decode(s.trim_start_matches("0x")).map_err(de::Error::custom)?;
        let tx = PooledTransactionsElement::decode_2718(&mut data.as_slice())
            .map_err(de::Error::custom)
            .map(|tx| FullTransaction { tx, sender: None })?;
        txs.push(tx);
    }

    Ok(txs)
}
