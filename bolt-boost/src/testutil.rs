//! Test utilities for bolt-boost
//!
//! This module is only available during testing or when the `test-utils` feature is enabled.

use alloy::primitives::{Bytes, B256};

#[cfg(any(test, feature = "test-utils"))]
use ssz_compat::Decode;
#[cfg(any(test, feature = "test-utils"))]
use types::{ExecPayload, MainnetEthSpec, SignedBeaconBlockDeneb};

#[cfg(any(test, feature = "test-utils"))]
const TEST_BLOCK: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/signed-mainnet-beacon-block.bin.ssz"
));

/// Reads and decodes a signed beacon block from `testdata`.
#[cfg(any(test, feature = "test-utils"))]
pub fn read_test_block() -> SignedBeaconBlockDeneb<MainnetEthSpec> {
    SignedBeaconBlockDeneb::from_ssz_bytes(TEST_BLOCK).unwrap()
}

/// Reads and decodes the transactions root and the transactions from the test block.
#[cfg(any(test, feature = "test-utils"))]
pub fn read_test_transactions() -> (B256, Vec<Bytes>) {
    let test_block = read_test_block();

    let transactions = test_block.message.body.execution_payload.transactions().unwrap();

    let transactions: Vec<Bytes> =
        transactions.into_iter().map(|tx| Bytes::from(tx.to_vec())).collect();

    let transactions_root =
        test_block.message.body.execution_payload.to_execution_payload_header().transactions_root();

    (B256::from_slice(transactions_root.as_ref()), transactions)
}
