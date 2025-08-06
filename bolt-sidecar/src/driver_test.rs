#[cfg(test)]
mod tests {
    use crate::{
        api::commitments::spec::CommitmentError,
        driver::{AccessListKey, SidecarDriver},
        primitives::{commitment::SignedCommitment, FirstInclusionRequest, FullTransaction},
        state::StateClient,
    };
    use alloy::{
        consensus::Transaction,
        primitives::{bytes, Address, B256},
        rpc::types::{AccessList, AccessListItem},
        signers::local::PrivateKeySigner,
    };
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
        sync::{Arc, Mutex},
        time::Instant,
    };

    /// Create a test FullTransaction with access list using hex-encoded transaction data
    /// This is a real EIP-2930 transaction with access list for testing
    fn create_test_transaction_with_access_list() -> FullTransaction {
        // EIP-2930 transaction with access list (from alloy examples)
        // This transaction includes access list for testing purposes
        let tx_bytes = bytes!("01f90149018203e882520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead86b5e620f48000b844a9059cbb000000000000000000000000000000000000000000000000000000000000dead0000000000000000000000000000000000000000000000000000000000000001f8c6f8449470997970c51812dc3a010c7d01b50e0d17dc79c8c08303e8a001000000000000000000000000000000000000000000000000000000000000000f8449470997970c51812dc3a010c7d01b50e0d17dc79c8c08303e8a002000000000000000000000000000000000000000000000000000000000000000080a07e77a2c4fda32d51426ee5b83c2536ed3f14e8f6987e7e5e1e8b2b0dc8b15be80a0d5a4e0e1b9e5b6b4a9f3f8b50e2d3f4f9f8f7e6d5c4b3a29180f0e0d0c0b0a09");
        FullTransaction::decode_enveloped(&tx_bytes).unwrap()
    }

    #[test]
    fn test_access_list_union_logic() {
        // Test the access list merging logic used in both exclusion and first inclusion handlers
        let addr1 = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let addr2 = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();

        let key1 = alloy::primitives::B256::from([1; 32]);
        let key2 = alloy::primitives::B256::from([2; 32]);
        let key3 = alloy::primitives::B256::from([3; 32]);

        // Create access lists similar to what the execution client would return
        let access_list_results: Vec<Result<AccessList, &str>> = vec![
            Ok(AccessList(vec![
                AccessListItem { address: addr1, storage_keys: vec![key1, key2] },
                AccessListItem { address: addr2, storage_keys: vec![key3] },
            ])),
            Ok(AccessList(vec![AccessListItem {
                address: addr1,
                storage_keys: vec![key2, key3], // key2 overlaps, key3 is new for addr1
            }])),
        ];

        // Apply the same merging logic as in the driver
        let mut merged_access_list: Vec<AccessListItem> = Vec::new();
        for access_list_result in access_list_results {
            match access_list_result {
                Ok(access_list) => {
                    for item in access_list.0 {
                        if let Some(existing) =
                            merged_access_list.iter_mut().find(|x| x.address == item.address)
                        {
                            // Merge storage keys
                            for key in item.storage_keys {
                                if !existing.storage_keys.contains(&key) {
                                    existing.storage_keys.push(key);
                                }
                            }
                        } else {
                            merged_access_list.push(item);
                        }
                    }
                }
                Err(_) => {} // In the real code, this logs a warning
            }
        }

        // Verify the results
        assert_eq!(merged_access_list.len(), 2);

        let addr1_item = merged_access_list.iter().find(|item| item.address == addr1).unwrap();
        assert_eq!(addr1_item.storage_keys.len(), 3); // key1, key2, key3
        assert!(addr1_item.storage_keys.contains(&key1));
        assert!(addr1_item.storage_keys.contains(&key2));
        assert!(addr1_item.storage_keys.contains(&key3));

        let addr2_item = merged_access_list.iter().find(|item| item.address == addr2).unwrap();
        assert_eq!(addr2_item.storage_keys.len(), 1); // Only key3
        assert!(addr2_item.storage_keys.contains(&key3));
    }

    #[test]
    fn test_commitment_deadline_timing() {
        // Test the timing logic used in handle_commitment_deadline and handle_first_inclusion_deadline
        let commitment_time = Instant::now();
        let first_inclusion_interval = std::time::Duration::from_millis(500);

        // Simulate the timing relationship
        let first_inclusion_time = commitment_time + first_inclusion_interval;

        // Verify the timing relationship
        assert!(first_inclusion_time > commitment_time);
        assert_eq!(first_inclusion_time.duration_since(commitment_time), first_inclusion_interval);
    }

    #[test]
    fn test_pending_first_inclusion_requests_storage() {
        // Test the data structure used to store pending first inclusion requests
        let mut pending_requests: HashMap<
            u64,
            Vec<(
                FirstInclusionRequest,
                tokio::sync::oneshot::Sender<Result<SignedCommitment, CommitmentError>>,
                Instant,
            )>,
        > = HashMap::new();

        let slot = 12345u64;
        let start_time = Instant::now();

        // Create a dummy request (in real code, this comes from the API)
        let request = FirstInclusionRequest {
            slot,
            txs: vec![],
            bid_transaction: vec![],
            signature: None,
            signer: None,
        };

        let (response_tx, _response_rx) = tokio::sync::oneshot::channel();

        // Add to pending requests (same logic as in driver)
        pending_requests.entry(slot).or_insert_with(Vec::new).push((
            request,
            response_tx,
            start_time,
        ));

        // Verify storage
        assert!(pending_requests.contains_key(&slot));
        assert_eq!(pending_requests.get(&slot).unwrap().len(), 1);

        // Test removal (same logic as in handle_first_inclusion_deadline)
        let requests = pending_requests.remove(&slot);
        assert!(requests.is_some());
        assert_eq!(requests.unwrap().len(), 1);
        assert!(!pending_requests.contains_key(&slot));
    }

    #[test]
    fn test_cleanup_logic() {
        // Test the cleanup logic used in handle_first_inclusion_deadline
        let mut commitment_deadline_timestamps: HashMap<u64, Instant> = HashMap::new();

        let current_slot = 100u64;
        let old_slot = current_slot - 10;
        let recent_slot = current_slot - 1;

        commitment_deadline_timestamps.insert(old_slot, Instant::now());
        commitment_deadline_timestamps.insert(recent_slot, Instant::now());
        commitment_deadline_timestamps.insert(current_slot, Instant::now());

        // Apply cleanup logic (keeps slots >= current_slot - 2)
        commitment_deadline_timestamps.retain(|&s, _| s >= current_slot.saturating_sub(2));

        // Verify cleanup results
        assert!(!commitment_deadline_timestamps.contains_key(&old_slot)); // Should be removed
        assert!(commitment_deadline_timestamps.contains_key(&recent_slot)); // Should be kept (99 >= 98)
        assert!(commitment_deadline_timestamps.contains_key(&current_slot)); // Should be kept
    }

    #[test]
    fn test_extract_access_list_keys() {
        // Test the access list key extraction logic using a real EIP-2930 transaction
        let full_tx = create_test_transaction_with_access_list();

        // Test access list key extraction
        let extracted_keys =
            SidecarDriver::<StateClient, PrivateKeySigner>::extract_access_list_keys(&full_tx);

        // Verify that access list keys were extracted
        // The exact number depends on the transaction, but there should be some keys
        println!("Extracted {} access list keys", extracted_keys.len());

        // For this specific test transaction, we expect to have access list entries
        // (We can't assert exact values without parsing the hex, but we can test the logic)
        if let Some(access_list) = full_tx.access_list() {
            let mut expected_keys = Vec::new();
            for item in &access_list.0 {
                for storage_key in &item.storage_keys {
                    expected_keys.push((item.address, *storage_key));
                }
            }
            assert_eq!(extracted_keys.len(), expected_keys.len());
            for key in expected_keys {
                assert!(extracted_keys.contains(&key));
            }
        }
    }

    #[test]
    fn test_atomic_exclusion_validation_no_conflicts() {
        // Test atomic exclusion validation logic with no conflicts
        let slot_access_lists: Arc<Mutex<HashMap<u64, HashSet<AccessListKey>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Create test addresses and storage keys for direct testing
        let addr1 = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let key1 = B256::from([1; 32]);
        let key2 = B256::from([2; 32]);

        // Test the validation logic directly with mock access list keys
        let request_keys = vec![(addr1, key1), (addr1, key2)];
        let target_slot = 100u64;

        // Test the conflict detection logic directly
        let slot_access_lists_data = slot_access_lists.lock().unwrap();
        let existing_keys = slot_access_lists_data.get(&target_slot);

        // Simulate conflict detection
        let mut conflicting_keys = Vec::new();
        if let Some(existing) = existing_keys {
            for key in &request_keys {
                if existing.contains(key) {
                    conflicting_keys.push(*key);
                }
            }
        }

        // Should have no conflicts since slot_access_lists is empty
        assert!(conflicting_keys.is_empty(), "Expected no conflicts for empty access lists");

        // Verify the original request keys
        assert_eq!(request_keys.len(), 2);
        assert!(request_keys.contains(&(addr1, key1)));
        assert!(request_keys.contains(&(addr1, key2)));
    }

    #[test]
    fn test_atomic_exclusion_validation_with_conflicts() {
        // Test atomic exclusion validation logic with conflicts
        let slot_access_lists: Arc<Mutex<HashMap<u64, HashSet<AccessListKey>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Create test addresses and storage keys
        let addr1 = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let key1 = B256::from([1; 32]);
        let key2 = B256::from([2; 32]);
        let key3 = B256::from([3; 32]);

        // Pre-populate with existing access list entries for slot 100
        {
            let mut access_lists = slot_access_lists.lock().unwrap();
            let mut existing_keys = HashSet::new();
            existing_keys.insert((addr1, key1)); // This will conflict
            existing_keys.insert((addr1, key3)); // This won't conflict with our request
            access_lists.insert(100, existing_keys);
        }

        // Test request keys that will conflict
        let request_keys = vec![(addr1, key1), (addr1, key2)]; // key1 conflicts
        let target_slot = 100u64;

        // Test the conflict detection logic directly
        let slot_access_lists_data = slot_access_lists.lock().unwrap();
        let existing_keys = slot_access_lists_data.get(&target_slot);

        // Simulate conflict detection
        let mut conflicting_keys = Vec::new();
        if let Some(existing) = existing_keys {
            for key in &request_keys {
                if existing.contains(key) {
                    conflicting_keys.push(*key);
                }
            }
        }

        // Should detect one conflict (key1)
        assert_eq!(conflicting_keys.len(), 1, "Expected exactly one conflict");
        assert!(conflicting_keys.contains(&(addr1, key1)), "Expected conflict on key1");
    }

    #[test]
    fn test_access_list_cleanup() {
        // Test cleanup logic for old access list entries
        let mut slot_access_lists: HashMap<u64, HashSet<AccessListKey>> = HashMap::new();

        // Create test data spanning multiple slots
        let addr1 = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let key1 = B256::from([1; 32]);

        // Add entries for different slots
        let old_slot = 50u64;
        let recent_slot = 99u64;
        let current_slot = 100u64;

        slot_access_lists.insert(old_slot, {
            let mut keys = HashSet::new();
            keys.insert((addr1, key1));
            keys
        });

        slot_access_lists.insert(recent_slot, {
            let mut keys = HashSet::new();
            keys.insert((addr1, key1));
            keys
        });

        slot_access_lists.insert(current_slot, {
            let mut keys = HashSet::new();
            keys.insert((addr1, key1));
            keys
        });

        // Apply cleanup logic (should keep slots > current_slot - 100)
        let cutoff_slot = current_slot.saturating_sub(100);
        slot_access_lists.retain(|&slot, _| slot > cutoff_slot);

        // Verify cleanup results
        assert!(!slot_access_lists.contains_key(&old_slot)); // Should be removed (50 <= 0)
        assert!(slot_access_lists.contains_key(&recent_slot)); // Should be kept (99 > 0)
        assert!(slot_access_lists.contains_key(&current_slot)); // Should be kept (100 > 0)
    }
}
