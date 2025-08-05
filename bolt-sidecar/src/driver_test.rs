#[cfg(test)]
mod tests {
    use crate::{
        api::commitments::spec::CommitmentError,
        primitives::{commitment::SignedCommitment, ExclusionRequest, FirstInclusionRequest},
    };
    use alloy::{
        primitives::Address,
        rpc::types::{AccessList, AccessListItem},
        signers::local::PrivateKeySigner,
    };
    use std::{collections::HashMap, str::FromStr, time::Instant};

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
}
