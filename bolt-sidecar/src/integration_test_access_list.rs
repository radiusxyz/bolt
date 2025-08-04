#[cfg(test)]
mod integration_tests {
    use crate::{
        primitives::{
            ConstraintsMessage, ExclusionRequest, FirstInclusionRequest, FullTransaction,
        },
        crypto::SignableBLS,
        test_util::default_test_transaction,
    };
    use alloy::{
        primitives::{Address, B256},
        rpc::types::{AccessList, AccessListItem},
        signers::local::PrivateKeySigner,
    };
    use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
    use std::str::FromStr;

    #[test]
    fn test_exclusion_request_with_access_list_integration() {
        // Create an address and storage key for testing
        let test_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let storage_key = B256::from([1; 32]);
        
        // Create access list
        let access_list = Some(AccessList(vec![AccessListItem {
            address: test_address,
            storage_keys: vec![storage_key],
        }]));

        // Create a transaction (using existing test transaction)
        let tx_bytes = alloy::hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();
        let tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();
        
        // Create exclusion request with access list
        let exclusion_request = ExclusionRequest {
            slot: 12345,
            txs: vec![tx],
            access_list: access_list.clone(),
            signature: None,
            signer: None,
        };

        // Test that access list is properly included
        assert!(exclusion_request.access_list.is_some());
        let access_list_ref = exclusion_request.access_list.as_ref().unwrap();
        assert_eq!(access_list_ref.0.len(), 1);
        assert_eq!(access_list_ref.0[0].address, test_address);
        assert_eq!(access_list_ref.0[0].storage_keys[0], storage_key);

        // Test digest includes access list
        let digest = exclusion_request.digest();
        assert_eq!(digest.len(), 32);

        // Create the same request without access list and verify different digest
        let exclusion_request_no_access = ExclusionRequest {
            slot: 12345,
            txs: exclusion_request.txs.clone(),
            access_list: None,
            signature: None,
            signer: None,
        };
        
        let digest_no_access = exclusion_request_no_access.digest();
        assert_ne!(digest, digest_no_access);
    }

    #[test]
    fn test_first_inclusion_request_with_access_list_integration() {
        // Create access list with multiple addresses and storage keys
        let addr1 = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let addr2 = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let key1 = B256::from([1; 32]);
        let key2 = B256::from([2; 32]);
        
        let access_list = Some(AccessList(vec![
            AccessListItem {
                address: addr1,
                storage_keys: vec![key1],
            },
            AccessListItem {
                address: addr2,
                storage_keys: vec![key2],
            },
        ]));

        // Create transactions (using existing test transactions)
        let tx_bytes = alloy::hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();
        let tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();
        let bid_tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap(); // Same tx for simplicity
        
        // Create first inclusion request
        let first_inclusion_request = FirstInclusionRequest {
            slot: 54321,
            txs: vec![tx],
            access_list: access_list.clone(),
            bid_transaction: vec![bid_tx],
            signature: None,
            signer: None,
        };

        // Test that access list is properly set
        assert!(first_inclusion_request.access_list.is_some());
        let access_list_ref = first_inclusion_request.access_list.as_ref().unwrap();
        assert_eq!(access_list_ref.0.len(), 2);
        
        // Verify first address
        assert_eq!(access_list_ref.0[0].address, addr1);
        assert_eq!(access_list_ref.0[0].storage_keys[0], key1);
        
        // Verify second address
        assert_eq!(access_list_ref.0[1].address, addr2);
        assert_eq!(access_list_ref.0[1].storage_keys[0], key2);

        // Test digest
        let digest = first_inclusion_request.digest();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_constraints_message_with_access_list_full_flow() {
        // Simulate the full flow from request to constraint creation
        let test_address = Address::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        let storage_key = B256::from([42; 32]);
        
        let access_list = Some(AccessList(vec![AccessListItem {
            address: test_address,
            storage_keys: vec![storage_key],
        }]));

        // Create a transaction
        let tx_bytes = alloy::hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();
        let tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();

        // Create constraints message with access list (simulating driver behavior)
        let constraints_msg = ConstraintsMessage::from_tx_with_access_list(
            BlsPublicKey::default(),
            99999,
            tx,
            access_list.clone(),
        );

        // Test that all fields are properly set
        assert_eq!(constraints_msg.slot, 99999);
        assert_eq!(constraints_msg.transactions.len(), 1);
        assert_eq!(constraints_msg.access_list, access_list);
        assert!(!constraints_msg.top);

        // Test serialization (important for bolt-boost communication)
        let json = serde_json::to_string(&constraints_msg).expect("Should serialize");
        let deserialized: ConstraintsMessage = serde_json::from_str(&json).expect("Should deserialize");
        
        assert_eq!(constraints_msg, deserialized);
        assert_eq!(deserialized.access_list, access_list);

        // Test that digest is deterministic and includes access list
        let digest1 = constraints_msg.digest();
        let digest2 = constraints_msg.digest();
        assert_eq!(digest1, digest2);

        // Test that changing access list changes digest
        let mut modified_constraints = constraints_msg.clone();
        modified_constraints.access_list = None;
        let digest_modified = modified_constraints.digest();
        assert_ne!(digest1, digest_modified);
    }

    #[test]
    fn test_access_list_union_in_constraints() {
        // Test the access list merging logic that would be used when creating constraints
        let addr = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let key1 = B256::from([1; 32]);
        let key2 = B256::from([2; 32]);
        let key3 = B256::from([3; 32]);

        // Simulate multiple access lists from different transactions
        let access_lists = vec![
            AccessList(vec![AccessListItem {
                address: addr,
                storage_keys: vec![key1, key2],
            }]),
            AccessList(vec![AccessListItem {
                address: addr,
                storage_keys: vec![key2, key3], // key2 overlaps
            }]),
        ];

        // Apply the same merging logic as in the driver
        let mut merged_access_list: Vec<AccessListItem> = Vec::new();
        for access_list in access_lists {
            for item in access_list.0 {
                if let Some(existing) = merged_access_list.iter_mut().find(|x| x.address == item.address) {
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

        // Test that union was computed correctly
        assert_eq!(merged_access_list.len(), 1);
        assert_eq!(merged_access_list[0].address, addr);
        assert_eq!(merged_access_list[0].storage_keys.len(), 3); // key1, key2, key3
        assert!(merged_access_list[0].storage_keys.contains(&key1));
        assert!(merged_access_list[0].storage_keys.contains(&key2));
        assert!(merged_access_list[0].storage_keys.contains(&key3));

        // Test using the merged access list in a constraint
        let tx_bytes = alloy::hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();
        let tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();

        let final_access_list = Some(AccessList(merged_access_list));
        let constraints_msg = ConstraintsMessage::from_tx_with_access_list(
            BlsPublicKey::default(),
            12345,
            tx,
            final_access_list,
        );

        // Verify the constraint contains the merged access list
        assert!(constraints_msg.access_list.is_some());
        let constraint_access_list = constraints_msg.access_list.as_ref().unwrap();
        assert_eq!(constraint_access_list.0.len(), 1);
        assert_eq!(constraint_access_list.0[0].storage_keys.len(), 3);
    }
}