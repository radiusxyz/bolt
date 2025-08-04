#[cfg(test)]
mod tests {
    use crate::{
        api::commitments::spec::{REQUEST_EXCLUSION_METHOD, REQUEST_FIRST_ACCESS_METHOD},
        crypto::SignableBLS,
        primitives::{ExclusionRequest, FirstInclusionRequest},
    };
    use alloy::{
        primitives::Address,
        rpc::types::{AccessList, AccessListItem},
    };
    use std::str::FromStr;

    #[tokio::test]
    async fn test_request_exclusion_method_success() {
        // Create a test exclusion request
        let exclusion_request = ExclusionRequest {
            slot: 12345,
            txs: vec![],
            access_list: Some(AccessList(vec![AccessListItem {
                address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
                storage_keys: vec![],
            }])),
            signature: None,
            signer: None,
        };

        // Test that the method name matches
        assert_eq!(REQUEST_EXCLUSION_METHOD, "bolt_requestExclusion");
        
        // Test JSON serialization/deserialization
        let json_value = serde_json::to_value(&exclusion_request).unwrap();
        let deserialized: ExclusionRequest = serde_json::from_value(json_value).unwrap();
        assert_eq!(exclusion_request, deserialized);
    }

    #[tokio::test]
    async fn test_request_first_inclusion_method_success() {
        // Create a test first inclusion request
        let first_inclusion_request = FirstInclusionRequest {
            slot: 12345,
            txs: vec![],
            access_list: Some(AccessList(vec![AccessListItem {
                address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
                storage_keys: vec![],
            }])),
            bid_transaction: vec![],
            signature: None,
            signer: None,
        };

        // Test that the method name matches
        assert_eq!(REQUEST_FIRST_ACCESS_METHOD, "bolt_requestFirstInclusion");
        
        // Test JSON serialization/deserialization
        let json_value = serde_json::to_value(&first_inclusion_request).unwrap();
        let deserialized: FirstInclusionRequest = serde_json::from_value(json_value).unwrap();
        assert_eq!(first_inclusion_request, deserialized);
    }

    #[test]
    fn test_access_list_union_computation() {
        let addr1 = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let addr2 = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        
        // Create two access lists with overlapping addresses
        let access_list1 = AccessList(vec![
            AccessListItem {
                address: addr1,
                storage_keys: vec![alloy::primitives::B256::from([1; 32])],
            },
            AccessListItem {
                address: addr2,
                storage_keys: vec![alloy::primitives::B256::from([2; 32])],
            },
        ]);

        let access_list2 = AccessList(vec![
            AccessListItem {
                address: addr1,
                storage_keys: vec![alloy::primitives::B256::from([3; 32])], // Different key
            },
        ]);

        // Simulate the union computation logic from the driver
        let mut merged_access_list: Vec<AccessListItem> = Vec::new();
        
        for access_list in [access_list1, access_list2] {
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

        // Verify the union is computed correctly
        assert_eq!(merged_access_list.len(), 2); // Two unique addresses
        
        let addr1_item = merged_access_list.iter().find(|item| item.address == addr1).unwrap();
        assert_eq!(addr1_item.storage_keys.len(), 2); // Two unique keys for addr1
        
        let addr2_item = merged_access_list.iter().find(|item| item.address == addr2).unwrap();
        assert_eq!(addr2_item.storage_keys.len(), 1); // One key for addr2
    }

    #[test]
    fn test_exclusion_request_digest_with_access_list() {
        let exclusion_request = ExclusionRequest {
            slot: 12345,
            txs: vec![],
            access_list: Some(AccessList(vec![AccessListItem {
                address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
                storage_keys: vec![alloy::primitives::B256::from([1; 32])],
            }])),
            signature: None,
            signer: None,
        };

        let digest = exclusion_request.digest();
        assert_eq!(digest.len(), 32); // Should be a valid 32-byte hash
    }

    #[test]
    fn test_first_inclusion_request_digest_with_access_list() {
        let first_inclusion_request = FirstInclusionRequest {
            slot: 12345,
            txs: vec![],
            access_list: Some(AccessList(vec![AccessListItem {
                address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
                storage_keys: vec![alloy::primitives::B256::from([1; 32])],
            }])),
            bid_transaction: vec![],
            signature: None,
            signer: None,
        };

        let digest = first_inclusion_request.digest();
        assert_eq!(digest.len(), 32); // Should be a valid 32-byte hash
    }

    #[test]
    fn test_constraints_message_with_access_list() {
        use crate::primitives::{ConstraintsMessage, FullTransaction};
        use ethereum_consensus::crypto::PublicKey as BlsPublicKey;

        let access_list = Some(AccessList(vec![AccessListItem {
            address: Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            storage_keys: vec![alloy::primitives::B256::from([1; 32])],
        }]));

        // Test from_tx_with_access_list constructor
        let tx_bytes = alloy::hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();
        let tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();

        let constraints_msg = ConstraintsMessage::from_tx_with_access_list(
            BlsPublicKey::default(),
            12345,
            tx,
            access_list.clone(),
        );

        // Verify access list is properly set
        assert_eq!(constraints_msg.access_list, access_list);
        assert_eq!(constraints_msg.slot, 12345);
        assert_eq!(constraints_msg.transactions.len(), 1);

        // Test that digest includes access list (different from without access list)
        let digest_with_access_list = constraints_msg.digest();
        
        let constraints_msg_without_access_list = ConstraintsMessage::from_tx(
            BlsPublicKey::default(),
            12345,
            constraints_msg.transactions[0].clone(),
        );
        let digest_without_access_list = constraints_msg_without_access_list.digest();

        // Digests should be different when access list is included
        assert_ne!(digest_with_access_list, digest_without_access_list);
    }
}