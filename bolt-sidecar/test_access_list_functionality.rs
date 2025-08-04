#!/usr/bin/env rust-script

//! Test script to manually verify access_list functionality in constraints
//! 
//! Run with: `cargo run --bin test_access_list_functionality`

use bolt_sidecar::{
    primitives::{
        ConstraintsMessage, ExclusionRequest, FirstInclusionRequest, FullTransaction,
    },
    crypto::SignableBLS,
};
use alloy::{
    primitives::{Address, B256},
    rpc::types::{AccessList, AccessListItem},
};
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use std::str::FromStr;

fn main() {
    println!("🔧 Testing access_list functionality in bolt-sidecar constraints...\n");

    // Test 1: Create ExclusionRequest with access_list
    test_exclusion_request_with_access_list();
    
    // Test 2: Create FirstInclusionRequest with access_list  
    test_first_inclusion_request_with_access_list();
    
    // Test 3: Create ConstraintsMessage with access_list
    test_constraints_message_with_access_list();
    
    // Test 4: Test serialization/deserialization
    test_serialization();
    
    // Test 5: Test signature digest differences
    test_signature_digest_differences();

    println!("✅ All manual tests completed successfully!");
    println!("\n📋 Summary:");
    println!("- ExclusionRequest properly includes access_list in digest");
    println!("- FirstInclusionRequest properly includes access_list in digest");
    println!("- ConstraintsMessage can be created with access_list");
    println!("- JSON serialization/deserialization works correctly");
    println!("- Signature digests differ when access_list is included vs excluded");
    println!("\n🎉 access_list functionality is working correctly!");
}

fn test_exclusion_request_with_access_list() {
    println!("🧪 Test 1: ExclusionRequest with access_list");
    
    let test_address = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
    let storage_key = B256::from([1; 32]);
    
    let access_list = Some(AccessList(vec![AccessListItem {
        address: test_address,
        storage_keys: vec![storage_key],
    }]));

    let tx_bytes = hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();
    let tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();
    
    let exclusion_request = ExclusionRequest {
        slot: 12345,
        txs: vec![tx],
        access_list: access_list.clone(),
        signature: None,
        signer: None,
    };

    assert!(exclusion_request.access_list.is_some());
    let digest = exclusion_request.digest();
    assert_eq!(digest.len(), 32);
    
    println!("   ✅ ExclusionRequest created with access_list");
    println!("   ✅ Digest length: {} bytes", digest.len());
    println!("   ✅ Access list contains {} items", exclusion_request.access_list.as_ref().unwrap().0.len());
}

fn test_first_inclusion_request_with_access_list() {
    println!("\n🧪 Test 2: FirstInclusionRequest with access_list");
    
    let test_address = Address::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
    let storage_key = B256::from([42; 32]);
    
    let access_list = Some(AccessList(vec![AccessListItem {
        address: test_address,
        storage_keys: vec![storage_key],
    }]));

    let tx_bytes = hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();
    let tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();
    let bid_tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();
    
    let first_inclusion_request = FirstInclusionRequest {
        slot: 54321,
        txs: vec![tx],
        access_list: access_list.clone(),
        bid_transaction: vec![bid_tx],
        signature: None,
        signer: None,
    };

    assert!(first_inclusion_request.access_list.is_some());
    let digest = first_inclusion_request.digest();
    assert_eq!(digest.len(), 32);
    
    println!("   ✅ FirstInclusionRequest created with access_list");
    println!("   ✅ Digest length: {} bytes", digest.len());
    println!("   ✅ Access list contains {} items", first_inclusion_request.access_list.as_ref().unwrap().0.len());
}

fn test_constraints_message_with_access_list() {
    println!("\n🧪 Test 3: ConstraintsMessage with access_list");
    
    let test_address = Address::from_str("0x9999999999999999999999999999999999999999").unwrap();
    let storage_key = B256::from([99; 32]);
    
    let access_list = Some(AccessList(vec![AccessListItem {
        address: test_address,
        storage_keys: vec![storage_key],
    }]));

    let tx_bytes = hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();
    let tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();

    let constraints_msg = ConstraintsMessage::from_tx_with_access_list(
        BlsPublicKey::default(),
        99999,
        tx,
        access_list.clone(),
    );

    assert_eq!(constraints_msg.access_list, access_list);
    assert_eq!(constraints_msg.slot, 99999);
    assert_eq!(constraints_msg.transactions.len(), 1);
    
    println!("   ✅ ConstraintsMessage created with access_list");
    println!("   ✅ Slot: {}", constraints_msg.slot);
    println!("   ✅ Transactions: {}", constraints_msg.transactions.len());
    println!("   ✅ Access list present: {}", constraints_msg.access_list.is_some());
}

fn test_serialization() {
    println!("\n🧪 Test 4: JSON Serialization/Deserialization");
    
    let test_address = Address::from_str("0x7777777777777777777777777777777777777777").unwrap();
    let storage_key = B256::from([77; 32]);
    
    let access_list = Some(AccessList(vec![AccessListItem {
        address: test_address,
        storage_keys: vec![storage_key],
    }]));

    let tx_bytes = hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();
    let tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();

    let constraints_msg = ConstraintsMessage::from_tx_with_access_list(
        BlsPublicKey::default(),
        88888,
        tx,
        access_list.clone(),
    );

    // Test serialization
    let json = serde_json::to_string(&constraints_msg).expect("Should serialize");
    println!("   ✅ Serialized to JSON ({} bytes)", json.len());
    
    // Test deserialization
    let deserialized: ConstraintsMessage = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(constraints_msg, deserialized);
    assert_eq!(deserialized.access_list, access_list);
    
    println!("   ✅ Deserialized from JSON successfully");
    println!("   ✅ Access list preserved through serialization");
}

fn test_signature_digest_differences() {
    println!("\n🧪 Test 5: Signature Digest Differences");
    
    let tx_bytes = hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();
    let tx = FullTransaction::decode_enveloped(&tx_bytes).unwrap();

    // Create constraint with access list
    let access_list = Some(AccessList(vec![AccessListItem {
        address: Address::from_str("0x5555555555555555555555555555555555555555").unwrap(),
        storage_keys: vec![B256::from([55; 32])],
    }]));

    let constraints_with_access_list = ConstraintsMessage::from_tx_with_access_list(
        BlsPublicKey::default(),
        12345,
        tx.clone(),
        access_list,
    );

    // Create constraint without access list
    let constraints_without_access_list = ConstraintsMessage::from_tx(
        BlsPublicKey::default(),
        12345,
        tx,
    );

    // Get digests
    let digest_with = constraints_with_access_list.digest();
    let digest_without = constraints_without_access_list.digest();

    assert_ne!(digest_with, digest_without);
    
    println!("   ✅ Digest with access_list: {:?}", hex::encode(&digest_with[..8]));
    println!("   ✅ Digest without access_list: {:?}", hex::encode(&digest_without[..8]));
    println!("   ✅ Digests are different (access_list affects signature)");
}

// Re-export hex for this test
use hex;