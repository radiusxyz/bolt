use bolt_boost::types::ConstraintsMessage;
use alloy::{
    primitives::{Address, B256, Bytes},
    rpc::types::{AccessList, AccessListItem, beacon::BlsPublicKey},
};
use std::str::FromStr;

fn main() {
    println!("🔧 Testing access_list functionality in bolt-boost constraints...\n");

    // Test 1: Create ConstraintsMessage with access_list
    test_constraints_message_with_access_list();
    
    // Test 2: Test serialization/deserialization
    test_serialization();
    
    // Test 3: Test signature digest differences
    test_signature_digest_differences();

    println!("✅ All manual tests completed successfully!");
    println!("\n📋 Summary:");
    println!("- ConstraintsMessage can be created with access_list");
    println!("- JSON serialization/deserialization works correctly");
    println!("- Signature digests differ when access_list is included vs excluded");
    println!("\n🎉 access_list functionality is working correctly in bolt-boost!");
}

fn test_constraints_message_with_access_list() {
    println!("🧪 Test 1: ConstraintsMessage with access_list");
    
    let test_address = Address::from_str("0x9999999999999999999999999999999999999999").unwrap();
    let storage_key = B256::from([99; 32]);
    
    let access_list = Some(AccessList(vec![AccessListItem {
        address: test_address,
        storage_keys: vec![storage_key],
    }]));

    let tx_bytes = alloy::hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();

    let constraints_msg = ConstraintsMessage {
        pubkey: BlsPublicKey::default(),
        slot: 99999,
        top: false,
        transactions: vec![Bytes::from(tx_bytes)],
        access_list: access_list.clone(),
    };

    assert_eq!(constraints_msg.access_list, access_list);
    assert_eq!(constraints_msg.slot, 99999);
    assert_eq!(constraints_msg.transactions.len(), 1);
    
    println!("   ✅ ConstraintsMessage created with access_list");
    println!("   ✅ Slot: {}", constraints_msg.slot);
    println!("   ✅ Transactions: {}", constraints_msg.transactions.len());
    println!("   ✅ Access list present: {}", constraints_msg.access_list.is_some());
}

fn test_serialization() {
    println!("\n🧪 Test 2: JSON Serialization/Deserialization");
    
    let test_address = Address::from_str("0x7777777777777777777777777777777777777777").unwrap();
    let storage_key = B256::from([77; 32]);
    
    let access_list = Some(AccessList(vec![AccessListItem {
        address: test_address,
        storage_keys: vec![storage_key],
    }]));

    let tx_bytes = alloy::hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();

    let constraints_msg = ConstraintsMessage {
        pubkey: BlsPublicKey::default(),
        slot: 88888,
        top: false,
        transactions: vec![Bytes::from(tx_bytes)],
        access_list: access_list.clone(),
    };

    // Test serialization
    let json = serde_json::to_string(&constraints_msg).expect("Should serialize");
    println!("   ✅ Serialized to JSON ({} bytes)", json.len());
    println!("   📝 Sample JSON: {}...", &json[..100.min(json.len())]);
    
    // Test deserialization
    let deserialized: ConstraintsMessage = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(constraints_msg, deserialized);
    assert_eq!(deserialized.access_list, access_list);
    
    println!("   ✅ Deserialized from JSON successfully");
    println!("   ✅ Access list preserved through serialization");
}

fn test_signature_digest_differences() {
    println!("\n🧪 Test 3: Signature Digest Differences");
    
    let tx_bytes = alloy::hex::decode("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").unwrap();

    // Create constraint with access list
    let access_list = Some(AccessList(vec![AccessListItem {
        address: Address::from_str("0x5555555555555555555555555555555555555555").unwrap(),
        storage_keys: vec![B256::from([55; 32])],
    }]));

    let constraints_with_access_list = ConstraintsMessage {
        pubkey: BlsPublicKey::default(),
        slot: 12345,
        top: false,
        transactions: vec![Bytes::from(tx_bytes.clone())],
        access_list,
    };

    // Create constraint without access list
    let constraints_without_access_list = ConstraintsMessage {
        pubkey: BlsPublicKey::default(),
        slot: 12345,
        top: false,
        transactions: vec![Bytes::from(tx_bytes)],
        access_list: None,
    };

    // Get digests
    let digest_with = constraints_with_access_list.digest().unwrap();
    let digest_without = constraints_without_access_list.digest().unwrap();

    assert_ne!(digest_with, digest_without);
    
    println!("   ✅ Digest with access_list: {}", alloy::hex::encode(&digest_with[..8]));
    println!("   ✅ Digest without access_list: {}", alloy::hex::encode(&digest_without[..8]));
    println!("   ✅ Digests are different (access_list affects signature)");
    println!("   📊 This proves that access_list is properly included in constraint signatures");
}