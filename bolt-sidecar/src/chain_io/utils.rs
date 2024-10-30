use alloy::primitives::{FixedBytes, B512};
use ethereum_consensus::primitives::BlsPublicKey;
use reth_primitives::keccak256;

/// A 20-byte compressed hash of a BLS public key.
///
/// Reference: https://github.com/chainbound/bolt/blob/lore/feat/holesky-launch/bolt-contracts/script/holesky/validators/registervalidators.s.sol#l65-l69.
pub(crate) type CompressedHash = FixedBytes<20>;

/// Hash the public keys of the proposers. This follows the same
/// implementation done on-chain in the BoltValidators contract.
pub fn pubkey_hashes(keys: &[BlsPublicKey]) -> Vec<CompressedHash> {
    keys.iter().map(pubkey_hash).collect()
}

/// Hash the public key of the proposer. This follows the same
/// implementation done on-chain in the BoltValidators contract.
///
/// Reference: https://github.com/chainbound/bolt/blob/lore/feat/holesky-launch/bolt-contracts/script/holesky/validators/registervalidators.s.sol#l65-l69
pub fn pubkey_hash(key: &BlsPublicKey) -> CompressedHash {
    let digest = pubkey_hash_digest(key);
    let hash = keccak256(digest);
    FixedBytes::<20>::from_slice(hash.get(0..20).expect("hash is longer than 20 bytes"))
}

fn pubkey_hash_digest(key: &BlsPublicKey) -> B512 {
    let mut onchain_pubkey_repr = B512::ZERO;

    // copy the pubkey bytes into the rightmost 48 bytes of the 512-bit buffer.
    // the result should look like this:
    //
    // 0x00000000000000000000000000000000b427fd179b35ef085409e4a98fb3ab84ee29c689df5c64020eab0b20a4f91170f610177db172dc091682df627c9f4021
    // |<---------- 16 bytes ---------->||<----------------------------------------- 48 bytes ----------------------------------------->|
    onchain_pubkey_repr[16..].copy_from_slice(key);
    onchain_pubkey_repr
}

#[cfg(test)]
mod tests {
    use alloy::hex;
    use ethereum_consensus::primitives::BlsPublicKey;

    use super::pubkey_hash;

    #[test]
    fn test_public_key_hash() {
        let bytes = hex!("87cbbfe6f08a0fd424507726cfcf5b9df2b2fd6b78a65a3d7bb6db946dca3102eb8abae32847d5a9a27e414888414c26").as_ref();
        let bls_public_key = BlsPublicKey::try_from(bytes).expect("valid bls public key");
        let hash = pubkey_hash(&bls_public_key);
        assert_eq!(hex::encode(hash.as_slice()), "cf44d8bca49d695164be6796108cf788d8d056e1");
    }
}
