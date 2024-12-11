use alloy::primitives::{keccak256, FixedBytes, B512};
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;

/// A 20-byte compressed hash of a BLS public key.
///
/// Reference: https://github.com/chainbound/bolt/blob/bec46baae6d7c16dddd81e5e72710ca8e3064f82/bolt-contracts/script/holesky/validators/RegisterValidators.s.sol#L65-L69
pub type CompressedHash = FixedBytes<20>;

/// Compress a BLS public key into a 20-byte hash.
pub fn compress_bls_pubkey(pubkey: &BlsPublicKey) -> CompressedHash {
    let mut onchain_pubkey_repr = B512::ZERO;

    // copy the pubkey bytes into the rightmost 48 bytes of the 512-bit buffer.
    // the result should look like this:
    //
    // 0x00000000000000000000000000000000b427fd179b35ef085409e4a98fb3ab84ee29c689df5c64020eab0b20a4f91170f610177db172dc091682df627c9f4021
    // |<---------- 16 bytes ---------->||<----------------------------------------- 48 bytes ----------------------------------------->|
    onchain_pubkey_repr[16..].copy_from_slice(pubkey.as_ref());

    // hash the pubkey
    let hash = keccak256(onchain_pubkey_repr);

    CompressedHash::from_slice(hash.get(0..20).expect("hash is longer than 20 bytes"))
}

#[cfg(test)]
mod tests {
    use ethereum_consensus::crypto::PublicKey as BlsPublicKey;

    use crate::common::hash::compress_bls_pubkey;

    #[test]
    fn test_compute_pubkey_hash() -> eyre::Result<()> {
        let pubkey = "8fa1c53218bdcbb4c8eb27a6c92b8147ca557717a6aeb1f5c347559255b421e5c7327ab047662be883fde91947ae0334";
        let pubkey = BlsPublicKey::try_from(hex::decode(pubkey)?.as_slice())?;

        let hash = compress_bls_pubkey(&pubkey);
        assert_eq!(
            hex::encode(hash),
            "9bf58e9a809e502234ece758ac401741d6c1a30d",
            "hash should match the expected value"
        );

        Ok(())
    }
}
