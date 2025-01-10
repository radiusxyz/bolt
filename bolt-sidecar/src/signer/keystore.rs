use std::{
    collections::HashSet,
    ffi::OsString,
    fmt::Debug,
    fs::{self, DirEntry, ReadDir},
    io,
    path::{Path, PathBuf},
};

use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use lighthouse_bls::Keypair;
use lighthouse_eth2_keystore::Keystore;

use crate::{builder::signature::compute_signing_root, config::ChainConfig, crypto::bls::BLSSig};

use super::SignerResult;

/// Error in the keystore signer.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum KeystoreError {
    #[error("failed to read keystore directory: {0}")]
    ReadFromDirectory(#[from] std::io::Error),
    #[error("failed to read keystore from JSON file {0}: {1}")]
    ReadFromJSON(PathBuf, String),
    #[error("failed to read keystore secret from file: {0}")]
    ReadFromSecretFile(String),
    #[error("failed to decrypt keypair from JSON file {0} with the provided password: {1}")]
    KeypairDecryption(PathBuf, String),
    #[error("could not find private key associated to public key {0}")]
    UnknownPublicKey(String),
    #[error("invalid signature key length -- signature: {0} -- message: {1}")]
    SignatureLength(String, String),
}

/// A signer that can sign messages with multiple keypairs loaded from
/// ERC-2335 keystores files.
#[derive(Clone)]
pub struct KeystoreSigner {
    keypairs: Vec<Keypair>,
    chain: ChainConfig,
}

impl KeystoreSigner {
    /// Creates a new `KeystoreSigner` from the keystore files in the `keys_path` directory.
    /// The secret is expected to be the same password for all the keystore files.
    pub fn from_password(
        keys_path: &PathBuf,
        password: &[u8],
        chain: ChainConfig,
    ) -> SignerResult<Self> {
        // Create the path to the keystore directory, starting from the root of the project
        let keystores_paths = find_json_keystores(keys_path)?;
        let mut keypairs = Vec::with_capacity(keystores_paths.len());

        for path in keystores_paths {
            let keystore = Keystore::from_json_file(path.clone())
                .map_err(|e| KeystoreError::ReadFromJSON(path.clone(), format!("{e:?}")))?;
            let keypair = keystore
                .decrypt_keypair(password)
                .map_err(|e| KeystoreError::KeypairDecryption(path.clone(), format!("{e:?}")))?;
            keypairs.push(keypair);
        }

        Ok(Self { keypairs, chain })
    }

    /// Creates a new `KeystoreSigner` from the keystore files in the `keys_path` directory.
    /// The secret files are expected to be in the `secrets_path` directory.
    pub fn from_secrets_directory(
        keys_path: &PathBuf,
        secrets_path: &Path,
        chain: ChainConfig,
    ) -> SignerResult<Self> {
        let keystores_paths = find_json_keystores(keys_path)?;

        let mut keypairs = Vec::with_capacity(keystores_paths.len());

        for path in keystores_paths {
            let keystore = Keystore::from_json_file(path.clone())
                .map_err(|e| KeystoreError::ReadFromJSON(path.clone(), format!("{e:?}")))?;

            let pubkey = format!("0x{}", keystore.pubkey());

            let mut secret_path = secrets_path.to_path_buf();
            secret_path.push(pubkey);

            let password = fs::read_to_string(secret_path)
                .map_err(|e| KeystoreError::ReadFromSecretFile(format!("{e:?}")))?;

            let keypair = keystore
                .decrypt_keypair(password.as_bytes())
                .map_err(|e| KeystoreError::KeypairDecryption(path.clone(), format!("{e:?}")))?;
            keypairs.push(keypair);
        }

        Ok(Self { keypairs, chain })
    }

    /// Returns the public keys of the keypairs in the keystore.
    pub fn pubkeys(&self) -> HashSet<BlsPublicKey> {
        self.keypairs
            .iter()
            .map(|kp| {
                BlsPublicKey::try_from(kp.pk.serialize().to_vec().as_ref()).expect("valid pubkey")
            })
            .collect::<HashSet<_>>()
    }

    /// Signs a message with the keystore signer and the Commit Boost domain
    pub fn sign_commit_boost_root(
        &self,
        root: [u8; 32],
        public_key: &BlsPublicKey,
    ) -> SignerResult<BLSSig> {
        self.sign_root(root, public_key, self.chain.commit_boost_domain())
    }

    /// Signs a message with the keystore signer.
    fn sign_root(
        &self,
        root: [u8; 32],
        public_key: &BlsPublicKey,
        domain: [u8; 32],
    ) -> SignerResult<BLSSig> {
        let sk = self
            .keypairs
            .iter()
            .find(|kp| kp.pk.serialize() == public_key.as_ref())
            .ok_or(KeystoreError::UnknownPublicKey(public_key.to_string()))?;

        let signing_root = compute_signing_root(root, domain);

        let sig = sk.sk.sign(signing_root.into()).serialize();
        let sig = BLSSig::try_from(sig.as_slice())
            .map_err(|e| KeystoreError::SignatureLength(hex::encode(sig), format!("{e:?}")))?;

        Ok(sig)
    }

    #[cfg(test)]
    #[allow(unused)]
    pub(crate) fn get_key_pairs(&self) -> Vec<Keypair> {
        self.keypairs.to_vec()
    }
}

impl Debug for KeystoreSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeystoreSigner")
            .field(
                "pubkeys",
                &self.keypairs.iter().map(|kp| kp.pk.as_hex_string()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Returns the paths of all the keystore files provided an optional `keys_path`, which defaults to
/// `keys`. `keys_path` is a relative path from the root of this cargo project
/// We're expecting a directory structure like:
/// ${keys_path}/
/// -- 0x1234.../validator.json
/// -- 0x5678.../validator.json
/// -- ...
fn find_json_keystores(keys_path: &PathBuf) -> SignerResult<Vec<PathBuf>> {
    let json_extension = OsString::from("json");

    let mut keystores_paths = vec![];
    // Iter over the `keys` directory
    for entry in read_dir(keys_path)? {
        let path = read_path(entry)?;
        if path.is_dir() {
            for entry in read_dir(&path)? {
                let path = read_path(entry)?;
                if path.is_file() && path.extension() == Some(&json_extension) {
                    keystores_paths.push(path);
                }
            }
        }
    }

    Ok(keystores_paths)
}

fn read_dir(path: &PathBuf) -> SignerResult<ReadDir> {
    Ok(fs::read_dir(path).map_err(KeystoreError::ReadFromDirectory)?)
}

fn read_path(entry: std::result::Result<DirEntry, io::Error>) -> SignerResult<PathBuf> {
    Ok(entry.map_err(KeystoreError::ReadFromDirectory)?.path())
}
