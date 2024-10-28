use ethereum_consensus::crypto::bls::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};
use eyre::Result;
use lighthouse_eth2_keystore::Keystore;

use crate::{
    cli::{KeySource, PubkeysCommand},
    common::{
        dirk::Dirk,
        keystore::{keystore_paths, KeystoreError, KeystoreSecret},
        write_to_file,
    },
    pb::eth2_signer_api::Account,
};

impl PubkeysCommand {
    pub async fn run(self) -> Result<()> {
        match self.source {
            KeySource::SecretKeys { secret_keys } => {
                let pubkeys = list_from_local_keys(&secret_keys)?;

                write_to_file(&self.out, &pubkeys)?;
                println!("Pubkeys generated and saved to {}", self.out);
            }
            KeySource::LocalKeystore { opts } => {
                let keystore_secret = KeystoreSecret::from_keystore_options(&opts)?;
                let pubkeys = list_from_keystore(&opts.path, keystore_secret)?;

                write_to_file(&self.out, &pubkeys)?;
                println!("Pubkeys generated and saved to {}", self.out);
            }
            KeySource::Dirk { opts } => {
                // Note: we don't need to unlock wallets to list pubkeys
                let mut dirk = Dirk::connect(opts.url, opts.tls_credentials).await?;

                let accounts = dirk.list_accounts(opts.wallet_path).await?;
                let pubkeys = list_from_dirk_accounts(&accounts)?;

                write_to_file(&self.out, &pubkeys)?;
                println!("Pubkeys generated and saved to {}", self.out);
            }
        }

        Ok(())
    }
}

/// Derive public keys from the provided secret keys.
pub fn list_from_local_keys(secret_keys: &[String]) -> Result<Vec<BlsPublicKey>> {
    let mut pubkeys = Vec::with_capacity(secret_keys.len());

    for sk in secret_keys {
        let sk = BlsSecretKey::try_from(sk.trim().to_string())?;
        pubkeys.push(sk.public_key());
    }

    Ok(pubkeys)
}

/// Derive public keys from the keystore files in the provided directory.
pub fn list_from_keystore(
    keys_path: &str,
    keystore_secret: KeystoreSecret,
) -> Result<Vec<BlsPublicKey>> {
    let keystores_paths = keystore_paths(keys_path)?;
    let mut pubkeys = Vec::with_capacity(keystores_paths.len());

    for path in keystores_paths {
        let ks = Keystore::from_json_file(path).map_err(KeystoreError::Eth2Keystore)?;
        let password = keystore_secret.get(ks.pubkey()).ok_or(KeystoreError::MissingPassword)?;
        let kp = ks.decrypt_keypair(password.as_bytes()).map_err(KeystoreError::Eth2Keystore)?;
        let pubkey = BlsPublicKey::try_from(kp.pk.serialize().to_vec().as_ref())?;
        pubkeys.push(pubkey);
    }

    Ok(pubkeys)
}

/// Derive public keys from the provided dirk accounts.
pub fn list_from_dirk_accounts(accounts: &[Account]) -> Result<Vec<BlsPublicKey>> {
    let mut pubkeys = Vec::with_capacity(accounts.len());

    for acc in accounts {
        let pubkey = BlsPublicKey::try_from(acc.public_key.as_slice())?;
        pubkeys.push(pubkey);
    }

    Ok(pubkeys)
}
