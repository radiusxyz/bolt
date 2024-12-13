use ethereum_consensus::crypto::bls::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};
use eyre::Result;
use lighthouse_eth2_keystore::Keystore;

use crate::{
    cli::{KeysSource, PubkeysCommand},
    common::{
        dirk::Dirk,
        keystore::{keystore_paths, KeystoreError},
        web3signer::Web3Signer,
        write_to_file,
    },
    pb::eth2_signer_api::ListAccountsResponse,
};

impl PubkeysCommand {
    pub async fn run(self) -> Result<()> {
        match self.source {
            KeysSource::SecretKeys { secret_keys } => {
                let pubkeys = list_from_local_keys(&secret_keys)?;

                write_to_file(&self.out, &pubkeys)?;
                println!("Pubkeys generated and saved to {}", self.out);
            }
            KeysSource::LocalKeystore { opts } => {
                let pubkeys = list_from_keystore(&opts.path)?;

                write_to_file(&self.out, &pubkeys)?;
                println!("Pubkeys generated from local keystore and saved to {}", self.out);
            }
            KeysSource::Dirk { opts } => {
                // Note: we don't need to unlock wallets to list pubkeys
                let mut dirk = Dirk::connect(opts.url, opts.tls_credentials).await?;

                let all_accounts = dirk.list_accounts(opts.wallet_path).await?;
                let pubkeys = list_from_dirk_accounts(all_accounts)?;

                write_to_file(&self.out, &pubkeys)?;
                println!("Pubkeys generated from Dirk and saved to {}", self.out);
            }
            KeysSource::Web3Signer { opts } => {
                let mut web3signer = Web3Signer::connect(opts.url, opts.tls_credentials).await?;

                let accounts = web3signer.list_accounts().await?;
                let pubkeys = list_from_web3signer_accounts(&accounts)?;

                write_to_file(&self.out, &pubkeys)?;
                println!("Pubkeys generated from Web3signer and saved to {}", self.out);
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
pub fn list_from_keystore(keys_path: &str) -> Result<Vec<BlsPublicKey>> {
    let keystores_paths = keystore_paths(keys_path)?;
    let mut pubkeys = Vec::with_capacity(keystores_paths.len());

    for path in keystores_paths {
        let ks = Keystore::from_json_file(path).map_err(KeystoreError::Eth2Keystore)?;
        let pubkey = BlsPublicKey::try_from(
            ks.public_key()
                .expect("to parse public key from keystore")
                .serialize()
                .to_vec()
                .as_ref(),
        )?;
        pubkeys.push(pubkey);
    }

    Ok(pubkeys)
}

/// Derive public keys from the provided dirk accounts.
pub fn list_from_dirk_accounts(accounts: ListAccountsResponse) -> Result<Vec<BlsPublicKey>> {
    let count = accounts.accounts.len() + accounts.distributed_accounts.len();
    let mut pubkeys = Vec::with_capacity(count);

    for acc in accounts.accounts {
        let pubkey = BlsPublicKey::try_from(acc.public_key.as_slice())?;
        pubkeys.push(pubkey);
    }
    for acc in accounts.distributed_accounts {
        let pubkey = BlsPublicKey::try_from(acc.composite_public_key.as_slice())?;
        pubkeys.push(pubkey);
    }

    Ok(pubkeys)
}

/// Derive public keys from the provided web3signer accounts.
pub fn list_from_web3signer_accounts(accounts: &[String]) -> Result<Vec<BlsPublicKey>> {
    let mut pubkeys = Vec::with_capacity(accounts.len());

    for acc in accounts {
        let trimmed_account = &acc.clone()[2..];
        let pubkey = BlsPublicKey::try_from(hex::decode(trimmed_account)?.as_slice())?;
        pubkeys.push(pubkey);
    }

    Ok(pubkeys)
}
