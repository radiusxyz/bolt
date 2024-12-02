use std::collections::HashMap;

use alloy::{
    primitives::B256,
    signers::k256::sha2::{Digest, Sha256},
};
use ethereum_consensus::crypto::{
    aggregate, PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature,
};
use eyre::{bail, Result};
use lighthouse_eth2_keystore::Keystore;
use serde::Serialize;
use tracing::{debug, warn};

use crate::{
    cli::{Action, Chain, DelegateCommand, DirkOpts, SecretsSource},
    common::{
        dirk::Dirk,
        keystore::{keystore_paths, KeystoreError, KeystoreSecret},
        parse_bls_public_key,
        signing::{
            compute_commit_boost_signing_root, compute_domain_from_mask, verify_commit_boost_root,
        },
        write_to_file,
    },
};

impl DelegateCommand {
    /// Run the `delegate` command.
    pub async fn run(self) -> Result<()> {
        match self.source {
            SecretsSource::SecretKeys { secret_keys } => {
                let delegatee_pubkey = parse_bls_public_key(&self.delegatee_pubkey)?;
                let signed_messages = generate_from_local_keys(
                    &secret_keys,
                    delegatee_pubkey,
                    self.chain,
                    self.action,
                )?;
                debug!("Signed {} messages with local keys", signed_messages.len());

                // Verify signatures
                for message in &signed_messages {
                    verify_message_signature(message, self.chain)?;
                }

                write_to_file(&self.out, &signed_messages)?;
                println!("Signed delegation messages generated and saved to {}", self.out);
            }
            SecretsSource::LocalKeystore { opts } => {
                let keystore_secret = KeystoreSecret::from_keystore_options(&opts)?;
                let delegatee_pubkey = parse_bls_public_key(&self.delegatee_pubkey)?;
                let signed_messages = generate_from_keystore(
                    &opts.path,
                    keystore_secret,
                    delegatee_pubkey,
                    self.chain,
                    self.action,
                )?;
                debug!("Signed {} messages with keystore", signed_messages.len());

                // Verify signatures
                for message in &signed_messages {
                    verify_message_signature(message, self.chain)?;
                }

                write_to_file(&self.out, &signed_messages)?;
                println!("Signed delegation messages generated and saved to {}", self.out);
            }
            SecretsSource::Dirk { opts } => {
                let delegatee_pubkey = parse_bls_public_key(&self.delegatee_pubkey)?;
                let signed_messages =
                    generate_from_dirk(opts, delegatee_pubkey, self.chain, self.action).await?;
                debug!("Signed {} messages with Dirk", signed_messages.len());

                // Verify signatures
                for message in &signed_messages {
                    verify_message_signature(message, self.chain)?;
                }

                write_to_file(&self.out, &signed_messages)?;
                println!("Signed delegation messages generated and saved to {}", self.out);
            }
        }

        Ok(())
    }
}

/// Generate signed delegations/revocations using local BLS private keys
///
/// - Use the provided private keys from either CLI or env variable
/// - Create message
/// - Compute the signing roots and sign the messages
/// - Return the signed messages
pub fn generate_from_local_keys(
    secret_keys: &[String],
    delegatee_pubkey: BlsPublicKey,
    chain: Chain,
    action: Action,
) -> Result<Vec<SignedMessage>> {
    let mut signed_messages = Vec::with_capacity(secret_keys.len());

    for sk in secret_keys {
        let sk = BlsSecretKey::try_from(sk.trim().to_string())?;

        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(sk.public_key(), delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), &chain)?;
                let signature = sk.sign(signing_root.0.as_ref());
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed))
            }
            Action::Revoke => {
                let message = RevocationMessage::new(sk.public_key(), delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), &chain)?;
                let signature = sk.sign(signing_root.0.as_ref());
                let signed = SignedRevocation { message, signature };
                signed_messages.push(SignedMessage::Revocation(signed));
            }
        }
    }

    Ok(signed_messages)
}

/// Generate signed delegations/revocations using a keystore file
///
/// - Read the keystore file
/// - Decrypt the keypairs using the password
/// - Create messages
/// - Compute the signing roots and sign the message
/// - Return the signed message
pub fn generate_from_keystore(
    keys_path: &str,
    keystore_secret: KeystoreSecret,
    delegatee_pubkey: BlsPublicKey,
    chain: Chain,
    action: Action,
) -> Result<Vec<SignedMessage>> {
    let keystores_paths = keystore_paths(keys_path)?;
    let mut signed_messages = Vec::with_capacity(keystores_paths.len());
    debug!("Found {} keys in the keystore", keystores_paths.len());

    for path in keystores_paths {
        let ks = Keystore::from_json_file(path).map_err(KeystoreError::Eth2Keystore)?;
        let password = keystore_secret.get(ks.pubkey()).ok_or(KeystoreError::MissingPassword)?;
        let kp = ks.decrypt_keypair(password.as_bytes()).map_err(KeystoreError::Eth2Keystore)?;
        let validator_pubkey = BlsPublicKey::try_from(kp.pk.serialize().to_vec().as_ref())?;
        let validator_private_key = kp.sk;

        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), &chain)?;
                let signature = validator_private_key.sign(signing_root.0.into());
                let signature = BlsSignature::try_from(signature.serialize().as_ref())?;
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed));
            }
            Action::Revoke => {
                let message = RevocationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), &chain)?;
                let signature = validator_private_key.sign(signing_root.0.into());
                let signature = BlsSignature::try_from(signature.serialize().as_ref())?;
                let signed = SignedRevocation { message, signature };
                signed_messages.push(SignedMessage::Revocation(signed));
            }
        }
    }

    Ok(signed_messages)
}

/// Generate signed delegations/revocations using remote Dirk signers
pub async fn generate_from_dirk(
    opts: DirkOpts,
    delegatee_pubkey: BlsPublicKey,
    chain: Chain,
    action: Action,
) -> Result<Vec<SignedMessage>> {
    // read the accounts from the remote Dirk signer at the provided URL
    let mut dirk = Dirk::connect(opts.url.clone(), opts.tls_credentials.clone()).await?;
    let accounts = dirk.list_accounts(opts.wallet_path).await?;
    debug!(
        regular = %accounts.accounts.len(),
        distributed = %accounts.distributed_accounts.len(),
        "Found remote accounts"
    );

    // specify the signing domain (it needs to be included in the signing requests)
    let domain = B256::from(compute_domain_from_mask(chain.fork_version()));

    let total_accounts = accounts.accounts.len() + accounts.distributed_accounts.len();
    let mut signed_messages = Vec::with_capacity(total_accounts);

    // regular and distributed account work differently.
    // - For regular accounts, we can sign the message directly
    // - For distributed accounts, we need to:
    //    - Look into the account's participants and threshold configuration
    //    - Connect to at least `threshold` nodes individually
    //    - Sign the message on each node
    //    - Aggregate the signatures

    for regular in accounts.accounts {
        let name = regular.name.clone();
        let validator_pubkey = BlsPublicKey::try_from(regular.public_key.as_slice())?;

        if let Some(passphrases) = &opts.passphrases {
            dirk.try_unlock_account_with_passphrases(name.clone(), passphrases).await?;
        } else {
            bail!("A passphrase is required in order to sign messages remotely with Dirk");
        }

        let signed = create_and_sign_message(
            &mut dirk,
            name.clone(),
            action,
            domain,
            validator_pubkey,
            delegatee_pubkey.clone(),
        )
        .await?;

        // Try to lock the account back after signing
        if let Err(err) = dirk.lock_account(name.clone()).await {
            warn!("Failed to lock account after signing {}: {:?}", name, err);
        }

        signed_messages.push(signed);
    }

    let mut dirk_conns = HashMap::<String, Dirk>::new();
    dirk_conns.insert(opts.url, dirk);

    for distributed in accounts.distributed_accounts {
        let name = distributed.name.clone();
        let validator_pubkey = BlsPublicKey::try_from(distributed.composite_public_key.as_slice())?;
        let threshold = distributed.signing_threshold as usize;
        let mut participant_signatures = Vec::new();

        for participant in distributed.participants {
            // Note: the Dirk endpoint address must be parsed as "https://name:port".
            // Sauce: https://github.com/wealdtech/go-eth2-wallet-dirk/blob/263190301ef3352fbda43f91363145f175a12cf6/grpc.go#L1706
            let addr = format!("https://{}:{}", participant.name, participant.port);

            // grab a connection to the participant instance. If it doesn't exist, create a new one
            let conn = if let Some(conn) = dirk_conns.get_mut(&addr) {
                conn
            } else {
                let new_conn = Dirk::connect(addr.clone(), opts.tls_credentials.clone()).await?;
                dirk_conns.insert(addr.clone(), new_conn);
                dirk_conns.get_mut(&addr).unwrap()
            };

            if let Some(passphrases) = &opts.passphrases {
                conn.try_unlock_account_with_passphrases(name.clone(), passphrases).await?;
            } else {
                bail!("A passphrase is required in order to sign messages remotely with Dirk");
            }

            let signed = create_and_sign_message(
                conn,
                name.clone(),
                action,
                domain,
                validator_pubkey.clone(),
                delegatee_pubkey.clone(),
            )
            .await?;

            let participant_signature = signed.signature().clone();
            participant_signatures.push(participant_signature);

            // Try to lock the account back after signing
            if let Err(err) = conn.lock_account(name.clone()).await {
                warn!("Failed to lock account after signing {}: {:?}", name, err);
            }
        }

        // Check that we have at least the minimum threshold of signatures
        let sigs = participant_signatures.into_iter().take(threshold).collect::<Vec<_>>();
        if sigs.len() < threshold {
            bail!(
                "Failed to get enough signatures for distributed account '{}'. Got {}, expected at least {}",
                name,
                sigs.len(),
                threshold
            );
        }

        // Aggregate the signatures
        let signature = aggregate(&sigs)?;
        let final_message = match action {
            Action::Delegate => {
                let message = DelegationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                SignedMessage::Delegation(SignedDelegation { message, signature })
            }
            Action::Revoke => {
                let message = RevocationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                SignedMessage::Revocation(SignedRevocation { message, signature })
            }
        };

        // Sanity check: verify the aggregated signature
        verify_message_signature(&final_message, chain)?;

        // Add the final message to the list of signed messages
        signed_messages.push(final_message);
    }

    // Sanity check: count the total number of signed messages
    if signed_messages.len() != total_accounts {
        bail!(
            "Failed to sign messages for all accounts. Expected {}, got {}",
            total_accounts,
            signed_messages.len()
        );
    }

    Ok(signed_messages)
}

/// Create and sign a message using the remote Dirk signer
async fn create_and_sign_message(
    dirk: &mut Dirk,
    account_name: String,
    action: Action,
    domain: B256,
    validator_pubkey: BlsPublicKey,
    delegatee_pubkey: BlsPublicKey,
) -> Result<SignedMessage> {
    match action {
        Action::Delegate => {
            let message = DelegationMessage::new(validator_pubkey, delegatee_pubkey);
            let signing_root = message.digest().into(); // Dirk does the hash tree root internally
            let signature = dirk.request_signature(account_name, signing_root, domain).await?;
            let signed = SignedDelegation { message, signature };
            Ok(SignedMessage::Delegation(signed))
        }
        Action::Revoke => {
            let message = RevocationMessage::new(validator_pubkey, delegatee_pubkey);
            let signing_root = message.digest().into(); // Dirk does the hash tree root internally
            let signature = dirk.request_signature(account_name, signing_root, domain).await?;
            let signed = SignedRevocation { message, signature };
            Ok(SignedMessage::Revocation(signed))
        }
    }
}

/// Event types that can be emitted by the validator pubkey to
/// signal some action on the Bolt protocol.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum SignedMessageAction {
    /// Signal delegation of a validator pubkey to a delegatee pubkey.
    Delegation,
    /// Signal revocation of a previously delegated pubkey.
    Revocation,
}

/// Transparent serialization of signed messages.
/// This is used to serialize and deserialize signed messages
///
/// e.g. serde_json::to_string(&signed_message):
/// ```
/// {
///    "message": {
///       "action": 0,
///       "validator_pubkey": "0x...",
///       "delegatee_pubkey": "0x..."
///    },
///   "signature": "0x..."
/// },
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SignedMessage {
    Delegation(SignedDelegation),
    Revocation(SignedRevocation),
}

impl SignedMessage {
    /// Get the message signature
    pub fn signature(&self) -> &BlsSignature {
        match self {
            Self::Delegation(signed_delegation) => &signed_delegation.signature,
            Self::Revocation(signed_revocation) => &signed_revocation.signature,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignedDelegation {
    pub message: DelegationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DelegationMessage {
    action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

impl DelegationMessage {
    /// Create a new delegation message.
    pub fn new(validator_pubkey: BlsPublicKey, delegatee_pubkey: BlsPublicKey) -> Self {
        Self { action: SignedMessageAction::Delegation as u8, validator_pubkey, delegatee_pubkey }
    }

    /// Compute the digest of the delegation message.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.action]);
        hasher.update(self.validator_pubkey.to_vec());
        hasher.update(self.delegatee_pubkey.to_vec());

        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignedRevocation {
    pub message: RevocationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RevocationMessage {
    action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

impl RevocationMessage {
    /// Create a new revocation message.
    pub fn new(validator_pubkey: BlsPublicKey, delegatee_pubkey: BlsPublicKey) -> Self {
        Self { action: SignedMessageAction::Revocation as u8, validator_pubkey, delegatee_pubkey }
    }

    /// Compute the digest of the revocation message.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.action]);
        hasher.update(self.validator_pubkey.to_vec());
        hasher.update(self.delegatee_pubkey.to_vec());

        hasher.finalize().into()
    }
}

/// Verify the signature of a signed message
pub fn verify_message_signature(message: &SignedMessage, chain: Chain) -> Result<()> {
    match message {
        SignedMessage::Delegation(signed_delegation) => {
            let signer_pubkey = signed_delegation.message.validator_pubkey.clone();
            let digest = signed_delegation.message.digest();

            let blst_sig =
                blst::min_pk::Signature::from_bytes(signed_delegation.signature.as_ref())
                    .map_err(|e| eyre::eyre!("Failed to parse signature: {:?}", e))?;

            // Verify the signature
            verify_commit_boost_root(signer_pubkey, digest, &blst_sig, &chain)
        }
        SignedMessage::Revocation(signed_revocation) => {
            let signer_pubkey = signed_revocation.message.validator_pubkey.clone();
            let digest = signed_revocation.message.digest();

            let blst_sig =
                blst::min_pk::Signature::from_bytes(signed_revocation.signature.as_ref())
                    .map_err(|e| eyre::eyre!("Failed to parse signature: {:?}", e))?;

            // Verify the signature
            verify_commit_boost_root(signer_pubkey, digest, &blst_sig, &chain)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cli::{Action, Chain, DirkOpts},
        common::{
            dirk::{self},
            keystore, parse_bls_public_key,
        },
    };

    use super::{generate_from_dirk, generate_from_keystore, verify_message_signature};

    #[test]
    fn test_delegation_keystore_signer_lighthouse() -> eyre::Result<()> {
        // Read the keystore from test_data
        let keys_path = env!("CARGO_MANIFEST_DIR").to_string() + "/test_data/lighthouse/validators";
        let secrets_path = env!("CARGO_MANIFEST_DIR").to_string() + "/test_data/lighthouse/secrets";

        let keystore_secret = keystore::KeystoreSecret::from_directory(&secrets_path)?;

        let delegatee_pubkey = "0x83eeddfac5e60f8fe607ee8713efb8877c295ad9f8ca075f4d8f6f2ae241a30dd57f78f6f3863a9fe0d5b5db9d550b93";
        let delegatee_pubkey = parse_bls_public_key(delegatee_pubkey)?;
        let chain = Chain::Mainnet;

        let signed_delegations = generate_from_keystore(
            &keys_path,
            keystore_secret,
            delegatee_pubkey,
            chain,
            Action::Delegate,
        )?;

        let signed_message = signed_delegations.first().expect("to get signed delegation");

        verify_message_signature(signed_message, chain)?;

        Ok(())
    }

    /// Test generating signed delegations using a remote Dirk signer (single instance).
    ///
    /// ```shell
    /// cargo test --package bolt --bin bolt -- commands::delegate::tests::test_delegation_dirk_single
    /// --exact --show-output --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "Requires Dirk to be installed on the system"]
    async fn test_delegation_dirk_single() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();
        let (url, cred, mut dirk_proc) = dirk::test_util::start_single_dirk_test_server().await?;

        let delegatee_pubkey = "0x83eeddfac5e60f8fe607ee8713efb8877c295ad9f8ca075f4d8f6f2ae241a30dd57f78f6f3863a9fe0d5b5db9d550b93";
        let delegatee_pubkey = parse_bls_public_key(delegatee_pubkey)?;
        let chain = Chain::Mainnet;

        let opts = DirkOpts {
            url,
            wallet_path: "wallet1".to_string(),
            tls_credentials: cred,
            passphrases: Some(vec!["secret".to_string()]),
        };

        let signed_delegations =
            generate_from_dirk(opts, delegatee_pubkey.clone(), chain, Action::Delegate).await?;

        let signed_message = signed_delegations.first().expect("to get signed delegation");

        verify_message_signature(signed_message, chain)?;

        dirk_proc.kill()?;

        Ok(())
    }

    /// Test generating signed delegations using a remote Dirk signer (multi-node instance).
    /// This test requires multiple instances of Dirk to be running.
    ///
    /// ```shell
    /// cargo test --package bolt --bin bolt -- commands::delegate::tests::test_delegation_dirk_multi
    /// --exact --show-output --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "Requires Dirk to be installed on the system"]
    async fn test_delegation_dirk_multi() -> eyre::Result<()> {
        Ok(())
    }
}
