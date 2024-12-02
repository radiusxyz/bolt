use alloy::primitives::B256;
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use eyre::{bail, Result};
use tracing::{debug, warn};

use crate::{
    cli::{Action, Chain, DirkOpts},
    common::{
        dirk::{distributed::DistributedDirkAccount, Dirk},
        signing::compute_domain_from_mask,
    },
};

use super::types::{
    DelegationMessage, RevocationMessage, SignedDelegation, SignedMessage, SignedRevocation,
};

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

    for account in accounts.accounts {
        let name = account.name.clone();
        let validator_pubkey = BlsPublicKey::try_from(account.public_key.as_slice())?;

        if let Some(passphrases) = &opts.passphrases {
            dirk.try_unlock_account_with_passphrases(name.clone(), passphrases).await?;
        } else {
            bail!("A passphrase is required in order to sign messages remotely with Dirk");
        }

        // Sign the message with the connected Dirk instance
        let signed_message = match action {
            Action::Delegate => {
                let message = DelegationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let root = message.digest().into(); // Dirk does the hash tree root internally
                let signature = dirk.request_signature(name.clone(), root, domain).await?;
                SignedMessage::Delegation(SignedDelegation { message, signature })
            }
            Action::Revoke => {
                let message = RevocationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let root = message.digest().into(); // Dirk does the hash tree root internally
                let signature = dirk.request_signature(name.clone(), root, domain).await?;
                SignedMessage::Revocation(SignedRevocation { message, signature })
            }
        };

        // Try to lock the account back after signing
        if let Err(err) = dirk.lock_account(name.clone()).await {
            warn!("Failed to lock account after signing {}: {:?}", name, err);
        }

        signed_messages.push(signed_message);
    }

    for account in accounts.distributed_accounts {
        let name = account.name.clone();
        let distributed_dirk = DistributedDirkAccount::new(account, opts.tls_credentials.clone())?;
        let validator_pubkey = distributed_dirk.composite_public_key().clone();

        // Sign the message with the distributed Dirk account (threshold signature of the quorum)
        let signed_message = match action {
            Action::Delegate => {
                let message = DelegationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let root = message.digest().into(); // Dirk does the hash tree root internally
                let signature = distributed_dirk.threshold_sign(name.clone(), root, domain).await?;
                SignedMessage::Delegation(SignedDelegation { message, signature })
            }
            Action::Revoke => {
                let message = RevocationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let root = message.digest().into(); // Dirk does the hash tree root internally
                let signature = distributed_dirk.threshold_sign(name.clone(), root, domain).await?;
                SignedMessage::Revocation(SignedRevocation { message, signature })
            }
        };

        // Sanity check: verify the recovered signature early to debug aggregate signature issues
        // Note: this is done twice (here and in the main loop) to help debug sharded signatures
        if let Err(err) = signed_message.verify_signature(chain) {
            bail!(
                "Failed to verify recovered signature for distributed account '{}': {:?}",
                name,
                err
            );
        }

        // Add the final message to the list of signed messages
        signed_messages.push(signed_message);
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

#[cfg(test)]
mod tests {
    use crate::{
        cli::{Action, Chain, DirkOpts},
        commands::delegate::dirk::generate_from_dirk,
        common::{dirk, parse_bls_public_key},
    };

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

        signed_message.verify_signature(chain)?;

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
        let _ = tracing_subscriber::fmt::try_init();
        let (url, cred, mut dirk_procs) = dirk::test_util::start_multi_dirk_test_server().await?;

        let delegatee_pubkey = "0x83eeddfac5e60f8fe607ee8713efb8877c295ad9f8ca075f4d8f6f2ae241a30dd57f78f6f3863a9fe0d5b5db9d550b93";
        let delegatee_pubkey = parse_bls_public_key(delegatee_pubkey)?;
        let chain = Chain::Mainnet;

        let opts = DirkOpts {
            url,
            // Use the distributed wallet path for the multi-node test
            wallet_path: "DistributedWallet1/1".to_string(),
            tls_credentials: cred,
            passphrases: Some(vec!["secret".to_string()]),
        };

        let signed_delegations =
            generate_from_dirk(opts, delegatee_pubkey.clone(), chain, Action::Delegate).await?;

        let signed_message = signed_delegations.first().expect("to get signed delegation");

        signed_message.verify_signature(chain)?;

        for dirk_proc in &mut dirk_procs {
            dirk_proc.kill()?;
        }

        Ok(())
    }
}
