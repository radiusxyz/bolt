use std::collections::HashMap;

use alloy::primitives::B256;
use ethereum_consensus::crypto::{aggregate, PublicKey as BlsPublicKey};
use eyre::{bail, Result};
use tracing::{debug, warn};

use crate::{
    cli::{Action, Chain, DirkOpts},
    commands::delegate::verify_message_signature,
    common::{dirk::Dirk, signing::compute_domain_from_mask},
};

use super::{
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

            let participant_pubkey = BlsPublicKey::try_from(distributed.public_key.as_slice())?;
            debug!(
                %participant_pubkey,
                %validator_pubkey,
                "Signed message for distributed account '{}'",
                name
            );

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
        if let Err(err) = verify_message_signature(&final_message, chain) {
            bail!(
                "Failed to verify aggregated signature for distributed account '{}': {:?}",
                name,
                err
            );
        }

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
