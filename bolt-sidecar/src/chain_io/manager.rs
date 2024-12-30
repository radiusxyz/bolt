use std::time::Duration;

use alloy::{
    contract::Error,
    primitives::Address,
    providers::{ProviderBuilder, RootProvider},
    sol,
    transports::{http::Http, RpcError},
};
use ethereum_consensus::primitives::BlsPublicKey;
use eyre::{bail, Context};
use reqwest::{Client, Url};
use serde::Serialize;
use tracing::{debug, warn};

use BoltManagerContract::{
    BoltManagerContractErrors, BoltManagerContractInstance, ProposerStatus, ValidatorDoesNotExist,
};

use super::utils::{self, CompressedHash};
use crate::config::chain::Chain;

/// Maximum number of keys to fetch from the EL node in a single query.
const MAX_CHUNK_SIZE: usize = 100;
/// Maximum number of retries for EL node connection attempts
const MAX_RETRIES: usize = 20;

/// A wrapper over a BoltManagerContract that exposes various utility methods.
#[derive(Debug, Clone)]
pub struct BoltManager(BoltManagerContractInstance<Http<Client>, RootProvider<Http<Client>>>);

impl BoltManager {
    /// Creates a new BoltRegistry instance. Returns `None` if a canonical BoltManager contract is
    /// not deployed on such chain.
    ///
    /// TODO: change after https://github.com/chainbound/bolt/issues/343 is completed
    pub fn from_chain<U: Into<Url>>(execution_client_url: U, chain: Chain) -> Option<Self> {
        let address = chain.manager_address()?;
        Some(Self::from_address(execution_client_url, address))
    }

    /// Creates a new BoltRegistry instance.
    pub fn from_address<U: Into<Url>>(execution_client_url: U, manager_address: Address) -> Self {
        let provider = ProviderBuilder::new().on_http(execution_client_url.into());
        let registry = BoltManagerContract::new(manager_address, provider);

        Self(registry)
    }

    /// Verify the provided validator public keys are registered in Bolt and are active
    /// and their authorized operator is the given commitment signer public key.
    ///
    /// NOTE: it also checks the operator associated to the `commitment_signer_pubkey` exists.
    pub async fn verify_validator_pubkeys(
        &self,
        keys: Vec<BlsPublicKey>,
        commitment_signer_pubkey: Address,
    ) -> eyre::Result<Vec<ProposerStatus>> {
        let hashes_with_preimages = utils::pubkey_hashes(keys);
        let mut hashes = hashes_with_preimages.keys().cloned().collect::<Vec<_>>();

        let total_keys = hashes.len();
        let chunk_count = total_keys.div_ceil(MAX_CHUNK_SIZE);

        let mut proposers_statuses = Vec::with_capacity(total_keys);

        let mut i = 0;
        while !hashes.is_empty() {
            i += 1;

            // No more than MAX_CHUNK_SIZE at a time to avoid EL config limits
            let chunk_size = MAX_CHUNK_SIZE.min(hashes.len());
            let hashes_chunk = hashes.drain(..chunk_size).collect::<Vec<_>>();

            debug!("fetching proposer statuses for chunk {} of {}", i, chunk_count);

            let mut retries = 0;
            let returndata = loop {
                retries += 1;
                if retries > MAX_RETRIES {
                    bail!("Max retries reached when fetching proposer statuses from EL client");
                }

                match self.0.getProposerStatuses(hashes_chunk.clone()).call().await {
                    Ok(data) => break data,
                    Err(Error::TransportError(RpcError::Transport(transport_err))) => {
                        // `retry_with_backoff_if` is not used here because we need to check
                        // that the error is retryable.
                        if transport_err.to_string().contains("error sending request for url") {
                            warn!("Transport error when connecting to EL node: {}", transport_err);
                            tokio::time::sleep(Duration::from_millis(100 * retries as u64)).await;
                            continue;
                        }
                        warn!(
                            "Non-retryable transport error when connecting to EL node: {}",
                            transport_err
                        );
                        return Err(transport_err.into());
                    }
                    Err(err) => {
                        // For other errors, parse and return immediately
                        let decoded_error = utils::try_parse_contract_error(err)
                            .wrap_err("Failed to fetch proposer statuses from EL client")?;

                        bail!(generate_bolt_manager_error(decoded_error, commitment_signer_pubkey));
                    }
                }
            };

            // Check that all validators are active and have the correct operator
            for status in &returndata.statuses {
                if !status.active {
                    if let Some(pubkey) = hashes_with_preimages.get(&status.pubkeyHash) {
                        bail!(
                            "The operator address {} is not 
                            active for providing commitments for the validator with public key:
                            {}.
                            
                            This most likely means that the operator does not have sufficient
                            collateral staked in Bolt. Please double check with the `bolt` CLI
                            with the following command:

                            `bolt operators <RESTAKING_PROTOCOL> status --rpc-url <RPC_URL> --address {}`
                            ",
                            status.operator,
                            pubkey,
                            status.operator
                        );
                    } else {
                        bail!(
                            "BoltManager returned an unexpected public key hash: {}",
                            status.pubkeyHash
                        );
                    }
                }

                if status.operator != commitment_signer_pubkey {
                    bail!(generate_operator_keys_mismatch_error(
                        status.pubkeyHash,
                        commitment_signer_pubkey,
                        status.operator
                    ));
                }
            }

            proposers_statuses.extend(returndata.statuses);

            continue;
        }

        Ok(proposers_statuses)
    }
}

fn generate_bolt_manager_error(
    error: BoltManagerContractErrors,
    commitment_signer_pubkey: Address,
) -> String {
    match error {
        BoltManagerContractErrors::ValidatorDoesNotExist(ValidatorDoesNotExist { pubkeyHash }) => {
            format!(
                "BoltManager::ValidatorDoesNotExist: validator with public key hash {} is not registered in Bolt",
                pubkeyHash
            )
        }
        BoltManagerContractErrors::InvalidQuery(_) => {
            "BoltManager::InvalidQuery: invalid zero public key hash".to_string()
        }
        BoltManagerContractErrors::KeyNotFound(_) => {
            format!(
                "BoltManager::KeyNotFound: operator associated with commitment signer public key {} is not registered in Bolt", 
                commitment_signer_pubkey
            )
        }
    }
}

fn generate_operator_keys_mismatch_error(
    pubkey_hash: CompressedHash,
    commitment_signer_pubkey: Address,
    operator: Address,
) -> String {
    format!(
        "Mismatch between commitment signer public key and authorized operator address for validator\nwith public key hash {:?}.
         - commitment signer public key: {}
         - authorized operator address: {}",
        pubkey_hash,
        commitment_signer_pubkey,
        operator
    )
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltManagerContract {
        #[derive(Debug, Default, Serialize)]
        struct ProposerStatus {
            bytes20 pubkeyHash;
            bool active;
            address operator;
            string operatorRPC;
            address[] collaterals;
            uint256[] amounts;
        }

        function getProposerStatuses(bytes20[] calldata pubkeyHashes) public view returns (ProposerStatus[] memory statuses);

        function isOperator(address operator) external view returns (bool isOperator);

        error KeyNotFound();
        error InvalidQuery();
        #[derive(Debug)]
        error ValidatorDoesNotExist(bytes20 pubkeyHash);
    }
}

#[cfg(test)]
mod tests {
    use ::hex::FromHex;
    use alloy::{hex, primitives::Address};
    use alloy_node_bindings::Anvil;
    use ethereum_consensus::primitives::BlsPublicKey;
    use reqwest::Url;
    use std::time::Duration;

    use crate::{
        chain_io::{manager::generate_operator_keys_mismatch_error, utils::pubkey_hash},
        config::chain::Chain,
    };

    use super::BoltManager;

    #[tokio::test]
    async fn test_verify_validator_pubkeys() {
        let url = Url::parse("http://remotebeast:48545").expect("valid url");

        // Skip the test if the tailnet server isn't reachable
        if reqwest::get(url.clone()).await.is_err_and(|err| err.is_timeout() || err.is_connect()) {
            eprintln!("Skipping test because remotebeast is not reachable");
            return;
        }

        let manager =
            BoltManager::from_chain(url, Chain::Holesky).expect("manager deployed on Holesky");

        let operator =
            Address::from_hex("725028b0b7c3db8b8242d35cd3a5779838b217b1").expect("valid address");

        let keys = vec![BlsPublicKey::try_from([0; 48].as_ref()).expect("valid bls public key")];
        let commitment_signer_pubkey = Address::ZERO;

        let res = manager.verify_validator_pubkeys(keys, commitment_signer_pubkey).await;
        assert!(res.unwrap_err().to_string().contains("ValidatorDoesNotExist"));

        let keys = vec![
            BlsPublicKey::try_from(
                hex!("87cbbfe6f08a0fd424507726cfcf5b9df2b2fd6b78a65a3d7bb6db946dca3102eb8abae32847d5a9a27e414888414c26")
                    .as_ref()).expect("valid bls public key")];
        let res = manager.verify_validator_pubkeys(keys.clone(), commitment_signer_pubkey).await;
        assert!(
            res.unwrap_err().to_string()
                == generate_operator_keys_mismatch_error(
                    pubkey_hash(&keys[0]),
                    commitment_signer_pubkey,
                    operator
                )
        );

        let commitment_signer_pubkey = operator;
        let res = manager
            .verify_validator_pubkeys(keys, commitment_signer_pubkey)
            .await
            .expect("active validator and correct operator");
        assert!(res[0].active);
    }

    #[tokio::test]
    async fn test_verify_validator_pubkeys_retry() {
        let _ = tracing_subscriber::fmt::try_init();

        // Point to an EL node that is not yet online
        let url = Url::parse("http://localhost:10000").expect("valid url");

        let manager =
            BoltManager::from_chain(url, Chain::Holesky).expect("manager deployed on Holesky");

        let keys = vec![
            BlsPublicKey::try_from(
                hex!("87cbbfe6f08a0fd424507726cfcf5b9df2b2fd6b78a65a3d7bb6db946dca3102eb8abae32847d5a9a27e414888414c26")
                    .as_ref()).expect("valid bls public key")];
        let commitment_signer_pubkey = Address::ZERO;

        tokio::spawn(async move {
            // Sleep for a bit so verify_validator_pubkeys is called before the anvil is up
            tokio::time::sleep(Duration::from_millis(100)).await;
            let anvil = Anvil::new()
                .fork(Url::parse("http://remotebeast:48545").unwrap())
                .port(10000u16)
                .spawn();
            println!("{}", anvil.endpoint());
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        let operator =
            Address::from_hex("725028b0b7c3db8b8242d35cd3a5779838b217b1").expect("valid address");

        let result = manager.verify_validator_pubkeys(keys.clone(), commitment_signer_pubkey).await;

        assert!(
            result.unwrap_err().to_string()
                == generate_operator_keys_mismatch_error(
                    pubkey_hash(&keys[0]),
                    commitment_signer_pubkey,
                    operator
                )
        );
    }
}
