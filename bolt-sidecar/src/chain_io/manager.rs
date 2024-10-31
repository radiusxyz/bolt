use std::str::FromStr;
use tracing::error;

use alloy::{
    contract::Error as ContractError,
    primitives::{Address, Bytes},
    providers::{ProviderBuilder, RootProvider},
    sol,
    sol_types::SolInterface,
    transports::{http::Http, TransportError},
};
use ethereum_consensus::primitives::BlsPublicKey;
use eyre::bail;
use reqwest::{Client, Url};
use serde::Serialize;

use tracing::debug;
use BoltManagerContract::{
    BoltManagerContractErrors, BoltManagerContractInstance, ProposerStatus, ValidatorDoesNotExist,
};

use crate::config::chain::Chain;

use super::utils::{self, CompressedHash};

const CHUNK_SIZE: usize = 100;

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

        let mut proposers_statuses = Vec::with_capacity(hashes.len());

        let mut i = 0;
        while !hashes.is_empty() {
            i += 1;

            // No more than CHUNK_SIZE at a time to avoid EL config limits
            //
            // TODO: write an unsafe function that splits a vec into owned chunks without
            // allocating
            let hashes_chunk = hashes.drain(..CHUNK_SIZE.min(hashes.len())).collect::<Vec<_>>();

            debug!(
                "fetching {} proposer statuses for chunk {} of {}",
                hashes_chunk.len(),
                i,
                total_keys.div_ceil(CHUNK_SIZE)
            );

            let returndata = self.0.getProposerStatuses(hashes_chunk).call().await;

            // TODO: clean this after https://github.com/alloy-rs/alloy/issues/787 is merged
            let error = match returndata.map(|data| data.statuses) {
                Ok(statuses) => {
                    for status in &statuses {
                        if !status.active {
                            bail!(
                            "validator with public key {:?} and public key hash {:?} is not active in Bolt",
                            hashes_with_preimages.get(&status.pubkeyHash),
                            status.pubkeyHash
                        );
                        } else if status.operator != commitment_signer_pubkey {
                            bail!(generate_operator_keys_mismatch_error(
                                status.pubkeyHash,
                                commitment_signer_pubkey,
                                status.operator
                            ));
                        }
                    }

                    proposers_statuses.extend(statuses);

                    continue;
                }
                Err(error) => match error {
                    ContractError::TransportError(TransportError::ErrorResp(err)) => {
                        error!("error response from contract: {:?}", err);
                        let data = err.data.unwrap_or_default();
                        let data = data.get().trim_matches('"');
                        let data = Bytes::from_str(data)?;

                        BoltManagerContractErrors::abi_decode(&data, true)?
                    }
                    e => return Err(e)?,
                },
            };

            match error {
                BoltManagerContractErrors::ValidatorDoesNotExist(ValidatorDoesNotExist {
                    pubkeyHash: pubkey_hash,
                }) => {
                    bail!("ValidatorDoesNotExist -- validator with public key {:?} and public key hash {:?} is not registered in Bolt", hashes_with_preimages.get(&pubkey_hash), pubkey_hash);
                }
                BoltManagerContractErrors::InvalidQuery(_) => {
                    bail!("InvalidQuery -- invalid zero public key hash");
                }
                BoltManagerContractErrors::KeyNotFound(_) => {
                    bail!("KeyNotFound -- operator associated with commitment signer public key {:?} is not registered in Bolt", commitment_signer_pubkey);
                }
            }
        }

        Ok(proposers_statuses)
    }
}

fn generate_operator_keys_mismatch_error(
    pubkey_hash: CompressedHash,
    commitment_signer_pubkey: Address,
    operator: Address,
) -> String {
    format!(
        "mismatch between commitment signer public key and authorized operator address for validator with public key hash {:?} in Bolt.\n - commitment signer public key: {:?}\n - authorized operator address: {:?}",
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
    use ethereum_consensus::primitives::BlsPublicKey;
    use reqwest::Url;

    use crate::{
        chain_io::{manager::generate_operator_keys_mismatch_error, utils::pubkey_hash},
        config::chain::Chain,
    };

    use super::BoltManager;

    #[tokio::test]
    #[ignore = "requires Chainbound tailnet"]
    async fn test_verify_validator_pubkeys() {
        let url = Url::parse("http://remotebeast:48545").expect("valid url");
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
}
