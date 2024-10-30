use std::str::FromStr;

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

use BoltManagerContract::{BoltManagerContractErrors, BoltManagerContractInstance, ProposerStatus};

use crate::config::chain::Chain;

use super::utils;

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
        keys: &[BlsPublicKey],
        commitment_signer_pubkey: Address,
    ) -> eyre::Result<Vec<ProposerStatus>> {
        let hashes = utils::pubkey_hashes(keys);

        let returndata = self.0.getProposerStatuses(hashes).call().await;

        // TODO: clean this after https://github.com/alloy-rs/alloy/issues/787 is merged
        let error = match returndata.map(|data| data.statuses) {
            Ok(statuses) => {
                for status in &statuses {
                    if !status.active {
                        bail!(
                            "validator with public key hash {:?} is not active in Bolt",
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

                return Ok(statuses);
            }
            Err(error) => match error {
                ContractError::TransportError(TransportError::ErrorResp(err)) => {
                    let data = err.data.unwrap_or_default();
                    let data = data.get().trim_matches('"');
                    let data = Bytes::from_str(data)?;

                    BoltManagerContractErrors::abi_decode(&data, true)?
                }
                e => return Err(e)?,
            },
        };

        match error {
            BoltManagerContractErrors::ValidatorDoesNotExist(pubkey_hash) => {
                bail!("validator with public key hash {:?} is not registered in Bolt", pubkey_hash);
            }
            BoltManagerContractErrors::InvalidQuery(_) => {
                bail!("invalid zero public key hash");
            }
            BoltManagerContractErrors::KeyNotFound(_) => {
                bail!("operator associated with commitment signer public key {:?} is not registered in Bolt", commitment_signer_pubkey);
            }
        }
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
