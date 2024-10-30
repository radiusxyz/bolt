use std::str::FromStr;

use alloy::{
    contract::Error as ContractError,
    primitives::{Address, Bytes},
    providers::{ProviderBuilder, RootProvider},
    sol,
    sol_types::{Error as SolError, SolInterface},
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

    /// Verify the provided operator address is registered in Bolt, returning an error if it
    /// doesn't
    pub async fn verify_operator(&self, operator: Address) -> eyre::Result<()> {
        let returndata = self.0.isOperator(operator).call().await;

        if !returndata.map(|data| data.isOperator)? {
            bail!("operator not found in Bolt Manager contract");
        }

        Ok(())
    }

    /// Verify the provided validator public keys are registered in Bolt and are active
    pub async fn verify_validator_pubkeys(
        &self,
        keys: &[BlsPublicKey],
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
                    }
                }

                return Ok(statuses);
            }
            Err(error) => match error {
                ContractError::TransportError(TransportError::ErrorResp(err)) => {
                    let data = err.data.unwrap_or_default();
                    let data = data.get().trim_matches('"');
                    let data = Bytes::from_str(data).unwrap_or_default();

                    BoltManagerContractErrors::abi_decode(&data, true)?
                }
                e => return Err(e)?,
            },
        };

        if matches!(error, BoltManagerContractErrors::ValidatorDoesNotExist(_)) {
            // TODO: improve this error message once https://github.com/chainbound/bolt/issues/338
            // is solved
            bail!("not all validators are registered in Bolt");
        } else {
            Err(SolError::custom(format!(
                "unexpected Solidity error selector: {:?}",
                error.selector()
            ))
            .into())
        }
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltManagerContract {
        #[derive(Debug, Default, Serialize)]
        struct ProposerStatus {
            bytes32 pubkeyHash;
            bool active;
            address operator;
            string operatorRPC;
            address[] collaterals;
            uint256[] amounts;
        }

        function getProposerStatuses(bytes32[] calldata pubkeyHashes) public view returns (ProposerStatus[] memory statuses);

        function isOperator(address operator) external view returns (bool isOperator);

        error InvalidQuery();
        error ValidatorDoesNotExist();
    }
}
