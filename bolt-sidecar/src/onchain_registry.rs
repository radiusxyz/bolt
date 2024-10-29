use std::str::FromStr;

use alloy::{
    contract::Error as ContractError,
    primitives::{Address, Bytes, B256, B512},
    providers::{ProviderBuilder, RootProvider},
    sol,
    sol_types::{Error as SolError, SolInterface},
    transports::{http::Http, TransportError},
};
use ethereum_consensus::primitives::BlsPublicKey;
use eyre::bail;
use reqwest::{Client, Url};
use reth_primitives::keccak256;
use serde::Serialize;

use BoltManagerContract::{BoltManagerContractErrors, BoltManagerContractInstance, ProposerStatus};

use crate::config::chain::Chain;

/// A wrapper over a BoltManagerContract that exposes various utility methods.
#[derive(Debug, Clone)]
pub struct BoltManager(BoltManagerContractInstance<Http<Client>, RootProvider<Http<Client>>>);

impl BoltManager {
    /// Returns the address of the canonical BoltManager contract for a given chain, if present
    pub fn address(chain: Chain) -> Option<Address> {
        match chain {
            Chain::Holesky => Some(
                Address::from_str("0x440202829b493F9FF43E730EB5e8379EEa3678CF")
                    .expect("valid address"),
            ),
            _ => None,
        }
    }

    /// Creates a new BoltRegistry instance. Returns `None` if a canonical BoltManager contract is
    /// not deployed on such chain.
    pub fn from_chain<U: Into<Url>>(execution_client_url: U, chain: Chain) -> Option<Self> {
        let address = Self::address(chain)?;
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
        let hashes = BoltValidators::pubkey_hashes(keys);

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

/// Utility functions related to the BoltValidators contract
pub struct BoltValidators;

impl BoltValidators {
    /// Hash the public keys of the proposers. This follows the same
    /// implementation done on-chain in the BoltValidators contract.
    pub fn pubkey_hashes(keys: &[BlsPublicKey]) -> Vec<B256> {
        keys.iter().map(Self::pubkey_hash).collect()
    }

    /// Hash the public key of the proposer. This follows the same
    /// implementation done on-chain in the BoltValidators contract.
    pub fn pubkey_hash(key: &BlsPublicKey) -> B256 {
        let digest = Self::pubkey_hash_digest(key);
        keccak256(digest)
    }

    fn pubkey_hash_digest(key: &BlsPublicKey) -> B512 {
        let mut onchain_pubkey_repr = B512::ZERO;

        // copy the pubkey bytes into the rightmost 48 bytes of the 512-bit buffer.
        // the result should look like this:
        //
        // 0x00000000000000000000000000000000b427fd179b35ef085409e4a98fb3ab84ee29c689df5c64020eab0b20a4f91170f610177db172dc091682df627c9f4021
        // |<---------- 16 bytes ---------->||<----------------------------------------- 48 bytes ----------------------------------------->|
        onchain_pubkey_repr[16..].copy_from_slice(key);
        onchain_pubkey_repr
    }
}

sol! {
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
