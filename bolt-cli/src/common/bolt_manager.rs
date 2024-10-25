use std::str::FromStr;

use alloy::{
    contract::{Error as ContractError, Result as ContractResult},
    primitives::{Address, Bytes, B256},
    providers::{ProviderBuilder, RootProvider},
    sol,
    sol_types::{Error as SolError, SolInterface},
    transports::{http::Http, TransportError},
};
use reqwest::{Client, Url};
use serde::Serialize;

use BoltManagerContract::{BoltManagerContractErrors, BoltManagerContractInstance, ProposerStatus};

/// Bolt Manager contract bindings.
#[derive(Debug, Clone)]
pub struct BoltManager(BoltManagerContractInstance<Http<Client>, RootProvider<Http<Client>>>);

impl BoltManager {
    /// Creates a new BoltManager instance.
    pub fn new<U: Into<Url>>(execution_client_url: U, manager_address: Address) -> Self {
        let provider = ProviderBuilder::new().on_http(execution_client_url.into());
        let manager = BoltManagerContract::new(manager_address, provider);

        Self(manager)
    }

    /// Gets the sidecar RPC URL for a given validator index.
    ///
    /// Returns Ok(None) if the operator is not found in the registry.
    pub async fn get_sidecar_rpc_url_for_validator(
        &self,
        pubkey_hash: B256,
    ) -> ContractResult<Option<String>> {
        let registrant = self.get_proposer_status(pubkey_hash).await?;
        Ok(registrant.and_then(|r| if r.active { Some(r.operatorRPC) } else { None }))
    }

    /// Gets the proposer status for a given pubkeyhash.
    ///
    /// Returns Ok(None) if the proposer is not found in the registry.
    pub async fn get_proposer_status(
        &self,
        pubkey_hash: B256,
    ) -> ContractResult<Option<ProposerStatus>> {
        let returndata = self.0.getProposerStatus(pubkey_hash).call().await;

        // TODO: clean this after https://github.com/alloy-rs/alloy/issues/787 is merged
        let error = match returndata.map(|data| data._0) {
            Ok(proposer) => return Ok(Some(proposer)),
            Err(error) => match error {
                ContractError::TransportError(TransportError::ErrorResp(err)) => {
                    let data = err.data.unwrap_or_default();
                    let data = data.get().trim_matches('"');
                    let data = Bytes::from_str(data).unwrap_or_default();

                    BoltManagerContractErrors::abi_decode(&data, true)?
                }
                e => return Err(e),
            },
        };

        if matches!(error, BoltManagerContractErrors::ValidatorDoesNotExist(_)) {
            Ok(None)
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

        function getProposerStatus(bytes32 pubkeyHash) external view returns (ProposerStatus memory);

        error InvalidQuery();
        error ValidatorDoesNotExist();
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::primitives::U256;

    use super::*;

    #[tokio::test]
    async fn test_get_operators_helder() -> eyre::Result<()> {
        let registry = BoltManager::new(
            Url::parse("http://remotebeast:4485")?,
            Address::from_str("0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9")?,
        );

        let sample_pubkey = B256::from_str("0xsamplepubkeyhash").expect("invalid pubkey");

        let registrant = registry.get_proposer_status(sample_pubkey).await;
        assert!(matches!(registrant, Ok(None)));

        let invalid_pubkey = B256::from_str("0xinvalidsamplepubkeyhash").expect("invalid pubkey");
        let registrant = match registry.get_proposer_status(invalid_pubkey).await {
            Ok(Some(registrant)) => registrant,
            e => panic!("unexpected error reading from registry: {:?}", e),
        };

        let expected = ProposerStatus {
            pubkeyHash: sample_pubkey,
            active: true,
            operator: Address::from_str("0xad3cd1b81c80f4a495d6552ae6423508492a27f8")?,
            operatorRPC: "http://sampleoperatorrpc:8000".to_string(),
            collaterals: vec![Address::from_str("0xsamplecollateral1")?],
            amounts: vec![U256::from(10000000000000000000u128)],
        };

        assert_eq!(registrant.pubkeyHash, expected.pubkeyHash);
        assert_eq!(registrant.active, expected.active);
        assert_eq!(registrant.operator, expected.operator);
        assert_eq!(registrant.operatorRPC, expected.operatorRPC);
        assert_eq!(registrant.collaterals, expected.collaterals);
        assert_eq!(registrant.amounts, expected.amounts);

        Ok(())
    }

    #[tokio::test]
    async fn test_check_validator_helder() -> eyre::Result<()> {
        let registry = BoltManager::new(
            Url::parse("http://remotebeast:48545")?,
            Address::from_str("0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9")?,
        );

        let pubkey_hash = B256::from_str("0xsamplepubkeyhash").expect("invalid pubkey");
        let registrant = registry.get_sidecar_rpc_url_for_validator(pubkey_hash).await?;
        assert!(registrant.is_some());

        dbg!(&registrant);
        Ok(())
    }
}
