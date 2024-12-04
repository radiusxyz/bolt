use alloy::{
    primitives::{Address, B256},
    rpc::types::Withdrawal,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};

/// Errors that can occur while interacting with the beacon API.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum BeaconApiError {
    #[error("Failed to fetch: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed to decode: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Failed to parse hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Failed to parse int: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Data not found: {0}")]
    DataNotFound(String),
    #[error("Failed to parse or build URL")]
    Url,
}

/// The result type for beacon API operations.
type BeaconApiResult<T> = Result<T, BeaconApiError>;

/// The [BeaconApi] is responsible for fetching information from the beacon node.
///
/// Unfortunately, we cannot rely on [beacon_api_client::Client] because its types
/// sometimes fail to deserialize and they don't allow for custom error handling
/// which is crucial for this service.
///
/// It would be more ideal for this to be an external crate and not part of this module.
#[derive(Debug, Clone)]
pub struct BeaconApi {
    client: reqwest::Client,
    beacon_rpc_url: Url,
}

impl BeaconApi {
    /// Create a new [BeaconApi] instance with the given beacon RPC URL.
    pub fn new(beacon_rpc_url: Url) -> Self {
        Self { client: reqwest::Client::new(), beacon_rpc_url }
    }

    /// Fetch the previous RANDAO value from the beacon node.
    pub async fn get_prev_randao(&self) -> BeaconApiResult<B256> {
        let url = self
            .beacon_rpc_url
            .join("/eth/v1/beacon/states/head/randao")
            .map_err(|_| BeaconApiError::Url)?;

        #[derive(Deserialize)]
        struct Inner {
            randao: B256,
        }

        // parse from /data/randao
        Ok(self.client.get(url).send().await?.json::<ResponseData<Inner>>().await?.data.randao)
    }

    /// Fetch the expected withdrawals for the given slot from the beacon chain.
    pub async fn get_expected_withdrawals_at_head(&self) -> BeaconApiResult<Vec<Withdrawal>> {
        let url = self
            .beacon_rpc_url
            .join("/eth/v1/builder/states/head/expected_withdrawals")
            .map_err(|_| BeaconApiError::Url)?;

        // This is needed because the Alloy struct expects
        // "validatorIndex" instead of "validator_index" in the JSON response.
        #[derive(Deserialize)]
        struct WithdrawalInner {
            index: String,
            validator_index: String,
            amount: String,
            address: Address,
        }

        // parse from /data
        let inner = self
            .client
            .get(url)
            .send()
            .await?
            .json::<ResponseData<Vec<WithdrawalInner>>>()
            .await?
            .data;

        let mut withdrawals = Vec::with_capacity(inner.len());
        for w in inner {
            withdrawals.push(Withdrawal {
                index: u64::from_str_radix(&w.index, 16)?,
                validator_index: u64::from_str_radix(&w.validator_index, 16)?,
                amount: u64::from_str_radix(&w.amount, 16)?,
                address: w.address,
            });
        }

        Ok(withdrawals)
    }

    /// Fetch the parent beacon block root from the beacon chain.
    pub async fn get_parent_beacon_block_root(&self) -> BeaconApiResult<B256> {
        let url = self
            .beacon_rpc_url
            .join("eth/v1/beacon/blocks/head/root")
            .map_err(|_| BeaconApiError::Url)?;

        #[derive(Deserialize)]
        struct Inner {
            root: B256,
        }

        // parse from /data/root
        Ok(self.client.get(url).send().await?.json::<ResponseData<Inner>>().await?.data.root)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseData<T> {
    pub data: T,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_get_prev_randao() {
        let url = Url::from_str("http://remotebeast:44400").unwrap();

        if reqwest::get(url.clone()).await.is_err_and(|err| err.is_timeout() || err.is_connect()) {
            eprintln!("Skipping test because remotebeast is not reachable");
            return;
        }

        let beacon_api = BeaconApi::new(url);

        assert!(beacon_api.get_prev_randao().await.is_ok());
    }

    #[tokio::test]
    async fn test_get_expected_withdrawals_at_head() {
        let url = Url::from_str("http://remotebeast:44400").unwrap();

        if reqwest::get(url.clone()).await.is_err_and(|err| err.is_timeout() || err.is_connect()) {
            eprintln!("Skipping test because remotebeast is not reachable");
            return;
        }

        let beacon_api = BeaconApi::new(url);

        assert!(beacon_api.get_expected_withdrawals_at_head().await.is_ok());
    }

    #[tokio::test]
    async fn test_get_parent_beacon_block_root() {
        let url = Url::from_str("http://remotebeast:44400").unwrap();

        if reqwest::get(url.clone()).await.is_err_and(|err| err.is_timeout() || err.is_connect()) {
            eprintln!("Skipping test because remotebeast is not reachable");
            return;
        }

        let beacon_api = BeaconApi::new(url);

        assert!(beacon_api.get_parent_beacon_block_root().await.is_ok());
    }
}
