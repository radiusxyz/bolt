use alloy::{primitives::B256, rpc::types::Withdrawal};
use reqwest::Url;
use serde::{Deserialize, Serialize};

/// Errors that can occur while interacting with the beacon API.
#[derive(Debug, thiserror::Error)]
pub enum BeaconApiError {
    #[error("Failed to fetch: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed to decode: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Failed to parse hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Data not found: {0}")]
    DataNotFound(String),
    #[error("Failed to parse or build URL")]
    Url,
}

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

        // parse from /data
        Ok(self.client.get(url).send().await?.json::<ResponseData<Vec<Withdrawal>>>().await?.data)
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
pub struct ResponseData<T> {
    pub data: T,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_get_prev_randao() {
        let beacon_rpc_url = Url::from_str("http://remotebeast:44400").unwrap();
        let beacon_api = BeaconApi::new(beacon_rpc_url);

        assert!(beacon_api.get_prev_randao().await.is_ok());
    }

    #[tokio::test]
    async fn test_get_expected_withdrawals_at_head() {
        let beacon_rpc_url = Url::from_str("http://remotebeast:44400").unwrap();
        let beacon_api = BeaconApi::new(beacon_rpc_url);

        assert!(beacon_api.get_expected_withdrawals_at_head().await.is_ok());
    }
}
