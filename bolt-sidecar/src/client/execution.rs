use alloy::{
    eips::BlockNumberOrTag,
    network::Ethereum,
    primitives::{Address, Bytes, TxHash, B256, U256, U64},
    providers::{ProviderBuilder, RootProvider},
    rpc::{
        client::{BatchRequest, ClientBuilder, RpcClient},
        types::{Block, FeeHistory, TransactionReceipt},
    },
    transports::{TransportErrorKind, TransportResult},
};
use alloy_provider::{fillers::FillProvider, utils::JoinedRecommendedFillers};
use derive_more::derive::{Deref, DerefMut};
use futures::{stream::FuturesUnordered, StreamExt};
use reqwest::Url;

use crate::primitives::AccountState;

/// An HTTP-based JSON-RPC execution client provider that supports batching.
///
/// This struct is a wrapper over an inner [`RootProvider`] and extends it with
/// methods that are relevant to the Bolt state.
#[derive(Clone, Debug, Deref, DerefMut)]
pub struct ExecutionClient {
    /// The custom RPC client that allows us to add custom batching and extend the provider.
    rpc: RpcClient,
    /// The inner provider that implements all the JSON-RPC methods, that can be
    /// easily used via dereferencing this struct.
    #[deref]
    #[deref_mut]
    inner: FillProvider<JoinedRecommendedFillers, RootProvider, Ethereum>,
}

impl ExecutionClient {
    /// Create a new `RpcClient` with the given URL.
    pub fn new<U: Into<Url>>(url: U) -> Self {
        let url = url.into();
        let rpc = ClientBuilder::default().http(url.clone());
        let inner = ProviderBuilder::new().on_http(url);

        Self { rpc, inner }
    }

    /// Create a new batch request.
    pub fn new_batch(&self) -> BatchRequest<'_> {
        self.rpc.new_batch()
    }

    /// Get the chain ID.
    pub async fn get_chain_id(&self) -> TransportResult<u64> {
        let chain_id: String = self.rpc.request("eth_chainId", ()).await?;
        let chain_id = chain_id
            .get(2..)
            .ok_or(TransportErrorKind::Custom("not hex prefixed result".into()))?;

        let decoded = u64::from_str_radix(chain_id, 16).map_err(|e| {
            TransportErrorKind::Custom(
                format!("could not decode {} into u64: {}", chain_id, e).into(),
            )
        })?;
        Ok(decoded)
    }

    /// Get the basefee of the latest block.
    pub async fn get_basefee(&self, block_number: Option<u64>) -> TransportResult<u128> {
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);

        let fee_history: FeeHistory =
            self.rpc.request("eth_feeHistory", (U64::from(1), tag, &[] as &[f64])).await?;

        let Some(base_fee) = fee_history.latest_block_base_fee() else {
            return Err(TransportErrorKind::Custom("Base fee not found".into()).into());
        };

        Ok(base_fee)
    }

    /// Get the blob basefee of the latest block.
    ///
    /// Reference: https://github.com/ethereum/execution-apis/blob/main/src/eth/fee_market.yaml
    pub async fn get_blob_basefee(&self, block_number: Option<u64>) -> TransportResult<u128> {
        let block_count = U64::from(1);
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);
        let reward_percentiles: Vec<f64> = vec![];
        let fee_history: FeeHistory =
            self.rpc.request("eth_feeHistory", (block_count, tag, &reward_percentiles)).await?;

        Ok(fee_history.latest_block_blob_base_fee().unwrap_or(0))
    }

    /// Get the latest block number
    pub async fn get_head(&self) -> TransportResult<u64> {
        let result: U64 = self.rpc.request("eth_blockNumber", ()).await?;

        Ok(result.to())
    }

    /// Gets the latest account state for the given address
    pub async fn get_account_state(
        &self,
        address: &Address,
        block_number: Option<u64>,
    ) -> TransportResult<AccountState> {
        let mut batch = self.rpc.new_batch();

        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);

        let balance =
            batch.add_call("eth_getBalance", &(address, tag)).expect("Correct parameters");

        let tx_count =
            batch.add_call("eth_getTransactionCount", &(address, tag)).expect("Correct parameters");

        let code = batch.add_call("eth_getCode", &(address, tag)).expect("Correct parameters");

        // After the batch is complete, we can get the results.
        // Note that requests may error separately!
        batch.send().await?;

        let tx_count: U64 = tx_count.await?;
        let balance: U256 = balance.await?;
        let code: Bytes = code.await?;

        Ok(AccountState { balance, transaction_count: tx_count.to(), has_code: !code.is_empty() })
    }

    /// Get the block with the given number. If `None`, the latest block is returned.
    pub async fn get_block(&self, block_number: Option<u64>, full: bool) -> TransportResult<Block> {
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);

        self.rpc.request("eth_getBlockByNumber", (tag, full)).await
    }

    /// Send a raw transaction to the network.
    #[allow(unused)]
    pub async fn send_raw_transaction(&self, raw: Bytes) -> TransportResult<B256> {
        self.rpc.request("eth_sendRawTransaction", [raw]).await
    }

    /// Get the receipts for a list of transaction hashes.
    pub async fn get_receipts(
        &self,
        hashes: &[TxHash],
    ) -> TransportResult<Vec<Option<TransactionReceipt>>> {
        let mut batch = self.rpc.new_batch();

        let futs = FuturesUnordered::new();

        for hash in hashes {
            futs.push(
                batch
                    .add_call("eth_getTransactionReceipt", &(&[hash]))
                    .expect("Correct parameters"),
            );
        }

        batch.send().await?;

        Ok(futs
            .collect::<Vec<TransportResult<TransactionReceipt>>>()
            .await
            .into_iter()
            .map(|r| r.ok())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::{
        consensus::constants::ETH_TO_WEI,
        primitives::{uint, Uint},
    };
    use dotenvy::dotenv;

    use crate::test_util::launch_anvil;

    use super::*;

    #[tokio::test]
    async fn test_rpc_client() {
        let anvil = launch_anvil();
        let anvil_url = Url::from_str(&anvil.endpoint()).unwrap();
        let client = ExecutionClient::new(anvil_url);

        let addr = anvil.addresses().first().unwrap();

        let account_state = client.get_account_state(addr, None).await.unwrap();

        // Accounts in Anvil start with 10_000 ETH
        assert_eq!(account_state.balance, uint!(10_000U256 * Uint::from(ETH_TO_WEI)));

        assert_eq!(account_state.transaction_count, 0);
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_receipts() {
        let _ = tracing_subscriber::fmt().try_init();
        let client = ExecutionClient::new(Url::from_str("http://localhost:8545").unwrap());

        let _receipts = client
            .get_receipts(&[
                TxHash::from_str(
                    "0x518d9497868b7380ddfa3d245bead7b418248a0776896f6152590da1bf92c3fe",
                )
                .unwrap(),
                TxHash::from_str(
                    "0x6825cfb19d21cc4e69070f4aa506e3de65e09249d38d79b4112f81688bf43379",
                )
                .unwrap(),
                TxHash::from_str(
                    "0x5825cfb19d21cc4e69070f4aa506e3de65e09249d38d79b4112f81688bf43379",
                )
                .unwrap(),
            ])
            .await
            .unwrap();

        println!("{_receipts:?}");
    }

    #[tokio::test]
    #[ignore]
    async fn test_smart_contract_code() -> eyre::Result<()> {
        dotenv().ok();
        let rpc_url = Url::parse(std::env::var("RPC_URL").unwrap().as_str())?;
        let rpc_client = ExecutionClient::new(rpc_url);

        // random deployed smart contract address
        let addr = Address::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8")?;
        let account = rpc_client.get_account_state(&addr, None).await?;

        assert!(account.has_code);

        Ok(())
    }
}
