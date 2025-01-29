use alloy::{
    consensus::{proofs, transaction::PooledTransaction, Block, Transaction},
    eips::{calc_excess_blob_gas, calc_next_block_base_fee, eip1559::BaseFeeParams},
    primitives::{Address, Bytes},
};
use tracing::debug;

use super::{
    engine_hinter::{EngineHinter, EngineHinterContext},
    DEFAULT_EXTRA_DATA,
};
use crate::{
    builder::BuilderError,
    client::{BeaconClient, ExecutionClient},
    config::Opts,
};

/// The fallback payload builder is responsible for assembling a valid
/// sealed block from a set of transactions. It (ab)uses the engine API
/// to fetch "hints" for missing header values, such as the block hash,
/// gas used, state root, etc.
///
/// The builder will keep querying the engine API until it has all the
/// necessary values to seal the block. This is a temporary solution
/// until the engine API is able to provide a full sealed block.
///
/// Find more information about this process & its reasoning here:
/// <https://github.com/chainbound/bolt/discussions/59>
#[derive(Debug)]
pub struct FallbackPayloadBuilder {
    extra_data: Bytes,
    fee_recipient: Address,
    beacon_api: BeaconClient,
    execution_api: ExecutionClient,
    engine_hinter: EngineHinter,
    slot_time: u64,
    genesis_time: u64,
}

impl FallbackPayloadBuilder {
    /// Create a new fallback payload builder
    pub fn new(opts: &Opts, genesis_time: u64) -> Self {
        let engine_hinter = EngineHinter::new(opts.engine_jwt_hex.0, opts.engine_api_url.clone());

        let beacon_api = BeaconClient::new(opts.beacon_api_url.clone());
        let execution_api = ExecutionClient::new(opts.execution_api_url.clone());

        Self {
            extra_data: DEFAULT_EXTRA_DATA.into(),
            fee_recipient: opts.fee_recipient,
            slot_time: opts.chain.slot_time(),
            engine_hinter,
            execution_api,
            genesis_time,
            beacon_api,
        }
    }

    /// Build a minimal payload to be used as a fallback in case PBS relays fail
    /// to provide a valid payload that fulfills the commitments made by Bolt.
    pub async fn build_fallback_payload(
        &self,
        target_slot: u64,
        transactions: &[PooledTransaction],
    ) -> Result<Block<PooledTransaction>, BuilderError> {
        // Fetch the latest block to get the necessary parent values for the new block.
        // For the timestamp, we must use the one expected by the beacon chain instead, to
        // prevent edge cases where the proposer before us has missed their slot and therefore
        // the timestamp of the previous block is too far in the past.
        let head_block_fut = self.execution_api.get_block(None, true);

        // Fetch the execution client info from the engine API in order to know what hint
        // types the engine hinter can parse from the engine API responses.
        let el_client_info_fut = self.engine_hinter.engine_client_version();

        let (head_block, el_client_info) = tokio::try_join!(head_block_fut, el_client_info_fut)?;

        let el_client_code = el_client_info[0].code;
        debug!(client = %el_client_code.client_name(), "Fetched execution client info");

        // Fetch required head info from the beacon client
        let parent_beacon_block_root_fut = self.beacon_api.get_parent_beacon_block_root();
        let withdrawals_fut = self.beacon_api.get_expected_withdrawals_at_head();
        let prev_randao_fut = self.beacon_api.get_prev_randao();

        let (parent_beacon_block_root, withdrawals, prev_randao) =
            tokio::try_join!(parent_beacon_block_root_fut, withdrawals_fut, prev_randao_fut)?;

        // The next block timestamp must be calculated manually rather than relying on the
        // previous execution block, to cover the edge case where any previous slots have
        // been missed by the proposers immediately before us.
        let block_timestamp = self.genesis_time + (target_slot * self.slot_time);

        let blob_versioned_hashes = transactions
            .iter()
            .flat_map(|tx| tx.blob_versioned_hashes())
            .flatten()
            .copied()
            .collect::<Vec<_>>();

        let base_fee = calc_next_block_base_fee(
            head_block.header.gas_used,
            head_block.header.gas_limit,
            head_block.header.base_fee_per_gas.unwrap_or_default(),
            BaseFeeParams::ethereum(),
        );

        let excess_blob_gas = calc_excess_blob_gas(
            head_block.header.excess_blob_gas.unwrap_or_default(),
            head_block.header.blob_gas_used.unwrap_or_default(),
        );

        let blob_gas_used =
            transactions.iter().fold(0, |acc, tx| acc + tx.blob_gas_used().unwrap_or_default());

        let ctx = EngineHinterContext {
            base_fee,
            blob_gas_used,
            excess_blob_gas,
            parent_beacon_block_root,
            prev_randao,
            extra_data: self.extra_data.clone(),
            fee_recipient: self.fee_recipient,
            transactions_root: proofs::calculate_transaction_root(transactions),
            withdrawals_root: proofs::calculate_withdrawals_root(&withdrawals),
            transactions: transactions.to_vec(),
            blob_versioned_hashes,
            block_timestamp,
            withdrawals,
            head_block,
            el_client_code,
            // start the context with empty hints
            hints: Default::default(),
        };

        // Use the engine API to fetch the missing value for the payload, until we have
        // all the necessary data to consider it valid and seal the block.
        self.engine_hinter.fetch_payload_from_hints(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use alloy::{
        consensus::{constants, proofs, transaction::PooledTransaction},
        eips::eip2718::{Decodable2718, Encodable2718},
        network::{EthereumWallet, TransactionBuilder},
        primitives::{hex, Address},
        providers::{Provider, ProviderBuilder},
        signers::{k256::ecdsa::SigningKey, local::PrivateKeySigner},
    };
    use beacon_api_client::mainnet::Client as BeaconClient;
    use tracing::warn;

    use crate::{
        builder::FallbackPayloadBuilder,
        test_util::{default_test_transaction, get_test_config},
    };

    #[tokio::test]
    async fn test_build_fallback_payload() -> eyre::Result<()> {
        if tracing_subscriber::fmt::try_init().is_err() {
            eprintln!("Failed to initialize logger");
        };

        let Some(mut cfg) = get_test_config().await else {
            warn!("Skipping test: missing test config");
            return Ok(());
        };

        // Set the engine to either geth or nethermind
        // ge: remotesmol:48551, nm: remotesmol:58551
        cfg.engine_api_url = "http://remotesmol:58551".parse()?;

        let raw_sk = std::env::var("PRIVATE_KEY")?;

        let provider = ProviderBuilder::new().on_http(cfg.execution_api_url.clone());
        let beacon_client = BeaconClient::new(cfg.beacon_api_url.clone());
        let genesis_time = beacon_client.get_genesis_details().await?.genesis_time;
        let builder = FallbackPayloadBuilder::new(&cfg, genesis_time);

        let sk = SigningKey::from_slice(hex::decode(raw_sk)?.as_slice())?;
        let signer = PrivateKeySigner::from_signing_key(sk.clone());
        let wallet = EthereumWallet::from(signer);

        let addy = Address::from_private_key(&sk);
        let nonce = provider.get_transaction_count(addy).await?;
        let tx = default_test_transaction(addy, Some(nonce)).with_chain_id(17000);
        let tx_signed = tx.build(&wallet).await?;
        let raw_encoded = tx_signed.encoded_2718();
        let tx_signed_reth = PooledTransaction::decode_2718(&mut raw_encoded.as_slice())?;

        let slot = genesis_time +
            (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / cfg.chain.slot_time()) +
            1;

        let block = builder.build_fallback_payload(slot, &[tx_signed_reth]).await?;

        assert_eq!(block.body.transactions.len(), 1);

        Ok(())
    }

    #[test]
    fn test_empty_el_withdrawals_root() {
        // Withdrawal root in the execution layer header is MPT.
        assert_eq!(proofs::calculate_withdrawals_root(&Vec::new()), constants::EMPTY_WITHDRAWALS);
    }
}
