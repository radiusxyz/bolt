use alloy::{
    consensus::Transaction,
    eips::{calc_excess_blob_gas, calc_next_block_base_fee, eip1559::BaseFeeParams},
    primitives::{Address, Bytes, B256},
    rpc::types::Withdrawals,
};
use reth_primitives::{proofs, BlockBody, SealedBlock, SealedHeader, TransactionSigned};

use super::{engine_hinter::EngineHinter, DEFAULT_EXTRA_DATA};

use crate::{
    builder::{compat::to_alloy_execution_payload, BeaconApi, BuilderError},
    client::RpcClient,
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
    beacon_api: BeaconApi,
    execution_api: RpcClient,
    engine_hinter: EngineHinter,
    slot_time: u64,
    genesis_time: u64,
}

/// Lightweight context struct to hold the necessary values for
/// building a sealed block. Some of this data is fetched from the
/// beacon chain, while others are calculated locally or from the
/// transactions themselves.
#[derive(Debug, Default)]
struct PayloadBuilderContext {
    extra_data: Bytes,
    base_fee: u64,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    prev_randao: B256,
    fee_recipient: Address,
    transactions_root: B256,
    withdrawals_root: B256,
    parent_beacon_block_root: B256,
    block_timestamp: u64,
}

impl FallbackPayloadBuilder {
    /// Create a new fallback payload builder
    pub fn new(opts: &Opts, genesis_time: u64) -> Self {
        let engine_hinter =
            EngineHinter::new(opts.engine_jwt_hex.0.clone(), opts.engine_api_url.clone());
        let beacon_api = BeaconApi::new(opts.beacon_api_url.clone());

        Self {
            engine_hinter,
            extra_data: DEFAULT_EXTRA_DATA.into(),
            fee_recipient: opts.fee_recipient,
            execution_api: RpcClient::new(opts.execution_api_url.clone()),
            slot_time: opts.chain.slot_time(),
            genesis_time,
            beacon_api,
        }
    }

    /// Build a minimal payload to be used as a fallback in case PBS relays fail
    /// to provide a valid payload that fulfills the commitments made by Bolt.
    pub async fn build_fallback_payload(
        &self,
        target_slot: u64,
        transactions: &[TransactionSigned],
    ) -> Result<SealedBlock, BuilderError> {
        // Fetch the latest block to get the necessary parent values for the new block.
        // For the timestamp, we must use the one expected by the beacon chain instead, to
        // prevent edge cases where the proposer before us has missed their slot and therefore
        // the timestamp of the previous block is too far in the past.
        let latest_block = self.execution_api.get_block(None, true).await?;

        // Fetch the execution client info from the engine API in order to know what hint
        // types the engine hinter can parse.
        let engine_info = self.engine_hinter.engine_client_info().await?;

        // Fetch required head info from the beacon chain
        let parent_beacon_block_root = self.beacon_api.get_parent_beacon_block_root().await?;
        let withdrawals = self.beacon_api.get_expected_withdrawals_at_head().await?;
        let prev_randao = self.beacon_api.get_prev_randao().await?;

        let versioned_hashes = transactions
            .iter()
            .flat_map(|tx| tx.blob_versioned_hashes())
            .flatten()
            .copied()
            .collect::<Vec<_>>();

        let base_fee = calc_next_block_base_fee(
            latest_block.header.gas_used,
            latest_block.header.gas_limit,
            latest_block.header.base_fee_per_gas.unwrap_or_default(),
            BaseFeeParams::ethereum(),
        );

        let excess_blob_gas = calc_excess_blob_gas(
            latest_block.header.excess_blob_gas.unwrap_or_default(),
            latest_block.header.blob_gas_used.unwrap_or_default(),
        );

        let blob_gas_used =
            transactions.iter().fold(0, |acc, tx| acc + tx.blob_gas_used().unwrap_or_default());

        // We must calculate the next block timestamp manually rather than rely on the
        // previous execution block, to cover the edge case where any previous slots have
        // been missed by the proposers immediately before us.
        let block_timestamp = self.genesis_time + (target_slot * self.slot_time);

        let ctx = PayloadBuilderContext {
            base_fee,
            blob_gas_used,
            excess_blob_gas,
            parent_beacon_block_root,
            prev_randao,
            extra_data: self.extra_data.clone(),
            fee_recipient: self.fee_recipient,
            transactions_root: proofs::calculate_transaction_root(transactions),
            withdrawals_root: proofs::calculate_withdrawals_root(&withdrawals),
            block_timestamp,
        };

        let body = BlockBody {
            ommers: Vec::new(),
            transactions: transactions.to_vec(),
            withdrawals: Some(Withdrawals::new(withdrawals)),
        };

        let mut hints = Hints::default();
        let max_iterations = 20;
        let mut i = 0;
        loop {
            let header = build_header_with_hints_and_context(&latest_block, &hints, &ctx);

            let sealed_hash = header.hash_slow();
            let sealed_header = SealedHeader::new(header, sealed_hash);
            let sealed_block = SealedBlock::new(sealed_header, body.clone());

            let block_hash = hints.block_hash.unwrap_or(sealed_block.hash());

            let exec_payload = to_alloy_execution_payload(&sealed_block, block_hash);

            let engine_hint = self
                .engine_hinter
                .fetch_next_payload_hint(&exec_payload, &versioned_hashes, parent_beacon_block_root)
                .await?;

            // match engine_hint {
            //     EngineApiHint::BlockHash(hash) => {
            //         trace!("Should not receive block hash hint {:?}", hash);
            //         hints.block_hash = Some(hash)
            //     }

            //     EngineApiHint::GasUsed(gas) => {
            //         hints.gas_used = Some(gas);
            //         hints.block_hash = None;
            //     }
            //     EngineApiHint::StateRoot(hash) => {
            //         hints.state_root = Some(hash);
            //         hints.block_hash = None
            //     }
            //     EngineApiHint::ReceiptsRoot(hash) => {
            //         hints.receipts_root = Some(hash);
            //         hints.block_hash = None
            //     }
            //     EngineApiHint::LogsBloom(bloom) => {
            //         hints.logs_bloom = Some(bloom);
            //         hints.block_hash = None
            //     }

            //     EngineApiHint::ValidPayload => return Ok(sealed_block),
            // }

            if i > max_iterations {
                return Err(BuilderError::Custom(
                    "Too many iterations: Failed to fetch all missing header values from geth error messages"
                        .to_string(),
                ));
            }

            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use alloy::{
        eips::eip2718::{Decodable2718, Encodable2718},
        network::{EthereumWallet, TransactionBuilder},
        primitives::{hex, Address},
        signers::{k256::ecdsa::SigningKey, local::PrivateKeySigner},
    };
    use beacon_api_client::mainnet::Client as BeaconClient;
    use reth_primitives::TransactionSigned;
    use tracing::warn;

    use crate::{
        builder::FallbackPayloadBuilder,
        test_util::{default_test_transaction, get_test_config},
    };

    #[tokio::test]
    async fn test_build_fallback_payload() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let Some(cfg) = get_test_config().await else {
            warn!("Skipping test: missing test config");
            return Ok(());
        };

        let raw_sk = std::env::var("PRIVATE_KEY")?;

        let beacon_client = BeaconClient::new(cfg.beacon_api_url.clone());
        let genesis_time = beacon_client.get_genesis_details().await?.genesis_time;
        let builder = FallbackPayloadBuilder::new(&cfg, genesis_time);

        let sk = SigningKey::from_slice(hex::decode(raw_sk)?.as_slice())?;
        let signer = PrivateKeySigner::from_signing_key(sk.clone());
        let wallet = EthereumWallet::from(signer);

        let addy = Address::from_private_key(&sk);
        let tx = default_test_transaction(addy, Some(3)).with_chain_id(1);
        let tx_signed = tx.build(&wallet).await?;
        let raw_encoded = tx_signed.encoded_2718();
        let tx_signed_reth = TransactionSigned::decode_2718(&mut raw_encoded.as_slice())?;

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
        assert_eq!(
            reth_primitives::proofs::calculate_withdrawals_root(&Vec::new()),
            alloy::consensus::constants::EMPTY_WITHDRAWALS
        );
    }
}
