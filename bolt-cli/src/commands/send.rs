use std::time::Duration;

use alloy::{
    consensus::{
        constants::GWEI_TO_WEI, BlobTransactionSidecar, SidecarBuilder, SimpleCoder, Transaction,
    },
    eips::eip2718::Encodable2718,
    hex,
    network::{EthereumWallet, TransactionBuilder, TransactionBuilder4844},
    primitives::{keccak256, Address, B256, U256},
    providers::{ProviderBuilder, SendableTx},
    rpc::types::TransactionRequest,
    signers::{local::PrivateKeySigner, Signer},
};
use eyre::{bail, Context, ContextCompat, Result};
use rand::Rng;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;

use crate::cli::SendCommand;

/// Path to the lookahead endpoint on the Bolt RPC server.
const BOLT_LOOKAHEAD_PATH: &str = "/api/v1/proposers/lookahead";

impl SendCommand {
    /// Run the `send` command.
    pub async fn run(self) -> Result<()> {
        let wallet: PrivateKeySigner = self.private_key.parse().wrap_err("invalid private key")?;

        if self.devnet {
            self.send_devnet_transaction(wallet).await
        } else {
            self.send_transaction(wallet).await
        }
    }

    /// Send a transaction.
    async fn send_transaction(self, wallet: PrivateKeySigner) -> Result<()> {
        let transaction_signer = EthereumWallet::from(wallet.clone());
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer)
            .on_http(self.bolt_rpc_url.join("/rpc")?);

        // Fetch the lookahead info from the Bolt RPC server
        let mut lookahead_url = self.bolt_rpc_url.join(BOLT_LOOKAHEAD_PATH)?;

        // Note: it's possible for users to override the target sidecar URL
        // for testing and development purposes. In most cases, the sidecar will
        // reject a request for a slot that it is not responsible for.
        let target_url = if let Some(sidecar_url) = self.override_bolt_sidecar_url {
            // Only get future slots
            lookahead_url.set_query(Some("futureOnly=true"));
            // If using the override URL, we don't need to fetch the active proposers only.
            // we will set the next slot as the target slot.
            sidecar_url
        } else {
            // Filter out slots that are not active or in the past, to fetch the next
            // active proposer slot.
            lookahead_url.set_query(Some("activeOnly=true&futureOnly=true"));
            self.bolt_rpc_url.join("/rpc")?
        };

        let lookahead_res = reqwest::get(lookahead_url).await?.json::<Vec<LookaheadSlot>>().await?;
        if lookahead_res.is_empty() {
            println!("no bolt proposer found in the lookahead, try again later 🥲");
            return Ok(());
        }

        // Extract the next preconfirmer slot from the lookahead info
        let target_slot = lookahead_res[0].slot;
        info!("Target slot: {}", target_slot);

        // Send the transactions to the Bolt sidecar
        let mut next_nonce = None;
        for _ in 0..self.count {
            // generate a simple self-transfer of ETH
            let mut req = create_tx_request(wallet.address(), self.blob);
            if let Some(max_fee) = self.max_fee {
                req.set_max_fee_per_gas(max_fee * GWEI_TO_WEI as u128);
            }

            req.set_max_priority_fee_per_gas(self.priority_fee * GWEI_TO_WEI as u128);

            if let Some(next_nonce) = next_nonce {
                req.set_nonce(next_nonce);
            }

            let (raw_tx, tx_hash) = match provider.fill(req).await.wrap_err("failed to fill")? {
                SendableTx::Builder(_) => bail!("expected a raw transaction"),
                SendableTx::Envelope(raw) => {
                    next_nonce = Some(raw.nonce() + 1);
                    (raw.encoded_2718(), *raw.tx_hash())
                }
            };

            send_rpc_request(
                vec![hex::encode(&raw_tx)],
                vec![tx_hash],
                target_slot,
                target_url.clone(),
                &wallet,
            )
            .await?;

            // Sleep for a bit to avoid spamming
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Ok(())
    }

    /// Send a transaction on the Kurtosis devnet.
    async fn send_devnet_transaction(self, wallet: PrivateKeySigner) -> Result<()> {
        let transaction_signer = EthereumWallet::from(wallet.clone());
        let el_url = self.devnet_execution_url.clone().wrap_err("missing devnet execution URL")?;
        let cl_url = self.devnet_beacon_url.clone().wrap_err("missing devnet beacon URL")?;
        let sidecar_url = self.devnet_sidecar_url.clone().wrap_err("missing devnet sidecar URL")?;

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer)
            .on_http(el_url);

        // Fetch the current slot from the devnet beacon node
        let slot = request_current_slot_number(&cl_url).await?;

        // Send the transactions to the devnet sidecar
        let mut next_nonce = None;
        for _ in 0..self.count {
            let mut req = create_tx_request(wallet.address(), self.blob);
            if let Some(next_nonce) = next_nonce {
                req.set_nonce(next_nonce);
            }

            let (raw_tx, tx_hash) = match provider.fill(req).await.wrap_err("failed to fill")? {
                SendableTx::Builder(_) => bail!("expected a raw transaction"),
                SendableTx::Envelope(raw) => {
                    next_nonce = Some(raw.nonce() + 1);
                    (raw.encoded_2718(), *raw.tx_hash())
                }
            };

            send_rpc_request(
                vec![hex::encode(&raw_tx)],
                vec![tx_hash],
                slot + 2,
                sidecar_url.clone(),
                &wallet,
            )
            .await?;

            // Sleep for a bit to avoid spamming
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Ok(())
    }
}

async fn request_current_slot_number(beacon_url: &Url) -> Result<u64> {
    let res = reqwest::get(beacon_url.join("eth/v1/beacon/headers/head")?).await?;
    let res = res.json::<Value>().await?;
    let slot = res.pointer("/data/header/message/slot").wrap_err("missing slot")?;
    Ok(slot.as_u64().unwrap_or(slot.as_str().wrap_err("invalid slot type")?.parse()?))
}

fn create_tx_request(to: Address, with_blob: bool) -> TransactionRequest {
    let mut req = TransactionRequest::default();
    req = req.with_to(to).with_value(U256::from(100_000));
    req = req.with_input(rand::thread_rng().gen::<[u8; 32]>());

    if with_blob {
        let sidecar = SidecarBuilder::<SimpleCoder>::from_slice(b"Blobs are fun!");
        let sidecar: BlobTransactionSidecar = sidecar.build().unwrap();
        req = req.with_blob_sidecar(sidecar);
        req = req.with_max_fee_per_blob_gas(3_000_000);
    }

    req
}

async fn send_rpc_request(
    txs_rlp: Vec<String>,
    tx_hashes: Vec<B256>,
    target_slot: u64,
    target_sidecar_url: Url,
    wallet: &PrivateKeySigner,
) -> Result<()> {
    let request = prepare_rpc_request(
        "bolt_requestInclusion",
        serde_json::json!({
            "slot": target_slot,
            "txs": txs_rlp,
        }),
    );

    info!(?tx_hashes, target_slot, %target_sidecar_url);
    let signature = sign_request(tx_hashes, target_slot, wallet).await?;

    let response = reqwest::Client::new()
        .post(target_sidecar_url)
        .header("content-type", "application/json")
        .header("x-bolt-signature", signature)
        .body(serde_json::to_string(&request)?)
        .send()
        .await
        .wrap_err("failed to send POST request")?;

    let response = response.text().await?;

    // strip out long series of zeros in the response (to avoid spamming blob contents)
    let response = response.replace(&"0".repeat(32), ".").replace(&".".repeat(4), "");
    info!("Response: {:?}", response);
    Ok(())
}

async fn sign_request(
    tx_hashes: Vec<B256>,
    target_slot: u64,
    wallet: &PrivateKeySigner,
) -> eyre::Result<String> {
    let digest = {
        let mut data = Vec::new();
        let hashes = tx_hashes.iter().map(|hash| hash.as_slice()).collect::<Vec<_>>().concat();
        data.extend_from_slice(&hashes);
        data.extend_from_slice(target_slot.to_le_bytes().as_slice());
        keccak256(data)
    };

    let signature = hex::encode_prefixed(wallet.sign_hash(&digest).await?.as_bytes());

    Ok(format!("{}:{}", wallet.address(), signature))
}

fn prepare_rpc_request(method: &str, params: Value) -> Value {
    serde_json::json!({
        "id": "1",
        "jsonrpc": "2.0",
        "method": method,
        "params": vec![params],
    })
}

/// Info about a specific slot in the beacon chain lookahead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookaheadSlot {
    /// Slot number in the beacon chain
    pub slot: u64,
    /// Validator index that will propose in this slot
    pub validator_index: u64,
    // TODO: add pubkey back once it's added in the rpc
    // /// Validator pubkey that will propose in this slot
    // pub validator_pubkey: String,
    /// Optional URL of the Bolt sidecar associated with the proposer
    pub sidecar_url: Option<String>,
}
