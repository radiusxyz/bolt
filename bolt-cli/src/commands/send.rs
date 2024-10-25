use alloy::{
    consensus::{BlobTransactionSidecar, SidecarBuilder, SimpleCoder},
    eips::eip2718::Encodable2718,
    network::{EthereumWallet, TransactionBuilder, TransactionBuilder4844},
    primitives::{keccak256, Address, B256, U256},
    providers::{ProviderBuilder, SendableTx},
    rpc::types::TransactionRequest,
    signers::{local::PrivateKeySigner, Signer},
};
use eyre::{bail, Context, Result};
use rand::Rng;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;

use crate::cli::SendCommand;

/// Path to the lookahead endpoint on the Bolt RPC server.
const BOLT_LOOKAHEAD_PATH: &str = "proposers/lookahead";

impl SendCommand {
    /// Run the `send` command.
    pub async fn run(self) -> Result<()> {
        let wallet: PrivateKeySigner = self.private_key.parse().wrap_err("invalid private key")?;
        let transaction_signer = EthereumWallet::from(wallet.clone());

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer)
            .on_http(self.bolt_rpc_url.clone());

        // Fetch the lookahead info from the Bolt RPC server
        let mut lookahead_url = self.bolt_rpc_url.join(BOLT_LOOKAHEAD_PATH)?;

        // Note: it's possible for users to override the target sidecar URL
        // for testing and development purposes. In most cases, the sidecar will
        // reject a request for a slot that it is not responsible for.
        let target_url = if let Some(sidecar_url) = self.override_bolt_sidecar_url {
            // If using the override URL, we don't need to fetch the active proposers only.
            // we will set the next slot as the target slot.
            sidecar_url.clone()
        } else {
            // Filter out slots that are not active or in the past, to fetch the next
            // active proposer slot.
            lookahead_url.set_query(Some("activeOnly=true&futureOnly=true"));
            self.bolt_rpc_url.clone()
        };

        let lookahead_res = reqwest::get(lookahead_url).await?.json::<Vec<LookaheadSlot>>().await?;
        if lookahead_res.is_empty() {
            println!("no bolt proposer found in the lookahead, try again later 🥲");
            return Ok(());
        }

        // Extract the next preconfirmer slot from the lookahead info
        let target_slot = lookahead_res[0].slot;
        info!("Target slot: {}", target_slot);

        for _ in 0..self.count {
            // generate a simple self-transfer of ETH
            let req = create_tx_request(wallet.address(), self.blob);

            let raw_tx = match provider.fill(req).await.wrap_err("failed to fill transaction")? {
                SendableTx::Builder(_) => bail!("expected a raw transaction"),
                SendableTx::Envelope(raw) => raw.encoded_2718(),
            };
            let tx_hash = B256::from(keccak256(&raw_tx));

            send_rpc_request(
                vec![hex::encode(&raw_tx)],
                vec![tx_hash],
                target_slot,
                target_url.clone(),
                &wallet,
            )
            .await?;
        }

        Ok(())
    }
}

fn create_tx_request(to: Address, with_blob: bool) -> TransactionRequest {
    let mut req = TransactionRequest::default();
    req = req.with_to(to).with_value(U256::from(100_000));
    req = req.with_input(rand::thread_rng().gen::<[u8; 32]>());

    if with_blob {
        let sidecar = SidecarBuilder::<SimpleCoder>::from_slice(b"Blobs are fun!");
        let sidecar: BlobTransactionSidecar = sidecar.build().unwrap();
        req = req.with_blob_sidecar(sidecar)
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

    let signature = hex::encode(wallet.sign_hash(&digest).await?.as_bytes());

    Ok(format!("{}:0x{}", wallet.address(), signature))
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
