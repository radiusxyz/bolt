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
    rpc::types::{AccessList, AccessListItem, TransactionRequest},
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
            let mut req = create_tx_request(wallet.address(), self.blob, self.with_access_list);
            if let Some(max_fee) = self.max_fee {
                req.set_max_fee_per_gas(max_fee * GWEI_TO_WEI as u128);
            }

            req.set_max_priority_fee_per_gas(self.priority_fee * GWEI_TO_WEI as u128);

            if let Some(next_nonce) = next_nonce {
                req.set_nonce(next_nonce);
            }

            info!("Transaction request: {:?}", req);

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
                if self.exclusion { RequestType::Exclusion } else { RequestType::Inclusion },
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

        let el_url_for_multi = el_url.clone();
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer)
            .on_http(el_url);

        // Fetch the current slot from the devnet beacon node
        let slot = request_current_slot_number(&cl_url).await?;

        if self.multi_exclusion && self.exclusion {
            // Special handling for multi-exclusion requests
            self.send_multi_exclusion_requests(slot, &sidecar_url, &el_url_for_multi).await?;
        } else {
            // Original single transaction logic
            let mut next_nonce = None;
            for _ in 0..self.count {
                let mut req = create_tx_request(wallet.address(), self.blob, self.with_access_list);
                if let Some(max_fee) = self.max_fee {
                    req.set_max_fee_per_gas(max_fee * GWEI_TO_WEI as u128);
                }

                req.set_max_priority_fee_per_gas(self.priority_fee * GWEI_TO_WEI as u128);

                if let Some(next_nonce) = next_nonce {
                    req.set_nonce(next_nonce);
                }

                info!("Transaction request: {:?}", req);

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
                    if self.exclusion { RequestType::Exclusion } else { RequestType::Inclusion },
                )
                .await?;

                // Sleep for a bit to avoid spamming
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }

        Ok(())
    }

    /// Send multiple exclusion requests concurrently with different signers and access lists
    async fn send_multi_exclusion_requests(
        &self,
        slot: u64,
        sidecar_url: &Url,
        execution_url: &Url,
    ) -> Result<()> {
        // Define the two signers with their private keys
        let signer1_key = "0x53321db7c1e331d93a11a41d16f004d7ff63972ec8ec7c25db329728ceeb1710"; // Funding account
        let signer2_key = "0x1d6e4bbdafe6f2b2d38536f543ac1268c788ca59fbb09a5470ca9697da6d72e2"; // Account 1

        let signer1: PrivateKeySigner = signer1_key.parse().wrap_err("invalid signer1 private key")?;
        let signer2: PrivateKeySigner = signer2_key.parse().wrap_err("invalid signer2 private key")?;

        info!("🚀 Starting integrated exclusion + first inclusion flow:");
        info!("  Signer 1: {} (access list: [0x000...001]) - EXPECTED TO SUCCEED", signer1.address());
        info!("  Signer 2: {} (access list: [0x000...001, 0x000...003]) - EXPECTED TO FAIL", signer2.address());
        info!("  First inclusion: Signer1 → [0x000...001] (subset of successful exclusion)");

        // Create transactions for both signers
        let req1 = create_tx_request_with_hardcoded_access_list(signer1.address(), 1);
        let req2 = create_tx_request_with_hardcoded_access_list(signer2.address(), 2);

        // Create separate providers for each signer
        let transaction_signer1 = EthereumWallet::from(signer1.clone());
        let provider1 = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer1)
            .on_http(execution_url.clone());

        let transaction_signer2 = EthereumWallet::from(signer2.clone());
        let provider2 = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer2)
            .on_http(execution_url.clone());

        // Fill transactions
        let mut req1 = req1;
        if let Some(max_fee) = self.max_fee {
            req1 = req1.with_max_fee_per_gas(max_fee * GWEI_TO_WEI as u128);
        }
        req1 = req1.with_max_priority_fee_per_gas(self.priority_fee * GWEI_TO_WEI as u128);

        let mut req2 = req2;
        if let Some(max_fee) = self.max_fee {
            req2 = req2.with_max_fee_per_gas(max_fee * GWEI_TO_WEI as u128);
        }
        req2 = req2.with_max_priority_fee_per_gas(self.priority_fee * GWEI_TO_WEI as u128);

        // Fill both transactions concurrently
        let (filled1, filled2) = tokio::try_join!(
            provider1.fill(req1),
            provider2.fill(req2)
        )?;

        let (raw_tx1, tx_hash1) = match filled1 {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => (raw.encoded_2718(), *raw.tx_hash()),
        };

        let (raw_tx2, tx_hash2) = match filled2 {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => (raw.encoded_2718(), *raw.tx_hash()),
        };

        // Send both exclusion requests concurrently (asynchronously)
        let target_slot = slot + 2;
        let sidecar_url1 = sidecar_url.clone();
        let sidecar_url2 = sidecar_url.clone();

        let task1 = send_rpc_request(
            vec![hex::encode(&raw_tx1)],
            vec![tx_hash1],
            target_slot,
            sidecar_url1,
            &signer1,
            RequestType::Exclusion,
        );

        let task2 = async {
            // Small delay to simulate 0.2 seconds apart
            tokio::time::sleep(Duration::from_millis(200)).await;
            send_rpc_request(
                vec![hex::encode(&raw_tx2)],
                vec![tx_hash2],
                target_slot,
                sidecar_url2,
                &signer2,
                RequestType::Exclusion,
            ).await
        };

        // Execute both requests concurrently
        let (result1, result2) = tokio::join!(task1, task2);

        // Check results
        let exclusion1_success = result1.is_ok();
        let exclusion2_success = result2.is_ok();
        
        if let Err(e) = result1 {
            info!("Exclusion request 1 failed as expected: {:?}", e);
        }
        if let Err(e) = result2 {
            info!("Exclusion request 2 failed: {:?}", e);
        }

        info!("Exclusion requests completed. Signer1 success: {}, Signer2 success: {}", 
              exclusion1_success, exclusion2_success);

        // 🎯 FIRST INCLUSION: Send first inclusion request from successful signer
        // Based on our access list strategy, signer1 should succeed (has [0x000...1] only)
        if exclusion1_success {
            info!("🚀 Sending first inclusion request from signer1 (successful exclusion)");
            
            // Small delay to simulate realistic timing (within 500ms window)
            tokio::time::sleep(Duration::from_millis(300)).await;
            
            self.send_first_inclusion_request(target_slot, sidecar_url, execution_url, &signer1).await?;
        } else {
            info!("⚠️ Signer1 exclusion failed, cannot send first inclusion request");
        }

        info!("✅ Multi-exclusion + first inclusion flow completed!");
        Ok(())
    }

    /// Send a first inclusion request from the successful exclusion signer
    /// This request uses a subset access list of the successful exclusion
    async fn send_first_inclusion_request(
        &self,
        target_slot: u64,
        sidecar_url: &Url,
        execution_url: &Url,
        signer: &PrivateKeySigner,
    ) -> Result<()> {
        info!("📋 Creating first inclusion transaction with subset access list");
        
        // Create first inclusion transaction with subset access list
        let req = create_tx_request_for_first_inclusion(signer.address());
        
        // Create provider for the signer
        let transaction_signer = EthereumWallet::from(signer.clone());
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer)
            .on_http(execution_url.clone());

        // Set gas parameters
        let mut req = req;
        if let Some(max_fee) = self.max_fee {
            req = req.with_max_fee_per_gas(max_fee * GWEI_TO_WEI as u128);
        }
        req = req.with_max_priority_fee_per_gas(self.priority_fee * GWEI_TO_WEI as u128);

        // Fill the transaction
        let filled_tx = provider.fill(req).await?;
        let (raw_tx, tx_hash) = match filled_tx {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => (raw.encoded_2718(), *raw.tx_hash()),
        };

        info!("🎯 Sending first inclusion request: tx_hash={:?}, slot={}", tx_hash, target_slot);

        // Send the first inclusion request
        send_rpc_request(
            vec![hex::encode(&raw_tx)],
            vec![tx_hash],
            target_slot,
            sidecar_url.clone(),
            signer,
            RequestType::FirstInclusion,
        ).await?;

        info!("✅ First inclusion request sent successfully!");
        Ok(())
    }
}

async fn request_current_slot_number(beacon_url: &Url) -> Result<u64> {
    let res = reqwest::get(beacon_url.join("eth/v1/beacon/headers/head")?).await?;
    let res = res.json::<Value>().await?;
    let slot = res.pointer("/data/header/message/slot").wrap_err("missing slot")?;
    Ok(slot.as_u64().unwrap_or(slot.as_str().wrap_err("invalid slot type")?.parse()?))
}

fn create_tx_request(to: Address, with_blob: bool, with_access_list: bool) -> TransactionRequest {
    let mut req = TransactionRequest::default();
    req = req.with_to(to).with_value(U256::from(100_000));
    req = req.with_input(rand::thread_rng().gen::<[u8; 32]>());

    if with_blob {
        let sidecar = SidecarBuilder::<SimpleCoder>::from_slice(b"Blobs are fun!");
        let sidecar: BlobTransactionSidecar = sidecar.build().unwrap();
        req = req.with_blob_sidecar(sidecar);
        req = req.with_max_fee_per_blob_gas(3_000_000);
    }

    if with_access_list {
        // Create a mock access list with random hex data for testing
        let access_list = AccessList(vec![
            AccessListItem { address: Address::ZERO, storage_keys: vec![B256::ZERO] },
            AccessListItem {
                address: Address::from([0xff; 20]), // Random address
                storage_keys: vec![
                    B256::from(rand::thread_rng().gen::<[u8; 32]>()),
                    B256::from(rand::thread_rng().gen::<[u8; 32]>()),
                ],
            },
        ]);
        req = req.with_access_list(access_list);
    }

    req
}

fn create_tx_request_with_hardcoded_access_list(
    to: Address, 
    access_list_type: u8
) -> TransactionRequest {
    let mut req = TransactionRequest::default();
    req = req.with_to(to).with_value(U256::from(100_000));
    req = req.with_input(rand::thread_rng().gen::<[u8; 32]>());

    let access_list = match access_list_type {
        1 => {
            // First exclusion request: access list with 0x000...001
            let mut key1 = [0u8; 32];
            key1[31] = 1; // Set the last byte to 1 for 0x000...001
            AccessList(vec![
                AccessListItem { 
                    address: Address::ZERO, 
                    storage_keys: vec![B256::from(key1)] 
                }
            ])
        },
        2 => {
            // Second exclusion request: access list with 0x000...001 and 0x000...003
            let mut key1 = [0u8; 32];
            key1[31] = 1; // 0x000...001
            let mut key3 = [0u8; 32];
            key3[31] = 3; // 0x000...003
            AccessList(vec![
                AccessListItem { 
                    address: Address::ZERO, 
                    storage_keys: vec![B256::from(key1), B256::from(key3)] 
                }
            ])
        },
        _ => panic!("Invalid access list type")
    };
    
    req.with_access_list(access_list)
}

/// Create a transaction request with first inclusion access list (subset of exclusion)
/// 
/// Access List Strategy:
/// - Signer1 exclusion: [0x000...1, 0x000...3] → FAILS (conflicts with existing)
/// - Signer2 exclusion: [0x000...1] → SUCCEEDS (no conflicts)  
/// - First inclusion: [0x000...1] → VALID (subset of signer2's successful exclusion)
///
/// This creates a transaction with access list that is a subset of the successful exclusion request
fn create_tx_request_for_first_inclusion(to: Address) -> TransactionRequest {
    let mut req = TransactionRequest::default();
    req = req.with_to(to).with_value(U256::from(100_000));
    req = req.with_input(rand::thread_rng().gen::<[u8; 32]>());

    // First inclusion access list: subset of successful exclusion (just 0x000...001)
    // This matches signer2's successful exclusion which had [0x000...001] only
    let mut key1 = [0u8; 32];
    key1[31] = 1; // 0x000...001
    
    let access_list = AccessList(vec![
        AccessListItem { 
            address: Address::ZERO, 
            storage_keys: vec![B256::from(key1)] // Only the key that was in successful exclusion
        }
    ]);
    
    req.with_access_list(access_list)
}

#[derive(Debug, Clone)]
enum RequestType {
    Inclusion,
    Exclusion,
    FirstInclusion,
}

async fn send_rpc_request(
    txs_rlp: Vec<String>,
    tx_hashes: Vec<B256>,
    target_slot: u64,
    target_sidecar_url: Url,
    wallet: &PrivateKeySigner,
    request_type: RequestType,
) -> Result<()> {
    let method = match request_type {
        RequestType::Inclusion => "bolt_requestInclusion",
        RequestType::Exclusion => "bolt_requestExclusion", 
        RequestType::FirstInclusion => "bolt_requestFirstInclusion",
    };
    let request = prepare_rpc_request(
        method,
        serde_json::json!({
            "slot": target_slot,
            "txs": txs_rlp,
        }),
    );

    info!(?tx_hashes, target_slot, %target_sidecar_url);
    let signature = sign_request(tx_hashes, target_slot, wallet, &request_type).await?;

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
    request_type: &RequestType,
) -> eyre::Result<String> {
    // User signs commitment digest
    let mut data = Vec::new();
    let hashes = tx_hashes.iter().map(|hash| hash.as_slice()).collect::<Vec<_>>().concat();
    data.extend_from_slice(&hashes);
    data.extend_from_slice(target_slot.to_le_bytes().as_slice());
    let digest = keccak256(data);

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
