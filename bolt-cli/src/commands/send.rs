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
use futures::future;
use rand::Rng;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;

use crate::cli::SendCommand;

/// Path to the lookahead endpoint on the Bolt RPC server.
const BOLT_LOOKAHEAD_PATH: &str = "/api/v1/proposers/lookahead";

// Test signer keys for multi-exclusion integration testing
const TEST_SIGNER1_KEY: &str = "0x53321db7c1e331d93a11a41d16f004d7ff63972ec8ec7c25db329728ceeb1710";
const TEST_SIGNER2_KEY: &str = "0x1d6e4bbdafe6f2b2d38536f543ac1268c788ca59fbb09a5470ca9697da6d72e2";
const TEST_SIGNER3_KEY: &str = "0x529b5151d7501017161593074c97546302346ebbecdf1a63119efab37ab150b0";

// Timing constants for multi-exclusion flow
const EXCLUSION_REQUEST_DELAY_MS: u64 = 200;

impl SendCommand {
    /// Set up gas parameters for a transaction request
    fn setup_gas_parameters(&self, mut req: TransactionRequest) -> TransactionRequest {
        if let Some(max_fee) = self.max_fee {
            req = req.with_max_fee_per_gas(max_fee * GWEI_TO_WEI as u128);
        }
        req.with_max_priority_fee_per_gas(self.priority_fee * GWEI_TO_WEI as u128)
    }

    /// Set up reasonable gas parameters for mempool transactions (much lower fees)
    fn setup_mempool_gas_parameters(&self, mut req: TransactionRequest) -> TransactionRequest {
        // Use much lower gas fees for mempool transactions to avoid exceeding caps
        req = req.with_max_fee_per_gas(20 * GWEI_TO_WEI as u128); // 20 gwei instead of 400000
        req.with_max_priority_fee_per_gas(2 * GWEI_TO_WEI as u128) // 2 gwei instead of 300000
    }

    /// Log detailed transaction information
    fn log_transaction_details(
        tx: &alloy::consensus::TxEnvelope,
        label: &str,
        signer_address: Address,
    ) {
        info!("📋 {label} DETAILS:");
        info!("  Hash: {}", tx.tx_hash());
        info!("  From: {signer_address}");
        info!("  To: {}", tx.to().unwrap_or_default());
        info!("  Nonce: {}", tx.nonce());
        info!("  Value: {} wei", tx.value());
        info!("  Gas Limit: {}", tx.gas_limit());
        info!("  Max Fee Per Gas: {} wei", tx.max_fee_per_gas());
        info!("  Access List: {:?}", tx.access_list());
    }

    /// Initialize test signers for multi-exclusion testing
    fn create_test_signers() -> Result<(PrivateKeySigner, PrivateKeySigner, PrivateKeySigner)> {
        let signer1 = TEST_SIGNER1_KEY.parse().wrap_err("invalid signer1 private key")?;
        let signer2 = TEST_SIGNER2_KEY.parse().wrap_err("invalid signer2 private key")?;
        let signer3 = TEST_SIGNER3_KEY.parse().wrap_err("invalid signer3 private key")?;
        Ok((signer1, signer2, signer3))
    }
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
        let (signer1, signer2, signer3) = Self::create_test_signers()?;

        info!("🚀 Starting integrated exclusion + first inclusion flow:");
        info!(
            "  Signer 1: {} (access list: [0x000...001]) - EXPECTED TO SUCCEED",
            signer1.address()
        );
        info!(
            "  Signer 2: {} (access list: [0x000...001, 0x000...002]) - EXPECTED TO FAIL",
            signer2.address()
        );
        info!("  First inclusion: Signer1 → [0x000...001] (subset of successful exclusion)");

        // Create transactions for both signers
        let req1 = create_tx_request_with_hardcoded_access_list(
            signer1.address(),
            AccessListType::SingleKey,
        );
        let req2 = create_tx_request_with_hardcoded_access_list(
            signer2.address(),
            AccessListType::DoubleKey,
        );

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

        // Set up gas parameters for both transactions
        let req1 = self.setup_gas_parameters(req1);
        let req2 = self.setup_gas_parameters(req2);

        // Fill both transactions concurrently
        let (filled1, filled2) = tokio::try_join!(provider1.fill(req1), provider2.fill(req2))?;

        let (raw_tx1, tx_hash1, nonce1) = match filled1 {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                Self::log_transaction_details(&raw, "EXCLUSION TX1", signer1.address());
                (raw.encoded_2718(), *raw.tx_hash(), raw.nonce())
            }
        };

        let (raw_tx2, tx_hash2, _nonce2) = match filled2 {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                Self::log_transaction_details(&raw, "EXCLUSION TX2", signer2.address());
                (raw.encoded_2718(), *raw.tx_hash(), raw.nonce())
            }
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
            tokio::time::sleep(Duration::from_millis(EXCLUSION_REQUEST_DELAY_MS)).await;
            send_rpc_request(
                vec![hex::encode(&raw_tx2)],
                vec![tx_hash2],
                target_slot,
                sidecar_url2,
                &signer2,
                RequestType::Exclusion,
            )
            .await
        };

        // Send 2 async transactions from signer3 concurrently
        info!(
            "🔄 Sending 2 async transactions from signer3: {} (ACCOUNT_3_PRIVATE_KEY)",
            signer3.address()
        );
        // Wait 2 seconds to allow commitment requests to be processed first
        tokio::time::sleep(Duration::from_secs(4)).await;
        let signer3_tasks = self
            .send_signer3_async_transactions(target_slot, sidecar_url, execution_url, &signer3)
            .await?;

        let (result1, result2) = tokio::join!(task1, task2);
        let exclusion1_success = result1.is_ok();
        let exclusion2_success = result2.is_ok();

        if let Err(e) = result1 {
            info!("Exclusion request 1 failed as expected: {:?}", e);
        }
        if let Err(e) = result2 {
            info!("Exclusion request 2 failed: {:?}", e);
        }

        // Wait for signer3 tasks to complete
        let signer3_results = future::join_all(signer3_tasks).await;
        let signer3_successes = signer3_results.iter().filter(|r| r.is_ok()).count();
        info!(
            "✅ Signer3 mempool transactions completed: {}/{} successful",
            signer3_successes,
            signer3_results.len()
        );

        info!(
            "Exclusion requests completed. Signer1 success: {}, Signer2 success: {}",
            exclusion1_success, exclusion2_success
        );

        if exclusion1_success {
            info!("🚀 Sending first inclusion request from signer1 (successful exclusion)");
            self.send_first_inclusion_request(
                target_slot,
                sidecar_url,
                execution_url,
                &signer1,
                nonce1,
            )
            .await?;
        } else {
            info!("⚠️ Signer1 exclusion failed, cannot send first inclusion request");
        }

        info!("✅ Multi-exclusion + first inclusion flow completed!");
        Ok(())
    }

    /// Send a first inclusion request from the successful exclusion signer
    async fn send_first_inclusion_request(
        &self,
        target_slot: u64,
        sidecar_url: &Url,
        execution_url: &Url,
        signer: &PrivateKeySigner,
        exclusion_nonce: u64,
    ) -> Result<()> {
        info!("📋 Creating first inclusion transaction with subset access list");

        let req = create_tx_request_for_first_inclusion(signer.address());
        let transaction_signer = EthereumWallet::from(signer.clone());
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer)
            .on_http(execution_url.clone());

        let req = self.setup_gas_parameters(req).with_nonce(exclusion_nonce + 1);

        info!(
            "🔢 First inclusion nonce: {} (exclusion used: {})",
            exclusion_nonce + 1,
            exclusion_nonce
        );

        let filled_tx = provider.fill(req).await?;
        let (raw_tx, tx_hash) = match filled_tx {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                Self::log_transaction_details(&raw, "FIRST INCLUSION TX", signer.address());
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        info!("🎯 Sending first inclusion request: tx_hash={:?}, slot={}", tx_hash, target_slot);

        send_first_inclusion_rpc_request(
            vec![hex::encode(&raw_tx)],
            vec![tx_hash],
            target_slot,
            sidecar_url.clone(),
            signer,
        )
        .await?;

        info!("✅ First inclusion request sent successfully!");
        Ok(())
    }

    /// Send 2 async transactions from signer3 (ACCOUNT_3_PRIVATE_KEY) directly to EL mempool
    /// 1 transaction with access list 0x000...001, 1 transaction with access list 0x000...002
    async fn send_signer3_async_transactions(
        &self,
        _target_slot: u64,
        _sidecar_url: &Url,
        execution_url: &Url,
        signer3: &PrivateKeySigner,
    ) -> Result<Vec<tokio::task::JoinHandle<Result<()>>>> {
        let transaction_signer3 = EthereumWallet::from(signer3.clone());
        let provider3 = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer3)
            .on_http(execution_url.clone());

        let mut tasks = Vec::new();
        let mut current_nonce: Option<u64> = None;

        // Transaction 1: access list 0x000...001
        info!("📝 Creating SIGNER3 TX1 with access list [0x000...001]");
        let mut req1 = create_tx_request_with_hardcoded_access_list(
            signer3.address(),
            AccessListType::SingleKey,
        );
        req1 = self.setup_mempool_gas_parameters(req1);

        // Set nonce for first transaction
        if let Some(nonce) = current_nonce {
            req1 = req1.with_nonce(nonce);
        }

        info!("📋 SIGNER3 TX1 Request Details:");
        info!("  To: {}", signer3.address());
        info!("  Access List Type: SingleKey (0x000...001)");
        info!("  Max Fee: 20 gwei, Priority Fee: 2 gwei");

        let filled_tx1 = provider3.fill(req1).await?;
        let (raw_tx1, tx_hash1, nonce1) = match filled_tx1 {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                Self::log_transaction_details(
                    &raw,
                    "SIGNER3 MEMPOOL TX1 (0x000...001)",
                    signer3.address(),
                );
                current_nonce = Some(raw.nonce() + 1); // Increment nonce for next transaction
                (raw.encoded_2718(), *raw.tx_hash(), raw.nonce())
            }
        };

        let execution_url_clone1 = execution_url.clone();
        let task1 = tokio::spawn(async move {
            send_transaction_to_mempool(
                hex::encode(&raw_tx1),
                tx_hash1,
                execution_url_clone1,
                nonce1,
                1,
            )
            .await
        });
        tasks.push(task1);

        // Transaction 2: access list 0x000...002
        info!("📝 Creating SIGNER3 TX2 with access list [0x000...002]");
        let mut req2 = create_tx_request_with_hardcoded_access_list(
            signer3.address(),
            AccessListType::DoubleKey,
        );
        req2 = self.setup_mempool_gas_parameters(req2);

        // Set nonce for second transaction
        if let Some(nonce) = current_nonce {
            req2 = req2.with_nonce(nonce);
        }

        info!("📋 SIGNER3 TX2 Request Details:");
        info!("  To: {}", signer3.address());
        info!("  Access List Type: DoubleKey (0x000...001 + 0x000...002)");
        info!("  Max Fee: 20 gwei, Priority Fee: 2 gwei");

        let filled_tx2 = provider3.fill(req2).await?;
        let (raw_tx2, tx_hash2, nonce2) = match filled_tx2 {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                Self::log_transaction_details(
                    &raw,
                    "SIGNER3 MEMPOOL TX2 (0x000...002)",
                    signer3.address(),
                );
                (raw.encoded_2718(), *raw.tx_hash(), raw.nonce())
            }
        };

        let execution_url_clone2 = execution_url.clone();
        let task2 = tokio::spawn(async move {
            send_transaction_to_mempool(
                hex::encode(&raw_tx2),
                tx_hash2,
                execution_url_clone2,
                nonce2,
                2,
            )
            .await
        });
        tasks.push(task2);

        Ok(tasks)
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
        let access_list = AccessList(vec![
            AccessListItem { address: Address::ZERO, storage_keys: vec![B256::ZERO] },
            AccessListItem {
                address: Address::from([0xff; 20]),
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
    access_list_type: AccessListType,
) -> TransactionRequest {
    let mut req = TransactionRequest::default();
    req = req.with_to(to).with_value(U256::from(100_000));
    req = req.with_input(rand::thread_rng().gen::<[u8; 32]>());
    req.with_access_list(access_list_type.create_access_list())
}

/// Create a transaction request with first inclusion access list (subset of exclusion)
fn create_tx_request_for_first_inclusion(to: Address) -> TransactionRequest {
    let mut req = TransactionRequest::default();
    req = req.with_to(to).with_value(U256::from(100_000));
    req = req.with_input(rand::thread_rng().gen::<[u8; 32]>());
    req.with_access_list(AccessListType::SingleKey.create_access_list())
}

#[derive(Debug, Clone)]
enum RequestType {
    Inclusion,
    Exclusion,
    FirstInclusion,
}

#[derive(Debug, Clone, Copy)]
enum AccessListType {
    SingleKey = 1, // Address: 0x000...001 with random storage key
    DoubleKey = 2, // Addresses: 0x000...001, 0x000...002 with random storage keys
}

impl AccessListType {
    fn create_access_list(self) -> AccessList {
        // Generate a random storage key that can be reused across addresses
        let random_storage_key = B256::from(rand::thread_rng().gen::<[u8; 32]>());

        match self {
            AccessListType::SingleKey => {
                // Single address: 0x000...001 with random storage key
                let mut addr = [0u8; 20];
                addr[19] = 1; // 0x000...001
                AccessList(vec![AccessListItem {
                    address: Address::from(addr),
                    storage_keys: vec![random_storage_key],
                }])
            }
            AccessListType::DoubleKey => {
                // Two different addresses: 0x000...001 and 0x000...002
                // Both can use the same random storage key (doesn't matter if same)
                let mut addr1 = [0u8; 20];
                addr1[19] = 1; // 0x000...001
                let mut addr2 = [0u8; 20];
                addr2[19] = 2; // 0x000...002

                AccessList(vec![
                    AccessListItem {
                        address: Address::from(addr1),
                        storage_keys: vec![random_storage_key],
                    },
                    AccessListItem {
                        address: Address::from(addr2),
                        storage_keys: vec![random_storage_key], // Same storage key is fine
                    },
                ])
            }
        }
    }
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

    let response = response.replace(&"0".repeat(32), ".").replace(&".".repeat(4), "");
    info!("Response: {:?}", response);
    Ok(())
}

async fn sign_request(
    tx_hashes: Vec<B256>,
    target_slot: u64,
    wallet: &PrivateKeySigner,
    _request_type: &RequestType,
) -> eyre::Result<String> {
    let mut data = Vec::new();
    let hashes = tx_hashes.iter().map(|hash| hash.as_slice()).collect::<Vec<_>>().concat();
    data.extend_from_slice(&hashes);
    data.extend_from_slice(target_slot.to_le_bytes().as_slice());
    let digest = keccak256(data);

    let signature = hex::encode_prefixed(wallet.sign_hash(&digest).await?.as_bytes());

    Ok(format!("{}:{}", wallet.address(), signature))
}

/// Send a first inclusion RPC request with proper JSON structure
async fn send_first_inclusion_rpc_request(
    txs_rlp: Vec<String>,
    tx_hashes: Vec<B256>,
    target_slot: u64,
    target_sidecar_url: Url,
    wallet: &PrivateKeySigner,
) -> Result<()> {
    let request = prepare_rpc_request(
        "bolt_requestFirstInclusion",
        serde_json::json!({
            "slot": target_slot,
            "txs": txs_rlp.clone(),
            "bid_transaction": txs_rlp,
        }),
    );

    info!(?tx_hashes, target_slot, %target_sidecar_url);
    let signature =
        sign_request(tx_hashes, target_slot, wallet, &RequestType::FirstInclusion).await?;

    let response = reqwest::Client::new()
        .post(target_sidecar_url)
        .header("content-type", "application/json")
        .header("x-bolt-signature", signature)
        .body(serde_json::to_string(&request)?)
        .send()
        .await
        .wrap_err("failed to send POST request")?;

    let response = response.text().await?;

    let response = response.replace(&"0".repeat(32), ".").replace(&".".repeat(4), "");
    info!("Response: {:?}", response);
    Ok(())
}

fn prepare_rpc_request(method: &str, params: Value) -> Value {
    serde_json::json!({
        "id": "1",
        "jsonrpc": "2.0",
        "method": method,
        "params": vec![params],
    })
}

/// Send a transaction directly to the execution layer mempool
async fn send_transaction_to_mempool(
    raw_tx: String,
    tx_hash: B256,
    execution_url: Url,
    nonce: u64,
    tx_number: usize,
) -> Result<()> {
    let request = prepare_rpc_request(
        "eth_sendRawTransaction",
        serde_json::json!("0x".to_string() + &raw_tx),
    );

    info!("📤 Sending SIGNER3 TX{} to EL mempool:", tx_number);
    info!("  📍 EL URL: {}", execution_url);
    info!("  🔗 TX Hash: {:?}", tx_hash);
    info!("  🔢 Nonce: {}", nonce);
    info!("  📊 Raw TX Length: {} bytes", raw_tx.len());

    let response = reqwest::Client::new()
        .post(execution_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request)?)
        .send()
        .await
        .wrap_err("failed to send transaction to EL mempool")?;

    let response_text = response.text().await?;

    if response_text.contains("error") {
        info!("⚠️  SIGNER3 TX{} mempool response: {}", tx_number, response_text);
    } else {
        info!("✅ SIGNER3 TX{} successfully submitted to mempool: {}", tx_number, response_text);
    }

    Ok(())
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
