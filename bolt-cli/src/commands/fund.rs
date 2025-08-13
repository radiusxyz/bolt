use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::utils::parse_ether,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use eyre::{Context, Result};
use tracing::info;

use crate::cli::FundCommand;

// Hardcoded test account private keys (without 0x prefix)
const TEST_ACCOUNTS: [&str; 3] = [
    "1d6e4bbdafe6f2b2d38536f543ac1268c788ca59fbb09a5470ca9697da6d72e2",
    "dceef37487843c70ed16300c9c596415c44694c217603e7af7d01de92127b77d",
    "529b5151d7501017161593074c97546302346ebbecdf1a63119efab37ab150b0",
];

impl FundCommand {
    /// Run the `fund` command.
    pub async fn run(self) -> Result<()> {
        let funding_wallet: PrivateKeySigner =
            self.funding_private_key.parse().wrap_err("invalid funding private key")?;

        info!("Funding wallet address: {}", funding_wallet.address());

        let transaction_signer = EthereumWallet::from(funding_wallet.clone());
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer)
            .on_http(self.execution_url);

        let amount =
            parse_ether(&self.amount.to_string()).wrap_err("failed to parse ETH amount")?;

        info!("Funding {} test accounts with {} ETH each", TEST_ACCOUNTS.len(), self.amount);

        // Derive addresses from private keys and fund them
        for (i, private_key_hex) in TEST_ACCOUNTS.iter().enumerate() {
            let target_wallet: PrivateKeySigner = format!("0x{}", private_key_hex)
                .parse()
                .wrap_err_with(|| format!("invalid private key for account {}", i + 1))?;

            let target_address = target_wallet.address();

            info!("Account {}: {} (funding with {} ETH)", i + 1, target_address, self.amount);

            let req = TransactionRequest::default().with_to(target_address).with_value(amount);

            match provider.send_transaction(req).await {
                Ok(pending_tx) => {
                    info!("Transaction sent for account {}: {}", i + 1, pending_tx.tx_hash());
                }
                Err(e) => {
                    info!("Failed to send transaction to account {}: {}", i + 1, e);
                }
            }
        }

        info!("Funding complete!\n\n\n\n");
        Ok(())
    }
}
