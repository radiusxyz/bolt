use alloy::{
    contract::Error as ContractError,
    network::EthereumWallet,
    primitives::{utils::format_ether, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol_types::SolInterface,
};
use eyre::{bail, Context};
use tracing::{info, warn};

use crate::{
    cli::{Chain, SymbioticSubcommand},
    common::{handle_rpc_dry_run, request_confirmation, shutdown_anvil, try_parse_contract_error},
    contracts::{
        bolt::{
            BoltManager::{self, BoltManagerErrors},
            BoltSymbioticMiddlewareHolesky::{self, BoltSymbioticMiddlewareHoleskyErrors},
            BoltSymbioticMiddlewareMainnet::{self, BoltSymbioticMiddlewareMainnetErrors},
            OperatorsRegistryV1::{self, OperatorsRegistryV1Errors},
        },
        deployments_for_chain,
        erc20::IERC20,
        symbiotic::{IOptInService, IVault},
    },
};

impl SymbioticSubcommand {
    /// Run the symbiotic subcommand.
    pub async fn run(self) -> eyre::Result<()> {
        match self {
            Self::Register { operator_rpc, operator_private_key, rpc_url, extra_data, dry_run } => {
                let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                    .wrap_err("valid private key")?;

                let (rpc, anvil) = handle_rpc_dry_run(rpc_url, dry_run)?;

                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(EthereumWallet::from(signer.clone()))
                    .on_http(rpc);

                let chain = Chain::try_from_provider(&provider).await?;

                let deployments = deployments_for_chain(chain);

                let operator_rpc = operator_rpc.unwrap_or_else(|| {
                    chain.bolt_rpc().unwrap_or_else(|| {
                        panic!( "The bolt RPC is not deployed on {:?}. Please use the `--operator-rpc` flag to specify one manually.", chain)
                    })
                });

                info!(operator = %signer.address(), rpc = %operator_rpc, ?chain, "Registering Symbiotic operator");

                request_confirmation();

                // Check if operator is opted in to the bolt network
                if !IOptInService::new(
                    deployments.symbiotic.network_opt_in_service,
                    provider.clone(),
                )
                .isOptedIn(signer.address(), deployments.symbiotic.network)
                .call()
                .await?
                ._0
                {
                    eyre::bail!(
                        "Operator with address {} not opted in to the bolt network ({})",
                        signer.address(),
                        deployments.symbiotic.network
                    );
                }

                // Sanitize extra data removing quotes and trimming whitespace
                let extra_data = extra_data.trim_matches('"').trim_start().trim_end().to_string();

                if chain == Chain::Mainnet {
                    let middleware = BoltSymbioticMiddlewareMainnet::new(
                        deployments.bolt.symbiotic_middleware,
                        provider.clone(),
                    );

                    match middleware
                        .registerOperator(operator_rpc.to_string(), extra_data)
                        .send()
                        .await
                    {
                        Ok(pending) => {
                            info!(
                                hash = ?pending.tx_hash(),
                                "registerOperator transaction sent, awaiting receipt..."
                            );

                            let receipt = pending.get_receipt().await?;
                            if !receipt.status() {
                                eyre::bail!("Transaction failed: {:?}", receipt)
                            }

                            info!("Successfully registered Symbiotic operator");
                        }
                        Err(e) => parse_symbiotic_middleware_mainnet_errors(e)?,
                    }
                } else if chain == Chain::Holesky {
                    let middleware = BoltSymbioticMiddlewareHolesky::new(
                        deployments.bolt.symbiotic_middleware,
                        provider.clone(),
                    );

                    match middleware.registerOperator(operator_rpc.to_string()).send().await {
                        Ok(pending) => {
                            info!(
                                hash = ?pending.tx_hash(),
                                "registerOperator transaction sent, awaiting receipt..."
                            );

                            let receipt = pending.get_receipt().await?;
                            if !receipt.status() {
                                eyre::bail!("Transaction failed: {:?}", receipt)
                            }

                            info!("Successfully registered Symbiotic operator");
                        }
                        Err(e) => parse_symbiotic_middleware_holesky_errors(e)?,
                    }
                }

                shutdown_anvil(anvil);

                Ok(())
            }

            Self::Deregister { rpc_url, operator_private_key, dry_run } => {
                let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                    .wrap_err("valid private key")?;

                let address = signer.address();

                let (rpc, anvil) = handle_rpc_dry_run(rpc_url, dry_run)?;

                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(EthereumWallet::from(signer))
                    .on_http(rpc);

                let chain = Chain::try_from_provider(&provider).await?;

                let deployments = deployments_for_chain(chain);

                info!(operator = %address, ?chain, "Deregistering Symbiotic operator");

                request_confirmation();

                // TODO(nico): consolidate holesky & mainnet smart contracts
                if chain == Chain::Mainnet {
                    let middleware = BoltSymbioticMiddlewareMainnet::new(
                        deployments.bolt.symbiotic_middleware,
                        provider.clone(),
                    );

                    match middleware.deregisterOperator().send().await {
                        Ok(pending) => {
                            info!(
                                hash = ?pending.tx_hash(),
                                "deregisterOperator transaction sent, awaiting receipt..."
                            );

                            let receipt = pending.get_receipt().await?;
                            if !receipt.status() {
                                eyre::bail!("Transaction failed: {:?}", receipt)
                            }

                            info!("Successfully deregistered Symbiotic operator");
                        }
                        Err(e) => parse_symbiotic_middleware_mainnet_errors(e)?,
                    }
                } else if chain == Chain::Holesky {
                    let middleware = BoltSymbioticMiddlewareHolesky::new(
                        deployments.bolt.symbiotic_middleware,
                        provider,
                    );

                    match middleware.deregisterOperator().send().await {
                        Ok(pending) => {
                            info!(
                                hash = ?pending.tx_hash(),
                                "deregisterOperator transaction sent, awaiting receipt..."
                            );

                            let receipt = pending.get_receipt().await?;
                            if !receipt.status() {
                                eyre::bail!("Transaction failed: {:?}", receipt)
                            }

                            info!("Successfully deregistered Symbiotic operator");
                        }
                        Err(e) => parse_symbiotic_middleware_holesky_errors(e)?,
                    }
                }

                shutdown_anvil(anvil);

                Ok(())
            }

            Self::UpdateRpc { rpc_url, operator_private_key, operator_rpc, dry_run } => {
                let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                    .wrap_err("valid private key")?;
                let address = signer.address();

                let (rpc, anvil) = handle_rpc_dry_run(rpc_url, dry_run)?;

                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(EthereumWallet::from(signer))
                    .on_http(rpc);

                let chain = Chain::try_from_provider(&provider).await?;

                info!(operator = %address, rpc = %operator_rpc, ?chain, "Updating Symbiotic operator RPC");

                request_confirmation();

                let deployments = deployments_for_chain(chain);

                let bolt_manager = BoltManager::new(deployments.bolt.manager, provider.clone());
                if bolt_manager.isOperator(address).call().await?._0 {
                    info!(?address, "Symbiotic operator is registered");
                } else {
                    warn!(?address, "Operator not registered");
                    return Ok(());
                }

                let result = match bolt_manager
                    .updateOperatorRPC(operator_rpc.to_string())
                    .send()
                    .await
                {
                    Ok(pending) => {
                        info!(
                            hash = ?pending.tx_hash(),
                            "updateOperatorRPC transaction sent, awaiting receipt..."
                        );

                        let receipt = pending.get_receipt().await?;
                        if !receipt.status() {
                            eyre::bail!("Transaction failed: {:?}", receipt)
                        }

                        info!("Successfully updated Symbiotic operator RPC");
                        Ok(())
                    }
                    Err(e) => match try_parse_contract_error::<BoltManagerErrors>(e)? {
                        BoltManagerErrors::OperatorNotRegistered(_) => {
                            eyre::bail!("Operator not registered in bolt")
                        }
                        other => {
                            unreachable!("Unexpected error with selector {:?}", other.selector())
                        }
                    },
                };

                shutdown_anvil(anvil);

                result
            }

            Self::Status { rpc_url, address } => {
                let provider = ProviderBuilder::new().on_http(rpc_url.clone());

                let chain = Chain::try_from_provider(&provider).await?;

                let deployments = deployments_for_chain(chain);

                info!(?address, ?chain, "Checking Symbiotic operator status");

                // TODO(nico): consolidate holesky & mainnet smart contracts
                if chain == Chain::Mainnet {
                    let middleware = BoltSymbioticMiddlewareMainnet::new(
                        deployments.bolt.symbiotic_middleware,
                        provider.clone(),
                    );

                    let registry = OperatorsRegistryV1::new(
                        deployments.bolt.operators_registry,
                        provider.clone(),
                    );

                    // TOOD: clean up, concurrent calls
                    match registry.isOperator(address).call().await {
                        Ok(is_operator) => {
                            if is_operator._0 {
                                info!(?address, "Symbiotic operator is registered");
                            } else {
                                warn!(?address, "Operator not registered");
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            let other = try_parse_contract_error::<OperatorsRegistryV1Errors>(e)?;
                            bail!("Unexpected error with selector {:?}", other.selector())
                        }
                    }

                    match registry.isActiveOperator(address).call().await {
                        Ok(is_active) => {
                            if is_active._0 {
                                info!(?address, "Operator is active");
                            } else {
                                warn!(?address, "Operator is not active yet");
                            }
                        }
                        Err(e) => {
                            let other = try_parse_contract_error::<OperatorsRegistryV1Errors>(e)?;
                            bail!("Unexpected error with selector {:?}", other.selector())
                        }
                    }

                    match middleware.getOperatorCollaterals(address).call().await {
                        Ok(collaterals) => {
                            for (token, amount) in collaterals._0.iter().zip(collaterals._1.iter())
                            {
                                if !amount.is_zero() {
                                    info!(?address, token = %token, amount = format_ether(*amount), "Operator has collateral");
                                }
                            }

                            let total_collateral = collaterals._1.iter().sum::<U256>();
                            info!(
                                ?address,
                                "Total operator collateral: {}",
                                format_ether(total_collateral)
                            );
                        }
                        Err(e) => parse_symbiotic_middleware_mainnet_errors(e)?,
                    }
                } else if chain == Chain::Holesky {
                    let bolt_manager = BoltManager::new(deployments.bolt.manager, provider.clone());

                    if bolt_manager.isOperator(address).call().await?._0 {
                        info!(?address, "Symbiotic operator is registered");
                    } else {
                        warn!(?address, "Operator not registered");
                        return Ok(());
                    }

                    let middleware = BoltSymbioticMiddlewareHolesky::new(
                        deployments.bolt.symbiotic_middleware,
                        provider.clone(),
                    );

                    match bolt_manager.getOperatorData(address).call().await {
                        Ok(operator_data) => {
                            info!(?address, operator_data = ?operator_data._0, "Operator data");
                        }
                        Err(e) => match try_parse_contract_error::<BoltManagerErrors>(e)? {
                            BoltManagerErrors::KeyNotFound(_) => {
                                warn!(?address, "Operator data not found");
                            }
                            other => {
                                unreachable!(
                                    "Unexpected error with selector {:?}",
                                    other.selector()
                                )
                            }
                        },
                    }

                    match middleware.getOperatorCollaterals(address).call().await {
                        Ok(collaterals) => {
                            for (token, amount) in collaterals._0.iter().zip(collaterals._1.iter())
                            {
                                if !amount.is_zero() {
                                    info!(?address, token = %token, amount = format_ether(*amount), "Operator has collateral");
                                }
                            }

                            let total_collateral = collaterals._1.iter().sum::<U256>();
                            info!(
                                ?address,
                                "Total operator collateral: {}",
                                format_ether(total_collateral)
                            );
                        }
                        Err(e) => parse_symbiotic_middleware_mainnet_errors(e)?,
                    }
                }

                Ok(())
            }

            Self::ListVaults { rpc_url } => {
                let provider = ProviderBuilder::new().on_http(rpc_url.clone());

                let chain = Chain::try_from_provider(&provider).await?;

                let deployments = deployments_for_chain(chain);

                info!("Listing all Symbiotic whitelisted vaults:");

                // TODO(nico): consolidate holesky & mainnet smart contracts
                let vaults = if chain == Chain::Mainnet {
                    let symb_middleware = BoltSymbioticMiddlewareMainnet::new(
                        deployments.bolt.symbiotic_middleware,
                        &provider,
                    );

                    symb_middleware.getActiveWhitelistedVaults().call().await?._0
                } else if chain == Chain::Holesky {
                    let symb_middleware = BoltSymbioticMiddlewareHolesky::new(
                        deployments.bolt.symbiotic_middleware,
                        &provider,
                    );

                    symb_middleware.getWhitelistedVaults().call().await?._0
                } else {
                    unreachable!("Invalid chain");
                };

                for vault_address in vaults {
                    let vault = IVault::new(vault_address, &provider);
                    let token_address = vault.collateral().call().await?._0;
                    let token = IERC20::new(token_address, &provider);
                    let token_symbol = token.symbol().call().await?._0;

                    info!("- Token: {} - Vault: {}", token_symbol, vault_address);
                }

                Ok(())
            }
        }
    }
}

/// Parse the errors from the Symbiotic middleware contract.
fn parse_symbiotic_middleware_mainnet_errors(err: ContractError) -> eyre::Result<()> {
    match try_parse_contract_error::<BoltSymbioticMiddlewareMainnetErrors>(err)? {
        BoltSymbioticMiddlewareMainnetErrors::NotOperator(_) => {
            bail!("Operator not registered in Symbiotic")
        }
        BoltSymbioticMiddlewareMainnetErrors::NotOperatorSpecificVault(_) => {
            bail!("Operator not registered in Symbiotic for this vault")
        }
        BoltSymbioticMiddlewareMainnetErrors::NotVault(_) => {
            bail!("Vault not registered in Symbiotic")
        }
        BoltSymbioticMiddlewareMainnetErrors::OperatorNotOptedIn(_) => {
            bail!("Operator not opted in to the bolt network")
        }
        BoltSymbioticMiddlewareMainnetErrors::OperatorNotRegistered(_) => {
            bail!("Operator not registered in bolt")
        }
        BoltSymbioticMiddlewareMainnetErrors::UnauthorizedVault(_) => {
            bail!("Unauthorized vault")
        }
        BoltSymbioticMiddlewareMainnetErrors::VaultAlreadyWhitelisted(_) => {
            bail!("Vault already whitelisted")
        }
        BoltSymbioticMiddlewareMainnetErrors::VaultNotInitialized(_) => {
            bail!("Vault not initialized")
        }
    }
}

/// Parse the errors from the Symbiotic middleware contract.
fn parse_symbiotic_middleware_holesky_errors(err: ContractError) -> eyre::Result<()> {
    match try_parse_contract_error::<BoltSymbioticMiddlewareHoleskyErrors>(err)? {
        BoltSymbioticMiddlewareHoleskyErrors::AlreadyRegistered(_) => {
            bail!("Operator already registered in bolt")
        }
        BoltSymbioticMiddlewareHoleskyErrors::KeyNotFound(_) => {
            bail!("Operator not registered in Symbiotic")
        }
        BoltSymbioticMiddlewareHoleskyErrors::NotOperator(_) => {
            bail!("Operator not registered in Symbiotic")
        }
        BoltSymbioticMiddlewareHoleskyErrors::NotRegistered(_) => {
            bail!("Operator not registered in bolt")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cli::{Chain, OperatorsCommand, OperatorsSubcommand, SymbioticSubcommand},
        contracts::deployments_for_chain,
    };
    use alloy::{
        network::EthereumWallet,
        node_bindings::Anvil,
        primitives::{address, keccak256, utils::parse_units, U256},
        providers::{ext::AnvilApi, ProviderBuilder, WalletProvider},
        signers::local::PrivateKeySigner,
        sol_types::SolValue,
    };
    use reqwest::Url;
    use std::process::{Command, Output};

    /// Ignored since it requires Symbiotic CLI: https://docs.symbiotic.fi/guides/cli/#installation
    /// To run this test, install the CLI, and then move the binary in the `symbiotic-cli` directory
    /// which is git-ignored for this purpose.
    #[tokio::test]
    #[ignore = "requires Symbiotic CLI installed"]
    async fn test_symbiotic_flow() {
        let s1 = PrivateKeySigner::random();
        let secret_key = s1.to_bytes();
        let wallet = EthereumWallet::new(s1);

        let rpc_url = "https://holesky.drpc.org";
        let anvil = Anvil::default().fork(rpc_url).spawn();
        let anvil_url = Url::parse(&anvil.endpoint()).expect("valid URL");
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(anvil_url.clone());

        let account = provider.default_signer_address();

        // Add balance to the operator
        provider.anvil_set_balance(account, U256::from(u64::MAX)).await.expect("set balance");

        let deployments = deployments_for_chain(Chain::Holesky);

        let weth_address = address!("94373a4919B3240D86eA41593D5eBa789FEF3848");

        // Mock WETH balance using the Anvil API.
        let hashed_slot = keccak256((account, U256::from(3)).abi_encode());
        let mocked_balance: U256 = parse_units("100.0", "ether").expect("parse ether").into();
        provider
            .anvil_set_storage_at(weth_address, hashed_slot.into(), mocked_balance.into())
            .await
            .expect("to set storage");

        let print_output = |output: Output| {
            println!("{}", String::from_utf8_lossy(&output.stdout));
        };

        // We now follow the steps described in the Holesky guide

        let register_operator = Command::new("python3")
            .arg("symbiotic-cli/symb.py")
            .arg("--chain")
            .arg("holesky")
            .arg("--provider")
            .arg(anvil_url.to_string())
            .arg("register-operator")
            .arg("--private-key")
            .arg(secret_key.to_string())
            .output()
            .expect("to register operator");

        print_output(register_operator);

        let opt_in_network = Command::new("python3")
            .arg("symbiotic-cli/symb.py")
            .arg("--chain")
            .arg("holesky")
            .arg("--provider")
            .arg(anvil_url.to_string())
            .arg("opt-in-network")
            .arg("--private-key")
            .arg(secret_key.to_string())
            .arg(deployments.symbiotic.network.to_string())
            .output()
            .expect("to opt-in-network");

        print_output(opt_in_network);

        let vault = address!("C56Ba584929c6f381744fA2d7a028fA927817f2b");

        let opt_in_vault = Command::new("python3")
            .arg("symbiotic-cli/symb.py")
            .arg("--chain")
            .arg("holesky")
            .arg("--provider")
            .arg(anvil_url.to_string())
            .arg("opt-in-vault")
            .arg("--private-key")
            .arg(secret_key.to_string())
            .arg(vault.to_string())
            .output()
            .expect("to opt-in-vault");

        print_output(opt_in_vault);

        let deposit = Command::new("python3")
            .arg("symbiotic-cli/symb.py")
            .arg("--chain")
            .arg("holesky")
            .arg("--provider")
            .arg(anvil_url.to_string())
            .arg("deposit")
            .arg("--private-key")
            .arg(secret_key.to_string())
            .arg(vault.to_string())
            .arg("1") // 1 ether
            .output()
            .expect("to opt-in-vault");

        print_output(deposit);

        let register_into_bolt = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::Register {
                    rpc_url: anvil_url.clone(),
                    operator_private_key: secret_key,
                    extra_data: "sudo rm -rf / --no-preserve-root".to_string(),
                    operator_rpc: None,
                    dry_run: false,
                },
            },
        };

        register_into_bolt.run().await.expect("to register into bolt");

        let check_status = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::Status {
                    rpc_url: anvil_url.clone(),
                    address: account,
                },
            },
        };

        check_status.run().await.expect("to check operator status");

        let update_rpc = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::UpdateRpc {
                    rpc_url: anvil_url.clone(),
                    operator_private_key: secret_key,
                    operator_rpc: "https://boooooooooooooooolt.chainbound.io"
                        .parse()
                        .expect("valid url"),
                    dry_run: false,
                },
            },
        };

        update_rpc.run().await.expect("to update operator rpc");

        let check_status = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::Status {
                    rpc_url: anvil_url.clone(),
                    address: account,
                },
            },
        };

        check_status.run().await.expect("to check operator status");

        let deregister_command = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::Deregister {
                    rpc_url: anvil_url.clone(),
                    operator_private_key: secret_key,
                    dry_run: false,
                },
            },
        };

        deregister_command.run().await.expect("to deregister operator");

        let check_status = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::Status { rpc_url: anvil_url, address: account },
            },
        };

        check_status.run().await.expect("to check operator status");
    }
}
