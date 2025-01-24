use std::collections::HashMap;

use alloy::primitives::{address, Address};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use crate::cli::Chain;

pub mod bolt;
pub mod eigenlayer;
pub mod erc20;
pub mod symbiotic;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Contracts {
    pub bolt: Bolt,
    pub symbiotic: Symbiotic,
    pub eigenlayer: EigenLayer,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Bolt {
    pub validators: Address,
    pub parameters: Address,
    pub manager: Address,
    pub eigenlayer_middleware: Address,
    pub symbiotic_middleware: Address,
    pub operators_registry: Address,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Symbiotic {
    pub network: Address,
    pub operator_registry: Address,
    pub network_opt_in_service: Address,
    pub vault_factory: Address,
    pub vault_configurator: Address,
    pub network_registry: Address,
    pub network_middleware_service: Address,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EigenLayer {
    pub avs_directory: Address,
    pub delegation_manager: Address,
    pub strategy_manager: Address,
}

pub fn deployments() -> HashMap<Chain, Contracts> {
    let mut deployments = HashMap::new();
    deployments.insert(Chain::Holesky, HOLESKY_DEPLOYMENTS.clone());
    deployments.insert(Chain::Mainnet, MAINNET_DEPLOYMENTS.clone());

    deployments
}

pub fn deployments_for_chain(chain: Chain) -> Contracts {
    deployments()
        .get(&chain)
        .cloned()
        .unwrap_or_else(|| panic!("no deployments for chain: {:?}", chain))
}

lazy_static! {
    pub static ref HOLESKY_DEPLOYMENTS: Contracts = Contracts {
        bolt: Bolt {
            validators: address!("47D2DC1DE1eFEFA5e6944402f2eda3981D36a9c8"),
            parameters: address!("20d1cf3A5BD5928dB3118b2CfEF54FDF9fda5c12"),
            manager: address!("440202829b493F9FF43E730EB5e8379EEa3678CF"),
            eigenlayer_middleware: address!("a632a3e652110Bb2901D5cE390685E6a9838Ca04"),
            symbiotic_middleware: address!("04f40d9CaE475E5BaA462acE53E5c58A0DD8D8e8"),

            // TODO(nico): refactor this out
            operators_registry: address!("0000000000000000000000000000000000000000"),
        },
        symbiotic: Symbiotic {
            network: address!("b017002D8024d8c8870A5CECeFCc63887650D2a4"),
            operator_registry: address!("6F75a4ffF97326A00e52662d82EA4FdE86a2C548"),
            network_opt_in_service: address!("58973d16FFA900D11fC22e5e2B6840d9f7e13401"),
            vault_factory: address!("407A039D94948484D356eFB765b3c74382A050B4"),
            vault_configurator: address!("D2191FE92987171691d552C219b8caEf186eb9cA"),
            network_registry: address!("7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9"),
            network_middleware_service: address!("62a1ddfD86b4c1636759d9286D3A0EC722D086e3"),
        },
        eigenlayer: EigenLayer {
            avs_directory: address!("055733000064333CaDDbC92763c58BF0192fFeBf"),
            delegation_manager: address!("A44151489861Fe9e3055d95adC98FbD462B948e7"),
            strategy_manager: address!("dfB5f6CE42aAA7830E94ECFCcAd411beF4d4D5b6"),
        },
    };
    pub static ref MAINNET_DEPLOYMENTS: Contracts = Contracts {
        bolt: Bolt {
            // TODO(nico): rm these which aren't part of the new deployment
            validators: address!("0000000000000000000000000000000000000000"),
            parameters: address!("0000000000000000000000000000000000000000"),
            manager: address!("0000000000000000000000000000000000000000"),

            // TODO(nico): change these to mainnet actual addresses
            // these point to our Anvil fork for now
            operators_registry: address!("Ed8D7d3A98CB4ea6C91a80dcd2220719c264531f"),
            eigenlayer_middleware: address!("2ca60d89144D4cdf85dA87af4FE12aBF9265F28C"),
            symbiotic_middleware: address!("fD3e0cEe740271f070607aEddd0Bf4Cf99C92204"),
        },
        symbiotic: Symbiotic {
            network: address!("A42ec46F2c9DC671a72218E145CC13dc119fB722"),
            operator_registry: address!("Ad817a6Bc954F678451A71363f04150FDD81Af9F"),
            network_opt_in_service: address!("7133415b33B438843D581013f98A08704316633c"),
            vault_factory: address!("AEb6bdd95c502390db8f52c8909F703E9Af6a346"),
            vault_configurator: address!("29300b1d3150B4E2b12fE80BE72f365E200441EC"),
            network_registry: address!("C773b1011461e7314CF05f97d95aa8e92C1Fd8aA"),
            network_middleware_service: address!("D7dC9B366c027743D90761F71858BCa83C6899Ad"),
        },
        eigenlayer: EigenLayer {
            avs_directory: address!("135dda560e946695d6f155dacafc6f1f25c1f5af"),
            delegation_manager: address!("39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A"),
            strategy_manager: address!("858646372CC42E1A627fcE94aa7A7033e7CF075A"),
        },
    };
}
