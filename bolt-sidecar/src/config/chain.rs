use core::fmt;
use std::{
    fmt::{Display, Formatter},
    ops::Deref,
    time::Duration,
};

use alloy::primitives::{address, Address};
use clap::{Args, ValueEnum};
use ethereum_consensus::deneb::{compute_fork_data_root, Root};
use serde::Deserialize;

/// Default commitment deadline duration.
///
/// The sidecar will stop accepting new commitments for the next block
/// after this deadline has passed. This is to ensure that builders and
/// relays have enough time to build valid payloads.
pub const DEFAULT_COMMITMENT_DEADLINE_IN_MILLIS: u64 = 8_000;

/// Default first inclusion timer interval in milliseconds.
///
/// The sidecar will check for pending first inclusion requests at this interval.
/// These requests are processed 500ms after the commitment deadline expires.
pub const DEFAULT_FIRST_INCLUSION_TIMER_INTERVAL_IN_MILLIS: u64 = 100;

/// Default slot time duration in seconds.
pub const DEFAULT_SLOT_TIME_IN_SECONDS: u64 = 12;

/// Default gas limit for the sidecar.
pub const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// The domain mask for signing application-builder messages.
pub const APPLICATION_BUILDER_DOMAIN_MASK: [u8; 4] = [0, 0, 0, 1];

/// The domain mask for signing commit-boost messages.
pub const COMMIT_BOOST_DOMAIN_MASK: [u8; 4] = [109, 109, 111, 67];

/// Default chain configuration for the sidecar.
pub const DEFAULT_CHAIN_CONFIG: ChainConfig = ChainConfig {
    chain: Chain::Mainnet,
    commitment_deadline: DEFAULT_COMMITMENT_DEADLINE_IN_MILLIS,
    first_inclusion_timer_interval: DEFAULT_FIRST_INCLUSION_TIMER_INTERVAL_IN_MILLIS,
    slot_time: DEFAULT_SLOT_TIME_IN_SECONDS,
    gas_limit: DEFAULT_GAS_LIMIT,
    enable_unsafe_lookahead: false,
};

/// The address of the canonical BoltManager contract for the Holesky chain.
///
/// https://holesky.etherscan.io/address/0x440202829b493F9FF43E730EB5e8379EEa3678CF
pub const MANAGER_ADDRESS_HOLESKY: Address = address!("440202829b493F9FF43E730EB5e8379EEa3678CF");

/// Configuration for the chain the sidecar is running on.
#[derive(Debug, Clone, Copy, Args, Deserialize)]
pub struct ChainConfig {
    /// Chain on which the sidecar is running
    #[clap(long, env = "BOLT_SIDECAR_CHAIN", default_value_t = Chain::Mainnet)]
    pub(crate) chain: Chain,
    /// The deadline in the slot at which the sidecar will stop accepting
    /// new commitments for the next block (parsed as milliseconds).
    #[clap(
        long,
        env = "BOLT_SIDECAR_COMMITMENT_DEADLINE",
        default_value_t = DEFAULT_CHAIN_CONFIG.commitment_deadline
    )]
    pub(crate) commitment_deadline: u64,
    /// The timer interval for checking pending first inclusion requests (parsed as milliseconds).
    /// First inclusion requests are processed 500ms after the commitment deadline expires.
    #[clap(
        long,
        env = "BOLT_SIDECAR_FIRST_INCLUSION_TIMER_INTERVAL",
        default_value_t = DEFAULT_CHAIN_CONFIG.first_inclusion_timer_interval
    )]
    pub(crate) first_inclusion_timer_interval: u64,
    /// The slot time duration in seconds. If provided,
    /// it overrides the default for the selected [Chain].
    #[clap(
        long,
        env = "BOLT_SIDECAR_SLOT_TIME",
        default_value_t = DEFAULT_CHAIN_CONFIG.slot_time,
    )]
    pub(crate) slot_time: u64,
    /// The gas limit for the sidecar.
    /// This is the maximum amount of gas that can be used for a single transaction.
    /// If provided, it overrides the default for the selected [Chain].
    #[clap(
        long,
        env = "BOLT_SIDECAR_GAS_LIMIT",
        default_value_t = DEFAULT_CHAIN_CONFIG.gas_limit
    )]
    pub(crate) gas_limit: u64,
    /// Toggle to enable unsafe lookahead for the sidecar. If `true`, commitments requests will be
    /// validated against a two-epoch lookahead window.
    #[clap(
        long,
        env = "BOLT_SIDECAR_ENABLE_UNSAFE_LOOKAHEAD",
        default_value_t = DEFAULT_CHAIN_CONFIG.enable_unsafe_lookahead
    )]
    pub(crate) enable_unsafe_lookahead: bool,
}

impl Default for ChainConfig {
    fn default() -> Self {
        DEFAULT_CHAIN_CONFIG
    }
}

impl Deref for ChainConfig {
    type Target = Chain;

    fn deref(&self) -> &Self::Target {
        &self.chain
    }
}

/// Supported chains for the sidecar
#[derive(Debug, Clone, Copy, ValueEnum, Deserialize)]
#[clap(rename_all = "kebab_case")]
#[allow(missing_docs)]
pub enum Chain {
    Mainnet,
    Holesky,
    Helder,
    Kurtosis,
}

impl Chain {
    /// Get the chain ID for the given chain.
    pub const fn id(&self) -> u64 {
        match self {
            Self::Mainnet => 1,
            Self::Holesky => 17000,
            Self::Helder => 7014190335,
            Self::Kurtosis => 3151908,
        }
    }

    /// Get the chain name for the given chain.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Holesky => "holesky",
            Self::Helder => "helder",
            Self::Kurtosis => "kurtosis",
        }
    }

    /// Get the fork version for the given chain.
    pub fn fork_version(&self) -> [u8; 4] {
        match self {
            Self::Mainnet => [0, 0, 0, 0],
            Self::Holesky => [1, 1, 112, 0],
            Self::Helder => [16, 0, 0, 0],
            Self::Kurtosis => [16, 0, 0, 56],
        }
    }

    /// Returns the address of the canonical BoltManager contract for a given chain, if present
    pub const fn manager_address(&self) -> Option<Address> {
        match self {
            Self::Holesky => Some(MANAGER_ADDRESS_HOLESKY),
            _ => None,
        }
    }
}

impl Display for Chain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl ChainConfig {
    /// Get the slot time for the given chain in seconds.
    pub fn slot_time(&self) -> u64 {
        self.slot_time
    }

    /// Get the gas limit for the given chain.
    pub fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    /// Get the domain for signing application-builder messages on the given chain.
    pub fn application_builder_domain(&self) -> [u8; 32] {
        self.compute_domain_from_mask(APPLICATION_BUILDER_DOMAIN_MASK)
    }

    /// Get the domain for signing commit-boost messages on the given chain.
    pub fn commit_boost_domain(&self) -> [u8; 32] {
        self.compute_domain_from_mask(COMMIT_BOOST_DOMAIN_MASK)
    }

    /// Get the commitment deadline duration for the given chain.
    pub fn commitment_deadline(&self) -> Duration {
        Duration::from_millis(self.commitment_deadline)
    }

    /// Get the first inclusion timer interval duration for the given chain.
    pub fn first_inclusion_timer_interval(&self) -> Duration {
        Duration::from_millis(self.first_inclusion_timer_interval)
    }

    /// Compute the domain for signing messages on the given chain.
    fn compute_domain_from_mask(&self, mask: [u8; 4]) -> [u8; 32] {
        let mut domain = [0; 32];

        let fork_version = self.chain.fork_version();

        // Note: the application builder domain specs require the genesis_validators_root
        // to be 0x00 for any out-of-protocol message. The commit-boost domain follows the
        // same rule.
        let root = Root::default();
        let fork_data_root = compute_fork_data_root(fork_version, root).expect("valid fork data");

        domain[..4].copy_from_slice(&mask);
        domain[4..].copy_from_slice(&fork_data_root[..28]);
        domain
    }
}

#[cfg(test)]
impl ChainConfig {
    /// Create a new chain configuration for Mainnet.
    pub fn mainnet() -> Self {
        Self { chain: Chain::Mainnet, ..Default::default() }
    }

    /// Create a new chain configuration for Holesky.
    pub fn holesky() -> Self {
        Self { chain: Chain::Holesky, ..Default::default() }
    }

    /// Create a new chain configuration for Helder.
    pub fn helder() -> Self {
        Self { chain: Chain::Helder, ..Default::default() }
    }

    /// Create a new chain configuration for Kurtosis.
    pub fn kurtosis(slot_time_in_seconds: u64, commitment_deadline: u64) -> Self {
        Self {
            chain: Chain::Kurtosis,
            slot_time: slot_time_in_seconds,
            commitment_deadline,
            first_inclusion_timer_interval: DEFAULT_FIRST_INCLUSION_TIMER_INTERVAL_IN_MILLIS,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::b256;

    const BUILDER_DOMAIN_MAINNET: [u8; 32] =
        b256!("00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9").0;

    const BUILDER_DOMAIN_HOLESKY: [u8; 32] =
        b256!("000000015b83a23759c560b2d0c64576e1dcfc34ea94c4988f3e0d9f77f05387").0;

    const BUILDER_DOMAIN_HELDER: [u8; 32] =
        b256!("0000000194c41af484fff7964969e0bdd922f82dff0f4be87a60d0664cc9d1ff").0;

    const BUILDER_DOMAIN_KURTOSIS: [u8; 32] =
        b256!("000000010b41be4cdb34d183dddca5398337626dcdcfaf1720c1202d3b95f84e").0;

    #[test]
    fn test_compute_builder_domains() {
        use super::ChainConfig;

        let mainnet = ChainConfig::mainnet();
        assert_eq!(mainnet.application_builder_domain(), BUILDER_DOMAIN_MAINNET);

        let holesky = ChainConfig::holesky();
        assert_eq!(holesky.application_builder_domain(), BUILDER_DOMAIN_HOLESKY);

        let helder = ChainConfig::helder();
        assert_eq!(helder.application_builder_domain(), BUILDER_DOMAIN_HELDER);

        let kurtosis = ChainConfig::kurtosis(0, 0);
        assert_eq!(kurtosis.application_builder_domain(), BUILDER_DOMAIN_KURTOSIS);
    }
}
