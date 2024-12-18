/// Handles pricing calculations for preconfirmations
#[derive(Debug)]
pub struct PreconfPricing {
    block_gas_limit: u64,
    base_multiplier: f64,
    gas_scalar: f64,
}

/// Errors that can occur during pricing calculations
#[derive(Debug, thiserror::Error)]
pub enum PricingError {
    /// Preconfirmed gas exceeds the block limit
    #[error("Preconfirmed gas {0} exceeds block limit {1}")]
    ExceedsBlockLimit(u64, u64),
    /// Insufficient remaining gas for the incoming transaction
    #[error("Insufficient remaining gas: requested {requested}, available {available}")]
    /// Insufficient remaining gas for the incoming transaction
    InsufficientGas {
        /// Gas requested by the incoming transaction
        requested: u64,
        /// Gas available in the block
        available: u64,
    },
    /// Incoming gas is zero
    #[error("Invalid gas limit: Incoming gas ({incoming_gas}) is zero")]
    InvalidGasLimit {
        /// Gas required by the incoming transaction
        incoming_gas: u64,
    },
}

impl PreconfPricing {
    /// Initializes a new PreconfPricing with default parameters.
    pub fn new() -> Self {
        Self { block_gas_limit: 30_000_000, base_multiplier: 0.019, gas_scalar: 1.02e-6 }
    }

    /// Calculate the minimum priority fee for a preconfirmation based on
    /// https://research.lido.fi/t/a-pricing-model-for-inclusion-preconfirmations/9136
    ///
    /// # Arguments
    /// * `incoming_gas` - Gas required by the incoming transaction
    /// * `preconfirmed_gas` - Total gas already preconfirmed
    ///
    /// # Returns
    /// * `Ok(f64)` - The minimum priority fee in Wei
    /// * `Err(PricingError)` - If the calculation cannot be performed
    pub fn calculate_min_priority_fee(
        &self,
        incoming_gas: u64,
        preconfirmed_gas: u64,
    ) -> Result<u64, PricingError> {
        // Check if preconfirmed gas exceeds block limit
        if preconfirmed_gas >= self.block_gas_limit {
            return Err(PricingError::ExceedsBlockLimit(preconfirmed_gas, self.block_gas_limit));
        }

        // Validate incoming gas
        if incoming_gas == 0 {
            return Err(PricingError::InvalidGasLimit { incoming_gas });
        }

        // Check if there is enough gas remaining in the block
        let remaining_gas = self.block_gas_limit - preconfirmed_gas;
        if incoming_gas > remaining_gas {
            return Err(PricingError::InsufficientGas {
                requested: incoming_gas,
                available: remaining_gas,
            });
        }

        // T(IG,UG) = 0.019 * ln(1.02⋅10^-6(30M-UG)+1 / 1.02⋅10^-6(30M-UG-IG)+1) / IG
        // where
        // IG = Gas used by the incoming transaction
        // UG = Gas already preconfirmed
        // T = Inclusion tip per gas
        // 30M = Current gas limit (36M soon?)
        let after_gas = remaining_gas - incoming_gas;

        // Calculate numerator and denominator for the logarithm
        let numerator = self.gas_scalar * (remaining_gas as f64) + 1.0;
        let denominator = self.gas_scalar * (after_gas as f64) + 1.0;

        // Calculate gas used
        let expected_val = self.base_multiplier * (numerator / denominator).ln();

        // Calculate the inclusion tip
        let inclusion_tip_ether = expected_val / (incoming_gas as f64);
        let inclusion_tip_wei = (inclusion_tip_ether * 1e18) as u64;

        Ok(inclusion_tip_wei)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_priority_fee_zero_preconfirmed() {
        let pricing = PreconfPricing::new();

        // Test minimum fee (21k gas ETH transfer, 0 preconfirmed)
        let incoming_gas = 21_000;
        let preconfirmed_gas = 0;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        // Expected fee: ~0.61 Gwei
        assert!(
            (min_fee_wei as f64 - 613_499_092.0).abs() < 1_000.0,
            "Expected ~610,000,000 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_min_priority_fee_medium_load() {
        let pricing = PreconfPricing::new();

        // Test medium load (21k gas, 15M preconfirmed)
        let incoming_gas = 21_000;
        let preconfirmed_gas = 15_000_000;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        // Expected fee: ~1.17 Gwei
        assert!(
            (min_fee_wei as f64 - 1_189_738_950.0).abs() < 1_000.0,
            "Expected ~1,189,738,950 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_min_priority_fee_max_load() {
        let pricing = PreconfPricing::new();

        // Test last preconfirmed transaction (21k gas, almost 30M preconfirmed)
        let incoming_gas = 21_000;
        let preconfirmed_gas = 30_000_000 - 21_000;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        // Expected fee: ~19 Gwei
        assert!(
            (min_fee_wei as f64 - 19_175_357_339.0).abs() < 1_000.0,
            "Expected ~19,175,357,339 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_error_exceeds_block_limit() {
        let pricing = PreconfPricing::new();

        let incoming_gas = 21_000;
        let preconfirmed_gas = 30_000_001;

        let result = pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas);
        assert!(matches!(result, Err(PricingError::ExceedsBlockLimit(30_000_001, 30_000_000))));
    }

    #[test]
    fn test_error_insufficient_gas() {
        let pricing = PreconfPricing::new();

        let incoming_gas = 15_000_001;
        let preconfirmed_gas = 15_000_000;

        let result = pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas);
        assert!(matches!(
            result,
            Err(PricingError::InsufficientGas { requested: 15_000_001, available: 15_000_000 })
        ));
    }

    #[test]
    fn test_error_zero_incoming_gas() {
        let pricing = PreconfPricing::new();

        let incoming_gas = 0;
        let preconfirmed_gas = 0;

        let result = pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas);
        assert!(matches!(result, Err(PricingError::InvalidGasLimit { incoming_gas: 0 })));
    }
}
