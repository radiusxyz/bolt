use std::ops::{Deref, DerefMut};

use alloy::primitives::Address;

use crate::{common::score_cache::ScoreCache, primitives::AccountState, telemetry::ApiMetrics};

const GET_SCORE: isize = 4;
const INSERT_SCORE: isize = 4;
const UPDATE_SCORE: isize = -1;

/// A scored cache for account states.
#[derive(Debug, Default)]
pub struct AccountStateCache(
    pub ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, Address, AccountState>,
);

impl Deref for AccountStateCache {
    type Target = ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, Address, AccountState>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AccountStateCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AccountStateCache {
    /// Insert an account state into the cache, and update the metrics.
    pub fn insert(&mut self, address: Address, account_state: AccountState) {
        ApiMetrics::set_account_states(self.len());
        self.0.insert(address, account_state);
    }
}
