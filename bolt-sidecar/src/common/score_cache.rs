use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

/// A cache that stores values with a score, and evicts the lowest scoring items once the cache
/// reaches a certain length.
///
/// To use when you need a map that periodically updates its values and requires a policy,
/// based on reads and insertion, to evicts elements that are not frequently used.
#[derive(Clone, Debug)]
pub struct LowestScoreCache<K, V> {
    // The hashmap that stores the values and their scores.
    map: HashMap<K, (V, usize)>,
    // The maximum length of the cache.
    max_len: usize,
    // The score bonus to apply when getting or inserting a new value.
    score_bonus: usize,
    // The score penalty to apply when updating a value
    score_penalty: usize,
}

impl<K: std::hash::Hash + Eq, V> LowestScoreCache<K, V> {
    // Create a new cache with the specified maximum length, score bump, and score penalty.
    pub fn new(max_len: usize, score_bump: usize, score_penalty: usize) -> Self {
        Self {
            map: HashMap::with_capacity(max_len),
            max_len,
            score_bonus: score_bump,
            score_penalty,
        }
    }

    // Get a value from the cache and bump its score.
    pub fn get_with_score_bump(&mut self, k: &K) -> Option<&V> {
        let bonus = self.score_bonus;
        self.get_mut(k).map(|(account, score)| {
            *score = score.saturating_add(bonus);
            // Return an immutable reference
            &*account
        })
    }

    // Insert a value into the cache with a starting score bump.
    pub fn insert_with_score_bump(&mut self, k: K, v: V) {
        self.clear_stales();
        self.map.insert(k, (v, self.score_bonus));
    }

    // Update a value in the cache with a score penalty.
    pub fn update_with_penalty(&mut self, k: &K, v: V) -> bool {
        let penalty = self.score_penalty;
        let Some((to_update, score)) = self.get_mut(k) else {
            return false;
        };
        *to_update = v;
        *score = score.saturating_sub(penalty);
        true
    }

    // Clear the stale values from the cache if there is any.
    fn clear_stales(&mut self) {
        let mut i = 0;
        while self.len() >= self.max_len {
            self.retain(|_, (_, score)| *score > i);
            i += 1;
        }
    }
}

impl<K, V> Deref for LowestScoreCache<K, V> {
    type Target = HashMap<K, (V, usize)>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<K, V> DerefMut for LowestScoreCache<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_SCORE_BUMP: usize = 1;
    const DEFAULT_SCORE_PENALTY: usize = 1;

    fn default_lowest_score_cache() -> LowestScoreCache<usize, String> {
        LowestScoreCache::new(2, DEFAULT_SCORE_BUMP, DEFAULT_SCORE_PENALTY)
    }

    #[test]
    fn test_score_logic() {
        let mut map = default_lowest_score_cache();

        map.insert_with_score_bump(1, "one".to_string());
        assert_eq!(map.get(&1), Some(&("one".to_string(), DEFAULT_SCORE_BUMP)));

        assert_eq!(map.get_with_score_bump(&1), Some(&"one".to_string()));
        assert_eq!(map.get(&1), Some(&("one".to_string(), DEFAULT_SCORE_BUMP * 2)));

        map.update_with_penalty(&1, "one".to_string());
        assert_eq!(
            map.get(&1),
            Some(&("one".to_string(), DEFAULT_SCORE_BUMP * 2 - DEFAULT_SCORE_PENALTY))
        );

        // Insert a new value and update it to set its score to zero.
        map.insert_with_score_bump(2, "two".to_string());
        for _ in 0..DEFAULT_SCORE_BUMP {
            map.update_with_penalty(&2, "two".to_string());
        }
        assert_eq!(map.get(&2), Some(&("two".to_string(), 0)));

        // Insert a new value: "2" should be dropped.
        map.insert_with_score_bump(3, "three".to_string());
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&2), None);
    }
}
