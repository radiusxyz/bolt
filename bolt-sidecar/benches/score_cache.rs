use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use std::collections::HashMap;

use bolt_sidecar::common::score_cache::ScoreCache;

const GET_SCORE: isize = 1;
const INSERT_SCORE: isize = 2;
const UPDATE_SCORE: isize = 3;

fn bench_scorecache_vs_hashmap(c: &mut Criterion) {
    let mut group = c.benchmark_group("ScoreCache vs HashMap");

    let sizes = vec![1_000];
    for size in sizes {
        // Insert benchmark
        group.bench_function(format!("ScoreCache Insert -- size: {}", size), |b| {
            b.iter_batched(
                || create_score_cache(size),
                |mut score_cache| {
                    for i in 0..size {
                        score_cache.insert(i, i);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("HashMap Insert -- size: {}", size), |b| {
            b.iter_batched(
                || create_hashmap(size),
                |mut hash_map| {
                    for i in 0..size {
                        hash_map.insert(i, i);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // Get benchmark
        group.bench_function(format!("ScoreCache Get -- size: {}", size), |b| {
            b.iter_batched(
                || create_score_cache_filled(size),
                |mut score_cache| {
                    for i in 0..size {
                        let _ = black_box(score_cache.get(&i));
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("HashMap Get -- size: {}", size), |b| {
            b.iter_batched(
                || create_hashmap_filled(size),
                |hash_map| {
                    for i in 0..size {
                        let _ = black_box(hash_map.get(&i));
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // Update benchmark
        let mut score_cache = create_score_cache(size);
        for i in 0..size {
            score_cache.insert(i, i);
        }
        group.bench_function(format!("ScoreCache Update -- size: {}", size), |b| {
            b.iter_batched(
                || create_score_cache_filled(size),
                |mut score_cache| {
                    for i in 0..size {
                        if let Some(value) = score_cache.get_mut(&i) {
                            *value += 1;
                        }
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("HashMap Update -- size: {}", size), |b| {
            b.iter_batched(
                || create_hashmap_filled(size),
                |mut hash_map| {
                    for i in 0..size {
                        if let Some(value) = hash_map.get_mut(&i) {
                            *value += 1;
                        }
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
}

// Actual size is doubled so we're sure to not it more than 50% capacity
fn create_score_cache(
    size: usize,
) -> ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, usize, usize> {
    ScoreCache::with_capacity_and_len(size * 2, size * 2)
}

fn create_score_cache_filled(
    size: usize,
) -> ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, usize, usize> {
    let mut score_cache = ScoreCache::with_capacity_and_len(size * 2, size * 2);
    for i in 0..size {
        score_cache.insert(i, i);
    }
    score_cache
}

// Actual size is doubled so we're sure to not it more than 50% capacity
fn create_hashmap(size: usize) -> HashMap<usize, usize> {
    HashMap::with_capacity(size * 2)
}

fn create_hashmap_filled(size: usize) -> HashMap<usize, usize> {
    let mut hash_map = HashMap::with_capacity(size * 2);
    for i in 0..size {
        hash_map.insert(i, i);
    }
    hash_map
}

fn configure_criterion() -> Criterion {
    Criterion::default().measurement_time(std::time::Duration::from_secs(10)) // Increase to 10 seconds
}

criterion_group!(
    name = benches;
    config = configure_criterion();
    targets = bench_scorecache_vs_hashmap
);
criterion_main!(benches);
