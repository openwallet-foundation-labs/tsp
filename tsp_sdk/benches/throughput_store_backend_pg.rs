use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};

use tsp_sdk::{AskarSecureStorage, OwnedVid, SecureStorage, SecureStore};

#[path = "common/criterion.rs"]
mod bench_criterion;
#[path = "common/tokio_rt.rs"]
mod tokio_rt;

fn wallet_2vid() -> SecureStore {
    let store = SecureStore::new();
    let alice = OwnedVid::new_did_peer("tcp://127.0.0.1:31001".parse().unwrap());
    let bob = OwnedVid::new_did_peer("tcp://127.0.0.1:31002".parse().unwrap());
    store
        .add_private_vid(alice, None::<serde_json::Value>)
        .unwrap();
    store
        .add_private_vid(bob, None::<serde_json::Value>)
        .unwrap();
    store
}

fn benches(c: &mut Criterion) {
    let Ok(url) = std::env::var("TSP_BENCH_PG_URL") else {
        return;
    };

    c.bench_function(
        "throughput.store.backend.askar.postgres.persist.wallet_2vid",
        |b| {
            let runtime = tokio_rt::current_thread();

            b.iter_custom(|iters| {
                runtime.block_on(async {
                    let vault = AskarSecureStorage::open(&url, b"password").await.unwrap();
                    let store = wallet_2vid();
                    let export = store.export().unwrap();

                    let start = Instant::now();
                    for _ in 0..iters {
                        vault.persist(export.clone()).await.unwrap();
                    }
                    let elapsed = start.elapsed();

                    vault.close().await.unwrap();
                    elapsed
                })
            });
        },
    );

    c.bench_function(
        "throughput.store.backend.askar.postgres.read.wallet_2vid",
        |b| {
            let runtime = tokio_rt::current_thread();

            b.iter_custom(|iters| {
                runtime.block_on(async {
                    let vault = AskarSecureStorage::open(&url, b"password").await.unwrap();
                    let store = wallet_2vid();
                    vault.persist(store.export().unwrap()).await.unwrap();

                    let start = Instant::now();
                    for _ in 0..iters {
                        let (vids, _aliases, _keys) = vault.read().await.unwrap();
                        std::hint::black_box(vids.len());
                    }
                    let elapsed = start.elapsed();

                    vault.close().await.unwrap();
                    elapsed
                })
            });
        },
    );
}

criterion_group!(name = throughput_store_backend_pg; config = bench_criterion::default_config(); targets = benches);
criterion_main!(throughput_store_backend_pg);
