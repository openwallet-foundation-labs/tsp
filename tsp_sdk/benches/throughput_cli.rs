use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use futures::StreamExt as _;
use url::Url;

use tsp_sdk::{
    AskarSecureStorage, AsyncSecureStore, OwnedVid, RelationshipStatus, SecureStorage, VerifiedVid,
};

#[path = "common/criterion.rs"]
mod bench_criterion;
mod bench_utils;
#[path = "common/failure.rs"]
mod failure_common;
#[path = "common/sqlite.rs"]
mod sqlite;
#[path = "common/tokio_rt.rs"]
mod tokio_rt;

fn merge_sample_counts(
    total_attempts: &std::cell::Cell<u64>,
    total_failures: &std::cell::Cell<u64>,
    sample_attempts: u64,
    sample_failures: u64,
) {
    total_attempts.set(total_attempts.get().saturating_add(sample_attempts));
    total_failures.set(total_failures.get().saturating_add(sample_failures));
}

fn flush_failure_summary(
    benchmark_id: &str,
    total_attempts: &std::cell::Cell<u64>,
    total_failures: &std::cell::Cell<u64>,
) {
    let attempts = total_attempts.get();
    let failures = total_failures.get();
    failure_common::write_failure_summary(benchmark_id, failures, attempts)
        .expect("failed to write failure summary");
    if failures > 0 {
        println!("bench={benchmark_id} failures={failures}/{attempts}");
    }
}

fn pick_unused_tcp_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .expect("failed to pick an unused tcp port")
}

fn tcp_url(host: &str, port: u16) -> Url {
    Url::parse(&format!("tcp://{host}:{port}")).expect("failed to parse tcp url")
}

fn fixture_owned_vid_with_transport(which: &str, transport: &Url) -> OwnedVid {
    let json = match which {
        "alice" => include_str!("../../examples/test/alice/piv.json"),
        "bob" => include_str!("../../examples/test/bob/piv.json"),
        _ => panic!("unknown fixture"),
    };
    let mut value: serde_json::Value = serde_json::from_str(json).expect("fixture json must parse");
    value["transport"] = serde_json::Value::String(transport.to_string());
    serde_json::from_str(&value.to_string()).expect("fixture must deserialize as OwnedVid")
}

fn relationship_bi_default() -> RelationshipStatus {
    RelationshipStatus::Bidirectional {
        thread_id: [0u8; 32],
        outstanding_nested_thread_ids: vec![],
    }
}

fn bench_send_receive_direct(c: &mut Criterion, backend: &'static str, payload_len: usize) {
    let id = format!(
        "throughput.cli.send_receive.direct.tcp.{backend}.{}",
        size_label(payload_len)
    );

    c.bench_function(&id, |b| {
        let runtime = tokio_rt::current_thread();
        let total_attempts = std::cell::Cell::new(0u64);
        let total_failures = std::cell::Cell::new(0u64);

        b.iter_custom(|iters| {
            runtime.block_on(async {
                let alice_transport = tcp_url("127.0.0.1", pick_unused_tcp_port());
                let bob_transport = tcp_url("127.0.0.1", pick_unused_tcp_port());

                let alice_vid = fixture_owned_vid_with_transport("alice", &alice_transport);
                let bob_vid = fixture_owned_vid_with_transport("bob", &bob_transport);

                let alice_id = alice_vid.identifier().to_string();
                let bob_id = bob_vid.identifier().to_string();

                let alice = AsyncSecureStore::new();
                let bob = AsyncSecureStore::new();

                alice.add_private_vid(alice_vid, None).unwrap();
                bob.add_private_vid(bob_vid, None).unwrap();

                alice
                    .add_verified_vid(
                        fixture_owned_vid_with_transport("bob", &bob_transport),
                        None,
                    )
                    .unwrap();
                bob.add_verified_vid(
                    fixture_owned_vid_with_transport("alice", &alice_transport),
                    None,
                )
                .unwrap();

                alice
                    .set_relation_and_status_for_vid(&bob_id, relationship_bi_default(), &alice_id)
                    .unwrap();
                bob.set_relation_and_status_for_vid(&alice_id, relationship_bi_default(), &bob_id)
                    .unwrap();

                let payload = bench_utils::seeded_bytes(
                    0x434C495F504C44u64 ^ payload_len as u64,
                    payload_len,
                );

                let (vault_alice, vault_bob) = if backend == "sqlite" {
                    let alice_db = sqlite::temp_url("tsp-cli-alice");
                    let bob_db = sqlite::temp_url("tsp-cli-bob");
                    let vault_alice = AskarSecureStorage::new(&alice_db, b"password")
                        .await
                        .unwrap();
                    let vault_bob = AskarSecureStorage::new(&bob_db, b"password").await.unwrap();
                    vault_alice.persist(alice.export().unwrap()).await.unwrap();
                    vault_bob.persist(bob.export().unwrap()).await.unwrap();
                    (Some(vault_alice), Some(vault_bob))
                } else {
                    (None, None)
                };

                let mut bob_incoming = tsp_sdk::transport::receive_messages(&bob_transport)
                    .await
                    .expect("bob receive_messages failed");

                let start = Instant::now();
                let mut sample_attempts = 0u64;
                let mut sample_failures = 0u64;
                for _ in 0..iters {
                    sample_attempts += 1;
                    let (_endpoint, message) = alice
                        .seal_message(&alice_id, &bob_id, None, payload.as_slice())
                        .unwrap();

                    if let Err(error) =
                        tsp_sdk::transport::send_message(&bob_transport, &message).await
                    {
                        sample_failures += 1;
                        std::hint::black_box(error);
                        continue;
                    }

                    let Some(sealed) = bob_incoming.next().await else {
                        sample_failures += 1;
                        std::hint::black_box("missing direct recv item");
                        break;
                    };
                    let Ok(sealed) = sealed else {
                        sample_failures += 1;
                        std::hint::black_box(sealed.err());
                        continue;
                    };
                    let mut sealed = sealed.to_vec();

                    let Ok(received) = bob.open_message(&mut sealed) else {
                        sample_failures += 1;
                        std::hint::black_box("open direct message failed");
                        continue;
                    };
                    let tsp_sdk::ReceivedTspMessage::GenericMessage {
                        receiver, message, ..
                    } = received
                    else {
                        sample_failures += 1;
                        std::hint::black_box(received);
                        continue;
                    };
                    debug_assert_eq!(receiver.as_deref(), Some(bob_id.as_str()));
                    std::hint::black_box(message.len());

                    if let (Some(vault_alice), Some(vault_bob)) = (&vault_alice, &vault_bob) {
                        vault_alice.persist(alice.export().unwrap()).await.unwrap();
                        vault_bob.persist(bob.export().unwrap()).await.unwrap();
                    }
                }
                merge_sample_counts(
                    &total_attempts,
                    &total_failures,
                    sample_attempts,
                    sample_failures,
                );
                let elapsed = start.elapsed();

                if let Some(vault_alice) = vault_alice {
                    let _ = vault_alice.destroy().await;
                }
                if let Some(vault_bob) = vault_bob {
                    let _ = vault_bob.destroy().await;
                }

                elapsed
            })
        });

        flush_failure_summary(&id, &total_attempts, &total_failures);
    });
}

fn bench_relationship_roundtrip(c: &mut Criterion, backend: &'static str) {
    let id = format!("throughput.cli.relationship.roundtrip.tcp.{backend}");
    c.bench_function(&id, |b| {
        let runtime = tokio_rt::current_thread();
        let total_attempts = std::cell::Cell::new(0u64);
        let total_failures = std::cell::Cell::new(0u64);

        b.iter_custom(|iters| {
            runtime.block_on(async {
                let alice_transport = tcp_url("127.0.0.1", pick_unused_tcp_port());
                let bob_transport = tcp_url("127.0.0.1", pick_unused_tcp_port());

                let alice_vid = fixture_owned_vid_with_transport("alice", &alice_transport);
                let bob_vid = fixture_owned_vid_with_transport("bob", &bob_transport);

                let alice_id = alice_vid.identifier().to_string();
                let bob_id = bob_vid.identifier().to_string();

                let alice = AsyncSecureStore::new();
                let bob = AsyncSecureStore::new();
                alice.add_private_vid(alice_vid, None).unwrap();
                bob.add_private_vid(bob_vid, None).unwrap();
                alice
                    .add_verified_vid(
                        fixture_owned_vid_with_transport("bob", &bob_transport),
                        None,
                    )
                    .unwrap();
                bob.add_verified_vid(
                    fixture_owned_vid_with_transport("alice", &alice_transport),
                    None,
                )
                .unwrap();

                let (vault_alice, vault_bob) = if backend == "sqlite" {
                    let alice_db = sqlite::temp_url("tsp-cli-alice-rel");
                    let bob_db = sqlite::temp_url("tsp-cli-bob-rel");
                    let vault_alice = AskarSecureStorage::new(&alice_db, b"password")
                        .await
                        .unwrap();
                    let vault_bob = AskarSecureStorage::new(&bob_db, b"password").await.unwrap();
                    vault_alice.persist(alice.export().unwrap()).await.unwrap();
                    vault_bob.persist(bob.export().unwrap()).await.unwrap();
                    (Some(vault_alice), Some(vault_bob))
                } else {
                    (None, None)
                };

                let mut bob_incoming = tsp_sdk::transport::receive_messages(&bob_transport)
                    .await
                    .expect("bob receive_messages failed");
                let mut alice_incoming = tsp_sdk::transport::receive_messages(&alice_transport)
                    .await
                    .expect("alice receive_messages failed");

                let start = Instant::now();
                let mut sample_attempts = 0u64;
                let mut sample_failures = 0u64;
                for _ in 0..iters {
                    sample_attempts += 1;
                    let (_endpoint, request_msg) = alice
                        .make_relationship_request(&alice_id, &bob_id, None)
                        .unwrap();
                    if let Err(error) =
                        tsp_sdk::transport::send_message(&bob_transport, &request_msg).await
                    {
                        sample_failures += 1;
                        std::hint::black_box(error);
                        continue;
                    }

                    let Some(sealed) = bob_incoming.next().await else {
                        sample_failures += 1;
                        std::hint::black_box("missing request recv item");
                        break;
                    };
                    let Ok(sealed) = sealed else {
                        sample_failures += 1;
                        std::hint::black_box(sealed.err());
                        continue;
                    };
                    let mut sealed = sealed.to_vec();
                    let Ok(received) = bob.open_message(&mut sealed) else {
                        sample_failures += 1;
                        std::hint::black_box("open relationship request failed");
                        continue;
                    };
                    let tsp_sdk::ReceivedTspMessage::RequestRelationship {
                        receiver,
                        thread_id,
                        ..
                    } = received
                    else {
                        sample_failures += 1;
                        std::hint::black_box(received);
                        continue;
                    };
                    debug_assert_eq!(receiver, bob_id);

                    let (_endpoint, accept_msg) = bob
                        .make_relationship_accept(&bob_id, &alice_id, thread_id, None)
                        .unwrap();
                    if let Err(error) =
                        tsp_sdk::transport::send_message(&alice_transport, &accept_msg).await
                    {
                        sample_failures += 1;
                        std::hint::black_box(error);
                        continue;
                    }

                    let Some(sealed) = alice_incoming.next().await else {
                        sample_failures += 1;
                        std::hint::black_box("missing accept recv item");
                        break;
                    };
                    let Ok(sealed) = sealed else {
                        sample_failures += 1;
                        std::hint::black_box(sealed.err());
                        continue;
                    };
                    let mut sealed = sealed.to_vec();
                    let Ok(received) = alice.open_message(&mut sealed) else {
                        sample_failures += 1;
                        std::hint::black_box("open relationship accept failed");
                        continue;
                    };
                    let tsp_sdk::ReceivedTspMessage::AcceptRelationship { receiver, .. } = received
                    else {
                        sample_failures += 1;
                        std::hint::black_box(received);
                        continue;
                    };
                    debug_assert_eq!(receiver, alice_id);

                    if let (Some(vault_alice), Some(vault_bob)) = (&vault_alice, &vault_bob) {
                        vault_alice.persist(alice.export().unwrap()).await.unwrap();
                        vault_bob.persist(bob.export().unwrap()).await.unwrap();
                    }
                }
                merge_sample_counts(
                    &total_attempts,
                    &total_failures,
                    sample_attempts,
                    sample_failures,
                );
                let elapsed = start.elapsed();

                if let Some(vault_alice) = vault_alice {
                    let _ = vault_alice.destroy().await;
                }
                if let Some(vault_bob) = vault_bob {
                    let _ = vault_bob.destroy().await;
                }

                elapsed
            })
        });

        flush_failure_summary(&id, &total_attempts, &total_failures);
    });
}

fn size_label(payload_len: usize) -> &'static str {
    match payload_len {
        0 => "0B",
        1024 => "1KiB",
        16_384 => "16KiB",
        _ => "custom",
    }
}

fn benches(c: &mut Criterion) {
    for payload_len in [0usize, 1024usize, 16 * 1024] {
        bench_send_receive_direct(c, "mem", payload_len);
        bench_send_receive_direct(c, "sqlite", payload_len);
    }

    bench_relationship_roundtrip(c, "mem");
    bench_relationship_roundtrip(c, "sqlite");
}

criterion_group!(name = throughput_cli; config = bench_criterion::default_config(); targets = benches);
criterion_main!(throughput_cli);
