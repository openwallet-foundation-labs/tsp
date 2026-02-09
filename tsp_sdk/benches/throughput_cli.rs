use std::time::Instant;

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use futures::{SinkExt as _, StreamExt as _};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use url::Url;

use tsp_sdk::{
    AskarSecureStorage, AsyncSecureStore, OwnedVid, RelationshipStatus, SecureStorage, VerifiedVid,
};

#[path = "common/criterion.rs"]
mod bench_criterion;
mod bench_utils;
#[path = "common/sqlite.rs"]
mod sqlite;
#[path = "common/tokio_rt.rs"]
mod tokio_rt;

fn tcp_url(host: &str, port: u16) -> Url {
    Url::parse(&format!("tcp://{host}:{port}")).expect("failed to parse tcp url")
}

fn length_delimited_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(2 * 1024 * 1024)
        .new_codec()
}

async fn bind_loopback_tcp() -> (TcpListener, Url) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("failed to bind loopback tcp listener");
    let addr = listener
        .local_addr()
        .expect("failed to read listener local addr");
    (listener, tcp_url("127.0.0.1", addr.port()))
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

        b.iter_custom(|iters| {
            runtime.block_on(async {
                // Only Bob needs to accept inbound TCP for this scenario.
                // Alice's transport is a metadata field; it is not dialed during this benchmark.
                let alice_transport = tcp_url("127.0.0.1", 18_080);
                let (bob_listener, bob_transport) = bind_loopback_tcp().await;

                let alice_vid = fixture_owned_vid_with_transport("alice", &alice_transport);
                let bob_vid = fixture_owned_vid_with_transport("bob", &bob_transport);

                let alice_id = alice_vid.identifier().to_string();
                let bob_id = bob_vid.identifier().to_string();

                let alice = AsyncSecureStore::new();
                let bob = AsyncSecureStore::new();

                alice.add_private_vid(alice_vid, None).unwrap();
                bob.add_private_vid(bob_vid, None).unwrap();

                // Add the peer VIDs (offline; no network).
                // Using OwnedVid as VerifiedVid is fine here: it is stored as VerifiedVid only.
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

                // Force an established relationship to avoid measuring handshake noise.
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

                let ack_sem = std::sync::Arc::new(Semaphore::new(0));
                let bob_for_server = bob.clone();
                let bob_id_for_server = bob_id.clone();
                let ack_sem_for_server = ack_sem.clone();
                let server = tokio::spawn(async move {
                    let (stream, _) = bob_listener.accept().await.expect("accept failed");
                    let mut framed = FramedRead::new(stream, length_delimited_codec());
                    while let Some(frame) = framed.next().await {
                        let bytes = frame.expect("tcp read failed");
                        let mut message = bytes.to_vec();
                        let received = bob_for_server
                            .open_message(&mut message)
                            .expect("open_message failed");
                        match received {
                            tsp_sdk::ReceivedTspMessage::GenericMessage {
                                receiver,
                                message,
                                ..
                            } => {
                                debug_assert_eq!(
                                    receiver.as_deref(),
                                    Some(bob_id_for_server.as_str())
                                );
                                std::hint::black_box(message.len());
                            }
                            other => panic!("unexpected message kind: {other:?}"),
                        }
                        ack_sem_for_server.add_permits(1);
                    }
                });

                let client = tokio::net::TcpStream::connect((
                    "127.0.0.1",
                    bob_transport.port().expect("tcp url must have port"),
                ))
                .await
                .expect("connect failed");
                let mut framed_out = FramedWrite::new(client, length_delimited_codec());

                let start = Instant::now();
                for _ in 0..iters {
                    let (_endpoint, message) = alice
                        .seal_message(&alice_id, &bob_id, None, payload.as_slice())
                        .unwrap();
                    framed_out
                        .send(Bytes::from(message))
                        .await
                        .expect("tcp send failed");
                    ack_sem
                        .acquire()
                        .await
                        .expect("ack semaphore acquire failed")
                        .forget();

                    if let (Some(vault_alice), Some(vault_bob)) = (&vault_alice, &vault_bob) {
                        vault_alice.persist(alice.export().unwrap()).await.unwrap();
                        vault_bob.persist(bob.export().unwrap()).await.unwrap();
                    }
                }
                let elapsed = start.elapsed();

                if let Some(vault_alice) = vault_alice {
                    vault_alice.destroy().await.unwrap();
                }
                if let Some(vault_bob) = vault_bob {
                    vault_bob.destroy().await.unwrap();
                }

                drop(framed_out);
                server.await.expect("server task failed");

                elapsed
            })
        });
    });
}

fn bench_relationship_roundtrip(c: &mut Criterion, backend: &'static str) {
    let id = format!("throughput.cli.relationship.roundtrip.tcp.{backend}");
    c.bench_function(&id, |b| {
        let runtime = tokio_rt::current_thread();

        b.iter_custom(|iters| {
            runtime.block_on(async {
                let (alice_listener, alice_transport) = bind_loopback_tcp().await;
                let (bob_listener, bob_transport) = bind_loopback_tcp().await;

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

                let (req_tx, mut req_rx) =
                    tokio::sync::mpsc::channel::<tsp_sdk::definitions::Digest>(1);
                let bob_for_server = bob.clone();
                let bob_id_for_server = bob_id.clone();
                let bob_server = tokio::spawn(async move {
                    let (stream, _) = bob_listener.accept().await.expect("accept failed");
                    let mut framed = FramedRead::new(stream, length_delimited_codec());
                    while let Some(frame) = framed.next().await {
                        let bytes = frame.expect("tcp read failed");
                        let mut message = bytes.to_vec();
                        let received = bob_for_server
                            .open_message(&mut message)
                            .expect("open_message failed");
                        match received {
                            tsp_sdk::ReceivedTspMessage::RequestRelationship {
                                receiver,
                                thread_id,
                                ..
                            } => {
                                debug_assert_eq!(receiver, bob_id_for_server);
                                let _ = req_tx.send(thread_id).await;
                            }
                            other => panic!("unexpected message kind: {other:?}"),
                        }
                    }
                });

                let accept_sem = std::sync::Arc::new(Semaphore::new(0));
                let alice_for_server = alice.clone();
                let alice_id_for_server = alice_id.clone();
                let accept_sem_for_server = accept_sem.clone();
                let alice_server = tokio::spawn(async move {
                    let (stream, _) = alice_listener.accept().await.expect("accept failed");
                    let mut framed = FramedRead::new(stream, length_delimited_codec());
                    while let Some(frame) = framed.next().await {
                        let bytes = frame.expect("tcp read failed");
                        let mut message = bytes.to_vec();
                        let received = alice_for_server
                            .open_message(&mut message)
                            .expect("open_message failed");
                        match received {
                            tsp_sdk::ReceivedTspMessage::AcceptRelationship {
                                receiver, ..
                            } => {
                                debug_assert_eq!(receiver, alice_id_for_server);
                                accept_sem_for_server.add_permits(1);
                            }
                            other => panic!("unexpected message kind: {other:?}"),
                        }
                    }
                });

                let alice_to_bob = tokio::net::TcpStream::connect((
                    "127.0.0.1",
                    bob_transport.port().expect("tcp url must have port"),
                ))
                .await
                .expect("connect failed");
                let mut alice_out = FramedWrite::new(alice_to_bob, length_delimited_codec());

                let bob_to_alice = tokio::net::TcpStream::connect((
                    "127.0.0.1",
                    alice_transport.port().expect("tcp url must have port"),
                ))
                .await
                .expect("connect failed");
                let mut bob_out = FramedWrite::new(bob_to_alice, length_delimited_codec());

                let start = Instant::now();
                for _ in 0..iters {
                    let (_endpoint, msg) = alice
                        .make_relationship_request(&alice_id, &bob_id, None)
                        .unwrap();
                    alice_out
                        .send(Bytes::from(msg))
                        .await
                        .expect("tcp send failed");
                    let thread_id = req_rx.recv().await.expect("request missing");

                    let (_endpoint, msg) = bob
                        .make_relationship_accept(&bob_id, &alice_id, thread_id, None)
                        .unwrap();
                    bob_out
                        .send(Bytes::from(msg))
                        .await
                        .expect("tcp send failed");
                    accept_sem
                        .acquire()
                        .await
                        .expect("accept semaphore acquire failed")
                        .forget();

                    if let (Some(vault_alice), Some(vault_bob)) = (&vault_alice, &vault_bob) {
                        vault_alice.persist(alice.export().unwrap()).await.unwrap();
                        vault_bob.persist(bob.export().unwrap()).await.unwrap();
                    }
                }
                let elapsed = start.elapsed();

                if let Some(vault_alice) = vault_alice {
                    vault_alice.destroy().await.unwrap();
                }
                if let Some(vault_bob) = vault_bob {
                    vault_bob.destroy().await.unwrap();
                }

                drop(alice_out);
                drop(bob_out);
                bob_server.await.expect("server task failed");
                alice_server.await.expect("server task failed");

                elapsed
            })
        });
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
