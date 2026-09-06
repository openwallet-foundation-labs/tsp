use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use criterion::{Criterion, criterion_group, criterion_main};
use futures::StreamExt as _;
use url::Url;

mod bench_utils;
#[path = "common/failure.rs"]
mod failure_common;
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
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .expect("failed to pick an unused tcp port")
}

fn pick_unused_udp_port() -> u16 {
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|socket| socket.local_addr())
        .map(|addr| addr.port())
        .expect("failed to pick an unused udp port")
}

fn url(scheme: &str, host: &str, port: u16) -> Url {
    Url::parse(&format!("{scheme}://{host}:{port}")).expect("failed to parse url")
}

/// Bind a receiver, retrying with a fresh port if the chosen one turns out to
/// be taken.
///
/// The probe binds an IPv4 address while a transport may bind another family:
/// `localhost` resolves to `::1` first, so a port that probes free on 127.0.0.1
/// can still be in use on ::1. QUIC hit this often enough to abort the run.
macro_rules! bind_receiver {
    ($scheme:expr, $host:expr, $what:expr) => {{
        let mut bound = None;
        for _ in 0..32 {
            let port = if $scheme == "quic" {
                pick_unused_udp_port()
            } else {
                pick_unused_tcp_port()
            };
            let candidate = url($scheme, $host, port);
            if let Ok(stream) = tsp_sdk::transport::receive_messages(&candidate).await {
                bound = Some((candidate, stream));
                break;
            }
        }
        bound.unwrap_or_else(|| panic!("{} receive_messages failed after 32 attempts", $what))
    }};
}

/// A genuine sealed TSP message carrying `payload_len` bytes of application
/// payload.
///
/// The transport benchmarks must send real CESR rather than random bytes. Code
/// on the send path that inspects the message rejects garbage immediately, so
/// its cost is invisible when the payload is noise: a debug formatter that ran
/// over every outgoing message went unnoticed here for exactly that reason,
/// while costing about 31 us/KiB in production. The sealed message is somewhat
/// larger than `payload_len`; the label names the application payload, which is
/// the quantity a caller controls.
fn sealed_message(payload_len: usize) -> Vec<u8> {
    use tsp_sdk::{OwnedVid, RelationshipStatus, SecureStore, VerifiedVid};

    let alice: OwnedVid = serde_json::from_str(include_str!("../../examples/test/alice/piv.json"))
        .expect("alice fixture must deserialize as OwnedVid");
    let bob: OwnedVid = serde_json::from_str(include_str!("../../examples/test/bob/piv.json"))
        .expect("bob fixture must deserialize as OwnedVid");

    let store = SecureStore::new();
    store
        .add_private_vid(alice.clone(), None)
        .expect("failed to add alice");
    store
        .add_private_vid(bob.clone(), None)
        .expect("failed to add bob");

    // application messages are only accepted within an established
    // relationship (spec 7.2.2); the benchmark measures the transport, not the
    // relationship forming that precedes it
    for (local, remote) in [(&alice, &bob), (&bob, &alice)] {
        store
            .set_relation_and_status_for_vid(
                remote.identifier(),
                RelationshipStatus::Bidirectional {
                    thread_id: [0x11; 32],
                    remote_thread_id: [0x22; 32],
                    outstanding_nested_requests: vec![],
                },
                local.identifier(),
            )
            .expect("failed to set relationship");
    }

    let payload =
        bench_utils::seeded_bytes(0x5452414E535F4D53u64 ^ payload_len as u64, payload_len);
    let (_endpoint, sealed) = store
        .seal_message(alice.identifier(), bob.identifier(), payload.as_slice())
        .expect("seal_message failed");

    sealed
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .without_plots()
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20)
}

fn bench_oneway(c: &mut Criterion, scheme: &'static str, host: &'static str, payload_len: usize) {
    let benchmark_id = format!(
        "throughput.transport.{scheme}.oneway.deliver.{}",
        size_label(payload_len)
    );

    c.bench_function(&benchmark_id, |b| {
        let runtime = tokio_rt::current_thread();
        let total_attempts = std::cell::Cell::new(0u64);
        let total_failures = std::cell::Cell::new(0u64);

        b.iter_custom(|iters| {
            runtime.block_on(async {
                let (server, mut incoming) = bind_receiver!(scheme, host, "server");

                let payload = sealed_message(payload_len);

                let start = Instant::now();
                let mut sample_attempts = 0u64;
                let mut sample_failures = 0u64;
                for _ in 0..iters {
                    sample_attempts += 1;
                    if let Err(error) =
                        tsp_sdk::transport::send_message(&server, payload.as_slice()).await
                    {
                        sample_failures += 1;
                        std::hint::black_box(error);
                        continue;
                    }

                    let Some(next_message) = incoming.next().await else {
                        sample_failures += 1;
                        std::hint::black_box("missing oneway recv item");
                        break;
                    };
                    let Ok(message) = next_message else {
                        sample_failures += 1;
                        std::hint::black_box(next_message.err());
                        continue;
                    };
                    std::hint::black_box(message.len());
                }
                merge_sample_counts(
                    &total_attempts,
                    &total_failures,
                    sample_attempts,
                    sample_failures,
                );
                start.elapsed()
            })
        });

        flush_failure_summary(&benchmark_id, &total_attempts, &total_failures);
    });
}

fn bench_roundtrip(
    c: &mut Criterion,
    scheme: &'static str,
    host: &'static str,
    payload_len: usize,
) {
    let benchmark_id = format!(
        "throughput.transport.{scheme}.roundtrip.echo.{}",
        size_label(payload_len)
    );

    c.bench_function(&benchmark_id, |b| {
        let runtime = tokio_rt::current_thread();
        let total_attempts = std::cell::Cell::new(0u64);
        let total_failures = std::cell::Cell::new(0u64);

        b.iter_custom(|iters| {
            runtime.block_on(async {
                let (server, mut server_incoming) = bind_receiver!(scheme, host, "server");
                let (client, mut client_incoming) = bind_receiver!(scheme, host, "client");

                let request = sealed_message(payload_len);

                let start = Instant::now();
                let mut sample_attempts = 0u64;
                let mut sample_failures = 0u64;
                for _ in 0..iters {
                    sample_attempts += 1;
                    if let Err(error) =
                        tsp_sdk::transport::send_message(&server, request.as_slice()).await
                    {
                        sample_failures += 1;
                        std::hint::black_box(error);
                        continue;
                    }

                    let Some(next_server_message) = server_incoming.next().await else {
                        sample_failures += 1;
                        std::hint::black_box("missing server recv item");
                        break;
                    };
                    let Ok(server_message) = next_server_message else {
                        sample_failures += 1;
                        std::hint::black_box(next_server_message.err());
                        continue;
                    };

                    if let Err(error) =
                        tsp_sdk::transport::send_message(&client, server_message.as_ref()).await
                    {
                        sample_failures += 1;
                        std::hint::black_box(error);
                        continue;
                    }

                    let Some(next_response) = client_incoming.next().await else {
                        sample_failures += 1;
                        std::hint::black_box("missing client recv item");
                        break;
                    };
                    let Ok(response) = next_response else {
                        sample_failures += 1;
                        std::hint::black_box(next_response.err());
                        continue;
                    };
                    std::hint::black_box(response.len());
                }
                merge_sample_counts(
                    &total_attempts,
                    &total_failures,
                    sample_attempts,
                    sample_failures,
                );
                start.elapsed()
            })
        });

        flush_failure_summary(&benchmark_id, &total_attempts, &total_failures);
    });
}

fn size_label(payload_len: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * KIB;
    if payload_len >= MIB && payload_len % MIB == 0 {
        format!("{}MiB", payload_len / MIB)
    } else if payload_len >= KIB && payload_len % KIB == 0 {
        format!("{}KiB", payload_len / KIB)
    } else {
        format!("{payload_len}B")
    }
}

/// Payload sizes to sweep, overridable with TSP_BENCH_SIZES as a
/// comma-separated list of byte counts.
fn sweep_sizes(default: &[usize]) -> Vec<usize> {
    match std::env::var("TSP_BENCH_SIZES") {
        Ok(spec) => spec
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .collect(),
        Err(_) => default.to_vec(),
    }
}

fn benches(c: &mut Criterion) {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * KIB;

    // The framed codec caps a message at 8 MiB, and a sealed message carries
    // overhead on top of the application payload, so 4 MiB is the largest
    // round size that fits.
    for payload_len in sweep_sizes(&[1, KIB, 16 * KIB, 64 * KIB, 256 * KIB, MIB, 4 * MIB]) {
        bench_oneway(c, "tcp", "127.0.0.1", payload_len);
        bench_roundtrip(c, "tcp", "127.0.0.1", payload_len);

        bench_oneway(c, "tls", "localhost", payload_len);
        bench_roundtrip(c, "tls", "localhost", payload_len);
    }

    for payload_len in sweep_sizes(&[1, KIB, 16 * KIB, 64 * KIB, 256 * KIB, MIB, 4 * MIB]) {
        bench_oneway(c, "quic", "localhost", payload_len);
        bench_roundtrip(c, "quic", "localhost", payload_len);
    }
}

criterion_group!(name = throughput_transport; config = criterion_config(); targets = benches);
criterion_main!(throughput_transport);
