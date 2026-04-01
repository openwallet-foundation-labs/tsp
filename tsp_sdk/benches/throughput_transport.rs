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
                let server_port = if scheme == "quic" {
                    pick_unused_udp_port()
                } else {
                    pick_unused_tcp_port()
                };
                let server = url(scheme, host, server_port);
                let mut incoming = tsp_sdk::transport::receive_messages(&server)
                    .await
                    .expect("receive_messages failed");

                let payload = bench_utils::seeded_bytes(
                    0x5452414E535F4F4Eu64 ^ payload_len as u64,
                    payload_len,
                );

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
                let elapsed = start.elapsed();
                elapsed
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
                let (server_port, client_port) = if scheme == "quic" {
                    (pick_unused_udp_port(), pick_unused_udp_port())
                } else {
                    (pick_unused_tcp_port(), pick_unused_tcp_port())
                };
                let server = url(scheme, host, server_port);
                let client = url(scheme, host, client_port);
                let mut server_incoming = tsp_sdk::transport::receive_messages(&server)
                    .await
                    .expect("server receive_messages failed");
                let mut client_incoming = tsp_sdk::transport::receive_messages(&client)
                    .await
                    .expect("client receive_messages failed");

                let request = bench_utils::seeded_bytes(
                    0x5452414E535F5254u64 ^ payload_len as u64,
                    payload_len,
                );

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
                let elapsed = start.elapsed();
                elapsed
            })
        });

        flush_failure_summary(&benchmark_id, &total_attempts, &total_failures);
    });
}

fn size_label(payload_len: usize) -> &'static str {
    match payload_len {
        1 => "1B",
        1024 => "1KiB",
        16_384 => "16KiB",
        _ => "custom",
    }
}

fn benches(c: &mut Criterion) {
    for payload_len in [1usize, 1024usize, 16 * 1024] {
        bench_oneway(c, "tcp", "127.0.0.1", payload_len);
        bench_roundtrip(c, "tcp", "127.0.0.1", payload_len);

        bench_oneway(c, "tls", "localhost", payload_len);
        bench_roundtrip(c, "tls", "localhost", payload_len);
    }

    // QUIC transport currently limits single-message size to 8KiB.
    for payload_len in [1usize, 1024usize] {
        bench_oneway(c, "quic", "localhost", payload_len);
        bench_roundtrip(c, "quic", "localhost", payload_len);
    }
}

criterion_group!(name = throughput_transport; config = criterion_config(); targets = benches);
criterion_main!(throughput_transport);
