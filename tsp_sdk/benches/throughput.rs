use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

#[path = "common/bench.rs"]
mod bench_common;
#[path = "common/criterion.rs"]
mod bench_criterion;
mod bench_utils;

fn benches(c: &mut Criterion) {
    c.bench_function("throughput.store.seal_open.direct.0B", |b| {
        let case = bench_common::setup_store("throughput.store.seal_open.direct.0B", 0);
        b.iter(|| bench_common::store_seal_open(&case));
    });

    c.bench_function("throughput.store.seal_open.direct.1KiB", |b| {
        let case = bench_common::setup_store("throughput.store.seal_open.direct.1KiB", 1024);
        b.iter(|| bench_common::store_seal_open(&case));
    });

    c.bench_function("throughput.store.seal_open.direct.16KiB", |b| {
        let case = bench_common::setup_store("throughput.store.seal_open.direct.16KiB", 16 * 1024);
        b.iter(|| bench_common::store_seal_open(&case));
    });

    c.bench_function("throughput.crypto.seal_open.direct.0B", |b| {
        let case = bench_common::setup_crypto("throughput.crypto.seal_open.direct.0B", 0);
        b.iter(|| bench_common::crypto_seal_open(&case));
    });

    c.bench_function("throughput.crypto.seal_open.direct.1KiB", |b| {
        let case = bench_common::setup_crypto("throughput.crypto.seal_open.direct.1KiB", 1024);
        b.iter(|| bench_common::crypto_seal_open(&case));
    });

    c.bench_function("throughput.crypto.seal_open.direct.16KiB", |b| {
        let case =
            bench_common::setup_crypto("throughput.crypto.seal_open.direct.16KiB", 16 * 1024);
        b.iter(|| bench_common::crypto_seal_open(&case));
    });

    c.bench_function("throughput.crypto.digest.sha256.0B", |b| {
        let input = bench_common::setup_digest_input("throughput.crypto.digest.sha256.0B", 0);
        b.iter(|| bench_common::crypto_sha256(input.as_slice()));
    });

    c.bench_function("throughput.crypto.digest.sha256.32B", |b| {
        let input = bench_common::setup_digest_input("throughput.crypto.digest.sha256.32B", 32);
        b.iter(|| bench_common::crypto_sha256(input.as_slice()));
    });

    c.bench_function("throughput.crypto.digest.sha256.1KiB", |b| {
        let input = bench_common::setup_digest_input("throughput.crypto.digest.sha256.1KiB", 1024);
        b.iter(|| bench_common::crypto_sha256(input.as_slice()));
    });

    c.bench_function("throughput.crypto.digest.sha256.16KiB", |b| {
        let input =
            bench_common::setup_digest_input("throughput.crypto.digest.sha256.16KiB", 16 * 1024);
        b.iter(|| bench_common::crypto_sha256(input.as_slice()));
    });

    c.bench_function("throughput.crypto.digest.blake2b256.0B", |b| {
        let input = bench_common::setup_digest_input("throughput.crypto.digest.blake2b256.0B", 0);
        b.iter(|| bench_common::crypto_blake2b256(input.as_slice()));
    });

    c.bench_function("throughput.crypto.digest.blake2b256.32B", |b| {
        let input = bench_common::setup_digest_input("throughput.crypto.digest.blake2b256.32B", 32);
        b.iter(|| bench_common::crypto_blake2b256(input.as_slice()));
    });

    c.bench_function("throughput.crypto.digest.blake2b256.1KiB", |b| {
        let input =
            bench_common::setup_digest_input("throughput.crypto.digest.blake2b256.1KiB", 1024);
        b.iter(|| bench_common::crypto_blake2b256(input.as_slice()));
    });

    c.bench_function("throughput.crypto.digest.blake2b256.16KiB", |b| {
        let input = bench_common::setup_digest_input(
            "throughput.crypto.digest.blake2b256.16KiB",
            16 * 1024,
        );
        b.iter(|| bench_common::crypto_blake2b256(input.as_slice()));
    });

    c.bench_function("throughput.cesr.decode_envelope.0B", |b| {
        let message = bench_common::setup_cesr_fixture("throughput.cesr.decode_envelope.0B", 0);
        b.iter_batched(
            || message.clone(),
            |mut msg| bench_common::cesr_decode_envelope(msg.as_mut_slice()),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("throughput.cesr.decode_envelope.1KiB", |b| {
        let message =
            bench_common::setup_cesr_fixture("throughput.cesr.decode_envelope.1KiB", 1024);
        b.iter_batched(
            || message.clone(),
            |mut msg| bench_common::cesr_decode_envelope(msg.as_mut_slice()),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("throughput.cesr.decode_envelope.16KiB", |b| {
        let message =
            bench_common::setup_cesr_fixture("throughput.cesr.decode_envelope.16KiB", 16 * 1024);
        b.iter_batched(
            || message.clone(),
            |mut msg| bench_common::cesr_decode_envelope(msg.as_mut_slice()),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("throughput.vid.verify.did_peer.offline", |b| {
        let input = bench_common::setup_vid_verify("throughput.vid.verify.did_peer.offline");
        b.iter(|| bench_common::vid_verify(&input));
    });

    c.bench_function("throughput.vid.verify.did_web.local", |b| {
        let input = bench_common::setup_vid_verify("throughput.vid.verify.did_web.local");
        b.iter(|| bench_common::vid_verify(&input));
    });

    c.bench_function("throughput.vid.verify.did_webvh.local", |b| {
        let input = bench_common::setup_vid_verify("throughput.vid.verify.did_webvh.local");
        b.iter(|| bench_common::vid_verify(&input));
    });
}

criterion_group!(name = throughput; config = bench_criterion::default_config(); targets = benches);
criterion_main!(throughput);
