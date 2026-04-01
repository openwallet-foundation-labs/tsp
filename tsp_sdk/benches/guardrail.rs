use gungraun::{
    LibraryBenchmarkConfig, OutputFormat, library_benchmark, library_benchmark_group, main,
};
#[path = "common/bench.rs"]
mod bench_common;
mod bench_utils;

#[library_benchmark]
#[bench::direct_0b(
    args = ("guardrail.store.seal_open.direct.0B", 0),
    setup = bench_common::setup_store
)]
#[bench::direct_1kib(
    args = ("guardrail.store.seal_open.direct.1KiB", 1024),
    setup = bench_common::setup_store
)]
#[bench::direct_16kib(
    args = ("guardrail.store.seal_open.direct.16KiB", 16 * 1024),
    setup = bench_common::setup_store
)]
fn guardrail_store_seal_open(case: bench_common::StoreCase) -> usize {
    bench_common::store_seal_open(&case)
}

#[library_benchmark]
#[bench::direct_0b(
    args = ("guardrail.crypto.seal_open.direct.0B", 0),
    setup = bench_common::setup_crypto
)]
#[bench::direct_1kib(
    args = ("guardrail.crypto.seal_open.direct.1KiB", 1024),
    setup = bench_common::setup_crypto
)]
#[bench::direct_16kib(
    args = ("guardrail.crypto.seal_open.direct.16KiB", 16 * 1024),
    setup = bench_common::setup_crypto
)]
fn guardrail_crypto_seal_open(case: bench_common::CryptoCase) -> usize {
    bench_common::crypto_seal_open(&case)
}

#[library_benchmark]
#[bench::b0b(args = ("guardrail.crypto.digest.sha256.0B", 0), setup = bench_common::setup_digest_input)]
#[bench::b32b(args = ("guardrail.crypto.digest.sha256.32B", 32), setup = bench_common::setup_digest_input)]
#[bench::b1kib(args = ("guardrail.crypto.digest.sha256.1KiB", 1024), setup = bench_common::setup_digest_input)]
#[bench::b16kib(
    args = ("guardrail.crypto.digest.sha256.16KiB", 16 * 1024),
    setup = bench_common::setup_digest_input
)]
fn guardrail_crypto_sha256(input: Vec<u8>) -> u8 {
    bench_common::crypto_sha256(input.as_slice())
}

#[library_benchmark]
#[bench::b0b(
    args = ("guardrail.crypto.digest.blake2b256.0B", 0),
    setup = bench_common::setup_digest_input
)]
#[bench::b32b(
    args = ("guardrail.crypto.digest.blake2b256.32B", 32),
    setup = bench_common::setup_digest_input
)]
#[bench::b1kib(
    args = ("guardrail.crypto.digest.blake2b256.1KiB", 1024),
    setup = bench_common::setup_digest_input
)]
#[bench::b16kib(
    args = ("guardrail.crypto.digest.blake2b256.16KiB", 16 * 1024),
    setup = bench_common::setup_digest_input
)]
fn guardrail_crypto_blake2b256(input: Vec<u8>) -> u8 {
    bench_common::crypto_blake2b256(input.as_slice())
}

#[library_benchmark]
#[bench::b0b(
    args = ("guardrail.cesr.decode_envelope.0B", 0),
    setup = bench_common::setup_cesr_fixture
)]
#[bench::b1kib(
    args = ("guardrail.cesr.decode_envelope.1KiB", 1024),
    setup = bench_common::setup_cesr_fixture
)]
#[bench::b16kib(
    args = ("guardrail.cesr.decode_envelope.16KiB", 16 * 1024),
    setup = bench_common::setup_cesr_fixture
)]
fn guardrail_cesr_decode_envelope(mut message: Vec<u8>) -> usize {
    bench_common::cesr_decode_envelope(message.as_mut_slice())
}

#[library_benchmark]
#[bench::did_peer_offline(
    args = ("guardrail.vid.verify.did_peer.offline",),
    setup = bench_common::setup_vid_verify
)]
#[bench::did_web_local(args = ("guardrail.vid.verify.did_web.local",), setup = bench_common::setup_vid_verify)]
#[bench::did_webvh_local(
    args = ("guardrail.vid.verify.did_webvh.local",),
    setup = bench_common::setup_vid_verify
)]
fn guardrail_vid_verify(input: bench_common::VidVerifyInput) -> usize {
    bench_common::vid_verify(&input)
}

library_benchmark_group!(
    name = guardrail;
    benchmarks =
        guardrail_store_seal_open,
        guardrail_crypto_seal_open,
        guardrail_crypto_sha256,
        guardrail_crypto_blake2b256,
        guardrail_cesr_decode_envelope,
        guardrail_vid_verify
);

main!(
    config = LibraryBenchmarkConfig::default().output_format({
        let mut output_format = OutputFormat::default();
        output_format.truncate_description(None);
        output_format
    });
    library_benchmark_groups = guardrail
);
