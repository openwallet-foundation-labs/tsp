#[cfg(any(feature = "nacl", not(feature = "pq")))]
fn main() {
    eprintln!(
        "`guardrail_pq` is only meaningful when built with `pq` and without `nacl`.\n\
\n\
Run it with:\n\
  cargo bench -p tsp_sdk --bench guardrail_pq --no-default-features --features pq,resolve\n"
    );
    std::process::exit(2);
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
use gungraun::{
    LibraryBenchmarkConfig, OutputFormat, library_benchmark, library_benchmark_group, main,
};
#[cfg(all(feature = "pq", not(feature = "nacl")))]
mod bench_utils;
#[cfg(all(feature = "pq", not(feature = "nacl")))]
use bench_utils::seeded_bytes;
#[cfg(all(feature = "pq", not(feature = "nacl")))]
use std::hint::black_box;
#[cfg(all(feature = "pq", not(feature = "nacl")))]
use tsp_sdk::{OwnedVid, definitions::Payload};

#[cfg(all(feature = "pq", not(feature = "nacl")))]
struct SealOpenCase {
    alice: OwnedVid,
    bob: OwnedVid,
    payload: Vec<u8>,
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
fn setup_seal_open(_benchmark_id: &'static str, payload_len: usize) -> SealOpenCase {
    let transport = "tcp://127.0.0.1:13371";
    SealOpenCase {
        alice: bench_utils::deterministic_owned_vid_mldsa65_x25519kyber768(
            "did:example:alice",
            transport,
            0x50515F414C494345u64,
        ),
        bob: bench_utils::deterministic_owned_vid_mldsa65_x25519kyber768(
            "did:example:bob",
            transport,
            0x50515F424F425F5Fu64,
        ),
        payload: seeded_bytes(0x48504B455F50515Fu64 ^ payload_len as u64, payload_len),
    }
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
#[library_benchmark]
#[bench::direct_0b(
    args = ("guardrail.crypto.seal_open.hpke_pq.direct.0B", 0),
    setup = setup_seal_open
)]
#[bench::direct_1kib(
    args = ("guardrail.crypto.seal_open.hpke_pq.direct.1KiB", 1024),
    setup = setup_seal_open
)]
#[bench::direct_16kib(
    args = ("guardrail.crypto.seal_open.hpke_pq.direct.16KiB", 16 * 1024),
    setup = setup_seal_open
)]
fn guardrail_crypto_seal_open_hpke_pq(case: SealOpenCase) -> usize {
    let mut sealed = tsp_sdk::crypto::seal(
        black_box(&case.alice),
        black_box(&case.bob),
        None,
        Payload::Content(case.payload.as_slice()),
    )
    .unwrap();

    let (_ncd, opened, _crypto_type, _sig_type) = tsp_sdk::crypto::open(
        black_box(&case.bob),
        black_box(&case.alice),
        sealed.as_mut_slice(),
    )
    .unwrap();

    black_box(opened.as_bytes().len())
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
struct SignVerifyCase {
    alice: OwnedVid,
    payload: Vec<u8>,
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
fn setup_sign_verify(_benchmark_id: &'static str, payload_len: usize) -> SignVerifyCase {
    SignVerifyCase {
        alice: bench_utils::deterministic_owned_vid_mldsa65_x25519kyber768(
            "did:example:alice",
            "tcp://127.0.0.1:13371",
            0x4D4C44534136355Fu64,
        ),
        payload: seeded_bytes(0x4D4C44534136355Fu64 ^ payload_len as u64, payload_len),
    }
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
#[library_benchmark]
#[bench::direct_0b(
    args = ("guardrail.crypto.sign_verify.mldsa65.direct.0B", 0),
    setup = setup_sign_verify
)]
#[bench::direct_1kib(
    args = ("guardrail.crypto.sign_verify.mldsa65.direct.1KiB", 1024),
    setup = setup_sign_verify
)]
#[bench::direct_16kib(
    args = ("guardrail.crypto.sign_verify.mldsa65.direct.16KiB", 16 * 1024),
    setup = setup_sign_verify
)]
fn guardrail_crypto_sign_verify_mldsa65(case: SignVerifyCase) -> usize {
    let mut signed = tsp_sdk::crypto::sign(
        black_box(&case.alice),
        None,
        black_box(case.payload.as_slice()),
    )
    .unwrap();

    let (payload, _msg_type) =
        tsp_sdk::crypto::verify(black_box(&case.alice), signed.as_mut_slice()).unwrap();

    black_box(payload.len())
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
library_benchmark_group!(
    name = guardrail_pq;
    benchmarks =
        guardrail_crypto_seal_open_hpke_pq,
        guardrail_crypto_sign_verify_mldsa65
);

#[cfg(all(feature = "pq", not(feature = "nacl")))]
main!(
    config = LibraryBenchmarkConfig::default().output_format({
        let mut output_format = OutputFormat::default();
        output_format.truncate_description(None);
        output_format
    });
    library_benchmark_groups = guardrail_pq
);
