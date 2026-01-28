#[cfg(any(feature = "nacl", feature = "pq"))]
fn main() {
    eprintln!(
        "`guardrail_hpke` is only meaningful when built without `nacl` and without `pq`.\n\
\n\
Run it with:\n\
  cargo bench -p tsp_sdk --bench guardrail_hpke --no-default-features --features resolve\n"
    );
    std::process::exit(2);
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
use iai_callgrind::{
    LibraryBenchmarkConfig, OutputFormat, library_benchmark, library_benchmark_group, main,
};
#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
mod bench_utils;
#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
use bench_utils::seeded_bytes;
#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
use std::hint::black_box;
#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
use tsp_sdk::{OwnedVid, definitions::Payload};

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
struct SealOpenCase {
    alice: OwnedVid,
    bob: OwnedVid,
    payload: Vec<u8>,
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
fn setup_seal_open(_benchmark_id: &'static str, payload_len: usize) -> SealOpenCase {
    let transport = "tcp://127.0.0.1:13371";
    SealOpenCase {
        alice: bench_utils::deterministic_owned_vid_ed25519_x25519(
            "did:example:alice",
            transport,
            0x48504B455F414C49u64,
        ),
        bob: bench_utils::deterministic_owned_vid_ed25519_x25519(
            "did:example:bob",
            transport,
            0x48504B455F424F42u64,
        ),
        payload: seeded_bytes(0x48504B455F504C44u64 ^ payload_len as u64, payload_len),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
#[library_benchmark]
#[bench::direct_1kib(
    args = ("guardrail.crypto.seal_open.hpke.direct.1KiB", 1024),
    setup = setup_seal_open
)]
#[bench::direct_16kib(
    args = ("guardrail.crypto.seal_open.hpke.direct.16KiB", 16 * 1024),
    setup = setup_seal_open
)]
fn guardrail_crypto_seal_open_hpke(case: SealOpenCase) -> usize {
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

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
struct SignVerifyCase {
    alice: OwnedVid,
    payload: Vec<u8>,
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
fn setup_sign_verify(_benchmark_id: &'static str, payload_len: usize) -> SignVerifyCase {
    SignVerifyCase {
        alice: bench_utils::deterministic_owned_vid_ed25519_x25519(
            "did:example:alice",
            "tcp://127.0.0.1:13371",
            0x454432353531395Fu64,
        ),
        payload: seeded_bytes(0x454432353531395Fu64 ^ payload_len as u64, payload_len),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
#[library_benchmark]
#[bench::direct_1kib(
    args = ("guardrail.crypto.sign_verify.ed25519.direct.1KiB", 1024),
    setup = setup_sign_verify
)]
#[bench::direct_16kib(
    args = ("guardrail.crypto.sign_verify.ed25519.direct.16KiB", 16 * 1024),
    setup = setup_sign_verify
)]
fn guardrail_crypto_sign_verify_ed25519(case: SignVerifyCase) -> usize {
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

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
library_benchmark_group!(
    name = guardrail_hpke;
    benchmarks =
        guardrail_crypto_seal_open_hpke,
        guardrail_crypto_sign_verify_ed25519
);

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
main!(
    config = LibraryBenchmarkConfig::default().output_format({
        let mut output_format = OutputFormat::default();
        output_format.truncate_description(None);
        output_format
    });
    library_benchmark_groups = guardrail_hpke
);
