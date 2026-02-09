#[cfg(any(feature = "nacl", feature = "pq"))]
fn main() {
    eprintln!(
        "`throughput_hpke` is only meaningful when built without `nacl` and without `pq`.\n\
\n\
Run it with:\n\
  cargo bench -p tsp_sdk --bench throughput_hpke --no-default-features --features resolve\n"
    );
    std::process::exit(2);
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
use criterion::{Criterion, criterion_group, criterion_main};

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
mod bench_utils;

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
#[path = "common/criterion.rs"]
mod bench_criterion;

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
fn setup_seal_open(benchmark_id: &'static str, payload_len: usize) -> SealOpenCase {
    let _ = benchmark_id;
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
        payload: bench_utils::seeded_bytes(0x48504B455F504C44u64 ^ payload_len as u64, payload_len),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
fn seal_open_hpke(case: &SealOpenCase) -> usize {
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
        payload: bench_utils::seeded_bytes(0x454432353531395Fu64 ^ payload_len as u64, payload_len),
    }
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
fn sign_verify_ed25519(case: &SignVerifyCase) -> usize {
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
fn benches(c: &mut Criterion) {
    c.bench_function("throughput.crypto.seal_open.hpke.direct.0B", |b| {
        let case = setup_seal_open("throughput.crypto.seal_open.hpke.direct.0B", 0);
        b.iter(|| seal_open_hpke(&case));
    });

    c.bench_function("throughput.crypto.seal_open.hpke.direct.1KiB", |b| {
        let case = setup_seal_open("throughput.crypto.seal_open.hpke.direct.1KiB", 1024);
        b.iter(|| seal_open_hpke(&case));
    });

    c.bench_function("throughput.crypto.seal_open.hpke.direct.16KiB", |b| {
        let case = setup_seal_open("throughput.crypto.seal_open.hpke.direct.16KiB", 16 * 1024);
        b.iter(|| seal_open_hpke(&case));
    });

    c.bench_function("throughput.crypto.sign_verify.ed25519.direct.0B", |b| {
        let case = setup_sign_verify("throughput.crypto.sign_verify.ed25519.direct.0B", 0);
        b.iter(|| sign_verify_ed25519(&case));
    });

    c.bench_function("throughput.crypto.sign_verify.ed25519.direct.1KiB", |b| {
        let case = setup_sign_verify("throughput.crypto.sign_verify.ed25519.direct.1KiB", 1024);
        b.iter(|| sign_verify_ed25519(&case));
    });

    c.bench_function("throughput.crypto.sign_verify.ed25519.direct.16KiB", |b| {
        let case = setup_sign_verify(
            "throughput.crypto.sign_verify.ed25519.direct.16KiB",
            16 * 1024,
        );
        b.iter(|| sign_verify_ed25519(&case));
    });
}

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
criterion_group!(name = throughput_hpke; config = bench_criterion::default_config(); targets = benches);
#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
criterion_main!(throughput_hpke);
