#[cfg(any(feature = "nacl", not(feature = "pq")))]
fn main() {
    eprintln!(
        "`throughput_pq` is only meaningful when built with `pq` and without `nacl`.\n\
\n\
Run it with:\n\
  cargo bench -p tsp_sdk --bench throughput_pq --no-default-features --features pq,resolve\n"
    );
    std::process::exit(2);
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
use criterion::{Criterion, criterion_group, criterion_main};

#[cfg(all(feature = "pq", not(feature = "nacl")))]
mod bench_utils;

#[cfg(all(feature = "pq", not(feature = "nacl")))]
#[path = "common/criterion.rs"]
mod bench_criterion;

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
        payload: bench_utils::seeded_bytes(0x48504B455F50515Fu64 ^ payload_len as u64, payload_len),
    }
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
fn seal_open_hpke_pq(case: &SealOpenCase) -> usize {
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
        payload: bench_utils::seeded_bytes(0x4D4C44534136355Fu64 ^ payload_len as u64, payload_len),
    }
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
fn sign_verify_mldsa65(case: &SignVerifyCase) -> usize {
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
fn benches(c: &mut Criterion) {
    c.bench_function("throughput.crypto.seal_open.hpke_pq.direct.0B", |b| {
        let case = setup_seal_open("throughput.crypto.seal_open.hpke_pq.direct.0B", 0);
        b.iter(|| seal_open_hpke_pq(&case));
    });

    c.bench_function("throughput.crypto.seal_open.hpke_pq.direct.1KiB", |b| {
        let case = setup_seal_open("throughput.crypto.seal_open.hpke_pq.direct.1KiB", 1024);
        b.iter(|| seal_open_hpke_pq(&case));
    });

    c.bench_function("throughput.crypto.seal_open.hpke_pq.direct.16KiB", |b| {
        let case = setup_seal_open(
            "throughput.crypto.seal_open.hpke_pq.direct.16KiB",
            16 * 1024,
        );
        b.iter(|| seal_open_hpke_pq(&case));
    });

    c.bench_function("throughput.crypto.sign_verify.mldsa65.direct.0B", |b| {
        let case = setup_sign_verify("throughput.crypto.sign_verify.mldsa65.direct.0B", 0);
        b.iter(|| sign_verify_mldsa65(&case));
    });

    c.bench_function("throughput.crypto.sign_verify.mldsa65.direct.1KiB", |b| {
        let case = setup_sign_verify("throughput.crypto.sign_verify.mldsa65.direct.1KiB", 1024);
        b.iter(|| sign_verify_mldsa65(&case));
    });

    c.bench_function("throughput.crypto.sign_verify.mldsa65.direct.16KiB", |b| {
        let case = setup_sign_verify(
            "throughput.crypto.sign_verify.mldsa65.direct.16KiB",
            16 * 1024,
        );
        b.iter(|| sign_verify_mldsa65(&case));
    });
}

#[cfg(all(feature = "pq", not(feature = "nacl")))]
criterion_group!(name = throughput_pq; config = bench_criterion::default_config(); targets = benches);
#[cfg(all(feature = "pq", not(feature = "nacl")))]
criterion_main!(throughput_pq);
