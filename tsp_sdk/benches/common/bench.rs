use std::hint::black_box;

use tsp_sdk::{
    ReceivedTspMessage, SecureStore, VerifiedVid,
    cesr::decode_envelope,
    crypto::{blake2b256, sha256},
    definitions::Payload,
    vid::{did::web::DidDocument, resolve::verify_vid_offline},
};

fn seeded_bytes(seed: u64, len: usize) -> Vec<u8> {
    use rand::{RngCore as _, SeedableRng as _};
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

pub fn fixture_owned_vid(path: &str) -> tsp_sdk::OwnedVid {
    let json = match path {
        "alice" => include_str!("../../../examples/test/alice/piv.json"),
        "bob" => include_str!("../../../examples/test/bob/piv.json"),
        _ => panic!("unknown fixture"),
    };
    serde_json::from_str(json).expect("fixture must deserialize as OwnedVid")
}

pub struct StoreCase {
    pub store: SecureStore,
    pub sender: String,
    pub receiver: String,
    pub payload: Vec<u8>,
}

pub fn setup_store(_benchmark_id: &'static str, payload_len: usize) -> StoreCase {
    let alice = fixture_owned_vid("alice");
    let bob = fixture_owned_vid("bob");

    let store = SecureStore::new();
    store.add_private_vid(alice.clone(), None).unwrap();
    store.add_private_vid(bob.clone(), None).unwrap();

    StoreCase {
        store,
        sender: alice.identifier().to_string(),
        receiver: bob.identifier().to_string(),
        payload: seeded_bytes(0x53544F52455F504Cu64 ^ payload_len as u64, payload_len),
    }
}

pub fn store_seal_open(case: &StoreCase) -> usize {
    let (_endpoint, mut sealed) = case
        .store
        .seal_message(&case.sender, &case.receiver, None, case.payload.as_slice())
        .unwrap();

    let opened = case.store.open_message(sealed.as_mut_slice()).unwrap();
    match opened {
        ReceivedTspMessage::GenericMessage { message, .. } => black_box(message.len()),
        _ => unreachable!("store.seal_open should produce a direct GenericMessage"),
    }
}

pub struct CryptoCase {
    pub alice: tsp_sdk::OwnedVid,
    pub bob: tsp_sdk::OwnedVid,
    pub payload: Vec<u8>,
}

pub fn setup_crypto(_benchmark_id: &'static str, payload_len: usize) -> CryptoCase {
    CryptoCase {
        alice: fixture_owned_vid("alice"),
        bob: fixture_owned_vid("bob"),
        payload: seeded_bytes(0x43525950544F5F50u64 ^ payload_len as u64, payload_len),
    }
}

pub fn crypto_seal_open(case: &CryptoCase) -> usize {
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

pub fn setup_digest_input(_benchmark_id: &'static str, payload_len: usize) -> Vec<u8> {
    seeded_bytes(0x4449474553545F50u64 ^ payload_len as u64, payload_len)
}

pub fn crypto_sha256(input: &[u8]) -> u8 {
    let out = sha256(black_box(input));
    black_box(out[0])
}

pub fn crypto_blake2b256(input: &[u8]) -> u8 {
    let out = blake2b256(black_box(input));
    black_box(out[0])
}

pub fn setup_cesr_fixture(_benchmark_id: &'static str, payload_len: usize) -> Vec<u8> {
    let alice = fixture_owned_vid("alice");
    let bob = fixture_owned_vid("bob");
    let payload = seeded_bytes(0x434553525F504C44u64 ^ payload_len as u64, payload_len);

    tsp_sdk::crypto::seal(&alice, &bob, None, Payload::Content(payload.as_slice())).unwrap()
}

pub fn cesr_decode_envelope(message: &mut [u8]) -> usize {
    let view = decode_envelope(message).unwrap();
    black_box(view.as_challenge().signed_data.len())
}

pub enum VidVerifyInput {
    DidPeer(String),
    DidWeb {
        did: String,
        doc_json: String,
    },
    DidWebvh {
        log_entry: didwebvh_rs::log_entry::LogEntry,
    },
}

fn setup_did_peer() -> VidVerifyInput {
    VidVerifyInput::DidPeer(
        "did:peer:2.Vz6MurhTjqX5uhQ5bJbAaoEwSDFcKDwVJTvoii51JBtSPpKzX.Ez6LbvBvy92yWENk8xKYmaX9X9nzMtQCQ2EqgdLKv2YkcpHo7.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0"
            .to_string(),
    )
}

fn setup_did_web() -> VidVerifyInput {
    let alice = fixture_owned_vid("alice");
    let did = alice.identifier().to_string();

    let doc_value = tsp_sdk::vid::did::web::vid_to_did_document(alice.vid());
    let doc_json = serde_json::to_string(&doc_value).unwrap();

    VidVerifyInput::DidWeb { did, doc_json }
}

fn setup_did_webvh() -> VidVerifyInput {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::{FixedOffset, TimeZone};
    use didwebvh_rs::{
        DIDWebVHState, affinidi_secrets_resolver::secrets::Secret, parameters::Parameters,
    };
    use serde_json::json;

    let alice = fixture_owned_vid("alice");

    let mut doc_value = tsp_sdk::vid::did::web::vid_to_did_document(alice.vid());
    doc_value["id"] = serde_json::Value::String("did:webvh:local:example".to_string());
    let did_doc: DidDocument = serde_json::from_value(doc_value).unwrap();

    let update_key = [7u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&update_key);
    let sigkey_private = signing_key.to_bytes().to_vec();
    let sigkey_public = signing_key.verifying_key().to_bytes();

    let mut webvh_signing_key = Secret::from_str(
        "webvh-signing-key",
        &json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": Base64UrlUnpadded::encode_string(&sigkey_public),
            "d": Base64UrlUnpadded::encode_string(&sigkey_private),
        }),
    )
    .unwrap();

    let webvh_signing_key_public = webvh_signing_key.get_public_keymultibase().unwrap();
    webvh_signing_key.id = [
        "did:key:",
        &webvh_signing_key_public,
        "#",
        &webvh_signing_key_public,
    ]
    .concat();

    let params = Parameters::new()
        .with_update_keys(vec![webvh_signing_key_public])
        .build();

    let mut webvh = DIDWebVHState::default();
    let did_doc_value = serde_json::to_value(&did_doc).unwrap();
    let fixed_time = FixedOffset::east_opt(0)
        .unwrap()
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap();
    let log_entry_state = webvh
        .create_log_entry(
            Some(fixed_time),
            &did_doc_value,
            &params,
            &webvh_signing_key,
        )
        .unwrap();

    VidVerifyInput::DidWebvh {
        log_entry: log_entry_state.log_entry.clone(),
    }
}

pub fn setup_vid_verify(benchmark_id: &'static str) -> VidVerifyInput {
    match benchmark_id {
        "guardrail.vid.verify.did_peer.offline" | "throughput.vid.verify.did_peer.offline" => {
            setup_did_peer()
        }
        "guardrail.vid.verify.did_web.local" | "throughput.vid.verify.did_web.local" => {
            setup_did_web()
        }
        "guardrail.vid.verify.did_webvh.local" | "throughput.vid.verify.did_webvh.local" => {
            setup_did_webvh()
        }
        other => panic!("unknown benchmark_id: {other}"),
    }
}

pub fn vid_verify(input: &VidVerifyInput) -> usize {
    match input {
        VidVerifyInput::DidPeer(did) => {
            let vid = verify_vid_offline(black_box(did)).unwrap();
            black_box(vid.identifier().len())
        }
        VidVerifyInput::DidWeb { did, doc_json } => {
            let did_doc: DidDocument = serde_json::from_str(doc_json).unwrap();
            let vid = tsp_sdk::vid::did::web::resolve_document(did_doc, did).unwrap();
            black_box(vid.identifier().len())
        }
        VidVerifyInput::DidWebvh { log_entry } => {
            use didwebvh_rs::log_entry::LogEntryMethods;
            let state = log_entry.get_state().to_owned();
            let did_doc: DidDocument = serde_json::from_value(state).unwrap();
            let did = did_doc.id.clone();
            let vid = tsp_sdk::vid::did::web::resolve_document(did_doc, &did).unwrap();
            black_box(vid.identifier().len())
        }
    }
}
