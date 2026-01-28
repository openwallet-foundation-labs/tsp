pub fn seeded_bytes(seed: u64, len: usize) -> Vec<u8> {
    use rand::{RngCore as _, SeedableRng as _};
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

#[allow(dead_code)]
pub fn deterministic_owned_vid_ed25519_x25519(
    id: &str,
    transport: &str,
    seed: u64,
) -> tsp_sdk::OwnedVid {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use hpke::Kem as _;
    use hpke::Serializable as _;

    let mut sig_seed = [0u8; 32];
    sig_seed.copy_from_slice(&seeded_bytes(seed ^ 0x5349475F45443235u64, 32));
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sig_seed);
    let sigkey = signing_key.to_bytes();
    let public_sigkey = signing_key.verifying_key().to_bytes();

    let ikm = seeded_bytes(seed ^ 0x454E435F58323535u64, 32);
    let (enckey, public_enckey) = hpke::kem::X25519HkdfSha256::derive_keypair(ikm.as_slice());
    let enckey = enckey.to_bytes();
    let public_enckey = public_enckey.to_bytes();

    let json = serde_json::json!({
        "id": id,
        "transport": transport,
        "sigKeyType": "Ed25519",
        "publicSigkey": Base64UrlUnpadded::encode_string(public_sigkey.as_slice()),
        "sigkey": Base64UrlUnpadded::encode_string(sigkey.as_slice()),
        "encKeyType": "X25519",
        "publicEnckey": Base64UrlUnpadded::encode_string(public_enckey.as_slice()),
        "enckey": Base64UrlUnpadded::encode_string(enckey.as_slice()),
    })
    .to_string();

    serde_json::from_str(&json).expect("deterministic OwnedVid must deserialize")
}

#[cfg(feature = "pq")]
#[allow(dead_code)]
pub fn deterministic_owned_vid_mldsa65_x25519kyber768(
    id: &str,
    transport: &str,
    seed: u64,
) -> tsp_sdk::OwnedVid {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use hpke_pq::Kem as _;
    use hpke_pq::Serializable as _;
    use ml_dsa::{KeyGen, MlDsa65};

    use rand::SeedableRng as _;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed ^ 0x4D4C44534136355Fu64);
    let sig = MlDsa65::key_gen(&mut rng);
    let sigkey = sig.signing_key().encode();
    let public_sigkey = sig.verifying_key().encode();

    let ikm = seeded_bytes(seed ^ 0x454E435F4B594245u64, 32);
    let (enckey, public_enckey) =
        hpke_pq::kem::X25519Kyber768Draft00::derive_keypair(ikm.as_slice());
    let enckey = enckey.to_bytes();
    let public_enckey = public_enckey.to_bytes();

    let json = serde_json::json!({
        "id": id,
        "transport": transport,
        "sigKeyType": "MlDsa65",
        "publicSigkey": Base64UrlUnpadded::encode_string(public_sigkey.as_slice()),
        "sigkey": Base64UrlUnpadded::encode_string(sigkey.as_slice()),
        "encKeyType": "X25519Kyber768Draft00",
        "publicEnckey": Base64UrlUnpadded::encode_string(public_enckey.as_slice()),
        "enckey": Base64UrlUnpadded::encode_string(enckey.as_slice()),
    })
    .to_string();

    serde_json::from_str(&json).expect("deterministic PQ OwnedVid must deserialize")
}
