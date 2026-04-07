use crate::{
    PrivateVid,
    definitions::{Digest, VidEncryptionKeyType, VidSignatureKeyType},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::{
    collections::HashSet,
    sync::{Mutex, OnceLock},
};

fn seen_entries() -> &'static Mutex<HashSet<String>> {
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(HashSet::new()))
}

fn mark_once(key: String) -> bool {
    let mut seen = seen_entries()
        .lock()
        .expect("emit vector print lock poisoned");
    seen.insert(key)
}

fn print_kv(key: &str, value: impl AsRef<str>) {
    println!("TV: {key} = {}", value.as_ref());
}

pub(crate) fn print_binary(key: &str, bytes: &[u8]) {
    print_kv(key, Base64UrlUnpadded::encode_string(bytes));
}

pub(crate) fn print_outbound_pair(sender: &dyn PrivateVid, receiver: &dyn PrivateVid) {
    if !mark_once(format!(
        "pair:{}->{}",
        sender.identifier(),
        receiver.identifier()
    )) {
        return;
    }

    let crypto_type = match receiver.encryption_key_type() {
        #[cfg(feature = "nacl")]
        VidEncryptionKeyType::X25519 => {
            if cfg!(feature = "essr") {
                "nacl-essr"
            } else {
                "nacl-auth"
            }
        }
        #[cfg(not(feature = "nacl"))]
        VidEncryptionKeyType::X25519 => {
            if cfg!(feature = "essr") {
                "hpke-essr"
            } else {
                "hpke-auth"
            }
        }
        #[cfg(feature = "pq")]
        VidEncryptionKeyType::X25519Kyber768Draft00 => "x25519-kyber768draft00",
    };

    print_kv("sender.did", sender.identifier());
    print_kv("receiver.did", receiver.identifier());
    print_kv("crypto.type", crypto_type);
    print_kv(
        "sender.signature_key_type",
        match sender.signature_key_type() {
            VidSignatureKeyType::Ed25519 => "Ed25519",
            #[cfg(feature = "pq")]
            VidSignatureKeyType::MlDsa65 => "MlDsa65",
        },
    );
    print_kv(
        "sender.encryption_key_type",
        match sender.encryption_key_type() {
            VidEncryptionKeyType::X25519 => "X25519",
            #[cfg(feature = "pq")]
            VidEncryptionKeyType::X25519Kyber768Draft00 => "X25519Kyber768Draft00",
        },
    );
    print_kv(
        "receiver.signature_key_type",
        match receiver.signature_key_type() {
            VidSignatureKeyType::Ed25519 => "Ed25519",
            #[cfg(feature = "pq")]
            VidSignatureKeyType::MlDsa65 => "MlDsa65",
        },
    );
    print_kv(
        "receiver.encryption_key_type",
        match receiver.encryption_key_type() {
            VidEncryptionKeyType::X25519 => "X25519",
            #[cfg(feature = "pq")]
            VidEncryptionKeyType::X25519Kyber768Draft00 => "X25519Kyber768Draft00",
        },
    );
    print_binary("sender.sign.public", sender.verifying_key().as_ref());
    print_binary("sender.sign.private", sender.signing_key().as_ref());
    print_binary("sender.enc.public", sender.encryption_key().as_ref());
    print_binary("sender.enc.private", sender.decryption_key().as_ref());
    print_binary("receiver.sign.public", receiver.verifying_key().as_ref());
    print_binary("receiver.sign.private", receiver.signing_key().as_ref());
    print_binary("receiver.enc.public", receiver.encryption_key().as_ref());
    print_binary("receiver.enc.private", receiver.decryption_key().as_ref());
}

pub(crate) fn print_relationship_request_message(tsp_message: &[u8], thread_id: &Digest) {
    print_binary("rfi.message", tsp_message);
    print_binary("rfi.thread_id", thread_id);
}

pub(crate) fn print_sealed_message(
    nonconfidential_data: Option<&[u8]>,
    message: &[u8],
    tsp_message: &[u8],
) {
    print_kv("message.plaintext", String::from_utf8_lossy(message));
    if let Some(data) = nonconfidential_data {
        print_kv(
            "message.nonconfidential_data",
            String::from_utf8_lossy(data),
        );
    }
    print_binary("message.sealed", tsp_message);
}
