use crate::{
    PrivateVid, VerifiedVid,
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

fn crypto_type(receiver: &dyn VerifiedVid) -> &'static str {
    match receiver.encryption_key_type() {
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
    }
}

fn print_key_types(prefix: &str, vid: &dyn VerifiedVid) {
    print_kv(
        &format!("{prefix}.signature_key_type"),
        match vid.signature_key_type() {
            VidSignatureKeyType::Ed25519 => "Ed25519",
            #[cfg(feature = "pq")]
            VidSignatureKeyType::MlDsa65 => "MlDsa65",
        },
    );
    print_kv(
        &format!("{prefix}.encryption_key_type"),
        match vid.encryption_key_type() {
            VidEncryptionKeyType::X25519 => "X25519",
            #[cfg(feature = "pq")]
            VidEncryptionKeyType::X25519Kyber768Draft00 => "X25519Kyber768Draft00",
        },
    );
}

fn print_public_keys(prefix: &str, vid: &dyn VerifiedVid) {
    print_binary(
        &format!("{prefix}.sign.public"),
        vid.verifying_key().as_ref(),
    );
    print_binary(
        &format!("{prefix}.enc.public"),
        vid.encryption_key().as_ref(),
    );
}

fn print_private_keys(prefix: &str, vid: &dyn PrivateVid) {
    print_binary(
        &format!("{prefix}.sign.private"),
        vid.signing_key().as_ref(),
    );
    print_binary(
        &format!("{prefix}.enc.private"),
        vid.decryption_key().as_ref(),
    );
}

pub(crate) fn print_outbound_pair(sender: &dyn PrivateVid, receiver: &dyn VerifiedVid) {
    if !mark_once(format!(
        "outbound-pair:{}->{}",
        sender.identifier(),
        receiver.identifier()
    )) {
        return;
    }

    print_kv("sender.did", sender.identifier());
    print_kv("receiver.did", receiver.identifier());
    print_kv("crypto.type", crypto_type(receiver));
    print_key_types("sender", sender);
    print_key_types("receiver", receiver);
    print_public_keys("sender", sender);
    print_private_keys("sender", sender);
    print_public_keys("receiver", receiver);
}

pub(crate) fn print_inbound_pair(sender: &dyn VerifiedVid, receiver: &dyn PrivateVid) {
    if !mark_once(format!(
        "inbound-pair:{}->{}",
        sender.identifier(),
        receiver.identifier()
    )) {
        return;
    }

    print_kv("received.sender.did", sender.identifier());
    print_kv("received.receiver.did", receiver.identifier());
    print_kv("received.crypto.type", crypto_type(receiver));
    print_key_types("received.sender", sender);
    print_key_types("received.receiver", receiver);
    print_public_keys("received.sender", sender);
    print_public_keys("received.receiver", receiver);
    print_private_keys("received.receiver", receiver);
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

pub(crate) fn print_received_relationship_request(
    sender: &dyn VerifiedVid,
    receiver: &dyn PrivateVid,
    thread_id: &Digest,
) {
    print_inbound_pair(sender, receiver);
    print_binary("received.rfi.thread_id", thread_id);
}

pub(crate) fn print_received_message(
    sender: &dyn VerifiedVid,
    receiver: &dyn PrivateVid,
    nonconfidential_data: Option<&[u8]>,
    message: &[u8],
) {
    print_inbound_pair(sender, receiver);
    print_kv(
        "received.message.plaintext",
        String::from_utf8_lossy(message),
    );
    if let Some(data) = nonconfidential_data {
        print_kv(
            "received.message.nonconfidential_data",
            String::from_utf8_lossy(data),
        );
    }
}
