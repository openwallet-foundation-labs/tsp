//! Against a real Google Cloud KMS key ring. Ignored unless run by hand with the ring and a
//! token in the environment:
//!
//!     TSP_KMS_KEYRING=projects/<p>/locations/<l>/keyRings/<r> \
//!     GCP_ACCESS_TOKEN=$(gcloud auth print-access-token) \
//!     cargo test -p tsp_sdk --features gcp-kms --test gcp_kms_live -- --ignored --nocapture
//!
//! Makes one key in the ring, which stays there: the grant does not destroy.
#![cfg(feature = "gcp-kms")]

use std::sync::Arc;
use tsp_sdk::{
    KeyType, SecureArea, SoftwareSecureArea,
    gcp_kms::{GcpKms, KmsSecureArea},
};

#[test]
#[ignore]
fn a_key_in_the_kms_signs_and_the_signature_verifies() {
    let ring = std::env::var("TSP_KMS_KEYRING").expect("TSP_KMS_KEYRING");
    let area = SoftwareSecureArea::new();
    area.attach_remote(Arc::new(KmsSecureArea::new(GcpKms::from_env(&ring))))
        .unwrap();

    let key = area.create_key(None, KeyType::Ed25519).unwrap();
    println!("made {} in the ring", key.alias);
    let signature = area.sign(&key.alias, b"signed in the KMS").unwrap();

    let vk =
        ed25519_dalek::VerifyingKey::from_bytes(&key.public.clone().try_into().unwrap()).unwrap();
    vk.verify_strict(
        b"signed in the KMS",
        &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
    )
    .unwrap();
    assert!(
        area.is_remote(&key.alias),
        "nothing of the key is in this process"
    );
    println!("the signature verifies against the public key the KMS reports");
}
