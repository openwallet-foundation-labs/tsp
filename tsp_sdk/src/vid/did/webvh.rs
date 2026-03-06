use crate::{
    OwnedVid, Vid,
    vid::{
        VidError,
        did::web::{DidDocument, resolve_document},
        vid_to_did_document,
    },
};
use base64ct::{Base64UrlUnpadded, Encoding};
use didwebvh_rs::{
    DIDWebVHState,
    affinidi_secrets_resolver::secrets::Secret,
    log_entry::{LogEntry, LogEntryMethods, MetaData},
    parameters::Parameters,
    url::WebVHURL,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

pub(crate) const SCHEME: &str = "webvh";

#[derive(Debug, Serialize, Deserialize)]
pub struct WebvhMetadata {
    pub webvh_meta_data: MetaData,
    pub update_keys: Option<Vec<String>>,
    /// Hash of the next update key (if precommit is active)
    pub next_key_hashes: Option<Vec<String>>,
}

/// Keys returned from create_webvh for storage
#[derive(Debug, Clone)]
pub struct WebvhKeys {
    /// Current update key ID (multibase public key)
    pub update_kid: String,
    /// Current update key (32 bytes private)
    pub update_key: Vec<u8>,
    /// Next update key ID (committed in genesis via next_key_hashes)
    pub next_update_kid: String,
    /// Next update key (32 bytes private, for future rotation)
    pub next_update_key: Vec<u8>,
}

/// Result of an update operation
#[derive(Debug, Clone)]
pub struct UpdateResult {
    /// The new log entry to publish
    pub log_entry: LogEntry,
    /// New current update key ID (the key that signed this entry)
    pub current_update_kid: String,
    /// New next update key ID (committed in this entry)
    pub next_update_kid: String,
    /// New next update key (32 bytes private)
    pub next_update_key: Vec<u8>,
}

/// Returns the Vid and [`WebvhMetadata`] for the given `id`.
pub async fn resolve(id: &str) -> Result<(Vid, serde_json::Value), VidError> {
    let mut webvh = DIDWebVHState::default();

    let (log_entry, meta_data) = webvh.resolve(id, None).await?;
    let did_doc: DidDocument = serde_json::from_value(log_entry.get_state().to_owned())?;

    let params = log_entry.get_parameters();

    let update_keys = params.update_keys.as_ref().map(|keys| (**keys).clone());

    let next_key_hashes = params
        .next_key_hashes
        .as_ref()
        .map(|hashes| (**hashes).clone());

    let metadata = WebvhMetadata {
        webvh_meta_data: meta_data,
        update_keys,
        next_key_hashes,
    };

    Ok((
        resolve_document(did_doc, id)?,
        serde_json::to_value(&metadata)?,
    ))
}

/// Creates a default WebVH DID that can be used with TSP.
/// did_path: Server path to use as the base for the DID ID (expects this to be server.name/path)
/// transport: URL to use for the service record
///
/// # Returns
/// * VID Record - contains key info
/// * The Genesis Log Entry record for WebVH DID's
/// * WebvhKeys containing current and next update keys (for precommit support)
pub async fn create_webvh(
    did_path: &str,
    transport: Url,
) -> Result<(OwnedVid, serde_json::Value, WebvhKeys), VidError> {
    // Create the initial DID ID
    let path_url = Url::parse(&["http://", did_path].concat())?;
    let webvh_url = WebVHURL::parse_url(&path_url)?;

    // Create default TSP VID
    let mut vid = OwnedVid::bind(webvh_url.to_string(), transport);

    // Generate the DID Document based on the VID
    let did_doc = vid_to_did_document(vid.vid());

    // Create the CURRENT WebVH UpdateKey
    let current_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let current_sigkey_private = current_signing_key.to_bytes().to_vec();
    let current_sigkey_public = current_signing_key.verifying_key().to_bytes();

    let mut current_webvh_key = Secret::from_str(
        "webvh-signing-key",
        &json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": Base64UrlUnpadded::encode_string(&current_sigkey_public),
            "d": Base64UrlUnpadded::encode_string(&current_sigkey_private),
        }),
    )
    .map_err(|e| VidError::InternalError(format!("Couldn't create WebVH UpdateKey: {}", e)))?;

    let current_key_public = current_webvh_key.get_public_keymultibase().map_err(|e| {
        VidError::InternalError(format!(
            "WebVH signing key couldn't get multibase key: {}",
            e
        ))
    })?;
    current_webvh_key.id = ["did:key:", &current_key_public, "#", &current_key_public].concat();

    // Create the NEXT WebVH UpdateKey (for precommit)
    let next_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let next_sigkey_private = next_signing_key.to_bytes().to_vec();
    let next_sigkey_public = next_signing_key.verifying_key().to_bytes();

    let next_webvh_key = Secret::from_str(
        "webvh-next-signing-key",
        &json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": Base64UrlUnpadded::encode_string(&next_sigkey_public),
            "d": Base64UrlUnpadded::encode_string(&next_sigkey_private),
        }),
    )
    .map_err(|e| VidError::InternalError(format!("Couldn't create WebVH next UpdateKey: {}", e)))?;

    let next_key_public = next_webvh_key.get_public_keymultibase().map_err(|e| {
        VidError::InternalError(format!(
            "WebVH next signing key couldn't get multibase key: {}",
            e
        ))
    })?;

    // Get the hash of the next key for precommit
    let next_key_hash = next_webvh_key.get_public_keymultibase_hash().map_err(|e| {
        VidError::InternalError(format!("WebVH next signing key couldn't get hash: {}", e))
    })?;

    // WebVH Parameters with precommit
    let params = Parameters::new()
        .with_update_keys(vec![current_key_public.clone()])
        .with_next_key_hashes(vec![next_key_hash])
        .build();

    // Create the first WebVH Log Entry
    let mut webvh = DIDWebVHState::default();
    let log_entry = webvh.create_log_entry(None, &did_doc, &params, &current_webvh_key)?;

    // Get the updated webvh ID
    vid.vid.id = log_entry
        .get_state()
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or(VidError::InternalError(
            "Couldn't get DID ID from WebVH Log Entry".to_string(),
        ))?
        .to_string();

    let genesis_log_entry = serde_json::to_value(&log_entry.log_entry)?;

    let keys = WebvhKeys {
        update_kid: current_key_public,
        update_key: current_webvh_key.get_private_bytes().to_vec(),
        next_update_kid: next_key_public,
        next_update_key: next_webvh_key.get_private_bytes().to_vec(),
    };

    Ok((vid, genesis_log_entry, keys))
}

/// Create a new LogEntry record for an existing WebVH DID with precommit support.
///
/// # Arguments
/// * `updated_document` - The updated DID Document to use
/// * `update_key` - The WebVH LogEntry update key that is authorized to make the update
///   (must match precommit if precommit was active)
///
/// # Returns
/// * `UpdateResult` containing the log entry and new next key for continued precommit
pub async fn update(
    updated_document: serde_json::Value,
    update_key: &[u8; 32],
) -> Result<UpdateResult, VidError> {
    // Create a valid UpdateKey from the provided bytes
    let signing_key = ed25519_dalek::SigningKey::from_bytes(update_key);
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
    .map_err(|e| VidError::InternalError(format!("Couldn't create WebVH UpdateKey: {}", e)))?;

    let current_key_public = webvh_signing_key.get_public_keymultibase().map_err(|e| {
        VidError::InternalError(format!(
            "WebVH signing key couldn't get multibase key: {}",
            e
        ))
    })?;
    webvh_signing_key.id = ["did:key:", &current_key_public, "#", &current_key_public].concat();

    // Generate the NEXT update key for continued precommit chain
    let next_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let next_sigkey_private = next_signing_key.to_bytes().to_vec();
    let next_sigkey_public = next_signing_key.verifying_key().to_bytes();

    let next_webvh_key = Secret::from_str(
        "webvh-next-signing-key",
        &json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": Base64UrlUnpadded::encode_string(&next_sigkey_public),
            "d": Base64UrlUnpadded::encode_string(&next_sigkey_private),
        }),
    )
    .map_err(|e| VidError::InternalError(format!("Couldn't create WebVH next UpdateKey: {}", e)))?;

    let next_key_public = next_webvh_key.get_public_keymultibase().map_err(|e| {
        VidError::InternalError(format!(
            "WebVH next signing key couldn't get multibase key: {}",
            e
        ))
    })?;

    // Get the hash of the next key for precommit
    let next_key_hash = next_webvh_key.get_public_keymultibase_hash().map_err(|e| {
        VidError::InternalError(format!("WebVH next signing key couldn't get hash: {}", e))
    })?;

    // Get the DID ID
    let did_id =
        updated_document
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or(VidError::InternalError(
                "Couldn't get DID ID from updated DID Document".to_string(),
            ))?;

    // Resolve the current DID WebVH State - gets context and is used to append the new LogEntry
    let mut webvh = DIDWebVHState::default();
    webvh.resolve(did_id, None).await?;

    // Parameters with precommit for the next update
    // IMPORTANT: We must specify updateKeys so the library knows this key is now authorized
    // The key we're signing with (current_key_public) must be in updateKeys
    let params = Parameters::new()
        .with_update_keys(vec![current_key_public.clone()])
        .with_next_key_hashes(vec![next_key_hash])
        .build();

    // Create the new Log Entry
    let log_entry = webvh.create_log_entry(None, &updated_document, &params, &webvh_signing_key)?;

    Ok(UpdateResult {
        log_entry: log_entry.log_entry.clone(),
        current_update_kid: current_key_public,
        next_update_kid: next_key_public,
        next_update_key: next_webvh_key.get_private_bytes().to_vec(),
    })
}

/// Legacy update function that returns just the LogEntry (for backward compatibility).
///
/// NOTE: This function does NOT continue the precommit chain.
/// Use `update()` instead for proper precommit support.
#[deprecated(
    since = "0.2.0",
    note = "Use update() which returns UpdateResult with precommit support"
)]
pub async fn update_legacy(
    updated_document: serde_json::Value,
    update_key: &[u8; 32],
) -> Result<LogEntry, VidError> {
    let result = update(updated_document, update_key).await?;
    Ok(result.log_entry)
}

#[cfg(feature = "async")]
#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn create_legacy_webvh_state(
        did_path: &str,
        transport: Url,
    ) -> (DIDWebVHState, serde_json::Value, Secret, String) {
        let path_url = Url::parse(&format!("http://{did_path}")).unwrap();
        let webvh_url = WebVHURL::parse_url(&path_url).unwrap();
        let vid = OwnedVid::bind(webvh_url.to_string(), transport);
        let did_doc = vid_to_did_document(vid.vid());

        let current_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let current_sigkey_private = current_signing_key.to_bytes().to_vec();
        let current_sigkey_public = current_signing_key.verifying_key().to_bytes();

        let mut current_webvh_key = Secret::from_str(
            "legacy-webvh-signing-key",
            &json!({
                "crv": "Ed25519",
                "kty": "OKP",
                "x": Base64UrlUnpadded::encode_string(&current_sigkey_public),
                "d": Base64UrlUnpadded::encode_string(&current_sigkey_private),
            }),
        )
        .expect("Couldn't create legacy WebVH update key");

        let current_key_public = current_webvh_key
            .get_public_keymultibase()
            .expect("Couldn't get legacy WebVH public key");
        current_webvh_key.id =
            ["did:key:", &current_key_public, "#", &current_key_public].concat();

        let legacy_params = Parameters::new()
            .with_update_keys(vec![current_key_public.clone()])
            .build();

        let mut webvh = DIDWebVHState::default();
        let legacy_entry = webvh
            .create_log_entry(None, &did_doc, &legacy_params, &current_webvh_key)
            .expect("Legacy genesis should be valid");
        let legacy_state = legacy_entry.get_state().clone();

        (
            webvh,
            legacy_state,
            current_webvh_key,
            current_key_public,
        )
    }

    #[tokio::test]
    async fn test_create_webvh_success() {
        // 1. Arrange
        let did_path = "example/endpoint/alice";
        let transport_url = Url::parse("tcp://example.com:1234").unwrap();

        // 2. Act
        let result = create_webvh(did_path, transport_url).await;
        assert!(result.is_ok());

        let (_vid, genesis_log_entry, keys) = result.unwrap();
        // 3. Assert
        assert!(genesis_log_entry.is_object());

        let version_id = genesis_log_entry["versionId"].as_str().unwrap();
        assert!(version_id.starts_with("1-"));

        // Check the DID ID in the state
        let did_id_from_state = genesis_log_entry["state"]["id"].as_str().unwrap();
        let scid = genesis_log_entry["parameters"]["scid"].as_str().unwrap();
        let expected_did_id = format!("did:webvh:{scid}:{}", did_path.replace("/", ":"));
        assert_eq!(
            did_id_from_state, expected_did_id,
            "DID ID in state is incorrect"
        );

        // Check the updateKeys in parameters
        let update_keys = genesis_log_entry["parameters"]["updateKeys"]
            .as_array()
            .unwrap();
        assert_eq!(
            update_keys.len(),
            1,
            "There should be exactly one update key"
        );
        assert_eq!(
            update_keys[0].as_str().unwrap(),
            keys.update_kid,
            "The update key in parameters does not match the returned public key"
        );

        // Check the proof's verificationMethod
        let verification_method = genesis_log_entry["proof"][0]["verificationMethod"]
            .as_str()
            .unwrap();
        let expected_vm = format!("did:key:{}#{}", keys.update_kid, keys.update_kid);
        assert_eq!(
            verification_method, expected_vm,
            "Verification method in proof is incorrect"
        );

        assert!(
            keys.update_kid.starts_with('z'),
            "Public key should be in multibase format starting with 'z'"
        );

        // Re-derive the public key from the returned private key and verify they match.
        let key_array: [u8; 32] = keys
            .update_key
            .clone()
            .try_into()
            .expect("private key must be 32 bytes");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();

        // Create a Secret to get the same multibase encoding as used in the main code
        let rederived_secret = Secret::from_str(
            "test-key",
            &json!({
                "crv": "Ed25519",
                "kty": "OKP",
                "x": Base64UrlUnpadded::encode_string(verifying_key.as_bytes()),
                "d": Base64UrlUnpadded::encode_string(&keys.update_key),
            }),
        )
        .expect("Failed to create test secret");

        let rederived_public_key_multibase = rederived_secret
            .get_public_keymultibase()
            .expect("Failed to get multibase key");

        assert_eq!(
            keys.update_kid, rederived_public_key_multibase,
            "Returned public key does not match the one re-derived from the private key"
        );
    }

    #[tokio::test]
    async fn test_create_webvh_with_precommit() {
        // Test that genesis has next_key_hashes for precommit
        let did_path = "example/endpoint/precommit-test";
        let transport_url = Url::parse("tcp://example.com:1234").unwrap();

        let result = create_webvh(did_path, transport_url).await;
        assert!(result.is_ok());

        let (_vid, genesis_log_entry, keys) = result.unwrap();

        // Genesis should have nextKeyHashes for precommit
        let next_key_hashes = genesis_log_entry["parameters"]["nextKeyHashes"]
            .as_array()
            .expect("Genesis should have nextKeyHashes for precommit");
        assert_eq!(
            next_key_hashes.len(),
            1,
            "Should have exactly one next key hash"
        );

        // Should have both current and next keys
        assert!(
            !keys.update_kid.is_empty(),
            "Current update_kid should not be empty"
        );
        assert!(
            !keys.next_update_kid.is_empty(),
            "Next update_kid should not be empty"
        );
        assert_eq!(
            keys.update_key.len(),
            32,
            "Current update key should be 32 bytes"
        );
        assert_eq!(
            keys.next_update_key.len(),
            32,
            "Next update key should be 32 bytes"
        );

        // Keys should be different
        assert_ne!(
            keys.update_kid, keys.next_update_kid,
            "Current and next update keys should be different"
        );
        assert_ne!(
            keys.update_key, keys.next_update_key,
            "Current and next private keys should be different"
        );

        // Verify the hash in nextKeyHashes matches the next key
        let next_key_hash_in_genesis = next_key_hashes[0].as_str().unwrap();

        // Re-create the next key and compute its hash
        let next_key_array: [u8; 32] = keys
            .next_update_key
            .clone()
            .try_into()
            .expect("next key must be 32 bytes");
        let next_signing_key = ed25519_dalek::SigningKey::from_bytes(&next_key_array);
        let next_verifying_key = next_signing_key.verifying_key();

        let rederived_next_secret = Secret::from_str(
            "test-next-key",
            &json!({
                "crv": "Ed25519",
                "kty": "OKP",
                "x": Base64UrlUnpadded::encode_string(next_verifying_key.as_bytes()),
                "d": Base64UrlUnpadded::encode_string(&keys.next_update_key),
            }),
        )
        .expect("Failed to create test secret for next key");

        let rederived_next_hash = rederived_next_secret
            .get_public_keymultibase_hash()
            .expect("Failed to get hash of next key");

        assert_eq!(
            next_key_hash_in_genesis, rederived_next_hash,
            "The nextKeyHashes entry should match the hash of the returned next key"
        );
    }

    #[test]
    fn test_legacy_did_can_enable_precommit_on_first_rotation() {
        let transport_url = Url::parse("tcp://example.com:1234").unwrap();
        let (mut webvh, updated_document, current_webvh_key, current_key_public) =
            create_legacy_webvh_state("example/endpoint/legacy-precommit-migration", transport_url);

        let next_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let next_sigkey_private = next_signing_key.to_bytes().to_vec();
        let next_sigkey_public = next_signing_key.verifying_key().to_bytes();

        let next_webvh_key = Secret::from_str(
            "legacy-webvh-next-signing-key",
            &json!({
                "crv": "Ed25519",
                "kty": "OKP",
                "x": Base64UrlUnpadded::encode_string(&next_sigkey_public),
                "d": Base64UrlUnpadded::encode_string(&next_sigkey_private),
            }),
        )
        .expect("Couldn't create next WebVH update key");

        let next_key_hash = next_webvh_key
            .get_public_keymultibase_hash()
            .expect("Couldn't hash next WebVH update key");

        // This matches the current update() implementation: it always sends both
        // updateKeys and nextKeyHashes when starting or continuing precommit.
        let params = Parameters::new()
            .with_update_keys(vec![current_key_public])
            .with_next_key_hashes(vec![next_key_hash])
            .build();

        let result = webvh
            .create_log_entry(None, &updated_document, &params, &current_webvh_key)
            .expect("Legacy DID should be able to start precommit on the first rotation");

        assert!(
            result.log_entry.get_parameters().update_keys.is_none(),
            "Unchanged updateKeys should be omitted from the diffed log entry for legacy migration"
        );
        assert!(
            result.log_entry.get_parameters().next_key_hashes.is_some(),
            "The first precommit rotation should still publish nextKeyHashes"
        );
    }

    #[tokio::test]
    async fn test_key_roundtrip_through_json_storage() {
        // Simulates what CLI does: serialize keys to JSON, then deserialize and use
        use std::collections::HashMap;

        let did_path = "example/endpoint/roundtrip-test";
        let transport_url = Url::parse("tcp://example.com:1234").unwrap();

        let result = create_webvh(did_path, transport_url).await;
        assert!(result.is_ok());

        let (_vid, genesis_log_entry, keys) = result.unwrap();

        // Get the committed hash
        let next_key_hash_in_genesis = genesis_log_entry["parameters"]["nextKeyHashes"][0]
            .as_str()
            .unwrap();

        // Simulate CLI storage: put in HashMap and serialize/deserialize via JSON
        let mut storage: HashMap<String, Vec<u8>> = HashMap::new();
        storage.insert(keys.next_update_kid.clone(), keys.next_update_key.clone());

        let json = serde_json::to_string(&storage).expect("Failed to serialize");
        let restored: HashMap<String, Vec<u8>> =
            serde_json::from_str(&json).expect("Failed to deserialize");

        // Retrieve and use
        let retrieved_key = restored.get(&keys.next_update_kid).expect("Key not found");
        assert_eq!(retrieved_key.len(), 32, "Retrieved key should be 32 bytes");

        // Re-derive the Secret (like update() does)
        let key_array: [u8; 32] = retrieved_key.clone().try_into().expect("must be 32 bytes");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();

        let rederived_secret = Secret::from_str(
            "rederived-key",
            &json!({
                "crv": "Ed25519",
                "kty": "OKP",
                "x": Base64UrlUnpadded::encode_string(verifying_key.as_bytes()),
                "d": Base64UrlUnpadded::encode_string(&key_array),
            }),
        )
        .expect("Failed to create rederived secret");

        let rederived_hash = rederived_secret
            .get_public_keymultibase_hash()
            .expect("Failed to get hash");

        assert_eq!(
            next_key_hash_in_genesis, rederived_hash,
            "Hash after JSON roundtrip should match committed hash"
        );
    }

    #[tokio::test]
    async fn test_precommit_key_hash_matches_stored_key() {
        // Verify that the hash committed in genesis matches the key we store

        let did_path = "example/endpoint/precommit-verify";
        let transport_url = Url::parse("tcp://example.com:1234").unwrap();

        let result = create_webvh(did_path, transport_url).await;
        assert!(result.is_ok());

        let (_vid, genesis_log_entry, keys) = result.unwrap();

        // Get the committed hash and next_kid
        let next_key_hash_committed = genesis_log_entry["parameters"]["nextKeyHashes"][0]
            .as_str()
            .expect("Should have nextKeyHashes");

        println!("Committed hash: {}", next_key_hash_committed);
        println!("Stored next_update_kid: {}", keys.next_update_kid);
        println!(
            "Stored next_update_key length: {}",
            keys.next_update_key.len()
        );

        // Compute hash of the stored kid (which should match)
        let computed_hash =
            Secret::base58_hash_string(&keys.next_update_kid).expect("Failed to compute hash");

        println!("Computed hash of stored kid: {}", computed_hash);

        assert_eq!(
            next_key_hash_committed, computed_hash,
            "Committed hash should equal hash of stored next_update_kid"
        );
    }
}
