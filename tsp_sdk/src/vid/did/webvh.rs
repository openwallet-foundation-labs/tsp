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
}

/// Returns the Vid and [`WebvhMetadata`] for the given `id`.
pub async fn resolve(id: &str) -> Result<(Vid, serde_json::Value), VidError> {
    let mut webvh = DIDWebVHState::default();

    let (log_entry, meta_data) = webvh.resolve(id, None).await?;
    let did_doc: DidDocument = serde_json::from_value(log_entry.get_state().to_owned())?;

    let update_keys = log_entry
        .get_parameters()
        .update_keys
        .map(|update_keys| (*update_keys).clone());

    let metadata = WebvhMetadata {
        webvh_meta_data: meta_data,
        update_keys,
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
/// * The Key ID of the WebVH Update Key
/// * The private key bytes for the WebVH Update Key
pub async fn create_webvh(
    did_path: &str,
    transport: Url,
) -> Result<(OwnedVid, serde_json::Value, String, Vec<u8>), VidError> {
    // Create the initial DID ID
    let path_url = Url::parse(&["http://", did_path].concat())?;
    let webvh_url = WebVHURL::parse_url(&path_url)?;

    // Create default TSP VID
    let mut vid = OwnedVid::bind(webvh_url.to_string(), transport);

    // Generate the DID Document based on the VID
    let did_doc = vid_to_did_document(vid.vid());

    // Create the WebVH UpdateKey
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    let sigkey_private = signing_key.to_bytes().to_vec();
    let sigkey_public = signing_key.verifying_key().to_bytes();

    let mut webvh_signing_key = Secret::from_str(
        "webvh-signing-key",
        &json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": Base64UrlUnpadded::encode_string(&sigkey_public),
            "d":Base64UrlUnpadded::encode_string(&sigkey_private),
        }),
    )
    .map_err(|e| VidError::InternalError(format!("Couldn't create WebVH UpdateKey: {}", e)))?;

    let webvh_signing_key_public = webvh_signing_key.get_public_keymultibase().map_err(|e| {
        VidError::InternalError(format!(
            "WebVH signing key couldn't get multibase key: {}",
            e
        ))
    })?;
    webvh_signing_key.id = [
        "did:key:",
        &webvh_signing_key_public,
        "#",
        &webvh_signing_key_public,
    ]
    .concat(); // Set the Key ID correctly (expects did:key:multikeyhash)

    // WebVH Parameters
    let params = Parameters::new()
        .with_update_keys(vec![webvh_signing_key_public.clone()])
        .build();

    // Create the first WebVH Log Entry
    let mut webvh = DIDWebVHState::default();
    let log_entry = webvh.create_log_entry(None, &did_doc, &params, &webvh_signing_key)?;

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

    Ok((
        vid,
        genesis_log_entry,
        webvh_signing_key_public,
        webvh_signing_key.get_private_bytes().to_vec(),
    ))
}

// Create a new LogEntry record for an existing WebVH DID
// updated_document: The updated DID Document to use
// update_key: The WebVH LogENtry update key that is authorised to make the update
pub async fn update(
    updated_document: serde_json::Value,
    update_key: &[u8; 32],
) -> Result<LogEntry, VidError> {
    // Create a valid UpdateKey to use
    let signing_key = ed25519_dalek::SigningKey::from_bytes(update_key);

    let sigkey_private = signing_key.to_bytes().to_vec();
    let sigkey_public = signing_key.verifying_key().to_bytes();

    let mut webvh_signing_key = Secret::from_str(
        "webvh-signing-key",
        &json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": Base64UrlUnpadded::encode_string(&sigkey_public),
            "d":Base64UrlUnpadded::encode_string(&sigkey_private),
        }),
    )
    .map_err(|e| VidError::InternalError(format!("Couldn't create WebVH UpdateKey: {}", e)))?;
    let webvh_signing_key_public = webvh_signing_key.get_public_keymultibase().map_err(|e| {
        VidError::InternalError(format!(
            "WebVH signing key couldn't get multibase key: {}",
            e
        ))
    })?;
    webvh_signing_key.id = [
        "did:key:",
        &webvh_signing_key_public,
        "#",
        &webvh_signing_key_public,
    ]
    .concat();

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

    // Create the new Log Entry
    let log_entry = webvh.create_log_entry(
        None,
        &updated_document,
        &Parameters::default(),
        &webvh_signing_key,
    )?;

    let mut proofs = Vec::new();
    for proof in log_entry.log_entry.get_proofs() {
        proofs.push(json!(proof));
    }

    // Create new HistoryEntry
    Ok(log_entry.log_entry.clone())
}

#[cfg(feature = "async")]
#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[tokio::test]
    async fn test_create_webvh_success() {
        // 1. Arrange
        let did_path = "example/endpoint/alice";
        let transport_url = Url::parse("tcp://example.com:1234").unwrap();

        // 2. Act
        let result = create_webvh(did_path, transport_url).await;
        assert!(result.is_ok());

        let (_vid, genesis_log_entry, webvh_update_key_public, private_key_bytes) = result.unwrap();
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
            webvh_update_key_public,
            "The update key in parameters does not match the returned public key"
        );

        // Check the proof's verificationMethod
        let verification_method = genesis_log_entry["proof"][0]["verificationMethod"]
            .as_str()
            .unwrap();
        let expected_vm = format!(
            "did:key:{}#{}",
            webvh_update_key_public, webvh_update_key_public
        );
        assert_eq!(
            verification_method, expected_vm,
            "Verification method in proof is incorrect"
        );

        assert!(
            webvh_update_key_public.starts_with('z'),
            "Public key should be in multibase format starting with 'z'"
        );

        // Re-derive the public key from the returned private key and verify they match.
        let key_array: [u8; 32] = private_key_bytes
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
                "d": Base64UrlUnpadded::encode_string(&private_key_bytes),
            }),
        )
        .expect("Failed to create test secret");

        let rederived_public_key_multibase = rederived_secret
            .get_public_keymultibase()
            .expect("Failed to get multibase key");

        assert_eq!(
            webvh_update_key_public, rederived_public_key_multibase,
            "Returned public key does not match the one re-derived from the private key"
        );
    }
}
