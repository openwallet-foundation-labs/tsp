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
    DIDWebVHState, affinidi_secrets_resolver::secrets::Secret, log_entry::LogEntryMethods,
    parameters::Parameters, url::WebVHURL,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

pub(crate) const SCHEME: &str = "webvh";

#[derive(Debug, Serialize, Deserialize)]
pub struct WebvhMetadata {
    version_id: Option<String>,
    updated: Option<String>,
    pub update_keys: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    version_id: String,
    version_time: String,
    parameters: serde_json::Value,
    pub state: DidDocument,
    proof: Vec<serde_json::Value>,
}

/// Returns the Vid and [`WebvhMetadata`] for the given `id`.
pub async fn resolve(id: &str) -> Result<(Vid, serde_json::Value), VidError> {
    let mut webvh = DIDWebVHState::default();

    let (log_entry, meta_data) = webvh.resolve(id, None).await?;
    let did_doc: DidDocument = serde_json::from_value(log_entry.get_state().to_owned())?;

    let update_keys = if let Some(update_keys) = log_entry.get_parameters().update_keys {
        Some((*update_keys).clone())
    } else {
        None
    };

    let metadata = WebvhMetadata {
        version_id: Some(meta_data.version_id),
        updated: Some(meta_data.updated),
        update_keys,
    };

    Ok((
        resolve_document(did_doc, id)?,
        serde_json::to_value(&metadata)?,
    ))
}

/// Creates a default WebVH DID that can be used with TSP.
/// did_path: Server path to use as base for the DID ID (expects this to be server.name/path)
/// transport: URL to use for the service record
///
/// Returns
/// VID Record - contains key info
/// The Genesis Log Entry record for WebVH DID's
/// The Key ID of the WebVH Update Key
/// The private key bytes for the WebVH Update Key
pub async fn create_webvh(
    did_path: &str,
    transport: Url,
) -> Result<(OwnedVid, serde_json::Value, String, Vec<u8>), VidError> {
    // Create the initial DID ID
    let path_url = Url::parse(&["http://", did_path].concat())?;
    let webvh_url = WebVHURL::parse_url(&path_url)?;

    // Create default TSP VID
    let mut vid = OwnedVid::bind(&webvh_url.to_string(), transport);

    // Generate the DID Document based on the VID
    let did_doc = vid_to_did_document(vid.vid());

    // Create the WebVH UpdateKey
    let (webvh_update_key, public_webvh_update_key) = crate::crypto::gen_sign_keypair();
    let mut webvh_signing_key = Secret::from_str(
        "webvh-signing-key",
        &json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": Base64UrlUnpadded::encode_string(&public_webvh_update_key),
            "d":Base64UrlUnpadded::encode_string(&webvh_update_key),
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

// Placeholder for native WebVH update DID function
pub async fn update(
    updated_document: serde_json::Value,
    update_key: &[u8; 32],
) -> Result<HistoryEntry, VidError> {
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
    Ok(HistoryEntry {
        version_id: log_entry.get_version_id().to_string(),
        version_time: log_entry.log_entry.get_version_time().to_rfc3339(),
        parameters: json!(log_entry.log_entry.get_parameters()),
        state: serde_json::from_value(log_entry.get_state().to_owned())?,
        proof: proofs,
    })
}
