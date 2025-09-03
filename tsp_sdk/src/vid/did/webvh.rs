use crate::{
    OwnedVid, Vid,
    vid::{
        VidError,
        did::web::{DidDocument, resolve_document},
    },
};
use base64ct::{Base64UrlUnpadded, Encoding};
use didwebvh_rs::{
    DIDWebVHState, affinidi_secrets_resolver::secrets::Secret, log_entry::LogEntryMethods,
    parameters::Parameters, url::WebVHURL,
};
use ed25519_dalek::{KEYPAIR_LENGTH, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::debug;
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
    let metadata = WebvhMetadata {
        version_id: Some(meta_data.version_id),
        updated: Some(meta_data.updated),
        update_keys: Some((*log_entry.get_parameters().active_update_keys).clone()),
    };

    Ok((
        resolve_document(did_doc, id)?,
        serde_json::to_value(&metadata)?,
    ))
}

/// Creates a default WebVH DID that can be used with TSP.
/// did_name: Name to use to create the DID ID (expects this to be server.name/path)
pub async fn create_webvh(
    did_name: &str,
    transport: Url,
) -> Result<(OwnedVid, serde_json::Value, String, Vec<u8>), VidError> {
    debug!("did_name: {did_name}");
    debug!("transport URL: {transport}");

    // Create the initial DID ID
    let path_url = Url::parse(&["http://", did_name].concat())?;
    let webvh_url = WebVHURL::parse_url(&path_url)?;

    // Create the DID verificationMethod keys
    let (sigkey, public_sigkey) = crate::crypto::gen_sign_keypair();
    let (enckey, public_enckey) = crate::crypto::gen_encrypt_keypair();
    let public_verification_key = Base64UrlUnpadded::encode_string(&public_sigkey);
    let public_encryption_key = Base64UrlUnpadded::encode_string(&public_enckey);

    // Create the default starting DID Document
    let did_doc = create_initial_did_document(
        &webvh_url.to_string(),
        transport.as_str(),
        &public_verification_key,
        &public_encryption_key,
    );

    // Create the WebVH UpdateKey
    let (webvh_update_key, public_webvh_update_key) = crate::crypto::gen_sign_keypair();
    let webvh_signing_key = Secret::from_str(
        "webvh-signing-key",
        &json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": Base64UrlUnpadded::encode_string(&public_webvh_update_key),
            "d":Base64UrlUnpadded::encode_string(&webvh_update_key),
        }),
    )
    .map_err(|e| VidError::InternalError(format!("Couldn't convert Secret: {}", e)))?;

    // WebVH Parameters
    let params = Parameters::new()
        .with_update_keys(vec![webvh_signing_key.get_public_keymultibase().map_err(
            |e| {
                VidError::InternalError(format!(
                    "WebVH signing key couldn't get multibase key: {}",
                    e
                ))
            },
        )?])
        .build();

    // Create the first WebVH Log Entry
    let mut webvh = DIDWebVHState::default();

    webvh.create_log_entry(None, &did_doc, &params, &webvh_signing_key)?;

    todo!()
}

// Placeholder for native WebVH update DID function
pub async fn update(
    updated_document: serde_json::Value,
    update_key: &[u8],
) -> Result<HistoryEntry, VidError> {
    todo!()
}

// ------------------- Internal Functions -------------------

/// Creates a WebVH DID Document (State)
/// id: The path part of the DID (e.g. what comes after did:webvh:<SCID>:)
/// service_endpoint: The service endpoint to include in the DID Document
/// verification_key: Public key to use for signing/verification
/// encryption_key: Public key to use for encryption/decryption
///
/// Returns Json Value representing the initial DID Document
fn create_initial_did_document(
    id: &str,
    service_endpoint: &str,
    verification_key: &str,
    encryption_key: &str,
) -> Value {
    // Default State DID Document
    json!({
        "@context": [
             "https://www.w3.org/ns/did/v1",
             "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "service": [
            {
                "id": "#tsp-transport",
                "serviceEndpoint": service_endpoint,
                "type": "TSPTransport"
            }
        ],
        "id": id,
        "authentication": [ ([id, "#verification-key"].concat()) ],
        "keyAgreement": [ ([id, "#encryption-key"].concat()) ],
        "verificationMethod": [
            {
                "controller": id,
                "id": ([id, "#verification-key"].concat()),
                "publicKeyJwk": {
                    "crv": "Ed25519",
                    "kty": "OKP",
                    "use": "sig",
                    "x": verification_key
                }
            },
            {
                "controller": id,
                "id": ([id, "#encryption-key"].concat()),
                "publicKeyJwk": {
                    "crv": "X25519",
                    "kty": "OKP",
                    "use": "enc",
                    "x": encryption_key
                }
            }
        ]
    })
}
