use crate::{
    OwnedVid, Vid,
    vid::{
        VidError,
        did::web::{DidDocument, resolve_document},
    },
};
use didwebvh_rs::{DIDWebVHState, log_entry::LogEntryMethods};
use serde::{Deserialize, Serialize};
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

// Placeholder for native WebVH create DID function
pub async fn create_webvh(
    did_name: &str,
    transport: Url,
) -> Result<(OwnedVid, serde_json::Value, String, Vec<u8>), VidError> {
    todo!()
}

// Placeholder for native WebVH update DID function
pub async fn update(
    updated_document: serde_json::Value,
    update_key: &[u8],
) -> Result<HistoryEntry, VidError> {
    todo!()
}
