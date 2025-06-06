#[cfg(not(target_arch = "wasm32"))]
use super::did::webvh;
use super::{
    did::{self, peer, web},
    error::VidError,
};
use crate::Vid;

#[cfg(feature = "resolve")]
/// Resolve and verify the vid identified by `id`, by using online and offline methods
pub async fn verify_vid(id: &str) -> Result<(Vid, Option<serde_json::Value>), VidError> {
    let parts = id.split(':').collect::<Vec<&str>>();

    match parts.get(0..2) {
        Some([did::SCHEME, web::SCHEME]) => Ok((web::resolve(id, parts).await?, None)),
        Some([did::SCHEME, peer::SCHEME]) => Ok((peer::verify_did_peer(&parts)?, None)),
        #[cfg(not(target_arch = "wasm32"))]
        Some([did::SCHEME, webvh::SCHEME]) => webvh::resolve(id)
            .await
            .map(|(vid, metadata)| (vid, Some(metadata))),
        _ => Err(VidError::InvalidVid(id.to_string())),
    }
}

/// Resolve and verify the vid identified by `id`, but only using offline methods
pub fn verify_vid_offline(id: &str) -> Result<Vid, VidError> {
    let parts = id.split(':').collect::<Vec<&str>>();

    match parts.get(0..2) {
        Some([did::SCHEME, peer::SCHEME]) => peer::verify_did_peer(&parts),
        _ => Err(VidError::InvalidVid(id.to_string())),
    }
}
