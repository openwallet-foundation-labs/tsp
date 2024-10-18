use super::{did, error::VidError};
use crate::Vid;

#[cfg(feature = "resolve")]
/// Resolve and verify the vid identified by `id`, by using online and offline methods
pub async fn verify_vid(id: &str) -> Result<Vid, VidError> {
    let parts = id.split(':').collect::<Vec<&str>>();

    match parts.get(0..2) {
        Some([did::SCHEME, did::web::SCHEME]) => did::web::resolve(id, parts).await,
        Some([did::SCHEME, did::peer::SCHEME]) => did::peer::verify_did_peer(&parts),
        Some([did::SCHEME, did::tdw::SCHEME]) => did::tdw::resolve(id, parts).await,
        _ => Err(VidError::InvalidVid(id.to_string())),
    }
}

/// Resolve and verify the vid identified by `id`, but only using offline methods
pub fn verify_vid_offline(id: &str) -> Result<Vid, VidError> {
    let parts = id.split(':').collect::<Vec<&str>>();

    match parts.get(0..2) {
        Some([did::SCHEME, did::peer::SCHEME]) => did::peer::verify_did_peer(&parts),
        _ => Err(VidError::InvalidVid(id.to_string())),
    }
}
