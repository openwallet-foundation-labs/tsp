use super::{
    did::{self, peer},
    error::VidError,
};
use crate::Vid;

pub async fn verify_vid(id: &str) -> Result<Vid, VidError> {
    let parts = id.split(':').collect::<Vec<&str>>();

    match parts.get(0..2) {
        Some([did::SCHEME, did::web::SCHEME]) => did::web::resolve(id, parts).await,
        Some([did::SCHEME, did::peer::SCHEME]) => peer::verify_did_peer(&parts),
        _ => Err(VidError::InvalidVid(id.to_string())),
    }
}
