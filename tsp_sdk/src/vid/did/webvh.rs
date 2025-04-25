use crate::Vid;
use crate::vid::VidError;
use didwebvh_resolver;
use didwebvh_resolver::{DefaultHttpClient, ResolutionOptions};
use crate::vid::did::web::{resolve_document, DidDocument};

pub(crate) const SCHEME: &str = "webvh";

pub async fn resolve(id: &str) -> Result<Vid, VidError> {
    let http = DefaultHttpClient::new();
    let resolver = didwebvh_resolver::resolver::WebVHResolver::new(http);
    let resolved = resolver.resolve(id, &ResolutionOptions::default()).await?;

    let did_doc: DidDocument = serde_json::from_value(resolved.did_document)?;
    
    resolve_document(did_doc, id)
}
