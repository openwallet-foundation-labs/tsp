use crate::{
    OwnedVid,
    definitions::VerifiedVid,
    store::WalletMethodState,
    vid::{
        ResolutionContext, VerifyVidOptions, VidError,
        did::{web, webvh},
    },
};
use serde::{Deserialize, Serialize};
use url::Url;

pub(crate) const SCHEME: &str = "scid";

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum ScidMethod {
    Vh,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum ScidSourceMethod {
    Webvh,
    Cheqd,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum ScidLocator {
    Src(String),
    Network(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScidDid {
    pub presented_id: String,
    pub method: ScidMethod,
    pub version: u8,
    pub scid: String,
    pub src: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScidResolutionContext {
    pub version: u8,
    pub method: ScidMethod,
    pub source_method: ScidSourceMethod,
    pub locator: ScidLocator,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScidResolvedSource {
    pub presented_id: String,
    pub source_did: String,
    pub source_method: ScidSourceMethod,
    pub resolve_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScidVidMetadata {
    pub scid: ScidResolvedSource,
    pub source_metadata: Option<serde_json::Value>,
    pub private_state: Option<ScidPrivateState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScidPrivateState {
    pub source_did: String,
    pub source_method: ScidSourceMethod,
    pub current_update_kid: Option<String>,
    pub next_update_kid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ScidCreateResult {
    pub private_vid: crate::OwnedVid,
    pub source_vid: crate::Vid,
    pub source_history: Option<serde_json::Value>,
    pub metadata: ScidVidMetadata,
    pub method_state: crate::store::WalletMethodState,
}

#[derive(Clone, Debug)]
pub struct ScidUpdateResult {
    pub private_vid: crate::OwnedVid,
    pub source_vid: crate::Vid,
    pub source_history_entry: Option<serde_json::Value>,
    pub metadata: ScidVidMetadata,
    pub method_state: crate::store::WalletMethodState,
}

pub fn parse(id: &str) -> Result<ScidDid, VidError> {
    let (base, src) = parse_scid_query(id)?;

    let parts = base.split(':').collect::<Vec<_>>();
    let [did, scheme, method, version, scid] = parts.as_slice() else {
        return Err(VidError::InvalidScid(id.to_string()));
    };

    if *did != "did" || *scheme != SCHEME {
        return Err(VidError::InvalidScid(id.to_string()));
    }

    let method = match *method {
        "vh" => ScidMethod::Vh,
        _ => return Err(VidError::InvalidScid(id.to_string())),
    };

    let version = version
        .parse::<u8>()
        .map_err(|_| VidError::InvalidScid(id.to_string()))?;

    if version != 1 || scid.is_empty() {
        return Err(VidError::InvalidScid(id.to_string()));
    }

    Ok(ScidDid {
        presented_id: base.clone(),
        method,
        version,
        scid: (*scid).to_string(),
        src,
    })
}

pub fn resolve_source(
    did: &ScidDid,
    context: Option<&ScidResolutionContext>,
) -> Result<ScidResolvedSource, VidError> {
    let context = context
        .cloned()
        .map(Ok)
        .or_else(|| {
            did.src
                .as_deref()
                .map(|src| context_from_src(&did.scid, src))
        })
        .transpose()?
        .ok_or_else(|| VidError::ResolutionContextRequired(did.presented_id.clone()))?;

    if context.version != did.version || context.method != did.method {
        return Err(VidError::InvalidScid(did.presented_id.clone()));
    }

    match (context.source_method, &context.locator) {
        (ScidSourceMethod::Webvh, ScidLocator::Src(src)) => {
            let source_did = normalize_webvh_source(src, &did.scid)?;

            Ok(ScidResolvedSource {
                presented_id: did.presented_id.clone(),
                resolve_url: Some(web::get_resolve_url(&source_did)?.to_string()),
                source_did,
                source_method: ScidSourceMethod::Webvh,
            })
        }
        (ScidSourceMethod::Cheqd, ScidLocator::Network(network)) => {
            let source_did = format!("did:cheqd:{network}:{}", did.scid);

            Ok(ScidResolvedSource {
                presented_id: did.presented_id.clone(),
                resolve_url: None,
                source_did,
                source_method: ScidSourceMethod::Cheqd,
            })
        }
        _ => Err(VidError::InvalidScid(did.presented_id.clone())),
    }
}

pub async fn resolve(
    id: &str,
    options: VerifyVidOptions,
) -> Result<(crate::Vid, serde_json::Value), VidError> {
    let did = parse(id)?;
    let resolved = resolve_source(&did, options.resolution_context.as_ref().and_then(as_scid))?;

    match resolved.source_method {
        ScidSourceMethod::Webvh => {
            let (source_vid, source_metadata) = webvh::resolve(&resolved.source_did).await?;

            if source_vid.identifier() != resolved.source_did {
                return Err(VidError::SourceDidMismatch(resolved.source_did));
            }

            let metadata = ScidVidMetadata {
                scid: resolved.clone(),
                source_metadata: Some(source_metadata),
                private_state: None,
            };

            Ok((
                source_vid.with_identifier(did.presented_id),
                serde_json::to_value(metadata)?,
            ))
        }
        ScidSourceMethod::Cheqd => Err(VidError::UnsupportedScidSource("cheqd".to_string())),
    }
}

pub fn resolve_offline(id: &str, options: VerifyVidOptions) -> Result<crate::Vid, VidError> {
    let did = parse(id)?;
    let resolved = resolve_source(&did, options.resolution_context.as_ref().and_then(as_scid))?;

    match resolved.source_method {
        ScidSourceMethod::Webvh => Err(VidError::ResolveVid(
            "did:scid source method is not available offline",
        )),
        ScidSourceMethod::Cheqd => Err(VidError::UnsupportedScidSource("cheqd".to_string())),
    }
}

pub async fn create(
    transport: Url,
    context: ScidResolutionContext,
) -> Result<ScidCreateResult, VidError> {
    match (&context.source_method, &context.locator) {
        (ScidSourceMethod::Webvh, ScidLocator::Src(src)) => {
            let (source_private_vid, source_history, keys) =
                webvh::create_webvh(src, transport).await?;
            let source_did = source_private_vid.identifier().to_string();
            let presented_id = presented_did_from_source(&source_did)?;
            let source_vid = source_private_vid.vid().clone();
            let private_vid = source_private_vid.with_identifier(presented_id.clone());
            let resolution_context = ScidResolutionContext {
                version: context.version,
                method: context.method,
                source_method: ScidSourceMethod::Webvh,
                locator: ScidLocator::Src(source_did.clone()),
            };

            let metadata = ScidVidMetadata {
                scid: ScidResolvedSource {
                    presented_id: presented_id.clone(),
                    resolve_url: Some(web::get_resolve_url(&source_did)?.to_string()),
                    source_did: source_did.clone(),
                    source_method: ScidSourceMethod::Webvh,
                },
                source_metadata: None,
                private_state: Some(ScidPrivateState {
                    source_did: source_did.clone(),
                    source_method: ScidSourceMethod::Webvh,
                    current_update_kid: Some(keys.update_kid.clone()),
                    next_update_kid: Some(keys.next_update_kid.clone()),
                }),
            };

            let mut method_state = WalletMethodState::default();
            method_state
                .secret_keys
                .insert(keys.update_kid.clone(), keys.update_key);
            method_state
                .secret_keys
                .insert(keys.next_update_kid.clone(), keys.next_update_key);
            method_state
                .resolution_contexts
                .insert(presented_id, ResolutionContext::Scid(resolution_context));

            Ok(ScidCreateResult {
                private_vid,
                source_vid,
                source_history: Some(source_history),
                metadata,
                method_state,
            })
        }
        (ScidSourceMethod::Cheqd, _) => Err(VidError::UnsupportedScidSource("cheqd".to_string())),
        _ => Err(VidError::InvalidScid(
            "invalid did:scid create context".to_string(),
        )),
    }
}

pub async fn update(
    private_vid: &OwnedVid,
    metadata: ScidVidMetadata,
    method_state: &WalletMethodState,
) -> Result<ScidUpdateResult, VidError> {
    let private_state = metadata
        .private_state
        .clone()
        .ok_or_else(|| VidError::InternalError("missing did:scid private state".to_string()))?;

    match private_state.source_method {
        ScidSourceMethod::Webvh => {
            let update_key = select_webvh_update_key(&metadata, method_state, &private_state)?;
            let source_private_vid = OwnedVid::bind(
                private_state.source_did.clone(),
                private_vid.endpoint().clone(),
            );
            let update_result = webvh::update(
                crate::vid::vid_to_did_document(source_private_vid.vid()),
                update_key.first_chunk::<32>().ok_or_else(|| {
                    VidError::WebVHError("Couldn't get WebVH UpdateKey Secret bytes".to_string())
                })?,
            )
            .await?;

            let updated_metadata = ScidVidMetadata {
                scid: metadata.scid,
                source_metadata: metadata.source_metadata,
                private_state: Some(ScidPrivateState {
                    source_did: private_state.source_did.clone(),
                    source_method: private_state.source_method,
                    current_update_kid: Some(update_result.current_update_kid.clone()),
                    next_update_kid: Some(update_result.next_update_kid.clone()),
                }),
            };

            let mut next_method_state = WalletMethodState::default();
            next_method_state.secret_keys.insert(
                update_result.next_update_kid.clone(),
                update_result.next_update_key,
            );

            Ok(ScidUpdateResult {
                private_vid: source_private_vid.with_identifier(private_vid.identifier()),
                source_vid: source_private_vid.vid().clone(),
                source_history_entry: Some(serde_json::to_value(update_result.log_entry)?),
                metadata: updated_metadata,
                method_state: next_method_state,
            })
        }
        ScidSourceMethod::Cheqd => Err(VidError::UnsupportedScidSource("cheqd".to_string())),
    }
}

pub fn query_resolution_context(id: &str) -> Result<Option<ScidResolutionContext>, VidError> {
    let did = parse(id)?;
    did.src
        .as_deref()
        .map(|src| context_from_src(&did.scid, src))
        .transpose()
}

fn as_scid(context: &ResolutionContext) -> Option<&ScidResolutionContext> {
    match context {
        ResolutionContext::Scid(context) => Some(context),
    }
}

fn parse_scid_query(id: &str) -> Result<(String, Option<String>), VidError> {
    let Some((base, query)) = id.split_once('?') else {
        return Ok((id.to_string(), None));
    };

    let mut src = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "src" if !value.is_empty() => src = Some(value.into_owned()),
            _ => return Err(VidError::InvalidScid(id.to_string())),
        }
    }

    Ok((base.to_string(), src))
}

fn context_from_src(scid: &str, src: &str) -> Result<ScidResolutionContext, VidError> {
    if src.starts_with("did:cheqd:") {
        let network = src
            .strip_prefix("did:cheqd:")
            .ok_or_else(|| VidError::InvalidScid(src.to_string()))?;

        Ok(ScidResolutionContext {
            version: 1,
            method: ScidMethod::Vh,
            source_method: ScidSourceMethod::Cheqd,
            locator: ScidLocator::Network(network.to_string()),
        })
    } else if src.starts_with("did:") && !src.starts_with("did:webvh:") {
        Err(VidError::InvalidScid(src.to_string()))
    } else {
        Ok(ScidResolutionContext {
            version: 1,
            method: ScidMethod::Vh,
            source_method: ScidSourceMethod::Webvh,
            locator: ScidLocator::Src(normalize_webvh_source(src, scid)?),
        })
    }
}

fn normalize_webvh_source(src: &str, scid: &str) -> Result<String, VidError> {
    if src.starts_with("did:webvh:") {
        let parts = src.split(':').collect::<Vec<_>>();
        match parts.get(2) {
            Some(source_scid) if *source_scid == scid => Ok(src.to_string()),
            _ => Err(VidError::SourceDidMismatch(src.to_string())),
        }
    } else if src.starts_with("did:") {
        Err(VidError::InvalidScid(src.to_string()))
    } else {
        let Some((host, path)) = src.split_once('/') else {
            return Ok(format!("did:webvh:{scid}:{src}"));
        };
        Ok(format!(
            "did:webvh:{scid}:{}:{}",
            host.replace(':', "%3A"),
            path.replace('/', ":")
        ))
    }
}

fn presented_did_from_source(source_did: &str) -> Result<String, VidError> {
    let parts = source_did.split(':').collect::<Vec<_>>();

    match parts.as_slice() {
        ["did", "webvh", scid, ..] => Ok(format!("did:scid:vh:1:{scid}")),
        _ => Err(VidError::InvalidScid(source_did.to_string())),
    }
}

fn select_webvh_update_key<'a>(
    metadata: &'a ScidVidMetadata,
    method_state: &'a WalletMethodState,
    private_state: &ScidPrivateState,
) -> Result<&'a Vec<u8>, VidError> {
    if let Some(next_update_kid) = private_state.next_update_kid.as_deref() {
        if let Some(secret) = method_state.secret_keys.get(next_update_kid) {
            return Ok(secret);
        }
    }

    let source_metadata = metadata
        .source_metadata
        .clone()
        .map(serde_json::from_value::<webvh::WebvhMetadata>)
        .transpose()?;

    if source_metadata
        .as_ref()
        .and_then(|metadata| metadata.next_key_hashes.as_ref())
        .is_some()
    {
        return Err(VidError::InternalError(
            "Server has precommit active but wallet has no matching key. Wallet may be out of sync."
                .to_string(),
        ));
    }

    if let Some(current_update_kid) = private_state.current_update_kid.as_deref() {
        if let Some(secret) = method_state.secret_keys.get(current_update_kid) {
            return Ok(secret);
        }
    }

    if let Some(update_kid) = source_metadata
        .as_ref()
        .and_then(|metadata| metadata.update_keys.as_ref())
        .and_then(|update_keys| update_keys.first())
    {
        if let Some(secret) = method_state.secret_keys.get(update_kid) {
            return Ok(secret);
        }
    }

    Err(VidError::InternalError(
        "Cannot find update keys to update the DID".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_scid() {
        let parsed = parse("did:scid:vh:1:testscid").expect("scid should parse");

        assert_eq!(parsed.method, ScidMethod::Vh);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.scid, "testscid");
        assert!(parsed.src.is_none());
    }

    #[test]
    fn parse_scid_with_src_query() {
        let parsed =
            parse("did:scid:vh:1:testscid?src=example.com/vid").expect("scid should parse");

        assert_eq!(parsed.presented_id, "did:scid:vh:1:testscid");
        assert_eq!(parsed.src.as_deref(), Some("example.com/vid"));
    }

    #[test]
    fn query_src_builds_webvh_context() {
        let context = query_resolution_context("did:scid:vh:1:testscid?src=example.com/vid/path")
            .expect("query context should parse")
            .expect("query context should exist");

        assert_eq!(context.source_method, ScidSourceMethod::Webvh);
        assert_eq!(
            context.locator,
            ScidLocator::Src("did:webvh:testscid:example.com:vid:path".to_string())
        );
    }

    #[test]
    fn query_src_escapes_webvh_host_port() {
        let context =
            query_resolution_context("did:scid:vh:1:testscid?src=localhost:3000/vid/path")
                .expect("query context should parse")
                .expect("query context should exist");

        assert_eq!(
            context.locator,
            ScidLocator::Src("did:webvh:testscid:localhost%3A3000:vid:path".to_string())
        );
    }

    #[test]
    fn query_src_builds_cheqd_context() {
        let context = query_resolution_context("did:scid:vh:1:testscid?src=did:cheqd:testnet")
            .expect("query context should parse")
            .expect("query context should exist");

        assert_eq!(context.source_method, ScidSourceMethod::Cheqd);
        assert_eq!(context.locator, ScidLocator::Network("testnet".to_string()));
    }

    #[test]
    fn parse_invalid_scid() {
        assert!(matches!(
            parse("did:scid:vh:testscid"),
            Err(VidError::InvalidScid(_))
        ));
    }

    #[test]
    fn peer_style_requires_context() {
        let did = parse("did:scid:vh:1:testscid").expect("scid should parse");

        assert!(matches!(
            resolve_source(&did, None),
            Err(VidError::ResolutionContextRequired(_))
        ));
    }

    #[test]
    fn resolve_source_builds_webvh_did() {
        let did = parse("did:scid:vh:1:testscid").expect("scid should parse");
        let resolved = resolve_source(
            &did,
            Some(&ScidResolutionContext {
                version: 1,
                method: ScidMethod::Vh,
                source_method: ScidSourceMethod::Webvh,
                locator: ScidLocator::Src("example.com:users:alice".to_string()),
            }),
        )
        .expect("source should resolve");

        assert_eq!(
            resolved.source_did,
            "did:webvh:testscid:example.com:users:alice"
        );
    }

    #[test]
    fn resolve_source_builds_cheqd_did_from_external_context() {
        let did = parse("did:scid:vh:1:testscid").expect("scid should parse");
        let resolved = resolve_source(
            &did,
            Some(&ScidResolutionContext {
                version: 1,
                method: ScidMethod::Vh,
                source_method: ScidSourceMethod::Cheqd,
                locator: ScidLocator::Network("testnet".to_string()),
            }),
        )
        .expect("source should resolve");

        assert_eq!(resolved.source_did, "did:cheqd:testnet:testscid");
    }
}
