//! `did:webvh`: creating an identity's first log entry, appending a later one, and resolving.
//!
//! Entries are built and signed here, so that the update key, which authorises every version
//! of the identity, never leaves the wallet's secure area: the entry's `eddsa-jcs-2022` proof
//! is computed over the entry and the key is asked only for the signature. The `didwebvh-rs`
//! library resolves and verifies; it signs nothing.

use crate::{
    OwnedVid, SecureArea, Vid,
    vid::{
        VidError,
        did::web::{DidDocument, resolve_document},
        vid_to_did_document,
    },
};
use didwebvh_rs::{
    DIDWebVHState,
    log_entry::{LogEntryMethods, MetaData},
    url::WebVHURL,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

pub(crate) const SCHEME: &str = "webvh";

#[derive(Debug, Serialize, Deserialize)]
pub struct WebvhMetadata {
    pub webvh_meta_data: MetaData,
    pub update_keys: Option<Vec<String>>,
    /// Hash of the next update key (if precommit is active)
    pub next_key_hashes: Option<Vec<String>>,
    /// Every `versionId` of the log as the server served it, oldest first: the held tip of
    /// an earlier resolution must be among them, and a watcher's copy is compared against
    /// them (flow 5).
    #[serde(default)]
    pub served_versions: Vec<String>,
    /// The watchers the log names, URLs: the default watchers a verifier asks.
    #[serde(default)]
    pub watchers: Vec<String>,
}

/// The update keys of an identity, by name. The keys themselves are in the secure area
/// the identity was created with, under these names.
#[derive(Debug, Clone)]
pub struct WebvhKeys {
    /// The key that signed the last entry: its multikey, which is also its alias.
    pub update_kid: String,
    /// The successor, committed by hash in that entry, unused until the next.
    pub next_update_kid: String,
}

/// The outcome of a later entry.
#[derive(Debug, Clone)]
pub struct UpdateResult {
    /// The new log entry to publish, one line of `did.jsonl`.
    pub log_entry: Value,
    /// The key that signed this entry.
    pub current_update_kid: String,
    /// The successor committed in this entry, already in the secure area.
    pub next_update_kid: String,
}

pub async fn resolve(id: &str) -> Result<(Vid, serde_json::Value), VidError> {
    let mut webvh = DIDWebVHState::default();

    let (log_entry, meta_data) = webvh.resolve(id, None).await?;
    // didwebvh-rs 0.1.10, on a later entry that fails verification, resolves to the last
    // valid entry with only a logged warning; the method requires an error. So the served
    // log's last entry must be the one resolved, or the log has an entry that does not
    // verify and the DID does not resolve.
    let served_versions = served_versions(id).await?;
    if served_versions.last().map(String::as_str) != Some(meta_data.version_id.as_str()) {
        return Err(VidError::ResolveVid(
            "the served log has an entry that does not verify",
        ));
    }
    if meta_data.deactivated {
        // the method returns no document for a deactivated DID; the outcome is the DID's state
        return Err(VidError::Deactivated(id.to_string()));
    }
    let watchers = meta_data.watchers.clone().unwrap_or_default();
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
        served_versions,
        watchers,
    };

    Ok((
        resolve_document(did_doc, id)?,
        serde_json::to_value(&metadata)?,
    ))
}

/// Every `versionId` of the log as served at the DID's URL, oldest first.
async fn served_versions(id: &str) -> Result<Vec<String>, VidError> {
    let url = WebVHURL::parse_did_url(id)?
        .get_http_url(Some("did.jsonl"))
        .map_err(|e| VidError::WebVHError(format!("log URL: {e}")))?;
    let log = reqwest::get(url.clone())
        .await
        .map_err(|e| VidError::Http(url.to_string(), e))?
        .text()
        .await
        .map_err(|e| VidError::Http(url.to_string(), e))?;
    let versions = versions_of(&log);
    if versions.is_empty() {
        return Err(VidError::ResolveVid("the served log has no entry"));
    }
    Ok(versions)
}

/// The `versionId`s of a `did.jsonl`, oldest first; a line that is not an entry ends the
/// list.
pub fn versions_of(log: &str) -> Vec<String> {
    log.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<Value>(l)
                .ok()
                .and_then(|e| e["versionId"].as_str().map(str::to_string))
        })
        .take_while(Option::is_some)
        .flatten()
        .collect()
}

/// The log as a watcher holds it, `GET /log?scid=`, as its `versionId`s; `None` if the
/// watcher holds no copy.
pub async fn watcher_versions(watcher: &str, scid: &str) -> Result<Option<Vec<String>>, VidError> {
    let url = format!("{}/log?scid={scid}", watcher.trim_end_matches('/'));
    let response = reqwest::get(&url)
        .await
        .map_err(|e| VidError::Http(url.clone(), e))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let log = response
        .error_for_status()
        .map_err(|e| VidError::Http(url.clone(), e))?
        .text()
        .await
        .map_err(|e| VidError::Http(url, e))?;
    Ok(Some(versions_of(&log)))
}

/// How a watcher's copy stands to the log the server serves, by `versionId`s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatcherComparison {
    /// The same log.
    Same,
    /// The served log extends the watcher's copy: the watcher has not caught up yet.
    ServerAhead,
    /// The watcher's copy extends the served log: the server serves less than it did, a
    /// rollback.
    WatcherAhead,
    /// The two share a prefix and differ after it: a fork.
    Fork,
    /// The watcher holds nothing for this log.
    WatcherEmpty,
}

pub fn compare_with_watcher(served: &[String], watched: &[String]) -> WatcherComparison {
    if watched.is_empty() {
        return WatcherComparison::WatcherEmpty;
    }
    let common = served
        .iter()
        .zip(watched.iter())
        .take_while(|(a, b)| a == b)
        .count();
    match (common == served.len(), common == watched.len()) {
        (true, true) => WatcherComparison::Same,
        (false, true) => WatcherComparison::ServerAhead,
        (true, false) => WatcherComparison::WatcherAhead,
        (false, false) => WatcherComparison::Fork,
    }
}

/// Resolve a DID from the copy a watcher holds, when the DID's own server serves nothing
/// (flow 5, "gone"): the watcher's `did.jsonl` and `did-witness.json` are verified as the
/// method's Read says, the watcher being a source, never an authority.
pub async fn resolve_from_watcher(
    id: &str,
    watcher: &str,
) -> Result<(Vid, serde_json::Value), VidError> {
    let scid = WebVHURL::parse_did_url(id)?.scid.clone();
    let base = watcher.trim_end_matches('/');
    let fetch = |path: String| async move {
        let r = reqwest::get(&path)
            .await
            .map_err(|e| VidError::Http(path.clone(), e))?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok::<Option<String>, VidError>(None);
        }
        Ok(Some(
            r.error_for_status()
                .map_err(|e| VidError::Http(path.clone(), e))?
                .text()
                .await
                .map_err(|e| VidError::Http(path, e))?,
        ))
    };
    let Some(log) = fetch(format!("{base}/log?scid={scid}")).await? else {
        return Err(VidError::ResolveVid("the watcher holds no copy of the log"));
    };
    let witness = fetch(format!("{base}/witness?scid={scid}")).await?;

    // the library resolves from files; the copy goes through two of them, briefly
    let dir = std::env::temp_dir().join(format!("tsp-watcher-{}-{scid}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| VidError::WebVHError(e.to_string()))?;
    let log_path = dir.join("did.jsonl");
    let witness_path = dir.join("did-witness.json");
    std::fs::write(&log_path, &log).map_err(|e| VidError::WebVHError(e.to_string()))?;
    if let Some(w) = &witness {
        std::fs::write(&witness_path, w).map_err(|e| VidError::WebVHError(e.to_string()))?;
    }
    let mut webvh = DIDWebVHState::default();
    let outcome = webvh
        .resolve_file(
            id,
            log_path.to_str().unwrap_or_default(),
            witness.as_ref().and(witness_path.to_str()),
        )
        .await;
    let _ = std::fs::remove_dir_all(&dir);
    let (log_entry, meta_data) = outcome?;
    let served_versions = versions_of(&log);
    if served_versions.last().map(String::as_str) != Some(meta_data.version_id.as_str()) {
        return Err(VidError::ResolveVid(
            "the watcher's copy has an entry that does not verify",
        ));
    }
    if meta_data.deactivated {
        return Err(VidError::Deactivated(id.to_string()));
    }
    let did_doc: DidDocument = serde_json::from_value(log_entry.get_state().to_owned())?;
    let params = log_entry.get_parameters();
    let metadata = WebvhMetadata {
        watchers: meta_data.watchers.clone().unwrap_or_default(),
        update_keys: params.update_keys.as_ref().map(|keys| (**keys).clone()),
        next_key_hashes: params.next_key_hashes.as_ref().map(|h| (**h).clone()),
        webvh_meta_data: meta_data,
        served_versions,
    };
    Ok((
        resolve_document(did_doc, id)?,
        serde_json::to_value(&metadata)?,
    ))
}

/// Options for the first log entry of a `did:webvh` beyond the keys: the parameters a host
/// may require of an identity it admits.
#[derive(Clone, Debug, Default)]
pub struct WebvhOptions {
    /// The witness keys the first entry names, as `did:key`s, any one of whose proof it must
    /// carry: the `witness` parameter with these witnesses and threshold 1.
    pub witnesses: Vec<String>,
    /// Watcher URLs for the `watchers` parameter.
    pub watchers: Vec<String>,
    /// The `portable` parameter: whether the DID may later move to another web location.
    pub portable: bool,
}

/// Creates a default WebVH DID that can be used with TSP. The two update keys are made in
/// `area` and stay there; see [`WebvhKeys`].
///
/// did_path: Server path to use as the base for the DID ID (expects this to be server.name/path)
/// transport: URL to use for the service record
///
/// # Returns
/// * VID Record - contains key info
/// * The Genesis Log Entry record for WebVH DID's
/// * WebvhKeys naming the current and next update keys
pub async fn create_webvh(
    area: &dyn SecureArea,
    did_path: &str,
    transport: Url,
) -> Result<(OwnedVid, Value, WebvhKeys), VidError> {
    create_webvh_with(area, did_path, transport, WebvhOptions::default()).await
}

/// [`create_webvh`] with explicit [`WebvhOptions`].
pub async fn create_webvh_with(
    area: &dyn SecureArea,
    did_path: &str,
    transport: Url,
    options: WebvhOptions,
) -> Result<(OwnedVid, Value, WebvhKeys), VidError> {
    // the DID with the SCID placeholder, as the method's create step starts from
    let path_url = Url::parse(&["http://", did_path].concat())?;
    let webvh_url = WebVHURL::parse_url(&path_url)?;
    let placeholder_did = webvh_url.to_string();

    let mut vid = OwnedVid::bind(placeholder_did.clone(), transport);

    // the update key and its committed successor, made where they will live
    let update = area.create_key(None, crate::KeyType::Ed25519)?;
    let next = area.create_key(None, crate::KeyType::Ed25519)?;

    let mut params = Map::new();
    params.insert(
        "nextKeyHashes".into(),
        json!([entry::key_hash(&next.alias)]),
    );
    if options.portable {
        params.insert("portable".into(), json!(true));
    }
    if !options.witnesses.is_empty() {
        let list: Vec<Value> = options
            .witnesses
            .iter()
            .map(|w| json!({ "id": w }))
            .collect();
        params.insert(
            "witness".into(),
            json!({ "threshold": 1, "witnesses": list }),
        );
    }
    if !options.watchers.is_empty() {
        params.insert("watchers".into(), json!(options.watchers));
    }

    let did_doc = vid_to_did_document(vid.vid());
    let state = did_doc
        .as_object()
        .cloned()
        .ok_or_else(|| VidError::InternalError("DID document is not an object".into()))?;

    let signer = |data: &[u8]| area.sign(&update.alias, data);
    let genesis = entry::first_entry(
        &placeholder_did,
        &entry::now(),
        params,
        &update.alias,
        state,
        &signer,
    )?;

    let id = genesis
        .pointer("/state/id")
        .and_then(Value::as_str)
        .ok_or(VidError::InternalError(
            "Couldn't get DID ID from WebVH Log Entry".to_string(),
        ))?
        .to_string();
    vid.set_identifier(id)?;

    Ok((
        vid,
        genesis,
        WebvhKeys {
            update_kid: update.alias,
            next_update_kid: next.alias,
        },
    ))
}

/// Create the next log entry of an existing WebVH DID, resolving its current log first.
///
/// `update_kid` names, in `area`, the key authorised to sign this entry: under pre-rotation
/// the successor committed in the previous entry. A new successor is made in `area` and
/// committed in this entry.
pub async fn update(
    area: &dyn SecureArea,
    updated_document: Value,
    update_kid: &str,
) -> Result<UpdateResult, VidError> {
    let did_id =
        updated_document
            .get("id")
            .and_then(Value::as_str)
            .ok_or(VidError::InternalError(
                "Couldn't get DID ID from updated DID Document".to_string(),
            ))?;

    let mut webvh = DIDWebVHState::default();
    let (previous, _) = webvh.resolve(did_id, None).await?;
    let previous = serde_json::to_value(previous)?;

    update_after(area, &previous, updated_document, update_kid)
}

/// [`update`] given the previous entry, for a log the caller already holds.
pub fn update_after(
    area: &dyn SecureArea,
    previous: &Value,
    updated_document: Value,
    update_kid: &str,
) -> Result<UpdateResult, VidError> {
    update_after_with(area, previous, updated_document, update_kid, Map::new())
}

/// [`update_after`] with further parameters for the entry: a new `witness` set, new
/// `watchers`. The update key hands over as always.
pub fn update_after_with(
    area: &dyn SecureArea,
    previous: &Value,
    updated_document: Value,
    update_kid: &str,
    mut params: Map<String, Value>,
) -> Result<UpdateResult, VidError> {
    let next = area.create_key(None, crate::KeyType::Ed25519)?;

    params.insert("updateKeys".into(), json!([update_kid]));
    params.insert(
        "nextKeyHashes".into(),
        json!([entry::key_hash(&next.alias)]),
    );

    let state = updated_document
        .as_object()
        .cloned()
        .ok_or_else(|| VidError::InternalError("DID document is not an object".into()))?;

    let signer = |data: &[u8]| area.sign(update_kid, data);
    let log_entry = entry::next_entry(
        previous,
        &entry::now_after(previous),
        params,
        state,
        update_kid,
        &signer,
    )?;

    Ok(UpdateResult {
        log_entry,
        current_update_kid: update_kid.to_string(),
        next_update_kid: next.alias,
    })
}

/// The two entries that end a log (spec §Deactivate, under pre-rotation): the first ends
/// pre-rotation, `nextKeyHashes: []` with `updateKeys` naming `update_kid`, the key the
/// previous entry committed; the second is `deactivated: true` with `updateKeys: []`,
/// signed by the same key, active since the first. One entry with `deactivated: true` and
/// a named update key is valid by the specification's text and accepted by the DIF Python
/// resolver, but `didwebvh-rs` refuses a deactivation whose `updateKeys` is not empty, and
/// under pre-rotation emptying them takes the first entry; two entries are valid under all
/// three. No successor is made: nothing may follow. The document is unchanged.
pub fn deactivate_after(
    area: &dyn SecureArea,
    previous: &Value,
    update_kid: &str,
) -> Result<[Value; 2], VidError> {
    let state = previous
        .get("state")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| VidError::InternalError("previous entry has no document".into()))?;
    let signer = |data: &[u8]| area.sign(update_kid, data);

    let mut params = Map::new();
    params.insert("updateKeys".into(), json!([update_kid]));
    params.insert("nextKeyHashes".into(), json!([]));
    let end_pre_rotation = entry::next_entry(
        previous,
        &entry::now_after(previous),
        params,
        state.clone(),
        update_kid,
        &signer,
    )?;

    let mut params = Map::new();
    params.insert("updateKeys".into(), json!([]));
    params.insert("deactivated".into(), json!(true));
    let deactivation = entry::next_entry(
        &end_pre_rotation,
        &entry::now_after(&end_pre_rotation),
        params,
        state,
        update_kid,
        &signer,
    )?;

    Ok([end_pre_rotation, deactivation])
}

/// Building and signing log entries (spec §Create, §Update, §Entry Hash Generation,
/// §Pre-Rotation), with the signature asked of a secure area.
pub mod entry {
    use crate::SecureAreaError;
    use crate::vid::VidError;
    use serde_json::{Map, Value, json};
    use sha2::{Digest, Sha256};

    pub const METHOD: &str = "did:webvh:1.0";

    pub type Signer<'a> = dyn Fn(&[u8]) -> Result<Vec<u8>, SecureAreaError> + 'a;

    /// JCS (RFC 8785) canonical form of a JSON value.
    pub fn jcs(value: &Value) -> String {
        serde_json_canonicalizer::to_string(value)
            .expect("a serde_json::Value always canonicalises")
    }

    /// `base58btc(multihash(sha256(bytes)))`: SCIDs and entry hashes.
    pub fn multihash_b58(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut mh = Vec::with_capacity(34);
        mh.push(0x12);
        mh.push(0x20);
        mh.extend_from_slice(&digest);
        bs58::encode(mh).into_string()
    }

    /// The pre-rotation hash of a multikey: what goes in `nextKeyHashes`.
    pub fn key_hash(multikey: &str) -> String {
        multihash_b58(multikey.as_bytes())
    }

    /// `did:key:<mb>#<mb>`, the verification method form the method requires.
    pub fn verification_method(multikey: &str) -> String {
        format!("did:key:{multikey}#{multikey}")
    }

    /// The current time as the method writes it, whole seconds, UTC.
    pub fn now() -> String {
        format_utc(chrono::Utc::now().timestamp())
    }

    /// Strictly after `previous`'s `versionTime`, and not in the future: a resolver refuses
    /// both. An entry made within the same second as the previous one waits for the next.
    pub fn now_after(previous: &Value) -> String {
        let prev = previous
            .get("versionTime")
            .and_then(Value::as_str)
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.timestamp())
            .unwrap_or(0);
        let mut now = chrono::Utc::now().timestamp();
        if now <= prev {
            std::thread::sleep(std::time::Duration::from_millis(
                ((prev + 1 - now) as u64) * 1000 + 50,
            ));
            now = chrono::Utc::now().timestamp();
        }
        format_utc(now.max(prev + 1))
    }

    fn format_utc(secs: i64) -> String {
        chrono::DateTime::from_timestamp(secs, 0)
            .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_default()
    }

    /// An `eddsa-jcs-2022` proof over `document`, which must not already contain `proof`,
    /// by the key `multikey`, whose signature `signer` provides.
    pub fn proof(
        document: &Map<String, Value>,
        multikey: &str,
        created: &str,
        signer: &Signer<'_>,
    ) -> Result<Value, SecureAreaError> {
        let options = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": created,
            "verificationMethod": verification_method(multikey),
            "proofPurpose": "assertionMethod",
        });
        let options_hash = Sha256::digest(jcs(&options).as_bytes());
        let doc_hash = Sha256::digest(jcs(&Value::Object(document.clone())).as_bytes());
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&options_hash);
        data[32..].copy_from_slice(&doc_hash);
        let signature = signer(&data)?;
        let mut p = options.as_object().cloned().expect("an object");
        p.insert(
            "proofValue".into(),
            Value::String(format!("z{}", bs58::encode(signature).into_string())),
        );
        Ok(Value::Object(p))
    }

    /// Build and sign a first entry. `placeholder_did` holds the literal `{SCID}`; `params`
    /// carries everything beyond `method`, `scid` and `updateKeys`, which are set here;
    /// `state` is the document for the placeholder DID. The SCID is the hash of the
    /// preliminary entry and replaces the placeholder everywhere.
    pub fn first_entry(
        placeholder_did: &str,
        version_time: &str,
        mut params: Map<String, Value>,
        update_multikey: &str,
        state: Map<String, Value>,
        signer: &Signer<'_>,
    ) -> Result<Value, VidError> {
        if !placeholder_did.contains("{SCID}") {
            return Err(VidError::InternalError(
                "a first entry starts from a DID with the {SCID} placeholder".into(),
            ));
        }
        params.insert("method".into(), json!(METHOD));
        params.insert("scid".into(), json!("{SCID}"));
        params.insert("updateKeys".into(), json!([update_multikey]));

        let mut pre = Map::new();
        pre.insert("versionId".into(), json!("{SCID}"));
        pre.insert("versionTime".into(), json!(version_time));
        pre.insert("parameters".into(), Value::Object(params));
        pre.insert("state".into(), Value::Object(state));

        let pre_text = jcs(&Value::Object(pre));
        let scid = multihash_b58(pre_text.as_bytes());
        let mut entry: Map<String, Value> =
            serde_json::from_str(&pre_text.replace("{SCID}", &scid))
                .map_err(|e| VidError::InternalError(format!("substituted entry: {e}")))?;
        let entry_hash = multihash_b58(jcs(&Value::Object(entry.clone())).as_bytes());
        entry.insert("versionId".into(), json!(format!("1-{entry_hash}")));
        let p = proof(&entry, update_multikey, version_time, signer)?;
        entry.insert("proof".into(), json!([p]));
        Ok(Value::Object(entry))
    }

    /// Build and sign the entry after `previous`: `params` are this entry's overrides,
    /// `state` the new document, `update_multikey` the key that signs, which under
    /// pre-rotation must be in `params.updateKeys`.
    pub fn next_entry(
        previous: &Value,
        version_time: &str,
        params: Map<String, Value>,
        state: Map<String, Value>,
        update_multikey: &str,
        signer: &Signer<'_>,
    ) -> Result<Value, VidError> {
        let prev_id = previous
            .get("versionId")
            .and_then(Value::as_str)
            .ok_or_else(|| VidError::InternalError("previous entry has no versionId".into()))?;
        let n: u64 = prev_id
            .split('-')
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| VidError::InternalError("previous versionId is malformed".into()))?;
        let mut pre = Map::new();
        pre.insert("versionId".into(), json!(prev_id));
        pre.insert("versionTime".into(), json!(version_time));
        pre.insert("parameters".into(), Value::Object(params));
        pre.insert("state".into(), Value::Object(state));
        let entry_hash = multihash_b58(jcs(&Value::Object(pre.clone())).as_bytes());
        pre.insert("versionId".into(), json!(format!("{}-{entry_hash}", n + 1)));
        let p = proof(&pre, update_multikey, version_time, signer)?;
        pre.insert("proof".into(), json!([p]));
        Ok(Value::Object(pre))
    }
}

#[cfg(feature = "async")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecureArea, SoftwareSecureArea, definitions::VerifiedVid};

    /// The log as `did.jsonl`, in a file the library's resolver reads.
    fn write_log(entries: &[&Value]) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for e in entries {
            writeln!(f, "{e}").unwrap();
        }
        f
    }

    #[tokio::test]
    async fn a_first_entry_signed_behind_the_boundary_resolves() {
        let area = SoftwareSecureArea::new();
        let (vid, genesis, keys) = create_webvh(
            &area,
            "example.com/endpoint/alice",
            "tcp://example.com:1234".parse().unwrap(),
        )
        .await
        .unwrap();

        // the keys are in the area under their multikeys, and nowhere else
        assert!(keys.update_kid.starts_with("z6Mk"));
        assert!(keys.next_update_kid.starts_with("z6Mk"));
        assert_eq!(
            crate::secure_area::ed25519_multikey(&area.public_key(&keys.update_kid).unwrap()),
            keys.update_kid
        );
        assert_eq!(
            genesis["parameters"]["nextKeyHashes"][0],
            entry::key_hash(&keys.next_update_kid)
        );
        assert_eq!(genesis["parameters"]["updateKeys"][0], keys.update_kid);
        assert!(vid.identifier().starts_with("did:webvh:"));
        assert!(!vid.identifier().contains("{SCID}"));
        assert_eq!(genesis["state"]["id"], vid.identifier());

        // and the library, which only verifies, accepts it
        let log = write_log(&[&genesis]);
        let mut webvh = DIDWebVHState::default();
        let (resolved, _) = webvh
            .resolve_file(vid.identifier(), log.path().to_str().unwrap(), None)
            .await
            .unwrap();
        assert_eq!(resolved.get_state()["id"], vid.identifier());
        assert!(resolved.get_version_id().starts_with("1-"));
    }

    #[tokio::test]
    async fn a_later_entry_hands_the_update_key_over_and_resolves() {
        let area = SoftwareSecureArea::new();
        let (vid, genesis, keys) = create_webvh(
            &area,
            "example.com/endpoint/bob",
            "tcp://example.com:1234".parse().unwrap(),
        )
        .await
        .unwrap();

        // a new transport, signed by the committed successor
        let new_vid = OwnedVid::bind(vid.identifier(), "tcp://example.com:4321".parse().unwrap());
        let doc = vid_to_did_document(new_vid.vid());
        let result = update_after(&area, &genesis, doc, &keys.next_update_kid).unwrap();
        assert_eq!(result.current_update_kid, keys.next_update_kid);
        assert_ne!(result.next_update_kid, keys.next_update_kid);
        assert!(area.has_key(&result.next_update_kid));
        assert!(
            result.log_entry["versionId"]
                .as_str()
                .unwrap()
                .starts_with("2-")
        );

        let log = write_log(&[&genesis, &result.log_entry]);
        let mut webvh = DIDWebVHState::default();
        let (resolved, _) = webvh
            .resolve_file(vid.identifier(), log.path().to_str().unwrap(), None)
            .await
            .unwrap();
        assert!(resolved.get_version_id().starts_with("2-"));
        assert_eq!(
            resolved.get_state()["service"][0]["serviceEndpoint"],
            "tcp://example.com:4321"
        );

        // a key the previous entry did not commit to: the resolver stops before that entry
        let stranger = area.create_key(None, crate::KeyType::Ed25519).unwrap();
        let doc = vid_to_did_document(new_vid.vid());
        let forged = update_after(&area, &genesis, doc, &stranger.alias).unwrap();
        let log = write_log(&[&genesis, &forged.log_entry]);
        let mut webvh = DIDWebVHState::default();
        let outcome = webvh
            .resolve_file(vid.identifier(), log.path().to_str().unwrap(), None)
            .await;
        assert!(
            outcome.is_err() || outcome.unwrap().0.get_version_id().starts_with("1-"),
            "the forged entry must not resolve"
        );
    }

    #[tokio::test]
    async fn a_deactivation_ends_the_log_and_nothing_follows() {
        let area = SoftwareSecureArea::new();
        let (vid, genesis, keys) = create_webvh(
            &area,
            "example.com/endpoint/dave",
            "tcp://example.com:1234".parse().unwrap(),
        )
        .await
        .unwrap();
        let [ended, last] = deactivate_after(&area, &genesis, &keys.next_update_kid).unwrap();
        assert_eq!(ended["parameters"]["nextKeyHashes"], serde_json::json!([]));
        assert_eq!(last["parameters"]["deactivated"], true);
        assert_eq!(last["parameters"]["updateKeys"], serde_json::json!([]));

        let log = write_log(&[&genesis, &ended, &last]);
        let mut webvh = DIDWebVHState::default();
        let (resolved, meta) = webvh
            .resolve_file(vid.identifier(), log.path().to_str().unwrap(), None)
            .await
            .unwrap();
        assert!(resolved.get_version_id().starts_with("3-"));
        assert!(meta.deactivated);

        // nothing may follow: a further entry, however signed, does not resolve past the end
        let doc = vid_to_did_document(vid.vid());
        let after = update_after(&area, &last, doc, &keys.next_update_kid).unwrap();
        let log = write_log(&[&genesis, &ended, &last, &after.log_entry]);
        let mut webvh = DIDWebVHState::default();
        let outcome = webvh
            .resolve_file(vid.identifier(), log.path().to_str().unwrap(), None)
            .await;
        assert!(
            outcome.is_err() || outcome.unwrap().1.deactivated,
            "an entry after deactivation must not resolve"
        );
    }

    #[tokio::test]
    async fn a_witness_change_lands_in_the_entry_and_the_key_hands_over() {
        let area = SoftwareSecureArea::new();
        let (vid, genesis, keys) = create_webvh_with(
            &area,
            "example.com/t/erin",
            "https://p.example/x".parse().unwrap(),
            WebvhOptions {
                witnesses: vec!["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into()],
                watchers: vec![],
                portable: true,
            },
        )
        .await
        .unwrap();
        let mut params = Map::new();
        params.insert(
            "witness".into(),
            json!({ "threshold": 1, "witnesses": [{ "id": "did:key:z6MktHhPycwsZ2yuckDzftLJqn7EqGrUn9AqnZdhERqPfUSH" }] }),
        );
        let doc = vid_to_did_document(vid.vid());
        let result =
            update_after_with(&area, &genesis, doc, &keys.next_update_kid, params).unwrap();
        let p = &result.log_entry["parameters"];
        assert_eq!(
            p["witness"]["witnesses"][0]["id"],
            "did:key:z6MktHhPycwsZ2yuckDzftLJqn7EqGrUn9AqnZdhERqPfUSH"
        );
        assert_eq!(p["updateKeys"][0], keys.next_update_kid);
        assert_eq!(
            p["nextKeyHashes"][0],
            entry::key_hash(&result.next_update_kid)
        );
    }

    #[test]
    fn the_served_versions_are_the_entries_in_order() {
        let log = "{\"versionId\":\"1-a\"}\n{\"versionId\":\"2-b\"}\n\n";
        assert_eq!(versions_of(log), vec!["1-a", "2-b"]);
        assert!(versions_of("").is_empty());
        assert!(versions_of("not json\n").is_empty());
    }

    #[test]
    fn a_watchers_copy_is_the_same_behind_ahead_or_forked() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        use WatcherComparison::*;
        assert_eq!(
            compare_with_watcher(&v(&["1-a", "2-b"]), &v(&["1-a", "2-b"])),
            Same
        );
        assert_eq!(
            compare_with_watcher(&v(&["1-a", "2-b"]), &v(&["1-a"])),
            ServerAhead
        );
        assert_eq!(
            compare_with_watcher(&v(&["1-a"]), &v(&["1-a", "2-b"])),
            WatcherAhead
        );
        assert_eq!(
            compare_with_watcher(&v(&["1-a", "2-x"]), &v(&["1-a", "2-b"])),
            Fork
        );
        assert_eq!(compare_with_watcher(&v(&["1-a"]), &v(&[])), WatcherEmpty);
    }

    #[tokio::test]
    async fn options_land_in_the_parameters() {
        let area = SoftwareSecureArea::new();
        let (_, genesis, _) = create_webvh_with(
            &area,
            "example.com/t/carol",
            "https://p.example/x".parse().unwrap(),
            WebvhOptions {
                witnesses: vec!["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into()],
                watchers: vec!["https://watch.example".into()],
                portable: true,
            },
        )
        .await
        .unwrap();
        let p = &genesis["parameters"];
        assert_eq!(p["portable"], true);
        assert_eq!(p["witness"]["threshold"], 1);
        assert_eq!(p["watchers"][0], "https://watch.example");
        assert_eq!(p["method"], "did:webvh:1.0");
    }
}
