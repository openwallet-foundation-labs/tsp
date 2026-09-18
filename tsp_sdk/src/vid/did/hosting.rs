//! A controller's side of the `did:webvh` hosting service: the registry of witnesses, the
//! apply to a witness, the publish to the server, the notification to a watcher, and the
//! reads a controller makes to see its own entry served. The interface is `API.md` of the
//! vidsvc repository; the flows are flows 1 and 2 of the flows note: create, and change the
//! document. Keys are made and used in the secure area handed in and never seen here.

use crate::{
    OwnedVid, SecureArea,
    definitions::VerifiedVid,
    vid::{
        VidError,
        did::webvh::{self, WebvhKeys, WebvhOptions},
        vid_to_did_document,
    },
};
use didwebvh_rs::url::WebVHURL;
use serde_json::{Value, json};
use url::Url;

/// A witness registered for a prefix: its `did:key` and where its `POST /apply` is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredWitness {
    pub id: String,
    pub contact: String,
}

/// One hosting server, reached over HTTPS, or plain HTTP for a local one.
#[derive(Clone, Debug)]
pub struct Hosting {
    client: reqwest::Client,
    /// `https://vidsvc.com`, or `http://localhost:8080`
    origin: String,
}

fn refused(what: &str, status: reqwest::StatusCode, body: &Value) -> VidError {
    VidError::WebVHError(format!(
        "{what} refused: {} ({status})",
        body["reason"].as_str().unwrap_or("no reason")
    ))
}

fn unreachable(what: &str, e: reqwest::Error) -> VidError {
    VidError::WebVHError(format!("{what} unreachable: {e}"))
}

impl Hosting {
    /// `server` is the domain as it appears in DIDs, `vidsvc.com` or `localhost:8080`; a
    /// scheme may be given explicitly, `http://lvh.me:8080`.
    pub fn new(client: reqwest::Client, server: &str) -> Self {
        let origin = if server.starts_with("http://") || server.starts_with("https://") {
            server.trim_end_matches('/').to_string()
        } else if server.starts_with("localhost") || server.starts_with("127.0.0.1") {
            format!("http://{server}")
        } else {
            format!("https://{server}")
        };
        Self { client, origin }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.origin, path.trim_start_matches('/'))
    }

    /// The active witnesses registered for `prefix`, `/a/` or `/t/`, from the server's
    /// `witnesses.json`.
    pub async fn registry_witnesses(
        &self,
        prefix: &str,
    ) -> Result<Vec<RegisteredWitness>, VidError> {
        let directory: Value = self
            .client
            .get(self.url(".well-known/witnesses.json"))
            .send()
            .await
            .map_err(|e| unreachable("witness directory", e))?
            .error_for_status()
            .map_err(|e| VidError::WebVHError(format!("witness directory: {e}")))?
            .json()
            .await
            .map_err(|e| VidError::WebVHError(format!("witness directory is not JSON: {e}")))?;
        Ok(directory["witnesses"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter(|w| {
                        w["retired"].is_null()
                            && w["prefixes"]
                                .as_array()
                                .is_some_and(|p| p.iter().any(|x| x == prefix))
                    })
                    .filter_map(|w| {
                        Some(RegisteredWitness {
                            id: w["id"].as_str()?.to_string(),
                            contact: w["contact"].as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// `POST /apply` at a witness: the proof over the entry, one element of
    /// `did-witness.json`. `scid` is `None` for a first entry.
    pub async fn apply(
        &self,
        contact: &str,
        entry: &Value,
        scid: Option<&str>,
    ) -> Result<Value, VidError> {
        let response = self
            .client
            .post(contact)
            .json(&json!({ "type": "webvh.witness.apply", "entry": entry, "scid": scid }))
            .send()
            .await
            .map_err(|e| unreachable("witness", e))?;
        let status = response.status();
        let mut proof: Value = response
            .json()
            .await
            .map_err(|e| VidError::WebVHError(format!("witness answer is not JSON: {e}")))?;
        if !status.is_success() || proof["type"] != "webvh.witness.proof" {
            return Err(refused("witness", status, &proof));
        }
        proof.as_object_mut().map(|p| p.remove("type"));
        Ok(proof)
    }

    /// `POST /publish` at the server: the entry and its witness proof.
    pub async fn publish(&self, entry: &Value, proof: &Value) -> Result<(), VidError> {
        let response = self
            .client
            .post(self.url("publish"))
            .json(&json!({ "entry": entry, "witness": proof }))
            .send()
            .await
            .map_err(|e| unreachable("DID server", e))?;
        let status = response.status();
        if !status.is_success() {
            let body: Value = response.json().await.unwrap_or_default();
            return Err(refused("DID server", status, &body));
        }
        Ok(())
    }

    /// `POST /log?did=` at a watcher: its `result`, `new`, `extended`, `unchanged`, or
    /// what it found instead.
    pub async fn notify(&self, watcher: &str, did: &str) -> Result<String, VidError> {
        let url = format!("{}/log?did={did}", watcher.trim_end_matches('/'));
        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| unreachable("watcher", e))?;
        let status = response.status();
        let body: Value = response.json().await.unwrap_or_default();
        if !status.is_success() {
            return Err(VidError::WebVHError(format!("watcher answered {status}")));
        }
        Ok(body["result"].as_str().unwrap_or("").to_string())
    }

    /// The log as the DID's own URL serves it, `did.jsonl`, the bytes as fetched.
    pub async fn read_log(&self, did: &str) -> Result<String, VidError> {
        let url = WebVHURL::parse_did_url(did)?
            .get_http_url(Some("did.jsonl"))
            .map_err(|e| VidError::WebVHError(format!("log URL: {e}")))?;
        self.client
            .get(url)
            .send()
            .await
            .map_err(|e| unreachable("DID server", e))?
            .error_for_status()
            .map_err(|e| VidError::WebVHError(format!("log: {e}")))?
            .text()
            .await
            .map_err(|e| VidError::WebVHError(format!("log: {e}")))
    }

    /// The log as a watcher holds it, `GET /log?scid=`.
    pub async fn watcher_log(&self, watcher: &str, scid: &str) -> Result<String, VidError> {
        let url = format!("{}/log?scid={scid}", watcher.trim_end_matches('/'));
        self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| unreachable("watcher", e))?
            .error_for_status()
            .map_err(|e| VidError::WebVHError(format!("watcher log: {e}")))?
            .text()
            .await
            .map_err(|e| VidError::WebVHError(format!("watcher log: {e}")))
    }
}

/// What a created or updated identity leaves the caller with.
#[derive(Debug)]
pub struct Published {
    /// The VID, with its current keys in `area`.
    pub private_vid: OwnedVid,
    /// The entry that was published.
    pub entry: Value,
    /// The update key that signed the entry, and the successor it committed.
    pub keys: WebvhKeys,
    /// Each watcher notified, with its answer or the error.
    pub watchers: Vec<(String, Result<String, VidError>)>,
    /// After a later entry: the key that signed the version before it, which can author
    /// nothing after this one and is the caller's to delete (flow 2 step 7). `None` after a
    /// first entry.
    pub retired_update_kid: Option<String>,
}

/// Flow 1: create a DID under `prefix` on the server, witnessed by every witness registered
/// for the prefix with threshold one, portable, naming `watchers`; publish; notify the
/// watchers; read the entry back from the server.
pub async fn create_witnessed(
    area: &dyn SecureArea,
    hosting: &Hosting,
    server: &str,
    prefix: &str,
    name: &str,
    transport: Url,
    watchers: &[String],
) -> Result<Published, VidError> {
    let segment = prefix.trim_matches('/');
    if segment.is_empty() || segment.contains('/') {
        return Err(VidError::WebVHError(format!(
            "prefix must be one path segment like /a/, got {prefix:?}"
        )));
    }
    let prefix = format!("/{segment}/");
    let registered = hosting.registry_witnesses(&prefix).await?;
    let Some(first) = registered.first() else {
        return Err(VidError::WebVHError(format!(
            "the server registers no witness for {prefix}"
        )));
    };
    let contact = first.contact.clone();

    let (private_vid, entry, keys) = webvh::create_webvh_with(
        area,
        &format!("{server}/{segment}/{name}"),
        transport,
        WebvhOptions {
            witnesses: registered.iter().map(|w| w.id.clone()).collect(),
            watchers: watchers.to_vec(),
            portable: true,
        },
    )
    .await?;

    let proof = hosting.apply(&contact, &entry, None).await?;
    hosting.publish(&entry, &proof).await?;
    let did = private_vid.identifier().to_string();
    let mut notified = Vec::new();
    for w in watchers {
        notified.push((w.clone(), hosting.notify(w, &did).await));
    }
    // read back: the server serves what was published
    let served = hosting.read_log(&did).await?;
    if !served
        .lines()
        .any(|l| l.contains(entry["versionId"].as_str().unwrap_or("?")))
    {
        return Err(VidError::WebVHError(
            "the server does not serve the entry it accepted".into(),
        ));
    }

    Ok(Published {
        private_vid,
        entry,
        keys,
        watchers: notified,
        retired_update_kid: None,
    })
}

/// What a later entry changes: a new transport, new VID keys, or both.
#[derive(Clone, Debug, Default)]
pub struct Change {
    pub transport: Option<Url>,
    pub rotate_keys: bool,
}

/// Flow 2: a later entry. `update_kid` names, in `area`, the key committed by the previous
/// entry; the entry is applied to a registered witness of the log's own witness set,
/// published, the watchers the log names notified, and read back from the server and each
/// watcher. The old update key and the old VID keys are still in `area` afterwards: retiring
/// them is the caller's, once the read-back has held (flow 2 step 7).
pub async fn update_witnessed(
    area: &dyn SecureArea,
    hosting: &Hosting,
    current: &OwnedVid,
    update_kid: &str,
    change: Change,
    extra_watchers: &[String],
) -> Result<Published, VidError> {
    let did = current.identifier().to_string();
    if change.transport.is_none() && !change.rotate_keys {
        return Err(VidError::WebVHError("nothing to change".into()));
    }

    // the log as served, verified: the witness set and watchers in force from the resolver,
    // the previous entry as the exact line the server serves, since the entry hash chains
    // from it and its updateKeys name the key to retire
    let mut state = didwebvh_rs::DIDWebVHState::default();
    let (_, meta) = state.resolve(&did, None).await?;
    let served_before = hosting.read_log(&did).await?;
    let previous: Value = served_before
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str(l).ok())
        .ok_or_else(|| VidError::WebVHError("the server serves no log for the DID".into()))?;
    let active_witnesses: Vec<String> = match &meta.witness {
        Some(didwebvh_rs::witness::Witnesses::Value { witnesses, .. }) => {
            witnesses.iter().map(|w| w.id.clone()).collect()
        }
        _ => Vec::new(),
    };
    let mut watchers: Vec<String> = meta.watchers.clone().unwrap_or_default();
    for w in extra_watchers {
        if !watchers.contains(w) {
            watchers.push(w.clone());
        }
    }

    // the new document: new transport, new keys, or both, under the same identifier
    let transport = change
        .transport
        .clone()
        .unwrap_or_else(|| current.endpoint().clone());
    let new_vid = if change.rotate_keys {
        OwnedVid::bind(&did, transport)
    } else {
        current.with_transport(transport)
    };
    let doc = vid_to_did_document(new_vid.vid());
    // the key that signed the previous entry: retired once this one is served
    let retired_update_kid = previous["parameters"]["updateKeys"][0]
        .as_str()
        .map(str::to_string)
        .filter(|k| k != update_kid);
    let result = webvh::update_after(area, &previous, doc, update_kid)?;
    let entry = result.log_entry;
    let scid = previous["parameters"]["scid"]
        .as_str()
        .map(str::to_string)
        .or_else(|| WebVHURL::parse_did_url(&did).ok().map(|u| u.scid.clone()))
        .ok_or_else(|| VidError::WebVHError("no SCID for the log".into()))?;

    // a registered witness of the set in force
    // the DID's path is `/<prefix>/<name>`; the prefix is what the registry keys on
    let prefix = WebVHURL::parse_did_url(&did)
        .ok()
        .and_then(|u| {
            u.path
                .trim_matches('/')
                .split('/')
                .next()
                .filter(|p| !p.is_empty())
                .map(|p| format!("/{p}/"))
        })
        .unwrap_or_else(|| "/a/".to_string());
    let registered = hosting.registry_witnesses(&prefix).await?;
    let Some(witness) = registered
        .iter()
        .find(|w| active_witnesses.contains(&w.id))
        .or(registered.first())
    else {
        return Err(VidError::WebVHError(format!(
            "the server registers no witness for {prefix}"
        )));
    };

    let proof = hosting.apply(&witness.contact, &entry, Some(&scid)).await?;
    hosting.publish(&entry, &proof).await?;
    let mut notified = Vec::new();
    for w in &watchers {
        notified.push((w.clone(), hosting.notify(w, &did).await));
    }

    // read back: the server and every watcher serve the same log, ending in this entry
    let served = hosting.read_log(&did).await?;
    let version_id = entry["versionId"].as_str().unwrap_or("?");
    if !served
        .lines()
        .last()
        .is_some_and(|l| l.contains(version_id))
    {
        return Err(VidError::WebVHError(
            "the server does not serve the entry it accepted".into(),
        ));
    }
    for (w, outcome) in notified.iter_mut() {
        if outcome.is_ok()
            && let Ok(held) = hosting.watcher_log(w, &scid).await
            && held.trim() != served.trim()
        {
            *outcome = Err(VidError::WebVHError(
                "the watcher holds a different log than the server serves".into(),
            ));
        }
    }

    Ok(Published {
        private_vid: new_vid,
        entry,
        keys: WebvhKeys {
            update_kid: result.current_update_kid,
            next_update_kid: result.next_update_kid,
        },
        watchers: notified,
        retired_update_kid,
    })
}
