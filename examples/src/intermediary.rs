use axum::{
    Router,
    body::Bytes,
    extract::{FromRequestParts, State, WebSocketUpgrade, ws::Message},
    http::{HeaderMap, StatusCode},
    response::{
        Html, IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::BytesMut;
use clap::Parser;
use futures::{sink::SinkExt, stream::Stream, stream::StreamExt};
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Notify, RwLock, RwLockWriteGuard, broadcast, mpsc};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp_sdk::{
    AskarSecureStorage, AsyncSecureStore, ReceivedRelationshipDelivery, ReceivedRelationshipForm,
    ReceivedTspMessage, SecureStorage, VerifiedVid, cesr, definitions::Digest, transport,
};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "demo-intermediary")]
#[command(about = "Host a TSP intermediary server", long_about = None)]
struct Cli {
    #[arg(
        short,
        long,
        default_value_t = 3001,
        help = "The port on which intermediary will be hosted (default is 3001)"
    )]
    port: u16,
    #[arg(index = 1, help = "e.g. \"p.teaspoon.world\" or \"localhost:3001\"")]
    domain: String,
    #[arg(
        long,
        default_value_t = 86400,
        help = "Message buffer TTL in seconds (default: 86400 = 24 hours)"
    )]
    buffer_ttl: u64,
    #[arg(
        long,
        default_value_t = 2000,
        help = "Max buffered messages per recipient (default: 2000)"
    )]
    buffer_max: usize,
    #[arg(
        long,
        default_value = "wallet",
        help = "Wallet name; stored at <name>.sqlite next to the working directory"
    )]
    wallet: String,
    #[arg(
        long,
        default_value = "did.teaspoon.world",
        help = "DID server hosting this intermediary's identity"
    )]
    did_server: String,
    #[arg(
        long,
        help = "Name to publish the identity under (default: the first label of the domain)"
    )]
    name: Option<String>,
    #[arg(
        long,
        help = "Bucket holding the wallet between runs. The wallet is kept on local disk while \
                running and written back whole on every change; the bucket is never mounted."
    )]
    bucket: Option<String>,
}

/// Read the wallet password.
///
/// In a deployment the service asks the secret store for it, authenticating as itself, so that
/// nothing sensitive appears in the deployment configuration. `TSP_WALLET_SECRET` names the
/// secret version to read. For local runs `TSP_WALLET_PASSWORD` supplies it directly.
///
/// There is deliberately no prompt: the service is headless, so a missing password must fail
/// at startup rather than block.
async fn wallet_password() -> String {
    if let Ok(resource) = std::env::var("TSP_WALLET_SECRET") {
        return fetch_secret(&resource)
            .await
            .expect("could not read the wallet password from the secret store");
    }

    if let Ok(password) = std::env::var("TSP_WALLET_PASSWORD") {
        return password;
    }

    panic!("no wallet password: set TSP_WALLET_SECRET or TSP_WALLET_PASSWORD");
}

/// An access token for the identity attached to this instance.
async fn access_token() -> Result<String, Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct Token {
        access_token: String,
    }

    let token: Token = http_client()
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(token.access_token)
}

/// The files that make up the wallet.
///
/// The second holds writes not yet folded into the first, so a copy is only complete with both.
/// The shared-memory file is deliberately absent: it is rebuilt on open, and restoring a stale
/// one would be worse than having none.
fn wallet_files(wallet: &str) -> [String; 2] {
    [format!("{wallet}.sqlite"), format!("{wallet}.sqlite-wal")]
}

/// The single object the wallet is kept in.
fn wallet_object(wallet: &str) -> String {
    format!("{wallet}.wallet")
}

/// Pack the wallet's files into one byte string, each preceded by its length.
///
/// The wallet is two files but must be stored as one object. A bucket writes an object completely
/// or not at all, so one object can never be found half-written; two objects written in sequence
/// can be, if the instance stops between them, leaving a database beside a log that does not
/// belong to it.
fn wallet_pack(parts: Vec<Vec<u8>>) -> Vec<u8> {
    let mut packed = Vec::new();

    for part in parts {
        packed.extend_from_slice(&(part.len() as u64).to_be_bytes());
        packed.extend_from_slice(&part);
    }

    packed
}

/// Undo `wallet_pack`.
fn wallet_unpack(packed: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut parts = Vec::new();
    let mut rest = packed;

    while !rest.is_empty() {
        let (header, body) = rest.split_at_checked(8)?;
        let length = u64::from_be_bytes(header.try_into().ok()?) as usize;
        let (part, remainder) = body.split_at_checked(length)?;

        parts.push(part.to_vec());
        rest = remainder;
    }

    Some(parts)
}

/// Fetch the wallet from the bucket, if there is one there.
///
/// The bucket holds whole objects, which is what it is good at, and the wallet is read and
/// written whole anyway. Nothing is mounted: the wallet lives on the instance's own disk while
/// running, and the bucket holds the copy that outlives it.
async fn wallet_download(bucket: &str, wallet: &str) -> Result<(), Box<dyn std::error::Error>> {
    let token = access_token().await?;
    let object = wallet_object(wallet);

    let response = http_client()
        .get(format!(
            "https://storage.googleapis.com/storage/v1/b/{bucket}/o/{object}?alt=media"
        ))
        .bearer_auth(&token)
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        tracing::info!("no wallet in {bucket} yet");

        return Ok(());
    }

    let packed = response.error_for_status()?.bytes().await?;
    let parts = wallet_unpack(&packed).ok_or("the stored wallet is malformed")?;

    for (file, part) in wallet_files(wallet).iter().zip(parts) {
        if part.is_empty() {
            let _ = tokio::fs::remove_file(file).await;

            continue;
        }

        tokio::fs::write(file, &part).await?;
        tracing::info!("restored {file} ({} bytes)", part.len());
    }

    Ok(())
}

/// Write the wallet back to the bucket as a single object.
async fn wallet_upload(bucket: &str, wallet: &str) -> Result<(), Box<dyn std::error::Error>> {
    let token = access_token().await?;
    let object = wallet_object(wallet);

    let mut parts = Vec::new();
    for file in wallet_files(wallet) {
        parts.push(tokio::fs::read(&file).await.unwrap_or_default());
    }

    http_client()
        .post(format!(
            "https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o?uploadType=media&name={object}"
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/octet-stream")
        .body(wallet_pack(parts))
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// Fetch a secret version, authenticating with the identity attached to this instance.
async fn fetch_secret(resource: &str) -> Result<String, Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct Payload {
        data: String,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Secret {
        payload: Payload,
    }

    let token = access_token().await?;

    let secret: Secret = http_client()
        .get(format!(
            "https://secretmanager.googleapis.com/v1/{resource}:access"
        ))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(String::from_utf8(base64ct::Base64::decode_vec(
        &secret.payload.data,
    )?)?)
}

/// Build a URL for the DID server.
///
/// Identity creation and resolution treat a local DID server as plain HTTP, so publishing has to
/// agree with them or it would post to a different place than the one clients read from.
fn did_server_url(did_server: &str, path: &str) -> String {
    let scheme = if did_server.starts_with("localhost") || did_server.starts_with("127.0.0.1") {
        "http"
    } else {
        "https"
    };

    format!("{scheme}://{did_server}/{path}")
}

/// An HTTP client that trusts the test certificate when built for local testing.
fn http_client() -> reqwest::Client {
    let client = reqwest::ClientBuilder::new()
        .user_agent(format!("TSP intermediary / {}", env!("CARGO_PKG_VERSION")));

    #[cfg(feature = "use_local_certificate")]
    let client = client.add_root_certificate({
        tracing::warn!("using the local root CA; for local testing only");
        reqwest::Certificate::from_pem(include_bytes!("../test/root-ca.pem")).unwrap()
    });

    client.build().unwrap()
}

/// The `{did}` path segment exactly as it appears in the URL.
///
/// An identifier can contain a percent-encoded colon, which the usual path extractor would
/// decode. Messages are buffered under the receiver identifier taken verbatim from the wire, so
/// decoding here would read under a different key than the one written, and buffered messages
/// would never be found. The raw text keeps both sides identical.
struct RawDid(String);

impl<S: Send + Sync> FromRequestParts<S> for RawDid {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Taken from the request path rather than through a path extractor: those decode the
        // capture while routing, which is exactly what has to be avoided here. Every route that
        // uses this puts the identifier in the final segment, and an identifier never contains a
        // slash, so the last segment is the whole of it.
        parts
            .uri
            .path()
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .map(|segment| RawDid(segment.to_string()))
            .ok_or(StatusCode::BAD_REQUEST)
    }
}

/// Alias under which the intermediary records its own identity.
const SELF_ALIAS: &str = "self";

/// Wallet key holding what is needed to publish the identity.
const PUBLISH_KEY: &str = "publish";

/// Wallet key recording the identity that has been published.
const PUBLISHED_KEY: &str = "published";

const PUBLISH_ATTEMPTS: u64 = 5;

/// Check the identity held in the wallet against the configuration and against what is published.
///
/// The wallet, the arguments and the DID server each carry part of the same fact, and a wrong
/// bucket or a copied deployment line can put them out of step. Running on regardless would mean
/// serving one identity while clients look up another, which is invisible from inside.
///
/// Returns whether the identity still needs publishing.
async fn check_identity(
    db: &AsyncSecureStore,
    did_server: &str,
    name: &str,
    domain: &str,
    did: &str,
) -> bool {
    // Where the identifier says it is published, which must be where this instance was told to
    // publish. Compared without a network call.
    let published_as = format!("{}:endpoint:{name}", did_server.replace(':', "%3A"));
    if !did.ends_with(&format!(":{published_as}")) {
        panic!(
            "the wallet holds {did}, which is not published as {published_as}. The wrong wallet \
             is configured, or --did-server and --name do not match it."
        );
    }

    // Where the identifier tells clients to send, which must be this instance.
    if let Ok(vid) = db.get_verified_vid(did) {
        let endpoint = vid.endpoint();
        let reachable_at = match endpoint.port() {
            Some(port) => format!("{}:{port}", endpoint.host_str().unwrap_or_default()),
            None => endpoint.host_str().unwrap_or_default().to_string(),
        };

        if reachable_at != domain {
            panic!(
                "the wallet holds {did}, which directs clients to {reachable_at}, but this \
                 instance was started for {domain}. The wrong wallet is configured, or the \
                 domain does not match it."
            );
        }
    }

    // What the DID server actually serves under this name. Only checked if it answers, so that an
    // unreachable DID server does not stop the intermediary from starting.
    let url = did_server_url(did_server, &format!("endpoint/{name}/did.json"));
    let Ok(response) = http_client().get(&url).send().await else {
        return false;
    };

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        tracing::warn!("{name} is not published at {did_server}; publishing it again");

        return true;
    }

    let registered = response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|doc| doc["id"].as_str().map(str::to_string));

    match registered {
        Some(registered) if registered == did => false,
        Some(registered) => panic!(
            "the name {name} at {did_server} is registered to {registered}, but this wallet holds \
             {did}. The wrong wallet is configured. Clients resolve the registered identity, so \
             this instance would be unreachable."
        ),
        None => false,
    }
}

/// Refuse to start if the name is already registered but the wallet holds no identity.
///
/// The name is fixed in configuration, so this can only mean the wallet has been lost or the
/// service was pointed at the wrong one. Creating a second identity under the same name would
/// leave the intermediary unresolvable, and every client that already trusts the registered one
/// would be silently stranded. Stopping makes it an operator decision.
async fn refuse_if_name_taken(did_server: &str, name: &str) {
    let url = did_server_url(did_server, &format!("endpoint/{name}/did.json"));

    let Ok(response) = http_client().get(&url).send().await else {
        // Unreachable at startup is the ordinary first-boot case, and publishing retries anyway.
        return;
    };

    if response.status().is_success() {
        panic!(
            "the name {name} is already registered at {did_server} but this wallet holds no \
             identity. The wallet is missing or the wrong one is configured. Restore it, or \
             choose a different name deliberately."
        );
    }
}

/// Create this intermediary's identity and record it, with everything needed to publish it.
async fn create_identity(
    vault: &AskarSecureStorage,
    db: &AsyncSecureStore,
    did_server: &str,
    name: &str,
    transport: Url,
) -> String {
    refuse_if_name_taken(did_server, name).await;

    let (private_vid, history, keys) =
        tsp_sdk::vid::did::webvh::create_webvh(&format!("{did_server}/endpoint/{name}"), transport)
            .await
            .expect("could not create an identity");

    let did = private_vid.identifier().to_string();

    // Both update keys are kept. The current one authorises the next log entry; the other is
    // committed in advance by hash. Without them the identity can never be updated again.
    db.add_secret_key(keys.update_kid.clone(), keys.update_key)
        .expect("could not store the update key");
    db.add_secret_key(keys.next_update_kid.clone(), keys.next_update_key)
        .expect("could not store the next update key");
    db.set_alias(format!("__next_update_kid:{did}"), keys.next_update_kid)
        .expect("could not record the next update key");

    // Kept so publishing can be retried on a later start without creating a second identity.
    vault
        .store_kv(
            PUBLISH_KEY,
            &serde_json::to_vec(&serde_json::json!({
                "vid": private_vid.vid(),
                "history": history,
            }))
            .expect("could not encode the identity"),
        )
        .await
        .expect("could not record the identity");

    db.add_private_vid(private_vid, None)
        .expect("could not store the identity");
    db.set_alias(SELF_ALIAS.to_string(), did.clone())
        .expect("could not record the identity");

    tracing::info!("created identity {did}");

    did
}

/// Publish the identity unless that has already been done.
///
/// Whether it was published is recorded in the wallet rather than tested by resolving it. The
/// wallet is the record of what this intermediary has done, resolution depends on the DID server
/// being reachable at startup, and a failed publish simply leaves the record unset so the next
/// start tries again.
async fn ensure_published(vault: &AskarSecureStorage, did_server: &str, did: &str) {
    if matches!(vault.get_kv(PUBLISHED_KEY).await, Ok(Some(ref published)) if published == did.as_bytes())
    {
        tracing::info!("identity {did} is already published");

        return;
    }

    let Ok(Some(stored)) = vault.get_kv(PUBLISH_KEY).await else {
        panic!("identity {did} does not resolve and the wallet holds nothing to publish with");
    };
    let stored: serde_json::Value =
        serde_json::from_slice(&stored).expect("could not decode the stored identity");

    let client = http_client();

    for attempt in 1..=PUBLISH_ATTEMPTS {
        match publish(&client, did_server, did, &stored).await {
            Ok(()) => {
                if let Err(e) = vault.store_kv(PUBLISHED_KEY, did.as_bytes()).await {
                    tracing::error!("published {did} but could not record that: {e}");
                }
                tracing::info!("published identity {did}");

                return;
            }
            Err(e) => {
                tracing::warn!("could not publish the identity (attempt {attempt}): {e}");
                tokio::time::sleep(Duration::from_secs(2 * attempt)).await;
            }
        }
    }

    // Not fatal. The identity is safe in the wallet, the next start tries again, and clients that
    // already know this intermediary can still reach it in the meantime.
    tracing::error!("could not publish identity {did}; it will be retried on the next start");
}

async fn publish(
    client: &reqwest::Client,
    did_server: &str,
    did: &str,
    stored: &serde_json::Value,
) -> Result<(), reqwest::Error> {
    client
        .post(did_server_url(did_server, "add-vid"))
        .json(&stored["vid"])
        .send()
        .await?
        .error_for_status()?;

    client
        .post(did_server_url(did_server, &format!("add-history/{did}")))
        .json(&stored["history"])
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// A buffered message waiting for delivery via SSE.
#[derive(Clone)]
struct BufferedMessage {
    /// Monotonic ID per recipient (for Last-Event-ID replay)
    id: u64,
    /// The raw CESR-encoded TSP message
    data: Bytes,
    /// When this message was buffered (for TTL expiry)
    timestamp: Instant,
}

/// Per-recipient message buffer with monotonic ID assignment.
struct RecipientBuffer {
    next_id: u64,
    messages: VecDeque<BufferedMessage>,
}

impl RecipientBuffer {
    fn new() -> Self {
        Self {
            next_id: 0,
            messages: VecDeque::new(),
        }
    }

    /// Add a message and return its assigned ID.
    fn push(&mut self, data: Bytes, max_size: usize) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.messages.push_back(BufferedMessage {
            id,
            data,
            timestamp: Instant::now(),
        });
        // Trim if over max size
        while self.messages.len() > max_size {
            self.messages.pop_front();
        }
        id
    }

    /// Get all messages after a given ID (for Last-Event-ID replay).
    fn messages_after(&self, after_id: Option<u64>) -> Vec<BufferedMessage> {
        match after_id {
            Some(id) => self
                .messages
                .iter()
                .filter(|m| m.id > id)
                .cloned()
                .collect(),
            None => self.messages.iter().cloned().collect(),
        }
    }

    /// Remove messages older than TTL.
    fn expire(&mut self, ttl: Duration) {
        self.messages.retain(|m| m.timestamp.elapsed() < ttl);
    }
}

/// Registry of SSE subscribers per recipient DID.
/// When a message arrives for a DID, only that DID's subscribers are notified.
struct SseSubscribers {
    /// Map from recipient DID to list of notification senders
    senders: HashMap<String, Vec<mpsc::Sender<u64>>>,
}

impl SseSubscribers {
    fn new() -> Self {
        Self {
            senders: HashMap::new(),
        }
    }

    /// Register a new SSE client for a DID. Returns a receiver for notifications.
    fn subscribe(&mut self, did: &str) -> mpsc::Receiver<u64> {
        let (tx, rx) = mpsc::channel(64);
        self.senders.entry(did.to_string()).or_default().push(tx);
        rx
    }

    /// Notify all SSE clients for a DID that a new message is available.
    fn notify(&mut self, did: &str, msg_id: u64) {
        if let Some(senders) = self.senders.get_mut(did) {
            // Remove closed channels (client disconnected)
            senders.retain(|tx| !tx.is_closed());
            for tx in senders.iter() {
                let _ = tx.try_send(msg_id);
            }
        }
    }

    /// Clean up empty entries.
    fn cleanup(&mut self) {
        self.senders.retain(|_, v| {
            v.retain(|tx| !tx.is_closed());
            !v.is_empty()
        });
    }
}

// Legacy: keep for WebSocket-based message forwarding (used by broadcast for
// the old WebSocket handler, log viewer, etc.)
#[derive(Clone)]
struct QueuedWsMessage {
    receiver: String,
    message: Message,
    id: Uuid,
}

impl QueuedWsMessage {
    pub fn new(message: impl Into<Bytes>, receiver: String) -> Self {
        QueuedWsMessage {
            message: Message::Binary(message.into()),
            receiver,
            id: Uuid::new_v4(),
        }
    }
}

struct IntermediaryState {
    domain: String,
    did: String,
    db: RwLock<AsyncSecureStore>,
    /// The wallet is the authoritative copy; `db` is a working copy of it held in memory.
    /// Anything that changes `db` is written back through here.
    vault: AskarSecureStorage,
    /// Where the wallet is kept between runs, and the name of its files on local disk.
    bucket: Option<String>,
    wallet: String,
    /// Held across a save so that two of them cannot interleave. Without it one save could read
    /// the wallet's files for storing while another is part way through writing them.
    saving: Mutex<()>,
    /// Per-recipient message buffers with monotonic IDs
    buffers: RwLock<HashMap<String, RecipientBuffer>>,
    /// Per-recipient SSE subscriber notifications
    subscribers: Mutex<SseSubscribers>,
    /// Buffer TTL (configurable via --buffer-ttl)
    buffer_ttl: Duration,
    /// Max messages per recipient (configurable via --buffer-max)
    buffer_max: usize,
    /// Legacy: broadcast for WebSocket handlers (log viewer, backward compat)
    message_tx: broadcast::Sender<QueuedWsMessage>,
    /// Legacy: old flat buffer (kept for backward compat during transition)
    message_buffer: RwLock<VecDeque<QueuedWsMessage>>,
    log: RwLock<VecDeque<LogEntry>>,
    log_tx: broadcast::Sender<String>,
}

#[derive(Clone, Serialize)]
struct LogEntry {
    text: String,
    timestamp: u64,
}

impl LogEntry {
    fn new(text: String) -> LogEntry {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        LogEntry { text, timestamp }
    }
}

impl IntermediaryState {
    async fn internal_log(&self, text: String) {
        let mut log = self.log.write().await;
        let entry = LogEntry::new(text);
        log.push_front(entry.clone());
        log.truncate(MAX_LOG_LEN);

        let json = serde_json::to_string(&entry).unwrap();
        let _ = self.log_tx.send(json);
    }

    /// Add an entry to the event log on the website
    async fn log(&self, text: String) {
        tracing::info!("{text}");
        self.internal_log(text).await;
    }

    /// Add an error entry to the event log on the website
    async fn log_error(&self, text: String) {
        tracing::error!("{text}");
        self.internal_log(text).await;
    }

    /// Write the in-memory copy back to the wallet.
    ///
    /// Called after anything that changes the store, so that a restart resumes from the same
    /// state. The whole wallet is rewritten each time, which is sound for a single instance;
    /// per-record writes are what several instances would need.
    async fn save(&self) {
        let _saving = self.saving.lock().await;

        let state = match self.db.read().await.export() {
            Ok(state) => state,
            Err(e) => {
                tracing::error!("could not export the wallet: {e}");
                return;
            }
        };

        if let Err(e) = self.vault.persist(state).await {
            tracing::error!("could not write the wallet: {e}");

            return;
        }

        // Written back whole, which is what a bucket does well and what the wallet is written as
        // anyway. If this fails the change survives only until the instance stops.
        if let Some(bucket) = &self.bucket
            && let Err(e) = wallet_upload(bucket, &self.wallet).await
        {
            tracing::error!("could not write the wallet to {bucket}: {e}");
        }
    }

    async fn verify_vid(&self, vid: &str) -> Result<(), tsp_sdk::Error> {
        if self.db.read().await.has_verified_vid(vid)? {
            tracing::trace!("VID {} already verified", vid);
            return Ok(());
        }

        tracing::trace!("Resolving vid, {vid}");
        let (verified_vid, metadata) = tsp_sdk::vid::verify_vid(vid).await?;

        tracing::trace!("storing resolved vid {vid}");
        // Immediately releases write lock
        self.db
            .write()
            .await
            .add_verified_vid(verified_vid, metadata)?;
        tracing::trace!("stored resolved vid: {vid}");
        self.save().await;

        Ok(())
    }
}

const MAX_LOG_LEN: usize = 10;
const MAX_BUFFER_LEN: usize = 100;
const SSE_KEEPALIVE_SECS: u64 = 15;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(false),
        )
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "demo_intermediary=trace,tsp=trace".into()),
        )
        .init();

    let args = Cli::parse();

    let name = args.name.clone().unwrap_or_else(|| {
        args.domain
            .split('.')
            .next()
            .unwrap_or("intermediary")
            .to_string()
    });

    // The transport carries a placeholder rather than the identifier. A did:webvh identifier is
    // derived from its own genesis log entry, so it is not known until the identity exists; the
    // placeholder is substituted with the recipient's identifier when a message is sent.
    let transport = Url::parse(&format!(
        "https://{}/transport/[vid_placeholder]",
        args.domain
    ))
    .unwrap();

    let password = wallet_password().await;

    // Starting without it would look like a first run and create a second identity, which the
    // startup checks would then refuse anyway. Failing here says why.
    if let Some(bucket) = &args.bucket
        && let Err(e) = wallet_download(bucket, &args.wallet).await
    {
        panic!("could not fetch the wallet from {bucket}: {e}");
    }

    let wallet_url = format!("sqlite://{}.sqlite", args.wallet);

    let (vault, db) = match AskarSecureStorage::open(&wallet_url, password.as_bytes()).await {
        Ok(vault) => {
            let (vids, aliases, keys) = vault.read().await.expect("could not read the wallet");
            let db = AsyncSecureStore::new();
            db.import(vids, aliases, keys)
                .expect("could not load the wallet");
            tracing::info!("opened wallet {}", args.wallet);

            (vault, db)
        }
        Err(_) => {
            let vault = AskarSecureStorage::new(&wallet_url, password.as_bytes())
                .await
                .expect("could not create a wallet");
            tracing::info!("created wallet {}", args.wallet);

            (vault, AsyncSecureStore::new())
        }
    };

    // The identity is created once and then reused for the life of the wallet. This is the whole
    // point of the wallet: without it the intermediary published a new key set on every start,
    // and every relationship a client held with it died.
    // An unknown alias resolves to itself, so the result only counts if the wallet actually holds
    // the private keys for it.
    let held = db
        .try_resolve_alias(SELF_ALIAS)
        .ok()
        .filter(|did| db.has_private_vid(did).unwrap_or(false));

    let did = match held {
        Some(did) => {
            tracing::info!("reusing the identity held in the wallet: {did}");

            if check_identity(&db, &args.did_server, &name, &args.domain, &did).await {
                // Recorded as published but no longer served, so let it be published again.
                let _ = vault.remove_kv(PUBLISHED_KEY).await;
            }

            did
        }
        None => create_identity(&vault, &db, &args.did_server, &name, transport).await,
    };

    // Publishing is checked on every start rather than only at creation, so that an identity
    // created while the DID server was unreachable is published later without operator action.
    ensure_published(&vault, &args.did_server, &did).await;

    vault
        .persist(db.export().expect("could not export the wallet"))
        .await
        .expect("could not write the wallet");

    if let Some(bucket) = &args.bucket {
        wallet_upload(bucket, &args.wallet)
            .await
            .expect("could not write the wallet to the bucket");
    }

    let buffer_ttl = Duration::from_secs(args.buffer_ttl);
    let buffer_max = args.buffer_max;

    tracing::info!(
        "Buffer config: TTL={}s ({}h), max={} per recipient",
        args.buffer_ttl,
        args.buffer_ttl / 3600,
        buffer_max
    );

    let state = Arc::new(IntermediaryState {
        domain: args.domain.to_owned(),
        did,
        db: RwLock::new(db),
        vault,
        bucket: args.bucket.clone(),
        wallet: args.wallet.clone(),
        saving: Mutex::new(()),
        buffers: RwLock::new(HashMap::new()),
        subscribers: Mutex::new(SseSubscribers::new()),
        buffer_ttl,
        buffer_max,
        message_tx: broadcast::channel(100).0,
        message_buffer: RwLock::new(VecDeque::with_capacity(100)),
        log: RwLock::new(VecDeque::with_capacity(MAX_LOG_LEN)),
        log_tx: broadcast::channel(100).0,
    });

    // Spawn buffer cleanup task
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let mut buffers = state.buffers.write().await;
                let mut expired_count = 0;
                for buf in buffers.values_mut() {
                    let before = buf.messages.len();
                    buf.expire(state.buffer_ttl);
                    expired_count += before - buf.messages.len();
                }
                // Note: do NOT remove empty buffers — the next_id counter
                // must survive so new messages get monotonically increasing IDs.
                // Otherwise, clients with Last-Event-ID will skip replayed messages
                // that got lower IDs after the counter reset.
                if expired_count > 0 {
                    tracing::debug!("Buffer cleanup: expired {expired_count} messages");
                }

                // Also cleanup subscriber entries for disconnected clients
                state.subscribers.lock().await.cleanup();
            }
        });
    }

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route("/transport/{did}", post(new_message).get(sse_handler))
        .route("/endpoint/{did}", post(new_message).get(sse_handler))
        .route("/messages/{did}", get(sse_handler))
        .route("/ack/{did}", post(ack_handler))
        // Legacy WebSocket endpoint for backward compatibility
        .route("/ws/transport/{did}", get(websocket_handler))
        .route("/ws/endpoint/{did}", get(websocket_handler))
        // The intermediary no longer serves its own DID document: a did:webvh identity resolves
        // at the DID server, which is what makes its key history verifiable.
        .route("/logs", get(log_websocket_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", args.port))
        .await
        .unwrap();
    tracing::info!(
        "intermediary {} listening on port {}",
        args.domain,
        args.port
    );

    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<Arc<IntermediaryState>>) -> Html<String> {
    let mut html = include_str!("../intermediary.html").to_string();
    html = html.replace("[[DOMAIN]]", &state.domain);
    html = html.replace("[[DID]]", &state.did);

    let log = state.log.read().await;
    let serialized_log = serde_json::to_string(&log.iter().collect::<Vec<_>>()).unwrap();
    html = html.replace("[[LOG_JSON]]", &serialized_log);

    Html(html)
}

async fn new_message(
    State(state): State<Arc<IntermediaryState>>,
    RawDid(did): RawDid,
    body: Bytes,
) -> Response {
    let mut message: BytesMut = body.into();

    // A message that fails verification or validation is discarded without a
    // distinguishing response: answering would tell whoever sent it what the
    // node knows and which of its checks failed (spec 3.7). The reason is
    // logged locally instead.
    fn discard(reason: &str) -> Response {
        tracing::debug!("discarded an incoming message: {reason}");

        StatusCode::OK.into_response()
    }

    let Ok((sender, Some(receiver))) = cesr::get_sender_receiver(&message) else {
        tracing::error!(
            "{} encountered invalid message, receiver missing",
            state.domain,
        );

        return discard("invalid message, receiver missing");
    };

    let Ok(sender) = std::str::from_utf8(sender) else {
        return discard("invalid sender");
    };
    let sender = sender.to_string();

    let Ok(receiver) = std::str::from_utf8(receiver) else {
        return discard("invalid receiver");
    };
    let receiver = receiver.to_string();

    // yes, this must be a separate variable https://github.com/rust-lang/rust/issues/37612
    let message_is_for_me = matches!(state.db.read().await.has_private_vid(&receiver), Ok(true));
    if !message_is_for_me {
        // Message is not for the intermediary — buffer it for delivery via SSE
        let msg_bytes: Bytes = message.freeze();

        state
            .log(format!(
                "Forwarding message from {sender} to {receiver} via SSE ({} bytes)",
                msg_bytes.len()
            ))
            .await;

        // Store in per-recipient buffer with monotonic ID
        let msg_id = {
            let mut buffers = state.buffers.write().await;
            let buf = buffers
                .entry(receiver.clone())
                .or_insert_with(RecipientBuffer::new);
            buf.push(msg_bytes.clone(), state.buffer_max)
        };

        // Notify SSE subscribers for this recipient
        state.subscribers.lock().await.notify(&receiver, msg_id);

        // Also push to legacy WebSocket broadcast (backward compat)
        let queued_message = QueuedWsMessage::new(msg_bytes, receiver);
        let mut buffer = state.message_buffer.write().await;
        buffer.push_back(queued_message.clone());
        while buffer.len() > MAX_BUFFER_LEN {
            buffer.pop_front();
        }
        drop(buffer);
        let _ = state.message_tx.send(queued_message);

        return StatusCode::OK.into_response();
    }

    tracing::debug!("verifying VID {sender} for {receiver}");
    if let Err(e) = state.verify_vid(&sender).await {
        tracing::error!("error verifying VID {sender}: {e}");
        return discard("error verifying VID");
    }

    let handle_relationship_request =
        async |sender: String, form, delivery, thread_id: Digest| -> Result<(), tsp_sdk::Error> {
            match (delivery, form) {
                (ReceivedRelationshipDelivery::Direct, ReceivedRelationshipForm::Direct) => {
                    tracing::trace!("Received relationship request from {}", sender);
                    let (endpoint, message) = state
                        .db
                        .read()
                        .await
                        .make_relationship_accept(&receiver, &sender, thread_id, None)?;

                    transport::send_message(&endpoint, &message).await?;
                    Ok(())
                }
                (
                    ReceivedRelationshipDelivery::Nested { nested_vid },
                    ReceivedRelationshipForm::Direct,
                ) => {
                    tracing::trace!("Requested new nested relationship");
                    let ((endpoint, message), my_new_nested_vid) = state
                        .db
                        .read()
                        .await
                        .make_nested_relationship_accept(&receiver, &nested_vid, thread_id)?;

                    transport::send_message(&endpoint, &message).await?;

                    tracing::debug!(
                        "Created nested {} for {nested_vid}",
                        my_new_nested_vid.vid().identifier()
                    );

                    Ok(())
                }
                (
                    ReceivedRelationshipDelivery::Direct,
                    ReceivedRelationshipForm::Parallel { new_vid, .. },
                )
                | (
                    ReceivedRelationshipDelivery::Nested { .. },
                    ReceivedRelationshipForm::Parallel { new_vid, .. },
                ) => {
                    tracing::error!("parallel relationship request from {sender}: {new_vid}");
                    Ok(())
                }
                (ReceivedRelationshipDelivery::Routed, _) => {
                    tracing::error!("routed relationship request from {sender}");
                    Ok(())
                }
            }
        };

    // yes, this must be a separate variable https://github.com/rust-lang/rust/issues/37612
    let res = state.db.read().await.open_message(message.as_mut());
    match res {
        Err(e) => {
            tracing::error!("error while opening message from {sender}: {e}")
        }
        Ok(ReceivedTspMessage::GenericMessage { sender, .. }) => {
            tracing::error!("received generic message from {sender}")
        }
        Ok(ReceivedTspMessage::ControlMessage { sender, .. }) => {
            tracing::error!("received an upper-layer control message from {sender}")
        }
        // padding exists to be ignored; an intermediary is not its destination
        // and there is nothing in it to forward
        Ok(ReceivedTspMessage::PaddingMessage { sender, .. }) => {
            tracing::debug!("discarding a padding message from {sender}")
        }
        Ok(ReceivedTspMessage::RequestRelationship {
            sender,
            receiver: _,
            thread_id,
            form,
            delivery,
        }) => {
            let nested_vid = match &delivery {
                ReceivedRelationshipDelivery::Nested { nested_vid } => Some(nested_vid.clone()),
                _ => None,
            };

            if let Err(e) =
                handle_relationship_request(sender.clone(), form, delivery, thread_id).await
            {
                state
                    .log_error(format!(
                        "error delivering relationship accept to {sender}: {e}"
                    ))
                    .await;
                return discard("error accepting relationship");
            }

            // The relationship now exists, so it has to outlive this process.
            state.save().await;

            state.log(if let Some(nested_vid) = nested_vid {
                    format!(
                        "Accepted nested relationship request from {sender} with nested VID {nested_vid}"
                    )
                } else {
                    format!("Accepted relationship request from {sender}")
                }).await;
        }
        Ok(ReceivedTspMessage::AcceptRelationship { sender, form, .. }) => match form {
            ReceivedRelationshipForm::Parallel { new_vid, .. } => {
                tracing::error!("parallel relationship accept from {sender}: {new_vid}")
            }
            ReceivedRelationshipForm::Direct => {
                tracing::error!("accept relationship message from {sender}")
            }
        },
        Ok(ReceivedTspMessage::CancelRelationship { sender, .. }) => {
            tracing::error!("cancel relationship message from {sender}")
        }
        Ok(ReceivedTspMessage::ForwardRequest {
            sender,
            receiver: _,
            next_hop,
            route,
            opaque_payload,
        }) => {
            if route.is_empty() {
                tracing::debug!("don't need to verify yourself");
            } else {
                tracing::debug!("verifying VID next hop {next_hop}");
                if let Err(e) = state.verify_vid(&next_hop).await {
                    tracing::error!("error verifying VID {next_hop}: {e}");
                    return discard("error verifying next hop VID");
                }

                let store = state.db.read().await;
                tracing::trace!(
                    "Sending relationship request from {} to {next_hop}",
                    state.did
                );
                if let Err(err) = store
                    .send_relationship_request(&state.did, &next_hop, None)
                    .await
                {
                    let err = format!("error forming relation with VID {next_hop}: {err}");
                    state.log_error(err).await;
                    return discard("error forwarding message");
                }
                tracing::trace!("Releasing lock guard on AsyncStore");
                drop(store);
                state.save().await;
            }

            let (transport, message) = match state.db.read().await.make_next_routed_message(
                &next_hop,
                route,
                &opaque_payload,
            ) {
                Ok(res) => res,
                Err(e) => {
                    state.log_error(e.to_string()).await;
                    return discard("error forwarding message");
                }
            };

            if transport.host_str() == Some(&state.domain) {
                tracing::debug!("Forwarding message to myself...");
                return Box::pin(new_message(State(state), RawDid(did), message.into())).await;
            } else {
                tracing::debug!("Sending forwarded message...");

                if let Err(e) = transport::send_message(&transport, &message).await {
                    state.log_error(e.to_string()).await;
                    return discard("error sending forwarded message");
                }

                state
                    .log(format!("Forwarded message from {sender} to {transport}",))
                    .await;
            }
        }
        Ok(ReceivedTspMessage::PendingMessage { unknown_vid, .. }) => {
            tracing::error!("pending message message from unknown VID {unknown_vid}")
        }
    }

    StatusCode::OK.into_response()
}

/// Handle SSE connections for message delivery.
///
/// Clients connect via GET /endpoint/{did} or GET /messages/{did}.
/// On connect: replay buffered messages since Last-Event-ID.
/// Then stream new messages as SSE events with monotonic IDs.
/// Server sends keepalive comments every 15 seconds to detect dead connections.
async fn sse_handler(
    State(state): State<Arc<IntermediaryState>>,
    RawDid(did): RawDid,
    headers: HeaderMap,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Parse Last-Event-ID for replay
    let last_event_id: Option<u64> = headers
        .get("Last-Event-ID")
        .or_else(|| headers.get("last-event-id"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    tracing::info!(
        "{} SSE client connected for {did}, last_event_id={:?}",
        state.domain,
        last_event_id
    );

    // Register as a subscriber for this DID
    let mut notify_rx = state.subscribers.lock().await.subscribe(&did);

    // Collect buffered messages to replay
    let replay_messages = {
        let buffers = state.buffers.read().await;
        if let Some(buf) = buffers.get(&did) {
            buf.messages_after(last_event_id)
        } else {
            Vec::new()
        }
    };

    if !replay_messages.is_empty() {
        tracing::info!(
            "{} replaying {} buffered messages for {did}",
            state.domain,
            replay_messages.len()
        );
    }

    let state_clone = Arc::clone(&state);
    let did_clone = did.clone();

    let stream = async_stream::stream! {
        // Phase 1: Replay buffered messages
        for msg in replay_messages {
            let encoded = Base64UrlUnpadded::encode_string(&msg.data);
            yield Ok(Event::default()
                .id(msg.id.to_string())
                .data(encoded));
        }

        // Phase 2: Stream new messages as they arrive
        loop {
            match notify_rx.recv().await {
                Some(msg_id) => {
                    let buffers = state_clone.buffers.read().await;
                    if let Some(buf) = buffers.get(&did_clone)
                        && let Some(msg) = buf.messages.iter().find(|m| m.id == msg_id) {
                            let encoded = Base64UrlUnpadded::encode_string(&msg.data);
                            yield Ok(Event::default()
                                .id(msg.id.to_string())
                                .data(encoded));
                        }
                }
                None => {
                    // Channel closed — subscriber was cleaned up
                    tracing::debug!("SSE subscriber channel closed for {}", did_clone);
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(SSE_KEEPALIVE_SECS))
            .text("keepalive"),
    )
}

/// Handle cumulative acknowledgment from a client.
///
/// The client sends `{"up_to_sequence": N}` to indicate it has processed
/// all messages up to and including sequence N. P deletes those messages
/// from the recipient's buffer.
async fn ack_handler(
    State(state): State<Arc<IntermediaryState>>,
    RawDid(did): RawDid,
    body: Bytes,
) -> Response {
    // Parse the ack body
    let ack: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Invalid ack body for {did}: {e}");
            return (StatusCode::BAD_REQUEST, "invalid JSON").into_response();
        }
    };

    let up_to = match ack.get("up_to_sequence").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => {
            return (StatusCode::BAD_REQUEST, "missing up_to_sequence").into_response();
        }
    };

    // Delete acked messages from the recipient buffer
    let deleted = {
        let mut buffers = state.buffers.write().await;
        if let Some(buf) = buffers.get_mut(&did) {
            let before = buf.messages.len();
            buf.messages.retain(|m| m.id > up_to);
            before - buf.messages.len()
        } else {
            0
        }
    };

    tracing::info!(
        recipient = %did,
        up_to_sequence = up_to,
        deleted = deleted,
        "Buffer ack received"
    );

    state
        .log(format!(
            "Ack from {did}: up_to_sequence={up_to}, deleted {deleted} messages"
        ))
        .await;

    StatusCode::OK.into_response()
}

/// Handle incoming websocket connections (legacy — kept for backward compatibility)
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<IntermediaryState>>,
    RawDid(did): RawDid,
) -> impl IntoResponse {
    tracing::info!("{} listening for messages intended for {did}", state.domain);
    let mut messages_rx = state.message_tx.subscribe();

    ws.on_upgrade(async |socket| {
        let (mut ws_send, mut ws_receiver) = socket.split();
        let shutdown_notify = Arc::new(Notify::new());
        let shutdown_notify_clone = shutdown_notify.clone();

        // read from WebSocket (detect disconnection)
        let recv_task = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_receiver.next().await {
                tracing::debug!("Received from client: {:?}", msg);
            }

            // notify sender task to shut down
            shutdown_notify_clone.notify_one();
        });

        // listen for new messages
        let send_task = tokio::spawn(async move {
            let mut send =
                async |message: QueuedWsMessage,
                       buffer: &mut RwLockWriteGuard<'_, VecDeque<QueuedWsMessage>>| {
                    let res = ws_send.send(message.message).await;
                    match res {
                        Ok(()) => {
                            // successfully delivered, remove message from buffer
                            buffer.retain(|m| m.id != message.id);
                            tracing::debug!("message buffer now contains {} messages", buffer.len());
                        }
                        Err(ref e) => tracing::error!("Could not send via WS: {e}"),
                    }
                    res
                };

            // send buffered messages for did (if any)
            let mut buffer = state.message_buffer.write().await;
            let messages = buffer
                .iter()
                .filter(|m| m.receiver == did)
                .cloned()
                .collect::<Vec<_>>();
            for message in messages {
                let _ = send(message, &mut buffer).await;
            }
            drop(buffer);

            loop {
                tokio::select! {
                    Ok(queued_message) = messages_rx.recv() => {
                        if queued_message.receiver == did {
                            tracing::debug!(
                                "{} forwarding message to {}",
                                state.domain,
                                queued_message.receiver
                            );
                            let mut buffer = state.message_buffer.write().await;
                            if send(queued_message, &mut buffer).await.is_err() {
                                break;
                            };
                            drop(buffer);
                        }
                    }
                    _ = shutdown_notify.notified() => {
                        // Shutdown signal from recv_task
                        break;
                    }
                }
            }
        });

        let _ = tokio::join!(recv_task, send_task);
    })
}

/// Handle incoming websocket connections for users viewing the web interface
async fn log_websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<IntermediaryState>>,
) -> impl IntoResponse {
    let mut logs_rx = state.log_tx.subscribe();

    ws.on_upgrade(|socket| {
        let (mut ws_send, _) = socket.split();

        async move {
            while let Ok(log) = logs_rx.recv().await {
                let _ = ws_send.send(Message::Text(log.into())).await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{wallet_pack, wallet_unpack};

    #[test]
    fn packing_a_wallet_is_reversible() {
        let parts = vec![b"a database".to_vec(), b"a log".to_vec()];

        assert_eq!(wallet_unpack(&wallet_pack(parts.clone())), Some(parts));
    }

    #[test]
    fn an_absent_log_survives_the_round_trip() {
        let parts = vec![b"a database".to_vec(), Vec::new()];

        assert_eq!(wallet_unpack(&wallet_pack(parts.clone())), Some(parts));
    }

    #[test]
    fn a_truncated_wallet_is_refused_rather_than_half_read() {
        let packed = wallet_pack(vec![b"a database".to_vec(), b"a log".to_vec()]);

        for length in 1..packed.len() {
            assert_ne!(
                wallet_unpack(&packed[..length]),
                Some(vec![b"a database".to_vec(), b"a log".to_vec()])
            );
        }
    }
}
