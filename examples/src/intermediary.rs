use axum::{
    Router,
    body::Bytes,
    extract::{Path, State, WebSocketUpgrade, ws::Message},
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
use reqwest::header;
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
    AsyncSecureStore, OwnedVid, ReceivedRelationshipDelivery, ReceivedRelationshipForm,
    ReceivedTspMessage, VerifiedVid, cesr, definitions::Digest, transport,
    vid::vid_to_did_document,
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

    // Generate PIV
    let did = format!("did:web:{}", args.domain.replace(":", "%3A"));
    let transport =
        Url::parse(format!("https://{}/transport/{did}", args.domain).as_str()).unwrap();
    let private_vid = OwnedVid::bind(did.clone(), transport);
    let did_doc = vid_to_did_document(private_vid.vid()).to_string();

    let db = AsyncSecureStore::new();
    db.add_private_vid(private_vid, None).unwrap();

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
                for (_, buf) in buffers.iter_mut() {
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
        .route(
            "/.well-known/did.json",
            get(async || ([(header::CONTENT_TYPE, "application/json")], did_doc)),
        )
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
    Path(did): Path<String>,
    body: Bytes,
) -> Response {
    let mut message: BytesMut = body.into();

    let Ok((sender, Some(receiver))) = cesr::get_sender_receiver(&message) else {
        tracing::error!(
            "{} encountered invalid message, receiver missing",
            state.domain,
        );

        return (StatusCode::BAD_REQUEST, "invalid message, receiver missing").into_response();
    };

    let Ok(sender) = std::str::from_utf8(sender) else {
        return (StatusCode::BAD_REQUEST, "invalid sender").into_response();
    };
    let sender = sender.to_string();

    let Ok(receiver) = std::str::from_utf8(receiver) else {
        return (StatusCode::BAD_REQUEST, "invalid receiver").into_response();
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
        return (StatusCode::BAD_REQUEST, "error verifying VID").into_response();
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
                state.log_error(e.to_string()).await;
                return (StatusCode::BAD_REQUEST, "error accepting relationship").into_response();
            }

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
                    return (StatusCode::BAD_REQUEST, "error verifying next hop VID")
                        .into_response();
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
                    return (StatusCode::BAD_REQUEST, "error forwarding message").into_response();
                }
                tracing::trace!("Releasing lock guard on AsyncStore");
                drop(store);
            }

            let (transport, message) = match state.db.read().await.make_next_routed_message(
                &next_hop,
                route,
                &opaque_payload,
            ) {
                Ok(res) => res,
                Err(e) => {
                    state.log_error(e.to_string()).await;
                    return (StatusCode::BAD_REQUEST, "error forwarding message").into_response();
                }
            };

            if transport.host_str() == Some(&state.domain) {
                tracing::debug!("Forwarding message to myself...");
                return Box::pin(new_message(State(state), Path(did), message.into())).await;
            } else {
                tracing::debug!("Sending forwarded message...");

                if let Err(e) = transport::send_message(&transport, &message).await {
                    state.log_error(e.to_string()).await;
                    return (StatusCode::BAD_REQUEST, "error sending forwarded message")
                        .into_response();
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
    Path(did): Path<String>,
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
    Path(did): Path<String>,
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
    Path(did): Path<String>,
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
