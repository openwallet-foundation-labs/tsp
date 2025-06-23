use axum::{
    Router,
    body::Bytes,
    extract::{Path, State, WebSocketUpgrade, ws::Message},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use bytes::BytesMut;
use clap::Parser;
use futures::{sink::SinkExt, stream::StreamExt};
use reqwest::header;
use serde::Serialize;
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::{RwLock, broadcast};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp_sdk::{
    AsyncSecureStore, OwnedVid, ReceivedTspMessage, VerifiedVid, cesr, definitions::Digest,
    transport, vid::vid_to_did_document,
};
use url::Url;

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
}

struct IntermediaryState {
    domain: String,
    did: String,
    db: RwLock<AsyncSecureStore>,
    message_tx: broadcast::Sender<(String, Vec<u8>)>,
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

    let state = Arc::new(IntermediaryState {
        domain: args.domain.to_owned(),
        did,
        db: RwLock::new(db),
        message_tx: broadcast::channel(100).0,
        log: RwLock::new(VecDeque::with_capacity(MAX_LOG_LEN)),
        log_tx: broadcast::channel(100).0,
    });

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route("/transport/{did}", post(new_message).get(websocket_handler))
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
    Path(_did): Path<String>,
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
    let has_private_vid = state.db.read().await.has_private_vid(&receiver);
    if matches!(has_private_vid, Ok(true)) {
        tracing::debug!("verifying VID {sender} for {receiver}");

        if let Err(e) = state.verify_vid(&sender).await {
            tracing::error!("error verifying VID {sender}: {e}");
            return (StatusCode::BAD_REQUEST, "error verifying VID").into_response();
        }

        let handle_relationship_request = async |sender: String,
                                                 route: Option<Vec<Vec<u8>>>,
                                                 nested_vid: Option<String>,
                                                 thread_id: Digest|
               -> Result<(), tsp_sdk::Error> {
            if let Some(nested_vid) = nested_vid {
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
            } else {
                tracing::trace!("Received relationship request from {}", sender);
                let route: Option<Vec<&str>> = route.as_ref().map(|vec| {
                    vec.iter()
                        .map(|vid| std::str::from_utf8(vid).unwrap())
                        .collect()
                });
                tracing::trace!("Requesting read lock to accept relationship request");
                let store = state.db.read().await;
                tracing::trace!("Acquired read lock to accept relationship request");

                let (endpoint, message) = store.make_relationship_accept(
                    &receiver,
                    &sender,
                    thread_id,
                    route.as_deref(),
                )?;

                tracing::trace!("Dropped read lock to accept relationship request");
                drop(store);

                transport::send_message(&endpoint, &message).await?;

                Ok(())
            }
        };

        // yes, this must be a separate variable https://github.com/rust-lang/rust/issues/37612
        let res = state.db.read().await.open_message(message.as_mut());
        match res {
            Err(e) => {
                tracing::error!("received opening message from {sender}: {e}")
            }
            Ok(ReceivedTspMessage::GenericMessage { sender, .. }) => {
                tracing::error!("received generic message from {sender}")
            }
            Ok(ReceivedTspMessage::RequestRelationship {
                sender,
                route,
                nested_vid,
                thread_id,
            }) => {
                if let Err(e) = handle_relationship_request(
                    sender.clone(),
                    route,
                    nested_vid.clone(),
                    thread_id,
                )
                .await
                {
                    state.log_error(e.to_string()).await;
                    return (StatusCode::BAD_REQUEST, "error accepting relationship")
                        .into_response();
                }

                state.log(if let Some(nested_vid) = nested_vid {
                    format!(
                        "Accepted nested relationship request from {sender} with nested VID {nested_vid}"
                    )
                } else {
                    format!("Accepted relationship request from {sender}")
                }).await;
            }
            Ok(ReceivedTspMessage::AcceptRelationship { sender, .. }) => {
                tracing::error!("accept relationship message from {sender}")
            }
            Ok(ReceivedTspMessage::CancelRelationship { sender }) => {
                tracing::error!("cancel relationship message from {sender}")
            }
            Ok(ReceivedTspMessage::ForwardRequest {
                sender,
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

                    tracing::trace!("Acquiring read lock on AsyncStore");
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
                        return (StatusCode::BAD_REQUEST, "error forwarding message")
                            .into_response();
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
                        return (StatusCode::BAD_REQUEST, "error forwarding message")
                            .into_response();
                    }
                };

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
            Ok(ReceivedTspMessage::NewIdentifier { sender, new_vid }) => {
                tracing::error!("new identifier message from {sender}: {new_vid}")
            }
            Ok(ReceivedTspMessage::Referral {
                sender,
                referred_vid,
            }) => tracing::error!("referral from {sender}: {referred_vid}"),
            Ok(ReceivedTspMessage::PendingMessage { unknown_vid, .. }) => {
                tracing::error!("pending message message from unknown VID {unknown_vid}")
            }
        }
    } else {
        state
            .log(format!(
                "Forwarding message from  {sender} to {receiver} via WebSockets ({} bytes)",
                message.len()
            ))
            .await;
        // insert message in queue
        let _ = state
            .message_tx
            .send((receiver.to_owned(), Vec::from(message)));
    }

    StatusCode::OK.into_response()
}

/// Handle incoming websocket connections
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<IntermediaryState>>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    tracing::info!("{} listening for messages intended for {did}", state.domain);
    let mut messages_rx = state.message_tx.subscribe();

    ws.on_upgrade(|socket| {
        let (mut ws_send, _) = socket.split();

        async move {
            while let Ok((receiver, message)) = messages_rx.recv().await {
                if receiver == did {
                    tracing::debug!(
                        "{} forwarding message to {receiver}, {} bytes",
                        state.domain,
                        message.len()
                    );

                    let a = ws_send.send(Message::Binary(Bytes::from(message))).await;
                    if let Err(e) = a {
                        tracing::error!("Could not send via WS: {e}");
                    }
                }
            }
        }
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
