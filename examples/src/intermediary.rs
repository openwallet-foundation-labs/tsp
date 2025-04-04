use axum::{
    Router,
    body::Bytes,
    extract::{Path, State, WebSocketUpgrade, ws::Message},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use futures::{sink::SinkExt, stream::StreamExt};
use reqwest::header;
use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
};
use tokio::sync::{Mutex, broadcast};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp::{AsyncStore, OwnedVid, VerifiedVid, definitions::Digest, vid::vid_to_did_document};
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
    db: Mutex<AsyncStore>,
    tx: broadcast::Sender<(String, Vec<u8>)>,
    log: RwLock<VecDeque<String>>,
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

    let db = AsyncStore::new();
    db.add_private_vid(private_vid).unwrap();

    let state = Arc::new(IntermediaryState {
        domain: args.domain.to_owned(),
        did,
        db: Mutex::new(db),
        tx: broadcast::channel(100).0,
        log: RwLock::new(VecDeque::with_capacity(MAX_LOG_LEN)),
    });

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route("/transport/{did}", post(new_message).get(websocket_handler))
        .route(
            "/.well-known/did.json",
            get(async || ([(header::CONTENT_TYPE, "application/json")], did_doc)),
        )
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

    let log = state.log.read().unwrap();
    if log.is_empty() {
        html = html.replace("[[LOG]]", "<i>The log is empty</i>");
    } else {
        let text: Vec<String> = log.iter().map(|line| format!(
            "<div class=\"card container text-bg-light my-3\"><div class=\"card-body\">{line}</div></div>"
        )).collect();
        html = html.replace("[[LOG]]", &text.join(""));
    }

    Html(html)
}

async fn new_message(
    State(state): State<Arc<IntermediaryState>>,
    Path(_did): Path<String>,
    body: Bytes,
) -> Response {
    let Ok((sender, Some(receiver))) = tsp::cesr::get_sender_receiver(&body) else {
        tracing::error!(
            "{} encountered invalid message, receiver missing",
            state.domain,
        );

        return (StatusCode::BAD_REQUEST, "invalid message, receiver missing").into_response();
    };

    let Ok(sender) = std::str::from_utf8(sender) else {
        return (StatusCode::BAD_REQUEST, "invalid sender").into_response();
    };

    let Ok(receiver) = std::str::from_utf8(receiver) else {
        return (StatusCode::BAD_REQUEST, "invalid receiver").into_response();
    };

    let mut message: Vec<u8> = body.to_vec();

    let mut db = state.db.lock().await;

    if let Ok(true) = db.has_private_vid(receiver) {
        tracing::debug!("verifying VID {sender} for {receiver}");
        if let Err(e) = db.verify_vid(sender).await {
            tracing::error!("error verifying VID {sender}: {e}");
            return (StatusCode::BAD_REQUEST, "error verifying VID").into_response();
        }

        let handle_relationship_request = async |sender: String,
                                                 route: Option<Vec<Vec<u8>>>,
                                                 nested_vid: Option<String>,
                                                 thread_id: Digest|
               -> Result<(), tsp::Error> {
            if let Some(nested_vid) = nested_vid {
                let my_new_nested_vid = db
                    .send_nested_relationship_accept(receiver, &nested_vid, thread_id)
                    .await?;
                tracing::debug!(
                    "Created nested {} for {nested_vid}",
                    my_new_nested_vid.vid().identifier()
                );

                Ok(())
            } else {
                let route: Option<Vec<&str>> = route.as_ref().map(|vec| {
                    vec.iter()
                        .map(|vid| std::str::from_utf8(vid).unwrap())
                        .collect()
                });
                db.send_relationship_accept(receiver, &sender, thread_id, route.as_deref())
                    .await
            }
        };

        match db.open_message(&mut message) {
            Err(e) => {
                tracing::error!("received opening message from {sender}: {e}")
            }
            Ok(tsp::ReceivedTspMessage::GenericMessage { sender, .. }) => {
                tracing::error!("received generic message from {sender}")
            }
            Ok(tsp::ReceivedTspMessage::RequestRelationship {
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
                    let log = e.to_string();
                    tracing::error!("{log}");
                    state.log.write().unwrap().push_front(log);

                    state.log.write().unwrap().truncate(MAX_LOG_LEN);
                    return (StatusCode::BAD_REQUEST, "error accepting relationship")
                        .into_response();
                }

                let log = if let Some(nested_vid) = nested_vid {
                    format!(
                        "Accepted nested relationship request from <code>{sender}</code> with nested VID <code>{nested_vid}</code>"
                    )
                } else {
                    format!("Accepted relationship request from <code>{sender}</code>")
                };
                tracing::info!("{log}");
                state.log.write().unwrap().push_front(log);
            }
            Ok(tsp::ReceivedTspMessage::AcceptRelationship { sender, .. }) => {
                tracing::error!("accept relationship message from {sender}")
            }
            Ok(tsp::ReceivedTspMessage::CancelRelationship { sender }) => {
                tracing::error!("cancel relationship message from {sender}")
            }
            Ok(tsp::ReceivedTspMessage::ForwardRequest {
                sender,
                next_hop,
                route,
                opaque_payload,
            }) => {
                if route.is_empty() {
                    tracing::debug!("don't need to verify yourself");
                } else {
                    tracing::debug!("verifying VID next hop {next_hop}");
                    if let Err(e) = db.verify_vid(&next_hop).await {
                        tracing::error!("error verifying VID {next_hop}: {e}");
                        return (StatusCode::BAD_REQUEST, "error verifying next hop VID")
                            .into_response();
                    }

                    if let Err(e) = db.set_relation_for_vid(&next_hop, Some(receiver)) {
                        tracing::error!("error setting relation with {next_hop}: {e}");
                        return (
                            StatusCode::BAD_REQUEST,
                            "error setting relation with next hop",
                        )
                            .into_response();
                    }
                }

                match db
                    .forward_routed_message(&next_hop, route, &opaque_payload)
                    .await
                {
                    Ok(url) => {
                        let log = format!(
                            "Forwarded message from <code>{sender}</code> to <code>{url}</code>",
                        );
                        tracing::info!("{log}");
                        state.log.write().unwrap().push_front(log);
                    }
                    Err(e) => {
                        let log = e.to_string();
                        tracing::error!("{log}");
                        state.log.write().unwrap().push_front(log);

                        state.log.write().unwrap().truncate(MAX_LOG_LEN);
                        return (StatusCode::BAD_REQUEST, "error forwarding message")
                            .into_response();
                    }
                }
            }
            Ok(tsp::ReceivedTspMessage::NewIdentifier { sender, new_vid }) => {
                tracing::error!("new identifier message from {sender}: {new_vid}")
            }
            Ok(tsp::ReceivedTspMessage::Referral {
                sender,
                referred_vid,
            }) => tracing::error!("referral from {sender}: {referred_vid}"),
            Ok(tsp::ReceivedTspMessage::PendingMessage { unknown_vid, .. }) => {
                tracing::error!("pending message message from unknown VID {unknown_vid}")
            }
        }
    } else {
        let log = format!(
            "Forwarding message from  <code>{sender}</code> to <code>{receiver}</code> via WebSockets ({} bytes)",
            message.len()
        );
        tracing::info!("{log}");
        state.log.write().unwrap().push_front(log);

        // insert message in queue
        let _ = state.tx.send((receiver.to_owned(), message));
    }

    state.log.write().unwrap().truncate(MAX_LOG_LEN);

    StatusCode::OK.into_response()
}

/// Handle incoming websocket connections
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<IntermediaryState>>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    tracing::info!("{} listening for messages intended for {did}", state.domain);
    let mut messages_rx = state.tx.subscribe();

    ws.on_upgrade(|socket| {
        let (mut ws_send, _) = socket.split();

        async move {
            while let Ok((receiver, message)) = messages_rx.recv().await {
                if receiver == did {
                    tracing::debug!(
                        "{} forwarding message to {receiver}, {} bytes",
                        message.len(),
                        state.domain
                    );

                    let _ = ws_send.send(Message::Binary(Bytes::from(message))).await;
                }
            }
        }
    })
}
