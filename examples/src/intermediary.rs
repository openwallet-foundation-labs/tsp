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
use std::{
    io::Read,
    sync::{Arc, RwLock},
};
use tokio::sync::broadcast;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp::{AsyncStore, OwnedVid, VerifiedVid};

#[derive(Debug, Parser)]
#[command(name = "demo-intermediary")]
#[command(about = "Host a TSP intermediary server", long_about = None)]
struct Cli {
    #[arg(index = 1, help = "Path to this server's config JSON file")]
    config: String,
}

#[derive(serde::Deserialize)]
struct Config {
    // DID server domain (e.g. "tsp-test.org")
    did_domain: String,
    /// The port on which intermediary will be hosted
    #[serde(default = "default_port")]
    port: u16,
    /// This server's Private VID
    piv: OwnedVid,
    /// VIDs to verify on startup
    #[serde(default)]
    verify_vids: Vec<String>,
    /// Setup relations towards these VIDs on startup, for forwarding messages
    #[serde(default)]
    relate_to: Vec<String>,
    /// Setup relation from this VIDs on startup, for final drop off in route (in reverse direction)
    #[serde(default)]
    relate_from: Option<String>,
}

/// Default port, as exposed by Docker container
fn default_port() -> u16 {
    3001
}

struct IntermediaryState {
    domain: String,
    did_domain: String,
    db: AsyncStore,
    tx: broadcast::Sender<(String, Vec<u8>)>,
    log: RwLock<Vec<String>>,
}

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

    let mut file = std::fs::File::open(args.config).unwrap();
    let mut file_data = String::new();
    file.read_to_string(&mut file_data).unwrap();
    let config: Config = serde_json::from_str(&file_data).unwrap();

    let did_domain = config.did_domain.replace(":", "%3A");

    let mut db = AsyncStore::new();

    let piv = config.piv;
    let domain = piv.vid().endpoint().host_str().unwrap().replace(":", "%3A");
    let id = piv.vid().identifier().to_owned();

    db.add_private_vid(piv).unwrap();

    for vid in config.verify_vids {
        tracing::info!("verifying {vid}");
        db.verify_vid(&vid).await.unwrap();
    }

    for vid in config.relate_to {
        db.set_relation_for_vid(&vid, Some(&id)).unwrap();
    }

    if let Some(vid) = config.relate_from {
        db.set_relation_for_vid(&id, Some(&vid)).unwrap();
    }

    let state = Arc::new(IntermediaryState {
        domain: domain.to_owned(),
        did_domain,
        db,
        tx: broadcast::channel(100).0,
        log: RwLock::new(vec![]),
    });

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route(
            "/transport/{name}",
            post(new_message).get(websocket_handler),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port))
        .await
        .unwrap();
    tracing::info!("intermediary {domain} listening on port {}", config.port);

    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<Arc<IntermediaryState>>) -> Html<String> {
    let mut html = include_str!("../intermediary.html").to_string();
    html = html.replace("[[TITLE]]", &format!("Log {}", state.domain));

    let log = state.log.read().unwrap();
    if log.is_empty() {
        html = html.replace("[[LOG]]", "<i>The log is empty</i>");
    } else {
        html = html.replace("[[LOG]]", &format!("<li>{}</li>", log.join("</li><li>")));
    }

    Html(html)
}

async fn new_message(
    State(state): State<Arc<IntermediaryState>>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    tracing::debug!("{} received message intended for {name}", state.domain);

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

    if let Ok(true) = state.db.has_private_vid(receiver) {
        let log = format!(
            "routing message from {sender} to {receiver}, {} bytes",
            message.len()
        );
        tracing::info!("{log}");
        state.log.write().unwrap().push(log);

        match state.db.route_message(sender, receiver, &mut message).await {
            Ok(url) => {
                let log = format!("sent message to {url}",);
                tracing::info!("{log}");
                state.log.write().unwrap().push(log);
            }
            Err(e) => {
                tracing::error!("error routing message: {e}");

                return (StatusCode::BAD_REQUEST, "error routing message").into_response();
            }
        }
    } else {
        let log = format!(
            "forwarding message from {sender} to {receiver}, {} bytes",
            message.len()
        );
        tracing::info!("{log}");
        state.log.write().unwrap().push(log);

        // insert message in queue
        let _ = state.tx.send((receiver.to_owned(), message));
    }

    state.log.write().unwrap().truncate(10);

    StatusCode::OK.into_response()
}

/// Handle incoming websocket connections
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<IntermediaryState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut messages_rx = state.tx.subscribe();
    let vid = format!("did:web:{}:user:{name}", state.did_domain);

    tracing::info!(
        "{} listening for messages intended for {name} ({vid})",
        state.domain
    );

    ws.on_upgrade(|socket| {
        let (mut ws_send, _) = socket.split();

        async move {
            while let Ok((receiver, message)) = messages_rx.recv().await {
                if receiver == vid {
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
