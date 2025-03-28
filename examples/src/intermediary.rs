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
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp::{AsyncStore, OwnedVid, vid::vid_to_did_document};
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

    // Generate PIV
    let did = format!("did:web:{}", args.domain.replace(":", "%3A"));
    let transport =
        Url::parse(format!("https://{}/transport/{did}", args.domain).as_str()).unwrap();
    let private_vid = OwnedVid::bind(did, transport);
    let did_doc = vid_to_did_document(private_vid.vid()).to_string();

    let db = AsyncStore::new();
    db.add_private_vid(private_vid).unwrap();

    let state = Arc::new(IntermediaryState {
        domain: args.domain.to_owned(),
        db,
        tx: broadcast::channel(100).0,
        log: RwLock::new(vec![]),
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
    Path(did): Path<String>,
    body: Bytes,
) -> Response {
    tracing::debug!("{} received message intended for {did}", state.domain);

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
            "Routing message from <code>{sender}</code> to <code>{receiver}</code>, {} bytes",
            message.len()
        );
        tracing::info!("{log}");
        state.log.write().unwrap().push(log);

        match state.db.route_message(sender, receiver, &mut message).await {
            Ok(url) => {
                let log = format!("Sent message to <code>{url}</code>",);
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
            "Forwarding message from  <code>{sender}</code> to <code>{receiver}</code>, {} bytes",
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
