use axum::{
    extract::{ws::Message, DefaultBodyLimit, Path, State, WebSocketUpgrade}, http::{header, Method, StatusCode}, response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form,
    Json,
    Router,
};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, net::SocketAddrV4, sync::Arc};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::{
    signal,
    sync::{broadcast, RwLock},
};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp_sdk::{VerifiedVid, Vid};

#[derive(Debug, Parser)]
#[command(name = "demo-did-web")]
#[command(about = "Host a DID:WEB support system", long_about = None)]
struct Cli {
    #[arg(short, long, default_value_t = 3000, help = "The port to listen on")]
    port: u16,
    #[arg(
        short,
        long,
        default_value = "https://demo.teaspoon.world/endpoint",
        help = "The base path of the transport for new DIDs"
    )]
    transport: String,
    #[arg(index = 1, help = "e.g. \"did.teaspoon.world\" or \"localhost:3000\"")]
    domain: String,
}

struct AppState {
    transport: String,
    domain: String,
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

impl AppState {
    async fn log(&self, text: String) {
        let mut log = self.log.write().await;
        let entry = LogEntry::new(text);
        log.push_front(entry.clone());
        log.truncate(MAX_LOG_LEN);

        let json = serde_json::to_string(&entry).unwrap();
        let _ = self.log_tx.send(json);
    }

    async fn announce_new_did(&self, did: &str) {
        self.log(format!(
            "Published DID: <a href=\"{}\" target=\"_blank\"><code>{}</code></a>",
            tsp_sdk::vid::did::get_resolve_url(did)
                .map(|url| url.to_string())
                .unwrap_or(".".to_string()),
            did
        ))
        .await;
    }
}

const MAX_LOG_LEN: usize = 20;

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
                .unwrap_or_else(|_| "did_web=trace,tsp=trace,info".into()),
        )
        .init();

    let args = Cli::parse();

    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any)
        // allow requests from any origin
        .allow_origin(Any);

    let state = Arc::new(AppState {
        transport: args.transport,
        domain: args.domain,
        log: RwLock::new(VecDeque::with_capacity(MAX_LOG_LEN)),
        log_tx: broadcast::channel(100).0,
    });

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route("/logs", get(log_websocket_handler))
        .route("/create-identity", post(create_identity))
        .route("/add-vid", post(add_vid).put(replace_vid))
        .route("/add-history/{id}", post(add_history).put(append_history))
        .route("/endpoint/{name}/did.json", get(get_did_doc))
        .route("/endpoint/{name}/did.jsonl", get(get_did_history))
        .route("/.well-known/endpoints.json", get(get_endpoints))
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddrV4::new("0.0.0.0".parse().unwrap(), args.port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn index(State(state): State<Arc<AppState>>) -> Html<String> {
    let mut html = include_str!("../did-web.html").to_string();
    html = html.replace("[[DOMAIN]]", &state.domain);

    let log = state.log.read().await;
    let serialized_log = serde_json::to_string(&log.iter().collect::<Vec<_>>()).unwrap();
    html = html.replace("[[LOG_JSON]]", &serialized_log);

    Html(html)
}

#[derive(Deserialize, Debug)]
struct CreateIdentityInput {
    name: String,
}

/// Create a new identity (private VID)
async fn create_identity(
    State(state): State<Arc<AppState>>,
    Form(form): Form<CreateIdentityInput>,
) -> Response {
    if !verify_name(&form.name) {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let (did_doc, _, private_vid) = tsp_sdk::vid::create_did_web(
        &form.name,
        &state.domain,
        &format!("{}/{}", &state.transport, form.name),
    );

    let key = private_vid.identifier();
    let resolve_url = tsp_sdk::vid::did::get_resolve_url(&key).unwrap();

    if let Err(e) = write_id(
        Identity {
            did_doc: did_doc.clone(),
            vid: private_vid.vid().clone(),
        },
        false,
    )
    .await
    {
        tracing::error!("error writing identity {key}: {e}");

        return (StatusCode::INTERNAL_SERVER_ERROR, "error writing identity").into_response();
    }

    tracing::debug!("created identity {key}");
    state.announce_new_did(key).await;

    let mut response = serde_json::to_value(private_vid).unwrap();
    response
        .as_object_mut()
        .unwrap()
        .insert("resolveUrl".to_string(), resolve_url.to_string().into());

    Json(response).into_response()
}

/// Get the DID document of an endpoint
async fn get_did_doc(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    if !verify_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let key = format!(
        "did:web:{}:endpoint:{name}",
        state.domain.replace(":", "%3A")
    );

    match read_id(&key).await {
        Ok(identity) => {
            tracing::debug!("served did.json for {key}");

            Json(identity.did_doc.clone()).into_response()
        }
        Err(e) => {
            tracing::error!("{key} not found: {e}");

            (StatusCode::NOT_FOUND, "no endpoint found").into_response()
        }
    }
}

/// Get the history of an webvh endpoint
async fn get_did_history(Path(name): Path<String>) -> Response {
    match read_history(&name).await {
        Ok(history) => {
            tracing::debug!("served did.jsonl for {name}");
            ([(header::CONTENT_TYPE, "application/json")], history).into_response()
        }
        Err(e) => {
            tracing::error!("{name} not found: {e}");
            (StatusCode::NOT_FOUND, "no endpoint found").into_response()
        }
    }
}

async fn get_endpoints(State(state): State<Arc<AppState>>) -> Response {
    let domain = state.domain.replace(":", "%3A");
    match list_all_ids(domain).await {
        Ok(dids) => Json(dids).into_response(),
        Err(e) => {
            tracing::error!("Could not load endpoints: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "error loading dids").into_response()
        }
    }
}

async fn add_history(Path(vid): Path<String>, history: String) -> Response {
    let name = match vid.split(':').next_back().ok_or("invalid name") {
        Ok(name) => name,
        Err(err) => {
            tracing::debug!("error extracting name from VID: {err:?}");
            return (StatusCode::BAD_REQUEST, "Invalid VID").into_response();
        }
    };
    let path = format!("data/{name}.jsonl");

    if std::path::Path::new(&path).exists() {
        tracing::error!("error writing identity '{name}': Name already exists");
        return (StatusCode::INTERNAL_SERVER_ERROR, "error writing identity").into_response();
    }

    if let Err(err) = tokio::fs::write(path, history).await {
        tracing::error!("error writing identity '{name}': {err}");
        (StatusCode::INTERNAL_SERVER_ERROR, "error writing identity").into_response()
    } else {
        StatusCode::OK.into_response()
    }
}

async fn append_history(Path(vid): Path<String>, history: String) -> Response {
    let name = match vid.split(':').next_back().ok_or("invalid name") {
        Ok(name) => name,
        Err(err) => {
            tracing::debug!("error extracting name from VID: {err:?}");
            return (StatusCode::BAD_REQUEST, "Invalid VID").into_response();
        }
    };
    let path = format!("data/{name}.jsonl");

    match File::options().append(true).open(path).await {
        Err(err) => {
            tracing::error!("error writing identity '{name}': {err}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error writing identity").into_response()
        }
        Ok(mut file) => {
            let history = format!("\n{history}");
            if let Err(err) = file.write_all(history.as_bytes()).await {
                tracing::error!("error writing identity '{name}': {err}");
            }
            StatusCode::OK.into_response()
        }
    }
}

async fn replace_vid(State(state): State<Arc<AppState>>, Json(vid): Json<Vid>) -> Response {
    let name = vid.identifier().split(':').next_back().unwrap_or_default();

    if !verify_name(name) {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let did_doc = tsp_sdk::vid::vid_to_did_document(&vid);

    if let Err(e) = write_id(
        Identity {
            did_doc,
            vid: vid.clone(),
        },
        true,
    )
    .await
    {
        tracing::error!("error writing identity {}: {e}", vid.identifier());

        return (StatusCode::INTERNAL_SERVER_ERROR, "error writing identity").into_response();
    }

    let did = vid.identifier();
    tracing::debug!("modified VID {}", did);
    state.announce_new_did(did).await;

    Json(&vid).into_response()
}

/// Add did document to the local state
async fn add_vid(State(state): State<Arc<AppState>>, Json(vid): Json<Vid>) -> Response {
    let name = vid.identifier().split(':').next_back().unwrap_or_default();

    if !verify_name(name) {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let did_doc = tsp_sdk::vid::vid_to_did_document(&vid);

    if let Err(e) = write_id(
        Identity {
            did_doc,
            vid: vid.clone(),
        },
        false,
    )
    .await
    {
        tracing::error!("error writing identity {}: {e}", vid.identifier());

        return (StatusCode::INTERNAL_SERVER_ERROR, "error writing identity").into_response();
    }

    let did = vid.identifier();
    tracing::debug!("added VID {}", did);
    state.announce_new_did(did).await;

    Json(&vid).into_response()
}

async fn read_id(vid: &str) -> Result<Identity, Box<dyn std::error::Error>> {
    let name = vid.split(':').next_back().ok_or("invalid name")?;
    let path = format!("data/{name}.json");
    let did = tokio::fs::read_to_string(path).await?;
    let id = serde_json::from_str(&did)?;

    Ok(id)
}

async fn read_history(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = format!("data/{name}.jsonl");
    let history = tokio::fs::read_to_string(path).await?;

    Ok(history)
}

async fn list_all_ids(domain: String) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut dir = tokio::fs::read_dir("data").await?;
    let mut dids = Vec::new();

    while let Some(entry) = dir.next_entry().await?
        && let Some(filename) = entry.file_name().to_str()
    {
        if let Some(name) = filename.strip_suffix(".json") {
            let did = format!("did:web:{domain}:endpoint:{name}");
            dids.push(did);
        }
    }

    Ok(dids)
}

// These characters are unreserved and can safely be used in any URL according to RFC3986
const ADDITIONAL_CHARS: &str = "-._~";

fn verify_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 64
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || ADDITIONAL_CHARS.contains(c))
}

/// Identity struct, used to store the DID document and VID of an endpoint
#[derive(Debug, Serialize, Deserialize)]
struct Identity {
    did_doc: serde_json::Value,
    vid: Vid,
}

async fn write_id(id: Identity, replace: bool) -> Result<(), Box<dyn std::error::Error>> {
    let name = id
        .vid
        .identifier()
        .split(':')
        .next_back()
        .ok_or("invalid name")?;
    let did = serde_json::to_string_pretty(&id)?;
    let path = format!("data/{name}.json");

    if !replace && std::path::Path::new(&path).exists() {
        return Err("identity already exists".into());
    }

    tokio::fs::write(path, did).await?;

    Ok(())
}

/// Handle incoming websocket connections for users viewing the web interface
async fn log_websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
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
