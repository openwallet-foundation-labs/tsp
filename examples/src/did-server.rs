use axum::{
    Form, Json, Router,
    extract::{DefaultBodyLimit, Path, State, WebSocketUpgrade, ws::Message},
    http::{Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, net::SocketAddrV4, sync::Arc};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::{
    signal,
    sync::{RwLock, broadcast},
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
    #[arg(
        long,
        default_value = "data",
        help = "Directory holding the published identities"
    )]
    data_dir: std::path::PathBuf,
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

/// Where identities are stored.
///
/// Process-wide rather than carried in the state: it is fixed for the life of the server, and
/// the functions that read and write identities are not handlers and take no state.
static DATA_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

fn data_path(file: &str) -> std::path::PathBuf {
    DATA_DIR
        .get_or_init(|| std::path::PathBuf::from("data"))
        .join(file)
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
                .unwrap_or_else(|_| "did_web=trace,tsp=trace,info".into()),
        )
        .init();

    let args = Cli::parse();

    let state = Arc::new(AppState {
        transport: args.transport,
        domain: args.domain,
        log: RwLock::new(VecDeque::with_capacity(MAX_LOG_LEN)),
        log_tx: broadcast::channel(100).0,
    });

    DATA_DIR
        .set(args.data_dir.clone())
        .expect("the data directory is set once");

    if let Err(e) = std::fs::create_dir_all(&args.data_dir) {
        tracing::error!("could not create {}: {e}", args.data_dir.display());
    }

    let app = app(state.clone());

    let addr = SocketAddrV4::new("0.0.0.0".parse().unwrap(), args.port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

/// Compose the routes.
fn app(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any)
        .allow_origin(Any);

    Router::new()
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
        .with_state(state)
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
        &format!("{}/{}", state.transport, form.name),
    );

    let key = private_vid.identifier();
    let resolve_url = tsp_sdk::vid::did::get_resolve_url(key).unwrap();

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

async fn get_endpoints() -> Response {
    match list_all_ids().await {
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
    let path = data_path(&format!("{name}.jsonl"));

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
    let path = data_path(&format!("{name}.jsonl"));

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
    let path = data_path(&format!("{name}.json"));
    let did = tokio::fs::read_to_string(path).await?;
    let id = serde_json::from_str(&did)?;

    Ok(id)
}

async fn read_history(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = data_path(&format!("{name}.jsonl"));
    let history = tokio::fs::read_to_string(path).await?;

    Ok(history)
}

async fn list_all_ids() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut dir = tokio::fs::read_dir(data_path("")).await?;
    let mut dids = Vec::new();

    while let Some(entry) = dir.next_entry().await?
        && let Some(filename) = entry.file_name().to_str()
    {
        if filename.ends_with(".json") {
            let contents = tokio::fs::read_to_string(entry.path()).await?;

            // Read the JSON contents of the file as an instance of `User`.
            let vid: serde_json::Value = serde_json::from_str(&contents)?;
            if let Some(vid) = vid.get("vid")
                && let Some(serde_json::Value::String(did)) = vid.get("id")
            {
                dids.push(did.to_owned())
            }
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
    let path = data_path(&format!("{name}.json"));

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

#[cfg(test)]
mod tests {
    use super::{AppState, DATA_DIR, MAX_LOG_LEN, app};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use std::{collections::VecDeque, sync::Arc};
    use tokio::sync::{RwLock, broadcast};
    use tsp_sdk::{OwnedVid, VerifiedVid, Vid};

    /// Start a server on a port of the system's choosing and return its address.
    ///
    /// The identity directory is process-wide and set once, so every test shares it. Each test
    /// therefore uses a name of its own rather than cleaning up, which also keeps them from
    /// interfering when run at the same time.
    async fn server() -> String {
        let _ = DATA_DIR.set(std::env::temp_dir().join("tsp-did-server-tests"));
        std::fs::create_dir_all(DATA_DIR.get().unwrap()).unwrap();

        let state = Arc::new(AppState {
            transport: "https://example.test/endpoint".to_string(),
            domain: "example.test".to_string(),
            log: RwLock::new(VecDeque::with_capacity(MAX_LOG_LEN)),
            log_tx: broadcast::channel(100).0,
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });

        format!("http://{address}")
    }

    /// A name no other test run has used, since published identities outlive the test.
    fn a_name(test: &str) -> String {
        format!("{test}-{:x}", rand::random::<u64>())
    }

    fn an_identity(name: &str) -> Vid {
        let id = format!("did:web:example.test:endpoint:{name}");
        let transport =
            url::Url::parse("https://example.test/transport/[vid_placeholder]").unwrap();

        OwnedVid::bind(id, transport).vid().clone()
    }

    #[tokio::test]
    async fn an_identity_can_be_read_back_after_publishing() {
        let base = server().await;
        let name = a_name("readable");
        let identity = an_identity(&name);

        let published = reqwest::Client::new()
            .post(format!("{base}/add-vid"))
            .json(&identity)
            .send()
            .await
            .unwrap();
        assert!(published.status().is_success(), "{}", published.status());

        let document: serde_json::Value = reqwest::get(format!("{base}/endpoint/{name}/did.json"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(document["id"], identity.identifier());
    }

    /// The intermediaries depend on this: a name that is already taken is how one of them
    /// discovers that its wallet is missing rather than that it is starting for the first time.
    #[tokio::test]
    async fn a_name_that_is_taken_cannot_be_claimed_again() {
        let base = server().await;
        let name = a_name("taken");
        let client = reqwest::Client::new();

        let first = an_identity(&name);
        assert!(
            client
                .post(format!("{base}/add-vid"))
                .json(&first)
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );

        // A different identity, since the keys are generated afresh, under the same name.
        let second = an_identity(&name);
        assert_ne!(first.verifying_key(), second.verifying_key());

        let refused = client
            .post(format!("{base}/add-vid"))
            .json(&second)
            .send()
            .await
            .unwrap();
        assert!(!refused.status().is_success(), "{}", refused.status());

        // and the identity already published is untouched
        let document: serde_json::Value = reqwest::get(format!("{base}/endpoint/{name}/did.json"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let key = document["verificationMethod"][0]["publicKeyJwk"]["x"]
            .as_str()
            .unwrap()
            .to_string();
        let expected = Base64UrlUnpadded::encode_string(first.verifying_key().as_ref());

        assert_eq!(key, expected, "the published identity was overwritten");
    }

    #[tokio::test]
    async fn a_name_that_is_taken_can_be_replaced_deliberately() {
        let base = server().await;
        let name = a_name("replaced");
        let client = reqwest::Client::new();

        client
            .post(format!("{base}/add-vid"))
            .json(&an_identity(&name))
            .send()
            .await
            .unwrap();

        let replacement = an_identity(&name);
        let replaced = client
            .put(format!("{base}/add-vid"))
            .json(&replacement)
            .send()
            .await
            .unwrap();

        assert!(replaced.status().is_success(), "{}", replaced.status());

        let document: serde_json::Value = reqwest::get(format!("{base}/endpoint/{name}/did.json"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let key = document["verificationMethod"][0]["publicKeyJwk"]["x"]
            .as_str()
            .unwrap()
            .to_string();
        let expected = Base64UrlUnpadded::encode_string(replacement.verifying_key().as_ref());

        assert_eq!(key, expected);
    }

    #[tokio::test]
    async fn an_unknown_name_is_not_found() {
        let base = server().await;
        let name = a_name("absent");

        let response = reqwest::get(format!("{base}/endpoint/{name}/did.json"))
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_name_that_is_not_allowed_is_refused() {
        let base = server().await;
        let identity = an_identity("not a valid name");

        let response = reqwest::Client::new()
            .post(format!("{base}/add-vid"))
            .json(&identity)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_history_can_be_published_and_read_back() {
        let base = server().await;
        let name = a_name("history");
        let identity = an_identity(&name);
        let client = reqwest::Client::new();

        client
            .post(format!("{base}/add-vid"))
            .json(&identity)
            .send()
            .await
            .unwrap();

        let entry = r#"{"versionId":"1-first"}"#;
        let published = client
            .post(format!("{base}/add-history/{}", identity.identifier()))
            .body(entry)
            .send()
            .await
            .unwrap();
        assert!(published.status().is_success(), "{}", published.status());

        let history = reqwest::get(format!("{base}/endpoint/{name}/did.jsonl"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(history, entry);

        let next = r#"{"versionId":"2-second"}"#;
        let appended = client
            .put(format!("{base}/add-history/{}", identity.identifier()))
            .body(next)
            .send()
            .await
            .unwrap();
        assert!(appended.status().is_success(), "{}", appended.status());

        let history = reqwest::get(format!("{base}/endpoint/{name}/did.jsonl"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(history, format!("{entry}\n{next}"));
    }
}
