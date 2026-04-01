use axum::{
    Form, Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{Method, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    routing::post,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use clap::Parser;
use core::time;
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    net::SocketAddrV4,
    str::from_utf8,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    signal,
    sync::{RwLock, broadcast},
};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp_sdk::{
    SecureStore, cesr,
    definitions::{Payload, VerifiedVid},
    vid::{OwnedVid, Vid},
};

#[derive(Debug, Parser)]
#[command(name = "demo-server")]
#[command(about = "Host a TSP demo server", long_about = None)]
struct Cli {
    #[arg(short, long, default_value_t = 3000, help = "The port to listen on")]
    port: u16,
    #[arg(short, long, help = "the URL of the DID support system to use")]
    did_server: String,
    #[arg(index = 1, help = "e.g. \"teaspoon.world\" or \"localhost:3000\"")]
    domain: String,
}

/// Application state, used to store the identities and the broadcast channel
struct AppState {
    domain: String,
    did_server: String,
    timestamp_server: SecureStore,
    tx: broadcast::Sender<(String, String, Vec<u8>)>,
}

/// Define the routes and start a server
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
                .unwrap_or_else(|_| "demo_server=trace,tsp=trace".into()),
        )
        .init();

    let args = Cli::parse();

    let timestamp_server = SecureStore::new();
    let piv: OwnedVid =
        serde_json::from_str(include_str!("../test/timestamp-server/piv.json")).unwrap();
    timestamp_server.add_private_vid(piv, None).unwrap();

    let state = Arc::new(AppState {
        domain: args.domain,
        did_server: args.did_server,
        timestamp_server,
        tx: broadcast::channel(100).0,
    });

    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any)
        // allow requests from any origin
        .allow_origin(Any);

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route("/script.js", get(script))
        .route("/vid/{did}", get(vid_page))
        .route("/create-identity", post(create_identity))
        .route("/verify-vid", post(verify_vid))
        .route("/endpoint/{user}", get(websocket_user_handler))
        .route("/endpoint/{user}", post(route_message))
        .route("/sign-timestamp", post(sign_timestamp))
        .route("/send-message", post(send_message))
        .route("/receive-messages", get(websocket_handler))
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

#[cfg(debug_assertions)]
async fn index() -> Html<String> {
    Html(std::fs::read_to_string("examples/index.html").unwrap())
}

#[cfg(not(debug_assertions))]
async fn index() -> Html<String> {
    Html(std::include_str!("../index.html").to_string())
}

#[cfg(debug_assertions)]
async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript")],
        std::fs::read_to_string("examples/script.js").unwrap(),
    )
}

#[cfg(not(debug_assertions))]
async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript")],
        std::include_str!("../script.js").to_string(),
    )
}

/// VID verification page - displays verified identity information
async fn vid_page(Path(did): Path<String>) -> Response {
    // URL-decode the DID (handles %3A for colons, etc.)
    let did = urlencoding::decode(&did)
        .map(|s| s.into_owned())
        .unwrap_or(did);

    // Verify the VID and get metadata
    match tsp_sdk::vid::resolve::verify_vid(&did).await {
        Ok((vid, metadata)) => {
            let html = render_vid_page(&did, &vid, metadata.as_ref());
            Html(html).into_response()
        }
        Err(e) => {
            let html = render_vid_error_page(&did, &format!("{:?}", e));
            (StatusCode::BAD_REQUEST, Html(html)).into_response()
        }
    }
}

/// Render the VID verification page HTML
fn render_vid_page(did: &str, vid: &Vid, metadata: Option<&serde_json::Value>) -> String {
    let short_did = if did.len() > 40 {
        format!("{}...{}", &did[..20], &did[did.len() - 12..])
    } else {
        did.to_string()
    };

    // Extract webvh-specific metadata if available
    let (created, updated, version, update_keys) = if let Some(meta) = metadata {
        let webvh_meta = meta.get("webvh_meta_data");
        let created = webvh_meta
            .and_then(|m| m.get("created"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let updated = webvh_meta
            .and_then(|m| m.get("updated"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let version = webvh_meta
            .and_then(|m| m.get("version_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let update_keys = meta
            .get("update_keys")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            });
        (created, updated, version, update_keys)
    } else {
        (None, None, None, None)
    };

    let endpoint = vid.endpoint().to_string();
    let is_webvh = did.starts_with("did:webvh:");
    let did_type = if is_webvh {
        "did:webvh"
    } else if did.starts_with("did:web:") {
        "did:web"
    } else if did.starts_with("did:peer:") {
        "did:peer"
    } else {
        "DID"
    };

    // Build history section for webvh
    let history_section = if is_webvh {
        let version_display = version.as_deref().unwrap_or("1");
        let created_display = created.as_deref().unwrap_or("Unknown");
        let updated_display = updated.as_deref().unwrap_or("Unknown");
        format!(
            r#"
        <div class="section">
            <div class="section-title">VERIFICATION HISTORY</div>
            <div class="timeline">
                <div class="timeline-item">
                    <div class="timeline-dot genesis"></div>
                    <div class="timeline-content">
                        <div class="timeline-label">Genesis</div>
                        <div class="timeline-date">{created_display}</div>
                    </div>
                </div>
                <div class="timeline-item">
                    <div class="timeline-dot current"></div>
                    <div class="timeline-content">
                        <div class="timeline-label">Current (v{version_display})</div>
                        <div class="timeline-date">{updated_display}</div>
                    </div>
                </div>
            </div>
        </div>
        "#
        )
    } else {
        String::new()
    };

    // Build update keys section if available
    let update_keys_section = if let Some(keys) = update_keys {
        let keys_html: String = keys.iter()
            .map(|k| {
                let short_key = if k.len() > 20 {
                    format!("{}...", &k[..20])
                } else {
                    k.clone()
                };
                format!(r#"<div class="key-item"><span class="key-icon">🔑</span><code>{}</code></div>"#, short_key)
            })
            .collect();
        format!(
            r#"
        <div class="section">
            <div class="section-title">UPDATE KEYS</div>
            {keys_html}
        </div>
        "#
        )
    } else {
        String::new()
    };

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verified Identity - {short_did}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 480px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            padding: 30px 20px;
            text-align: center;
            color: white;
        }}
        .avatar {{
            width: 80px;
            height: 80px;
            background: white;
            border-radius: 50%;
            margin: 0 auto 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            margin-top: 10px;
        }}
        .badge-icon {{ font-size: 18px; }}
        .did-type {{
            font-size: 12px;
            opacity: 0.9;
            margin-top: 5px;
        }}
        .content {{ padding: 20px; }}
        .section {{
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }}
        .section:last-child {{ border-bottom: none; margin-bottom: 0; }}
        .section-title {{
            font-size: 11px;
            font-weight: 600;
            color: #999;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}
        .did-box {{
            display: flex;
            align-items: center;
            gap: 10px;
            background: #f5f5f5;
            padding: 12px;
            border-radius: 10px;
            cursor: pointer;
        }}
        .did-box:hover {{ background: #eee; }}
        .did-box code {{
            flex: 1;
            font-size: 13px;
            word-break: break-all;
            color: #333;
        }}
        .copy-btn {{
            background: none;
            border: none;
            font-size: 18px;
            cursor: pointer;
            padding: 5px;
        }}
        .info-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
        }}
        .info-label {{ color: #666; font-size: 14px; }}
        .info-value {{ font-weight: 500; font-size: 14px; color: #333; }}
        .endpoint {{
            font-size: 13px;
            color: #666;
            word-break: break-all;
        }}
        .timeline {{
            position: relative;
            padding-left: 25px;
        }}
        .timeline::before {{
            content: '';
            position: absolute;
            left: 8px;
            top: 5px;
            bottom: 5px;
            width: 2px;
            background: #ddd;
        }}
        .timeline-item {{
            position: relative;
            padding: 10px 0;
        }}
        .timeline-dot {{
            position: absolute;
            left: -21px;
            top: 14px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            border: 2px solid white;
            box-shadow: 0 0 0 2px #ddd;
        }}
        .timeline-dot.genesis {{ background: #667eea; box-shadow: 0 0 0 2px #667eea; }}
        .timeline-dot.current {{ background: #38ef7d; box-shadow: 0 0 0 2px #38ef7d; }}
        .timeline-label {{ font-weight: 500; font-size: 14px; }}
        .timeline-date {{ font-size: 12px; color: #999; margin-top: 2px; }}
        .key-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 0;
            font-size: 13px;
        }}
        .key-icon {{ font-size: 14px; }}
        .key-item code {{ color: #666; }}
        .actions {{
            display: flex;
            gap: 10px;
            padding: 20px;
            background: #f9f9f9;
        }}
        .btn {{
            flex: 1;
            padding: 14px;
            border: none;
            border-radius: 10px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .btn-secondary {{
            background: white;
            color: #333;
            border: 1px solid #ddd;
        }}
        .toast {{
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            display: none;
            z-index: 1000;
        }}
        .toast.show {{ display: block; animation: fadeIn 0.3s; }}
        @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="avatar">🤖</div>
            <div class="badge">
                <span class="badge-icon">✓</span>
                VERIFIED
            </div>
            <div class="did-type">{did_type}</div>
        </div>

        <div class="content">
            <div class="section">
                <div class="section-title">IDENTIFIER</div>
                <div class="did-box" onclick="copyDid()">
                    <code id="full-did">{did}</code>
                    <button class="copy-btn" title="Copy DID">📋</button>
                </div>
            </div>

            <div class="section">
                <div class="section-title">SERVICE ENDPOINT</div>
                <div class="endpoint">{endpoint}</div>
            </div>

            {history_section}
            {update_keys_section}
        </div>

        <div class="actions">
            <button class="btn btn-secondary" onclick="shareDid()">
                🔗 Share
            </button>
        </div>
    </div>

    <div class="toast" id="toast">Copied to clipboard!</div>

    <script>
        function copyDid() {{
            const did = document.getElementById('full-did').textContent;
            navigator.clipboard.writeText(did).then(() => showToast('DID copied!'));
        }}

        function shareDid() {{
            const url = window.location.href;
            if (navigator.share) {{
                navigator.share({{ title: 'Verified Identity', url: url }});
            }} else {{
                navigator.clipboard.writeText(url).then(() => showToast('Link copied!'));
            }}
        }}

        function showToast(msg) {{
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2000);
        }}
    </script>
</body>
</html>
"##
    )
}

/// Render an error page when VID verification fails
fn render_vid_error_page(did: &str, error: &str) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Failed</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            min-height: 100vh;
            padding: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            max-width: 480px;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
            text-align: center;
            padding: 40px 20px;
        }}
        .icon {{ font-size: 60px; margin-bottom: 20px; }}
        h1 {{ font-size: 24px; color: #e74c3c; margin-bottom: 10px; }}
        .did {{
            font-size: 12px;
            color: #999;
            word-break: break-all;
            margin: 15px 0;
            padding: 10px;
            background: #f5f5f5;
            border-radius: 8px;
        }}
        .error {{
            font-size: 14px;
            color: #666;
            margin-top: 15px;
            padding: 10px;
            background: #fff5f5;
            border-radius: 8px;
            border: 1px solid #ffe0e0;
        }}
        .btn {{
            display: inline-block;
            margin-top: 20px;
            padding: 12px 24px;
            background: #e74c3c;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">❌</div>
        <h1>Verification Failed</h1>
        <div class="did">{did}</div>
        <div class="error">{error}</div>
        <a href="/" class="btn">Go Home</a>
    </div>
</body>
</html>
"##
    )
}

/// Create a new identity (private VID)
async fn create_identity(State(state): State<Arc<AppState>>) -> Response {
    Redirect::temporary(format!("{}/create-identity", &state.did_server).as_str()).into_response()
}

#[derive(Deserialize, Debug)]
struct ResolveVidInput {
    vid: String,
}

/// Resolve and verify a VID to JSON encoded key material
async fn verify_vid(Form(form): Form<ResolveVidInput>) -> Response {
    let vid = tsp_sdk::vid::verify_vid(&form.vid).await.ok();

    match vid {
        Some(vid) => {
            tracing::debug!("verified VID {}", form.vid);
            Json(&vid).into_response()
        }
        None => {
            tracing::debug!("could not find VID {}", form.vid);
            (StatusCode::BAD_REQUEST, "invalid vid").into_response()
        }
    }
}

/// Format CESR-encoded message parts to descriptive JSON
fn format_part(title: &str, part: &cesr::Part, plain: Option<&[u8]>) -> serde_json::Value {
    let full = [part.prefix, part.data].concat();

    json!({
        "title": title,
        "prefix": part.prefix.iter().map(|b| format!("{b:#04x}")).collect::<Vec<String>>().join(" "),
        "data": Base64UrlUnpadded::encode_string(&full),
        "plain": plain
            .and_then(|b| std::str::from_utf8(b).ok())
            .or(std::str::from_utf8(part.data).ok()),
    })
}

/// Decode a CESR-encoded message into descriptive JSON
fn open_message(message: &[u8], payload: Option<&[u8]>) -> Option<serde_json::Value> {
    let parts = cesr::open_message_into_parts(message).ok()?;

    Some(json!({
        "original": Base64UrlUnpadded::encode_string(message),
        "prefix": format_part("Prefix", &parts.prefix, None),
        "sender": format_part("Sender", &parts.sender, None),
        "receiver": parts.receiver.map(|v| format_part("Receiver", &v, None)),
        "nonconfidentialData": parts.nonconfidential_data.map(|v| format_part("Non-confidential data", &v, None)),
        "ciphertext": parts.ciphertext.map(|v| format_part("Ciphertext", &v, payload)),
        "signature": format_part("Signature", &parts.signature, None),
        "cryptoType": match parts.crypto_type {
            cesr::CryptoType::Plaintext => "Plain text",
            cesr::CryptoType::HpkeAuth => "HPKE Auth",
            cesr::CryptoType::HpkeEssr => "HPKE ESSR",
            cesr::CryptoType::NaclAuth => "NaCl Auth",
            cesr::CryptoType::NaclEssr => "NaCl ESSR",
            #[cfg(feature = "pq")]
            cesr::CryptoType::X25519Kyber768Draft00 => "X25519 Kyber768 Draft 00",
        },
        "signatureType": match parts.signature_type {
            cesr::SignatureType::NoSignature => "No Signature",
            cesr::SignatureType::Ed25519 => "Ed25519",
            #[cfg(feature = "pq")]
            cesr::SignatureType::MlDsa65 => "MlDsa65",
        }
    }))
}

/// Form to send a TSP message
#[derive(Deserialize, Debug)]
struct SendMessageForm {
    message: String,
    nonconfidential_data: Option<String>,
    sender: OwnedVid,
    receiver: Vid,
}

#[derive(Deserialize, Debug)]
struct Metadata {
    name: String,
    timestamp: u64,
}

async fn sign_timestamp(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<impl IntoResponse, Response> {
    let bytes: Vec<u8> = body.into();
    let mut header_bytes = bytes.clone();
    let header = cesr::probe(&mut header_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Error probing message").into_response())?;

    let metadata = header
        .get_nonconfidential_data()
        .ok_or((StatusCode::BAD_REQUEST, "No nonconfidential data").into_response())?;

    let receiver = header
        .get_receiver()
        .ok_or((StatusCode::BAD_REQUEST, "No receiver set").into_response())?;

    let receiver = from_utf8(receiver)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Receiver vid is not valid utf8").into_response())?;

    let metadata: Metadata = serde_json::from_slice(metadata)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Error parsing json").into_response())?;

    tracing::info!(
        "received timestamp sign request from {}: {}",
        metadata.name,
        metadata.timestamp
    );

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid timestamp").into_response())?
        .as_secs();
    let delta = metadata.timestamp.max(since_the_epoch) - metadata.timestamp.min(since_the_epoch);

    if delta > time::Duration::from_secs(60).as_secs() {
        tracing::error!("timestamp delta to large: {delta} seconds");

        return Err((StatusCode::BAD_REQUEST, "Invalid timestamp").into_response());
    }

    tracing::info!("timestamp delta ok: {delta} seconds");

    let (verified_vid, metadata) = tsp_sdk::vid::verify_vid(receiver)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Error verifying vid").into_response())?;
    state
        .timestamp_server
        .add_verified_vid(verified_vid, metadata)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Error adding verified vid").into_response())?;

    let (_url, response_bytes) = state
        .timestamp_server
        .seal_message(
            &format!(
                "did:web:did.{}:endpoint:timestamp-server",
                state.domain.replace(":", "%3A")
            ),
            receiver,
            Some(&bytes),
            &[],
        )
        .map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "Error signing message").into_response()
        })?;

    tracing::info!("timestamped message");

    Ok(response_bytes)
}

async fn route_message(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let Ok((sender, Some(receiver))) = cesr::get_sender_receiver(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid message").into_response();
    };

    let sender = String::from_utf8_lossy(sender).to_string();
    let receiver = String::from_utf8_lossy(receiver).to_string();

    // translate received identifier into the transport; either because it is a
    // known endpoint or because it is a did:peer. note that this allows "snooping" messages
    // that are not intended for you --- but that will allow building interesting demo cases
    // since the unintended recipient cannot read the message: the security of TSP is not based
    // on security of the transport layer.
    if let Ok((vid, _metadata)) = tsp_sdk::vid::resolve::verify_vid(&receiver).await {
        vid.endpoint().to_string()
    } else {
        return (StatusCode::BAD_REQUEST, "unknown receiver").into_response();
    };

    tracing::debug!("forwarded message from {sender} to endpoint {receiver}");

    // insert message in queue
    let _ = state.tx.send((sender, receiver, body.into()));

    StatusCode::OK.into_response()
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    tracing::debug!("received websocket connection");

    ws.on_upgrade(|socket| websocket(socket, state))
}

/// Send a TSP message using a HTML form
async fn send_message(
    State(state): State<Arc<AppState>>,
    Json(form): Json<SendMessageForm>,
) -> Response {
    let result = tsp_sdk::crypto::seal(
        &form.sender,
        &form.receiver,
        form.nonconfidential_data.as_deref().and_then(|d| {
            if d.is_empty() {
                None
            } else {
                Some(d.as_bytes())
            }
        }),
        Payload::Content(form.message.as_bytes()),
    );

    match result {
        Ok(message) => {
            // insert message in queue
            let _ = state.tx.send((
                form.sender.identifier().to_owned(),
                form.receiver.identifier().to_owned(),
                message.clone(),
            ));

            let decoded = open_message(&message, Some(form.message.as_bytes())).unwrap();

            tracing::debug!(
                "sent message from {} to {}",
                form.sender.identifier(),
                form.receiver.identifier()
            );

            Json(decoded).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "error creating message").into_response(),
    }
}

/// Handle incoming websocket connections for vid
async fn websocket_user_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Path(vid): Path<String>,
) -> impl IntoResponse {
    let mut messages_rx = state.tx.subscribe();

    tracing::debug!("new websocket connection for {vid}");

    ws.on_upgrade(|socket| {
        let (mut ws_send, _) = socket.split();

        async move {
            while let Ok((_, receiver, message)) = messages_rx.recv().await {
                if receiver == vid {
                    let _ = ws_send.send(Message::Binary(Bytes::from(message))).await;
                }
            }
        }
    })
}

#[derive(Deserialize, Debug)]
struct EncodedMessage {
    sender: String,
    receiver: String,
    message: String,
}

/// Handle the websocket connection
/// Keep track of the verified VIDs, private VIDs and forward messages
async fn websocket(stream: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = stream.split();
    let mut rx = state.tx.subscribe();
    let senders = Arc::new(RwLock::new(HashMap::<String, Vid>::new()));
    let receivers = Arc::new(RwLock::new(HashMap::<String, OwnedVid>::new()));

    // Forward messages from the broadcast channel to the websocket
    let incoming_senders = senders.clone();
    let incoming_receivers = receivers.clone();
    let mut send_task = tokio::spawn(async move {
        while let Ok((sender_id, receiver_id, message)) = rx.recv().await {
            let incoming_senders_read = incoming_senders.read().await;

            let incoming_receivers_read = incoming_receivers.read().await;
            let Some(receiver_vid) = incoming_receivers_read.get(&receiver_id) else {
                continue;
            };

            tracing::debug!("forwarding message {sender_id} {receiver_id}");

            let mut encrypted_message = message.clone();

            // if the sender is verified, decrypt the message
            let result = if let Some(sender_vid) = incoming_senders_read.get(&sender_id) {
                let Ok((_, payload, _, _)) =
                    tsp_sdk::crypto::open(receiver_vid, sender_vid, &mut encrypted_message)
                else {
                    continue;
                };

                open_message(&message, Some(payload.as_bytes()))
            } else {
                open_message(&message, None)
            };

            let Some(decoded) = result else {
                continue;
            };

            if sender
                .send(Message::Text(decoded.to_string().into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Receive encoded VIDs from the websocket and store them in the local state
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(incoming_message))) = receiver.next().await {
            if let Ok(identity) = serde_json::from_str::<OwnedVid>(&incoming_message) {
                receivers
                    .write()
                    .await
                    .insert(identity.identifier().to_string(), identity);
            }

            if let Ok(identity) = serde_json::from_str::<Vid>(&incoming_message) {
                senders
                    .write()
                    .await
                    .insert(identity.identifier().to_string(), identity);
            }

            if let Ok(encoded) = serde_json::from_str::<EncodedMessage>(&incoming_message)
                && let Ok(original) = Base64UrlUnpadded::decode_vec(&encoded.message)
            {
                let _ = state.tx.send((encoded.sender, encoded.receiver, original));
            }
        }
    });

    // Abort the tasks when one of them finishes
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }
}
