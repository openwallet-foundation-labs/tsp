use axum::{
    Form, Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use core::time;
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    str::from_utf8,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{RwLock, broadcast};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp::{
    Store,
    definitions::{Payload, VerifiedVid},
    vid::{OwnedVid, Vid},
};

const DOMAIN: &str = "localhost:3000";

/// Identity struct, used to store the DID document and VID of a user
#[derive(Debug, Serialize, Deserialize)]
struct Identity {
    did_doc: serde_json::Value,
    vid: Vid,
}

async fn write_id(id: Identity) -> Result<(), Box<dyn std::error::Error>> {
    let name = id
        .vid
        .identifier()
        .split(':')
        .next_back()
        .ok_or("invalid name")?;
    let did = serde_json::to_string_pretty(&id)?;
    let path = format!("data/{name}.json");

    if std::path::Path::new(&path).exists() {
        return Err("identity already exists".into());
    }

    tokio::fs::write(path, did).await?;

    Ok(())
}

async fn read_id(vid: &str) -> Result<Identity, Box<dyn std::error::Error>> {
    let name = vid.split(':').next_back().ok_or("invalid name")?;
    let path = format!("data/{name}.json");
    let did = tokio::fs::read_to_string(path).await?;
    let id = serde_json::from_str(&did)?;

    Ok(id)
}

fn verify_name(name: &str) -> bool {
    !name.is_empty() && name.len() < 64 && name.chars().all(|c| c.is_alphanumeric())
}

/// Application state, used to store the identities and the broadcast channel
struct AppState {
    timestamp_server: Store,
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

    let timestamp_server = Store::new();
    let piv: OwnedVid =
        serde_json::from_str(include_str!("../test/timestamp-server.json")).unwrap();
    timestamp_server.add_private_vid(piv).unwrap();

    let state = Arc::new(AppState {
        timestamp_server,
        tx: broadcast::channel(100).0,
    });

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route("/script.js", get(script))
        .route("/create-identity", post(create_identity))
        .route("/verify-vid", post(verify_vid))
        .route("/add-vid", post(add_vid))
        .route("/user/{name}/did.json", get(get_did_doc))
        .route("/vid/{vid}", get(websocket_vid_handler))
        .route("/user/{user}", get(websocket_user_handler))
        .route("/user/{user}", post(route_message))
        .route("/sign-timestamp", post(sign_timestamp))
        .route("/send-message", post(send_message))
        .route("/receive-messages", get(websocket_handler))
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
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

#[derive(Deserialize, Debug)]
struct CreateIdentityInput {
    name: String,
}

/// Create a new identity (private VID)
async fn create_identity(Form(form): Form<CreateIdentityInput>) -> Response {
    if !verify_name(&form.name) {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let (did_doc, _, private_vid) = tsp::vid::create_did_web(
        &form.name,
        DOMAIN,
        &format!("https://{DOMAIN}/user/{}", form.name),
    );

    let key = private_vid.identifier();

    if let Err(e) = write_id(Identity {
        did_doc: did_doc.clone(),
        vid: private_vid.vid().clone(),
    })
    .await
    {
        tracing::error!("error writing identity {key}: {e}");

        return (StatusCode::INTERNAL_SERVER_ERROR, "error writing identity").into_response();
    }

    tracing::debug!("created identity {key}");

    Json(private_vid).into_response()
}

#[derive(Deserialize, Debug)]
struct ResolveVidInput {
    vid: String,
}

/// Resolve and verify a VID to JSON encoded key material
async fn verify_vid(Form(form): Form<ResolveVidInput>) -> Response {
    let name = form.vid.split(':').next_back().unwrap_or_default();

    if !verify_name(name) {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    // local state lookup
    if let Ok(identity) = read_id(&form.vid).await {
        return Json(&identity.vid).into_response();
    }

    // remote lookup
    let vid = tsp::vid::verify_vid(&form.vid).await.ok();

    tracing::debug!("verified VID {}", form.vid);

    match vid {
        Some(vid) => Json(&vid).into_response(),
        None => (StatusCode::BAD_REQUEST, "invalid vid").into_response(),
    }
}

/// Add did document to the local state
async fn add_vid(Json(vid): Json<Vid>) -> Response {
    let name = vid.identifier().split(':').next_back().unwrap_or_default();

    if !verify_name(name) {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let did_doc = tsp::vid::vid_to_did_document(&vid);

    if let Err(e) = write_id(Identity {
        did_doc,
        vid: vid.clone(),
    })
    .await
    {
        tracing::error!("error writing identity {}: {e}", vid.identifier());

        return (StatusCode::INTERNAL_SERVER_ERROR, "error writing identity").into_response();
    }

    tracing::debug!("added VID {}", vid.identifier());

    Json(&vid).into_response()
}

/// Get the DID document of a user
async fn get_did_doc(Path(name): Path<String>) -> Response {
    if !verify_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let key = format!("did:web:{}:user:{name}", DOMAIN.replace(":", "%3A"));

    match read_id(&key).await {
        Ok(identity) => {
            tracing::debug!("served did.json for {key}");

            Json(identity.did_doc.clone()).into_response()
        }
        Err(e) => {
            tracing::error!("{key} not found: {e}");

            (StatusCode::NOT_FOUND, "no user found").into_response()
        }
    }
}

/// Format CESR-encoded message parts to descriptive JSON
fn format_part(title: &str, part: &tsp::cesr::Part, plain: Option<&[u8]>) -> serde_json::Value {
    let full = [part.prefix, part.data].concat();

    json!({
        "title": title,
        "prefix": part.prefix.iter().map(|b| format!("{:#04x}", b)).collect::<Vec<String>>().join(" "),
        "data": Base64UrlUnpadded::encode_string(&full),
        "plain": plain
            .and_then(|b| std::str::from_utf8(b).ok())
            .or(std::str::from_utf8(part.data).ok()),
    })
}

/// Decode a CESR-encoded message into descriptive JSON
fn open_message(message: &[u8], payload: Option<&[u8]>) -> Option<serde_json::Value> {
    let parts = tsp::cesr::open_message_into_parts(message).ok()?;

    Some(json!({
        "original": Base64UrlUnpadded::encode_string(message),
        "prefix": format_part("Prefix", &parts.prefix, None),
        "sender": format_part("Sender", &parts.sender, None),
        "receiver": parts.receiver.map(|v| format_part("Receiver", &v, None)),
        "nonconfidentialData": parts.nonconfidential_data.map(|v| format_part("Non-confidential data", &v, None)),
        "ciphertext": parts.ciphertext.map(|v| format_part("Ciphertext", &v, payload)),
        "signature": format_part("Signature", &parts.signature, None),
        "cryptoType": match parts.crypto_type {
            tsp::cesr::CryptoType::Plaintext => "Plain text",
            tsp::cesr::CryptoType::HpkeAuth => "HPKE Auth",
            tsp::cesr::CryptoType::HpkeEssr => "HPKE ESSR",
            tsp::cesr::CryptoType::NaclAuth => "NaCl Auth",
            tsp::cesr::CryptoType::NaclEssr => "NaCl ESSR",
        },
        "signatureType": match parts.signature_type {
            tsp::cesr::SignatureType::NoSignature => "No Signature",
            tsp::cesr::SignatureType::Ed25519 => "Ed25519",
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
    let header = tsp::cesr::probe(&mut header_bytes)
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

    let verified_vid = tsp::vid::verify_vid(receiver)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Error verifying vid").into_response())?;
    state
        .timestamp_server
        .add_verified_vid(verified_vid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Error adding verified vid").into_response())?;

    let (_url, response_bytes) = state
        .timestamp_server
        .seal_message(
            &format!(
                "did:web:did.{}:user:timestamp-server",
                DOMAIN.replace(":", "%3A")
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
    let Ok((sender, Some(receiver))) = tsp::cesr::get_sender_receiver(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid message").into_response();
    };

    let sender = String::from_utf8_lossy(sender).to_string();
    let receiver = String::from_utf8_lossy(receiver).to_string();

    // translate received identifier into the transport; either because it is a
    // known user or because it is a did:peer. note that this allows "snooping" messages
    // that are not intended for you --- but that will allow to build interesting demo cases
    // since the unintended recipient cannot read the message: the security of TSP is not based
    // on security of the transport layer.
    let receiver = if let Ok(receiver) = read_id(&receiver).await {
        receiver.vid.endpoint().to_string()
    } else if let Ok(vid) = tsp::vid::resolve::verify_vid_offline(&receiver) {
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
    let result = tsp::crypto::seal(
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
async fn websocket_vid_handler(
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

/// Handle incoming websocket connections for user
async fn websocket_user_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut messages_rx = state.tx.subscribe();
    let current = format!("https://{DOMAIN}/user/{name}");

    tracing::debug!("new websocket connection for {current}");

    ws.on_upgrade(|socket| {
        let (mut ws_send, _) = socket.split();

        async move {
            while let Ok((_, receiver, message)) = messages_rx.recv().await {
                if receiver == current {
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
                    tsp::crypto::open(receiver_vid, sender_vid, &mut encrypted_message)
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

            if let Ok(encoded) = serde_json::from_str::<EncodedMessage>(&incoming_message) {
                if let Ok(original) = Base64UrlUnpadded::decode_vec(&encoded.message) {
                    let _ = state.tx.send((encoded.sender, encoded.receiver, original));
                }
            }
        }
    });

    // Abort the tasks when one of them finishes
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
}
