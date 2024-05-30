use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, RwLock};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp::{
    definitions::{Payload, VerifiedVid},
    vid::{OwnedVid, Vid},
    AsyncStore,
};

use crate::intermediary::start_intermediary;

mod intermediary;

const DOMAIN: &str = "tsp-test.org";

/// Identity struct, used to store the DID document and VID of a user
struct Identity {
    did_doc: serde_json::Value,
    vid: Vid,
}

/// Application state, used to store the identities and the broadcast channel
struct AppState {
    db: RwLock<HashMap<String, Identity>>,
    tx: broadcast::Sender<(String, String, Vec<u8>)>,
}

/// Define the routes and start a server
#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "demo_server=trace,tsp=trace".into()),
        )
        .init();

    let state = Arc::new(AppState {
        db: Default::default(),
        tx: broadcast::channel(100).0,
    });

    // Compose the routes
    let app = Router::new()
        .route("/", get(index))
        .route("/script.js", get(script))
        .route("/create-identity", post(create_identity))
        .route("/verify-vid", post(verify_vid))
        .route("/add-vid", post(add_vid))
        .route("/user/:name/did.json", get(get_did_doc))
        .route("/user/:user", get(websocket_user_handler))
        .route("/user/:user", post(route_message))
        .route("/send-message", post(send_message))
        .route("/receive-messages", get(websocket_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    tokio::task::spawn(async {
        let mut db = AsyncStore::new();
        let piv: OwnedVid = serde_json::from_str(include_str!("../test/p.json")).unwrap();
        db.add_private_vid(piv).unwrap();
        db.verify_vid("did:web:did.tsp-test.org:user:q")
            .await
            .unwrap();
        db.verify_vid("did:web:did.tsp-test.org:user:a")
            .await
            .unwrap();

        db.set_relation_for_vid(
            "did:web:did.tsp-test.org:user:q",
            Some("did:web:did.tsp-test.org:user:p"),
        )
        .unwrap();

        if let Err(e) = start_intermediary("p.tsp-test.org", 3001, db).await {
            eprintln!("error starting intermediary: {:?}", e);
        }
    });

    tokio::task::spawn(async {
        let mut db = AsyncStore::new();
        let piv: OwnedVid = serde_json::from_str(include_str!("../test/q.json")).unwrap();
        db.add_private_vid(piv).unwrap();
        db.verify_vid("did:web:did.tsp-test.org:user:p")
            .await
            .unwrap();
        db.verify_vid("did:web:did.tsp-test.org:user:b")
            .await
            .unwrap();
        db.set_relation_for_vid(
            "did:web:did.tsp-test.org:user:q",
            Some("did:web:did.tsp-test.org:user:b"),
        )
        .unwrap();

        if let Err(e) = start_intermediary("q.tsp-test.org", 3002, db).await {
            eprintln!("error starting intermediary: {:?}", e);
        }
    });

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
async fn create_identity(
    State(state): State<Arc<AppState>>,
    Form(form): Form<CreateIdentityInput>,
) -> impl IntoResponse {
    let (did_doc, _, private_vid) = tsp::vid::create_did_web(
        &form.name,
        DOMAIN,
        &format!("https://{DOMAIN}/user/{}", form.name),
    );

    let key = private_vid.identifier();

    state.db.write().await.insert(
        key.to_string(),
        Identity {
            did_doc: did_doc.clone(),
            vid: private_vid.vid().clone(),
        },
    );

    tracing::debug!("created identity {key}");

    Json(private_vid)
}

#[derive(Deserialize, Debug)]
struct ResolveVidInput {
    vid: String,
}

/// Resolve and verify a VID to JSON encoded key material
async fn verify_vid(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ResolveVidInput>,
) -> Response {
    // local state lookup
    if let Some(identity) = state.db.read().await.get(&form.vid) {
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
async fn add_vid(State(state): State<Arc<AppState>>, Json(vid): Json<Vid>) -> Response {
    let did_doc = tsp::vid::vid_to_did_document(&vid);

    state.db.write().await.insert(
        vid.identifier().to_string(),
        Identity {
            did_doc,
            vid: vid.clone(),
        },
    );

    tracing::debug!("added VID {}", vid.identifier());

    Json(&vid).into_response()
}

/// Get the DID document of a user
async fn get_did_doc(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let key = format!("did:web:{DOMAIN}:user:{name}");

    match state.db.read().await.get(&key) {
        Some(identity) => {
            tracing::debug!("served did.json for {key}");

            Json(identity.did_doc.clone()).into_response()
        }
        None => {
            let keys = state.db.read().await;
            let keys = keys.keys().collect::<Vec<_>>();
            eprintln!("{key} not found, stored identities: {:?}", keys);

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

async fn route_message(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let message: Vec<u8> = body.to_vec();
    let Ok((sender, Some(receiver))) = tsp::cesr::get_sender_receiver(&message) else {
        return (StatusCode::BAD_REQUEST, "invalid message").into_response();
    };

    let sender = String::from_utf8_lossy(sender).to_string();
    let receiver = String::from_utf8_lossy(receiver).to_string();

    tracing::debug!("forwarded message {sender} {receiver}");

    // insert message in queue
    let _ = state.tx.send((sender, receiver, body.to_vec()));

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

/// Handle incoming websocket connections
async fn websocket_user_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut messages_rx = state.tx.subscribe();
    let current = format!("did:web:{DOMAIN}:user:{name}");

    tracing::debug!("new websocket connection for {current}");

    ws.on_upgrade(|socket| {
        let (mut ws_send, _) = socket.split();

        async move {
            while let Ok((_, receiver, message)) = messages_rx.recv().await {
                if receiver == current {
                    let _ = ws_send.send(Message::Binary(message)).await;
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
                let Ok((_, payload, _)) =
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
                .send(Message::Text(decoded.to_string()))
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
