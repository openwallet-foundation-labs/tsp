use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::SocketAddrV4;
use tokio::signal;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tsp::{VerifiedVid, Vid};

#[derive(Debug, Parser)]
#[command(name = "demo-did-web")]
#[command(about = "Host a DID:WEB support system", long_about = None)]
struct Cli {
    #[arg(short, long, default_value_t = 3000, help = "The port to listen on")]
    port: u16,
    #[arg(
        index = 1,
        help = "e.g. \"did-web.teaspoon.world\" or \"localhost:3000\""
    )]
    domain: String,
}

#[derive(Clone)]
struct AppState {
    domain: String,
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
    let state = AppState {
        domain: args.domain,
    };

    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any)
        // allow requests from any origin
        .allow_origin(Any);

    // Compose the routes
    let app = Router::new()
        .route("/create-identity", post(create_identity))
        .route("/user/{name}/did.json", get(get_did_doc))
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

#[derive(Deserialize, Debug)]
struct CreateIdentityInput {
    name: String,
}

/// Create a new identity (private VID)
async fn create_identity(
    State(state): State<AppState>,
    Form(form): Form<CreateIdentityInput>,
) -> Response {
    if !verify_name(&form.name) {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let (did_doc, _, private_vid) = tsp::vid::create_did_web(
        &form.name,
        &state.domain,
        &format!("https://{}/user/{}", &state.domain, form.name),
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

/// Get the DID document of a user
async fn get_did_doc(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    if !verify_name(&name) {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let key = format!("did:web:{}:user:{name}", state.domain.replace(":", "%3A"));

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

async fn read_id(vid: &str) -> Result<Identity, Box<dyn std::error::Error>> {
    let name = vid.split(':').last().ok_or("invalid name")?;
    let path = format!("data/{name}.json");
    let did = tokio::fs::read_to_string(path).await?;
    let id = serde_json::from_str(&did)?;

    Ok(id)
}

fn verify_name(name: &str) -> bool {
    !name.is_empty() && name.len() < 64 && name.chars().all(|c| c.is_alphanumeric())
}

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
        .last()
        .ok_or("invalid name")?;
    let did = serde_json::to_string_pretty(&id)?;
    let path = format!("data/{name}.json");

    if std::path::Path::new(&path).exists() {
        return Err("identity already exists".into());
    }

    tokio::fs::write(path, did).await?;

    Ok(())
}
