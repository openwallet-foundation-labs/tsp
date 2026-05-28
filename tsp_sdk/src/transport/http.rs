use crate::definitions::TSPStream;
use async_stream::stream;
use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::BytesMut;
use futures::StreamExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

/// Shared cursor that the SSE stream updates with the latest event ID.
/// The application can read this to persist the cursor and send acks.
pub type SseCursor = Arc<AtomicU64>;

use super::TransportError;
#[cfg(feature = "use_local_certificate")]
use {
    rustls_pki_types::{CertificateDer, pem::PemObject},
    tokio_tungstenite::Connector,
    tracing::warn,
};

pub(crate) const SCHEME_HTTP: &str = "http";
pub(crate) const SCHEME_HTTPS: &str = "https";

pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), TransportError> {
    let url = url.clone();
    let client = crate::http_client::reqwest_client()
        .map_err(|e| TransportError::Http(e.context.to_string(), e.source))?;

    let response = client
        .post(url.clone())
        .body(tsp_message.to_vec())
        .send()
        .await
        .map_err(|e| TransportError::Http(url.to_string(), e))?;

    if let Err(e) = response.error_for_status_ref() {
        if let Ok(text) = response.text().await {
            tracing::error!("{text}");
        }
        return Err(TransportError::Http(url.to_string(), e));
    }

    Ok(())
}

/// Send a cumulative acknowledgment to the intermediary's buffer.
///
/// Tells the intermediary "I have processed all messages up to and including
/// this sequence number. You may delete them."
///
/// The `address` should be the intermediary's base URL (e.g., https://p.teaspoon.world).
/// The `recipient_did` identifies which recipient queue to ack.
pub(crate) async fn send_ack(
    address: &Url,
    recipient_did: &str,
    up_to_sequence: u64,
) -> Result<(), TransportError> {
    let mut ack_url = address.clone();
    ack_url.set_path(&format!("/ack/{}", recipient_did));

    let client = crate::http_client::reqwest_client()
        .map_err(|e| TransportError::Http(e.context.to_string(), e.source))?;

    let body = format!("{{\"up_to_sequence\":{}}}", up_to_sequence);

    let response = client
        .post(ack_url.clone())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| TransportError::Http(ack_url.to_string(), e))?;

    if let Err(e) = response.error_for_status_ref() {
        return Err(TransportError::Http(ack_url.to_string(), e));
    }

    tracing::debug!(
        recipient = %recipient_did,
        up_to_sequence = up_to_sequence,
        "Buffer ack sent"
    );

    Ok(())
}

/// Receive messages via Server-Sent Events (SSE).
///
/// Opens a GET request with `Accept: text/event-stream` to the transport URL.
/// The server pushes messages as SSE events with CESR-T (base64url) encoded data
/// and monotonic IDs. On disconnect, the SSE client auto-reconnects with
/// `Last-Event-ID` to resume from where it left off.
///
/// Falls back to WebSocket if SSE is not supported by the server.
pub(crate) async fn receive_messages(
    address: &Url,
    last_event_id: Option<&str>,
) -> Result<TSPStream<BytesMut, TransportError>, TransportError> {
    let (stream, _cursor) = receive_messages_tracked(address, last_event_id).await?;
    Ok(stream)
}

/// Receive messages and return a shared cursor that tracks the latest event ID.
/// The caller can read the cursor to persist it and send acks.
pub async fn receive_messages_tracked(
    address: &Url,
    last_event_id: Option<&str>,
) -> Result<(TSPStream<BytesMut, TransportError>, SseCursor), TransportError> {
    let sse_url = address.clone();
    let address_owned = address.clone();
    let initial_cursor: Option<u64> = last_event_id.and_then(|s| s.parse::<u64>().ok());
    let cursor_str = last_event_id.map(|s| s.to_string());

    // Shared cursor — updated by the stream, readable by the caller
    let cursor = Arc::new(AtomicU64::new(initial_cursor.unwrap_or(0)));
    let cursor_for_stream = Arc::clone(&cursor);

    tracing::debug!("Opening SSE connection to {}", sse_url);

    // Build the SSE request, optionally with Last-Event-ID for cursor resume
    let mut es = if let Some(ref cursor_val) = cursor_str {
        tracing::debug!("SSE resuming from Last-Event-ID: {}", cursor_val);
        let client = crate::http_client::reqwest_client()
            .map_err(|e| TransportError::Http(e.context.to_string(), e.source))?;
        let request = client
            .get(sse_url.as_str())
            .header("Last-Event-ID", cursor_val.as_str());
        reqwest_eventsource::EventSource::new(request)
            .map_err(|e| TransportError::InvalidMessageReceived(format!("SSE init error: {}", e)))?
    } else {
        reqwest_eventsource::EventSource::get(sse_url.as_str())
    };

    let stream = Box::pin(stream! {
        let mut last_processed_id: Option<u64> = initial_cursor;

        loop {
            match es.next().await {
                Some(Ok(reqwest_eventsource::Event::Open)) => {
                    tracing::debug!("SSE connection opened to {}", address_owned);
                }
                Some(Ok(reqwest_eventsource::Event::Message(msg))) => {
                    // Deduplication: skip events we've already processed
                    if let Ok(event_id) = msg.id.parse::<u64>() {
                        if let Some(last_id) = last_processed_id
                            && event_id <= last_id
                        {
                            tracing::debug!("SSE dedup: skipping event id={} (last_processed={})", event_id, last_id);
                            continue;
                        }
                        last_processed_id = Some(event_id);
                        cursor_for_stream.store(event_id, Ordering::Relaxed);
                    }

                    // SSE event data is CESR-T (base64url) encoded
                    match Base64UrlUnpadded::decode_vec(&msg.data) {
                        Ok(binary) => {
                            yield Ok(BytesMut::from(binary.as_slice()));
                        }
                        Err(e) => {
                            tracing::debug!("SSE event not base64url, treating as raw: {}", e);
                            // Try treating as raw binary (backward compat with non-encoded data)
                            yield Ok(BytesMut::from(msg.data.as_bytes()));
                        }
                    }
                }
                Some(Err(reqwest_eventsource::Error::StreamEnded)) => {
                    // Stream ended normally — the library will auto-reconnect
                    tracing::debug!("SSE stream ended, auto-reconnecting");
                }
                Some(Err(e)) => {
                    tracing::debug!("SSE error: {}", e);
                    // For fatal errors, try falling back to WebSocket
                    if is_fatal_sse_error(&e) {
                        tracing::info!("SSE not supported, falling back to WebSocket");
                        es.close();
                        break;
                    }
                    // Non-fatal errors: the library retries automatically
                }
                None => {
                    // Stream exhausted — shouldn't happen with auto-reconnect
                    tracing::debug!("SSE stream exhausted");
                    break;
                }
            }
        }

        // Fallback: try WebSocket (for backward compatibility with older intermediaries)
        tracing::debug!("Attempting WebSocket fallback for {}", address_owned);
        let ws_stream = match open_websocket(&address_owned).await {
            Ok(stream) => stream,
            Err(e) => {
                yield Err(e);
                return;
            }
        };

        let mut ws_stream = ws_stream;
        while let Some(result) = ws_stream.next().await {
            yield result;
        }
    });

    Ok((stream, cursor))
}

/// Open a WebSocket connection (fallback for servers that don't support SSE).
async fn open_websocket(
    address: &Url,
) -> Result<TSPStream<BytesMut, TransportError>, TransportError> {
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let mut ws_address = address.clone();
    match address.scheme() {
        SCHEME_HTTP => ws_address.set_scheme("ws"),
        SCHEME_HTTPS => ws_address.set_scheme("wss"),
        _ => Err(()),
    }
    .map_err(|_| TransportError::InvalidTransportScheme(address.scheme().to_owned()))?;

    #[allow(unused)]
    let mut connector = None;
    #[cfg(feature = "use_local_certificate")]
    {
        warn!("Using local root CA (should only be used for local testing)");
        let cert = include_bytes!("../../../examples/test/root-ca.pem");
        let mut store = rustls::RootCertStore::empty();
        store.add_parsable_certificates([CertificateDer::from_pem_slice(cert).unwrap()]);
        let rustls_client = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(store)
                .with_no_client_auth(),
        );
        connector = Some(Connector::Rustls(rustls_client));
    }

    let ws_stream = match tokio_tungstenite::connect_async_tls_with_config(
        ws_address.as_str(),
        None,
        false,
        connector,
    )
    .await
    {
        Ok((stream, _)) => stream,
        Err(e) => {
            return Err(TransportError::Websocket(
                ws_address.to_string(),
                Box::new(e),
            ));
        }
    };

    let (_, mut receiver) = ws_stream.split();

    Ok(Box::pin(stream! {
        while let Some(result) = receiver.next().await {
            match result {
                Ok(WsMessage::Binary(b)) => {
                    yield Ok(b.into());
                }
                Ok(WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Text(_) | WsMessage::Frame(_)) => {
                    continue;
                }
                Ok(WsMessage::Close(_)) | Err(_) => {
                    break;
                }
            }
        }
    }))
}

/// Determine if an SSE error is fatal (should fall back to WebSocket)
/// vs transient (library will auto-retry).
fn is_fatal_sse_error(err: &reqwest_eventsource::Error) -> bool {
    match err {
        // 404, 405, etc. — server doesn't support SSE at this endpoint
        reqwest_eventsource::Error::InvalidStatusCode(status, _) => {
            status.as_u16() == 404 || status.as_u16() == 405
        }
        // Content-type mismatch — server returned HTML or JSON, not event-stream
        reqwest_eventsource::Error::InvalidContentType(_, _) => true,
        // Other errors are transient (network issues, timeouts)
        _ => false,
    }
}
