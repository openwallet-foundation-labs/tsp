use crate::definitions::TSPStream;
use bytes::BytesMut;
use url::Url;

pub mod error;

mod http;
mod quic;
mod tcp;
mod tls;

pub use error::TransportError;
pub use http::SseCursor;
pub use http::receive_messages_tracked;

pub async fn send_message(transport: &Url, tsp_message: &[u8]) -> Result<(), TransportError> {
    if let Ok(colored) = crate::cesr::color_format(tsp_message) {
        tracing::trace!("CESR-encoded message: {}", colored);
    }

    match transport.scheme() {
        tcp::SCHEME => tcp::send_message(tsp_message, transport).await,
        tls::SCHEME => tls::send_message(tsp_message, transport).await,
        quic::SCHEME => quic::send_message(tsp_message, transport).await,
        http::SCHEME_HTTP => http::send_message(tsp_message, transport).await,
        http::SCHEME_HTTPS => http::send_message(tsp_message, transport).await,
        _ => Err(TransportError::InvalidTransportScheme(
            transport.scheme().to_string(),
        )),
    }
}

/// Send a cumulative buffer acknowledgment to an HTTP intermediary.
/// Only applicable to HTTP/HTTPS transports. No-op for others.
pub async fn send_ack(
    transport: &Url,
    recipient_did: &str,
    up_to_sequence: u64,
) -> Result<(), TransportError> {
    match transport.scheme() {
        http::SCHEME_HTTP | http::SCHEME_HTTPS => {
            http::send_ack(transport, recipient_did, up_to_sequence).await
        }
        _ => Ok(()), // No-op for non-HTTP transports
    }
}

pub async fn receive_messages(
    transport: &Url,
) -> Result<TSPStream<BytesMut, TransportError>, TransportError> {
    receive_messages_with_cursor(transport, None).await
}

/// Receive messages with an optional SSE cursor (Last-Event-ID).
/// On initial connect, the server replays messages after this ID.
/// For non-HTTP transports, the cursor is ignored.
pub async fn receive_messages_with_cursor(
    transport: &Url,
    last_event_id: Option<String>,
) -> Result<TSPStream<BytesMut, TransportError>, TransportError> {
    match transport.scheme() {
        tcp::SCHEME => tcp::receive_messages(transport).await,
        tls::SCHEME => tls::receive_messages(transport).await,
        quic::SCHEME => quic::receive_messages(transport).await,
        http::SCHEME_HTTP => http::receive_messages(transport, last_event_id.as_deref()).await,
        http::SCHEME_HTTPS => http::receive_messages(transport, last_event_id.as_deref()).await,
        _ => Err(TransportError::InvalidTransportScheme(
            transport.scheme().to_string(),
        )),
    }
}
