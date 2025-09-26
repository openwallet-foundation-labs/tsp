use crate::definitions::TSPStream;
use bytes::BytesMut;
use url::Url;

pub mod error;

mod http;
mod quic;
mod tcp;
mod tls;

pub use error::TransportError;

pub async fn send_message(transport: &Url, tsp_message: &[u8]) -> Result<(), TransportError> {
    if tracing::enabled!(tracing::Level::TRACE) {
        println!(
            "CESR-encoded message: {}",
            crate::cesr::color_format(&tsp_message)
                .map_err(|_| TransportError::InvalidMessageReceived("DecodeError".to_string()))?
        );
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

pub async fn receive_messages(
    transport: &Url,
) -> Result<TSPStream<BytesMut, TransportError>, TransportError> {
    match transport.scheme() {
        tcp::SCHEME => tcp::receive_messages(transport).await,
        tls::SCHEME => tls::receive_messages(transport).await,
        quic::SCHEME => quic::receive_messages(transport).await,
        http::SCHEME_HTTP => http::receive_messages(transport).await,
        http::SCHEME_HTTPS => http::receive_messages(transport).await,
        _ => Err(TransportError::InvalidTransportScheme(
            transport.scheme().to_string(),
        )),
    }
}
