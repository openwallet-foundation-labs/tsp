use crate::definitions::TSPStream;
use tokio_util::bytes::BytesMut;
use url::Url;

pub mod error;

mod http;
pub mod tcp;

pub use error::TransportError;

pub async fn send_message(transport: &Url, tsp_message: &[u8]) -> Result<(), TransportError> {
    match transport.scheme() {
        tcp::SCHEME => tcp::send_message(tsp_message, transport).await,
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
        http::SCHEME_HTTP => http::receive_messages(transport).await,
        http::SCHEME_HTTPS => http::receive_messages(transport).await,
        _ => Err(TransportError::InvalidTransportScheme(
            transport.scheme().to_string(),
        )),
    }
}
