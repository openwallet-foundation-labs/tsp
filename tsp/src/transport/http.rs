use crate::definitions::TSPStream;
use async_stream::stream;
use futures::StreamExt;
use tokio_util::bytes::BytesMut;
use url::Url;

use super::TransportError;

pub(crate) const SCHEME_HTTP: &str = "http";
pub(crate) const SCHEME_HTTPS: &str = "https";

pub(crate) const SCHEME_WS: &str = "ws";
pub(crate) const SCHEME_WSS: &str = "wss";

pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), TransportError> {
    let client = reqwest::Client::new();
    let url = url.clone();

    client
        .post(url.clone())
        .body(tsp_message.to_vec())
        .send()
        .await
        .map_err(|e| TransportError::Http(url.to_string(), e))?;

    Ok(())
}

pub(crate) async fn receive_messages(
    address: &Url,
) -> Result<TSPStream<BytesMut, TransportError>, TransportError> {
    let mut ws_address = address.clone();

    match address.scheme() {
        SCHEME_HTTP => ws_address.set_scheme(SCHEME_WS),
        SCHEME_HTTPS => ws_address.set_scheme(SCHEME_WSS),
        _ => Err(()),
    }
    .map_err(|_| TransportError::InvalidTransportScheme(address.scheme().to_owned()))?;

    let ws_stream = match tokio_tungstenite::connect_async(&ws_address).await {
        Ok((stream, _)) => stream,
        Err(e) => return Err(TransportError::Websocket(ws_address.to_string(), e)),
    };

    let (_, mut receiver) = ws_stream.split();

    Ok(Box::pin(stream! {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                tokio_tungstenite::tungstenite::Message::Binary(b) => {
                    yield Ok(BytesMut::from(&b[..]));
                }
                m => {
                    yield Err(TransportError::InvalidMessageReceived(
                        m
                            .into_text()
                            .map_err(|_| TransportError::InvalidMessageReceived("invalid UTF8 character encountered".to_string()))?
                    ));
                }
            };
        }
    }))
}
