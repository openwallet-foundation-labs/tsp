use crate::definitions::TSPStream;
use async_stream::stream;
use bytes::BytesMut;
use futures::StreamExt;
use url::Url;

#[cfg(feature = "use_local_certificate")]
use std::io::Read;

use super::TransportError;

pub(crate) const SCHEME_HTTP: &str = "http";
pub(crate) const SCHEME_HTTPS: &str = "https";

pub(crate) const SCHEME_WS: &str = "ws";
pub(crate) const SCHEME_WSS: &str = "wss";

pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), TransportError> {
    let client = reqwest::Client::builder();

    #[cfg(feature = "use_local_certificate")]
    let cert = {
        tracing::warn!("Using local root CA! (should only be used for local testing)");
        let mut buf = Vec::new();
        std::fs::File::open("./test/root-ca.pem")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        reqwest::Certificate::from_pem(&buf).unwrap()
    };

    #[cfg(feature = "use_local_certificate")]
    let client = client.add_root_certificate(cert);

    let url = url.clone();

    client
        .build()
        .map_err(|e| TransportError::Http("Client build error".to_string(), e))?
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

    let ws_stream = match tokio_tungstenite::connect_async(ws_address.as_str()).await {
        Ok((stream, _)) => stream,
        Err(e) => return Err(TransportError::Websocket(ws_address.to_string(), e)),
    };

    let (_, mut receiver) = ws_stream.split();

    Ok(Box::pin(stream! {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                tokio_tungstenite::tungstenite::Message::Binary(b) => {
                    yield Ok(b.into());
                }
                m => {
                    yield Err(TransportError::InvalidMessageReceived(
                        m
                            .into_text()
                            .map(|m| m.to_string())
                            .map_err(|_| TransportError::InvalidMessageReceived("invalid UTF8 character encountered".to_string()))?
                    ));
                }
            };
        }
    }))
}
