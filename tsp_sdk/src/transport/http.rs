use crate::definitions::TSPStream;
use async_stream::stream;
use bytes::BytesMut;
use futures::StreamExt;
use url::Url;

use super::TransportError;
#[cfg(feature = "use_local_certificate")]
use {
    rustls_pki_types::{CertificateDer, pem::PemObject},
    std::sync::Arc,
    tokio_tungstenite::Connector,
    tracing::warn,
};

pub(crate) const SCHEME_HTTP: &str = "http";
pub(crate) const SCHEME_HTTPS: &str = "https";

pub(crate) const SCHEME_WS: &str = "ws";
pub(crate) const SCHEME_WSS: &str = "wss";

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
