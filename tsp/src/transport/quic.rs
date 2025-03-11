use async_stream::stream;
use bytes::{Bytes, BytesMut};
use once_cell::sync::Lazy;
use quinn::{
    ClientConfig, Endpoint,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::mpsc;
use url::Url;

use super::TransportError;
use crate::definitions::TSPStream;

pub(crate) const SCHEME: &str = "quic";

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

static QUIC_CONFIG: Lazy<ClientConfig> = Lazy::new(|| {
    let mut config = super::tls::create_tls_config();
    config.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(Arc::new(config))
            .expect("could not convert TLS config to QUIC config"),
    ))
});

/// Send a message over QUIC
/// Connects to the specified transport address and sends the message.
/// Note that a new connection is opened for each message.
pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), TransportError> {
    let addresses = url
        .socket_addrs(|| None)
        .map_err(|_| TransportError::InvalidTransportAddress(url.to_string()))?;

    let Some(address) = addresses.first().cloned() else {
        return Err(TransportError::InvalidTransportAddress(url.to_string()));
    };

    let domain = url
        .domain()
        .ok_or(TransportError::InvalidTransportAddress(format!(
            "could not resolve {url} to a domain"
        )))?
        .to_owned();

    // passing 0 as port number opens a random port
    let listen_address: SocketAddr = if address.is_ipv6() {
        (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 0).into()
    } else {
        (Ipv4Addr::new(127, 0, 0, 1), 0).into()
    };

    let mut endpoint = Endpoint::client(listen_address).map_err(|_| TransportError::ListenPort)?;

    endpoint.set_default_client_config(QUIC_CONFIG.clone());

    let connection = endpoint
        .connect(address, &domain)
        .map_err(|e| TransportError::QuicConnection(address.to_string(), e))?
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e.into()))?;

    let mut send = connection
        .open_uni()
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e.into()))?;

    send.write_all(tsp_message)
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e.into()))?;

    send.finish()
        .map_err(|e| TransportError::Connection(address.to_string(), e.into()))?;

    send.stopped()
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e.into()))?;

    connection.close(0u32.into(), b"done");

    Ok(())
}

/// Receive (multiple) messages over QUIC
/// Listens on the specified transport port and yields messages as they arrive
/// This function handles multiple connections and messages and
/// combines them in a single stream. It uses an internal queue of 16 messages.
pub(crate) async fn receive_messages(
    address: &Url,
) -> Result<TSPStream<BytesMut, TransportError>, TransportError> {
    let addresses = address
        .socket_addrs(|| None)
        .map_err(|_| TransportError::InvalidTransportAddress(address.to_string()))?;

    let Some(address) = addresses.first().cloned() else {
        return Err(TransportError::InvalidTransportAddress(address.to_string()));
    };

    let (cert, key) = super::tls::load_certificate()?;

    let mut server_crypto =
        rustls::ServerConfig::builder_with_provider(super::tls::CRYPTO_PROVIDER.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(cert, key)?;

    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).map_err(|_| TransportError::Internal)?,
    ));

    let endpoint = Endpoint::server(server_config, address)
        .map_err(|e| TransportError::Connection(address.to_string(), e))?;

    let (tx, mut rx) = mpsc::channel::<Result<Vec<u8>, TransportError>>(16);

    tokio::spawn(async move {
        while let Some(incoming_conn) = endpoint.accept().await {
            let tx = tx.clone();

            tokio::spawn(async move {
                let conn = incoming_conn
                    .await
                    .map_err(|e| TransportError::Connection(address.to_string(), e.into()))?;

                let receive = conn.accept_uni().await;

                let mut receive = match receive {
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(TransportError::Connection(address.to_string(), e.into()));
                    }
                    Ok(s) => s,
                };

                let message = receive.read_to_end(8 * 1024).await.map_err(|_| {
                    TransportError::InvalidMessageReceived(format!(
                        "message from {address} is too long",
                    ))
                });

                tx.send(message)
                    .await
                    .map_err(|_| TransportError::Internal)?;

                Ok(())
            });
        }
    });

    Ok(Box::pin(stream! {
        while let Some(item) = rx.recv().await {
            yield item.map(Bytes::from).map(BytesMut::from);
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn test_quic_transport() {
        let url = Url::parse("quic://localhost:3737").unwrap();
        let message = b"Hello, world!";

        let mut incoming_stream = receive_messages(&url).await.unwrap();

        send_message(message, &url).await.unwrap();

        let received_message = incoming_stream.next().await.unwrap().unwrap();

        assert_eq!(message, received_message.iter().as_slice());
    }
}
