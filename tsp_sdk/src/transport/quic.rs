use async_stream::stream;
use bytes::{Bytes, BytesMut};
use once_cell::sync::Lazy;
use quinn::{
    ClientConfig, Endpoint,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::{Mutex as TokioMutex, mpsc};
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

/// Cached QUIC connections keyed by URL string.
/// Each entry holds the Endpoint (owns the UDP socket) and the Connection.
static QUIC_CONNECTIONS: Lazy<TokioMutex<HashMap<String, (Endpoint, quinn::Connection)>>> =
    Lazy::new(|| TokioMutex::new(HashMap::new()));

/// Get an existing cached connection or create a new one.
async fn get_or_create_connection(url: &Url) -> Result<quinn::Connection, TransportError> {
    let key = url.to_string();
    let mut cache = QUIC_CONNECTIONS.lock().await;

    // Return cached connection if still alive
    if let Some((_, conn)) = cache.get(&key) {
        if conn.close_reason().is_none() {
            return Ok(conn.clone());
        }
        // Connection is dead, remove it
        cache.remove(&key);
    }

    // Create a new connection
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

    cache.insert(key, (endpoint, connection.clone()));

    Ok(connection)
}

/// Evict a cached connection so the next send will reconnect.
async fn invalidate_connection(url: &Url) {
    let key = url.to_string();
    let mut cache = QUIC_CONNECTIONS.lock().await;
    cache.remove(&key);
}

/// Send a single message on an existing connection by opening a unidirectional stream.
async fn send_on_connection(
    connection: &quinn::Connection,
    tsp_message: &[u8],
    address: &str,
) -> Result<(), TransportError> {
    let mut send = connection
        .open_uni()
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e.into()))?;

    send.write_all(tsp_message)
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e.into()))?;

    send.finish()
        .map_err(|e| TransportError::Connection(address.to_string(), e.into()))?;

    Ok(())
}

/// Send a message over QUIC
/// Reuses a cached connection to the target endpoint. A new unidirectional
/// stream is opened for each message, which is cheap in QUIC.
/// If the cached connection is stale, it reconnects automatically.
pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), TransportError> {
    let address = url.to_string();
    let connection = get_or_create_connection(url).await?;

    match send_on_connection(&connection, tsp_message, &address).await {
        Ok(()) => Ok(()),
        Err(_) => {
            // Connection may be stale — evict and retry once
            invalidate_connection(url).await;
            let connection = get_or_create_connection(url).await?;
            send_on_connection(&connection, tsp_message, &address).await
        }
    }
}

/// Receive (multiple) messages over QUIC
/// Listens on the specified transport port and yields messages as they arrive.
/// This function handles multiple connections and multiple streams per connection,
/// combining them in a single stream. It uses an internal queue of 16 messages.
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

                // Accept multiple unidirectional streams on this connection
                loop {
                    let mut receive = match conn.accept_uni().await {
                        Ok(s) => s,
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
                        Err(quinn::ConnectionError::ConnectionClosed { .. }) => break,
                        Err(e) => {
                            let _ = tx
                                .send(Err(TransportError::Connection(
                                    address.to_string(),
                                    e.into(),
                                )))
                                .await;
                            break;
                        }
                    };

                    let message = receive.read_to_end(usize::MAX).await.map_err(|_| {
                        TransportError::InvalidMessageReceived(format!(
                            "message from {address} is too long",
                        ))
                    });

                    if tx.send(message).await.is_err() {
                        break;
                    }
                }

                Ok::<(), TransportError>(())
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
    use crate::test_utils::TestPortAllocator;
    use futures::StreamExt;

    #[tokio::test]
    async fn test_quic_transport() {
        let allocator = TestPortAllocator::new();
        let url = Url::parse(&format!("quic://localhost:{}", allocator.allocate())).unwrap();

        let mut incoming_stream = receive_messages(&url).await.unwrap();

        // Send multiple messages to verify connection reuse and multi-stream receiving
        let messages: Vec<Vec<u8>> = (0..10)
            .map(|i| format!("Hello, world! {i}").into_bytes())
            .collect();

        for msg in &messages {
            send_message(msg, &url).await.unwrap();
        }

        for expected in &messages {
            let received = incoming_stream.next().await.unwrap().unwrap();
            assert_eq!(expected.as_slice(), received.iter().as_slice());
        }
    }
}
