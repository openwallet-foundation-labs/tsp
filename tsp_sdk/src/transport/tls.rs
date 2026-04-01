use async_stream::stream;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use rustls::{ClientConfig, RootCertStore, crypto::CryptoProvider};
use rustls_pki_types::{ServerName, pem::PemObject};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex as TokioMutex;
use tokio::{net::TcpListener, sync::mpsc};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use url::Url;

use super::TransportError;
use crate::definitions::TSPStream;

pub(crate) const SCHEME: &str = "tls";

/// Load a certificate and key from files specified by the environment
/// variables `TSP_TLS_CERT` and `TSP_TLS_KEY`.
/// When running tests the test certificate and key will always be used.
pub(super) fn load_certificate() -> Result<
    (
        Vec<rustls_pki_types::CertificateDer<'static>>,
        rustls_pki_types::PrivateKeyDer<'static>,
    ),
    TransportError,
> {
    #[cfg(all(not(test), not(feature = "bench-criterion")))]
    let cert_path = std::env::var("TSP_TLS_CERT").map_err(|_| TransportError::TLSConfiguration)?;
    #[cfg(all(not(test), not(feature = "bench-criterion")))]
    let key_path = std::env::var("TSP_TLS_KEY").map_err(|_| TransportError::TLSConfiguration)?;
    #[cfg(any(test, feature = "bench-criterion"))]
    let cert_path = "../examples/test/localhost.pem".to_string();
    #[cfg(any(test, feature = "bench-criterion"))]
    let key_path = "../examples/test/localhost-key.pem".to_string();

    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_file_iter(&cert_path)
            .map_err(|_| TransportError::TLSMissingFile(cert_path))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TransportError::TLSCertificate)?;

    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(&key_path)
        .map_err(|_| TransportError::TLSKey(key_path))?;

    Ok((certs, key))
}

pub(super) fn create_tls_config() -> ClientConfig {
    // Load native system certificates
    let mut root_cert_store = RootCertStore::empty();
    for cert in
        rustls_native_certs::load_native_certs().expect("could not load native certificates")
    {
        root_cert_store
            .add(cert)
            .expect("could not add native certificate");
    }

    // Add local test CA certificate (for tests and local dev benches only).
    #[cfg(any(test, feature = "bench-criterion"))]
    {
        let cert_path = "../examples/test/root-ca.pem";
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::CertificateDer::pem_file_iter(cert_path)
                .expect("could not find test CA certificate")
                .collect::<Result<Vec<_>, _>>()
                .expect("could not read test CA certificate");

        for cert in certs {
            root_cert_store
                .add(cert)
                .expect("could not add test CA certificate")
        }
    }

    // Add custom CA certificate from TSP_TLS_CA environment variable (if set)
    #[cfg(not(test))]
    if let Ok(ca_path) = std::env::var("TSP_TLS_CA") {
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::CertificateDer::pem_file_iter(&ca_path)
                .unwrap_or_else(|_| panic!("could not find CA certificate at {ca_path}"))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|_| panic!("could not read CA certificate at {ca_path}"));

        for cert in certs {
            root_cert_store
                .add(cert)
                .expect("could not add custom CA certificate");
        }
    }

    rustls::ClientConfig::builder_with_provider(CRYPTO_PROVIDER.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth()
}

pub(super) static CRYPTO_PROVIDER: Lazy<Arc<CryptoProvider>> =
    Lazy::new(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
pub(super) static TLS_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| Arc::new(create_tls_config()));

type TlsFramed = Framed<TlsStream<tokio::net::TcpStream>, LengthDelimitedCodec>;

/// Cached TLS connections keyed by URL string.
static TLS_CONNECTIONS: Lazy<TokioMutex<HashMap<String, TlsFramed>>> =
    Lazy::new(|| TokioMutex::new(HashMap::new()));

/// Get an existing cached TLS connection or create a new one.
async fn get_or_create_connection(url: &Url) -> Result<(), TransportError> {
    let key = url.to_string();
    let mut cache = TLS_CONNECTIONS.lock().await;

    if let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(key) {
        let addresses = url
            .socket_addrs(|| None)
            .map_err(|_| TransportError::InvalidTransportAddress(url.to_string()))?;

        let Some(address) = addresses.first().cloned() else {
            return Err(TransportError::InvalidTransportAddress(url.to_string()));
        };

        let tcp_stream = tokio::net::TcpStream::connect(address)
            .await
            .map_err(|e| TransportError::Connection(address.to_string(), e))?;

        let domain = url
            .domain()
            .ok_or(TransportError::InvalidTransportAddress(format!(
                "could not resolve {url} to a domain"
            )))?
            .to_owned();

        let dns_name = ServerName::try_from(domain).map_err(|_| {
            TransportError::InvalidTransportAddress(format!(
                "could not resolve {url} to a server name"
            ))
        })?;

        let connector = TlsConnector::from(TLS_CONFIG.clone());

        let tls_stream = connector
            .connect(dns_name, tcp_stream)
            .await
            .map_err(|e| TransportError::Connection(address.to_string(), e))?;

        let framed = Framed::new(tls_stream, LengthDelimitedCodec::new());
        entry.insert(framed);
    }

    Ok(())
}

/// Evict a cached connection so the next send will reconnect.
async fn invalidate_connection(url: &Url) {
    let key = url.to_string();
    let mut cache = TLS_CONNECTIONS.lock().await;
    cache.remove(&key);
}

/// Send a message over TLS.
/// Reuses a cached connection with length-delimited framing.
/// If the connection is stale, it reconnects automatically.
pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), TransportError> {
    let key = url.to_string();

    // First attempt
    {
        get_or_create_connection(url).await?;
        let mut cache = TLS_CONNECTIONS.lock().await;
        if let Some(framed) = cache.get_mut(&key)
            && framed
                .send(Bytes::copy_from_slice(tsp_message))
                .await
                .is_ok()
        {
            return Ok(());
        }
    }

    // Retry once on failure
    invalidate_connection(url).await;
    {
        get_or_create_connection(url).await?;
        let mut cache = TLS_CONNECTIONS.lock().await;
        let framed = cache.get_mut(&key).ok_or(TransportError::Internal)?;
        framed
            .send(Bytes::copy_from_slice(tsp_message))
            .await
            .map_err(|e| TransportError::Connection(key, e))?;
    }

    Ok(())
}

/// Receive (multiple) messages over TLS.
/// Listens on the specified transport port and yields messages as they arrive.
/// Uses length-delimited framing to support multiple messages per connection.
pub(crate) async fn receive_messages(
    address: &Url,
) -> Result<TSPStream<BytesMut, TransportError>, TransportError> {
    let addresses = address
        .socket_addrs(|| None)
        .map_err(|_| TransportError::InvalidTransportAddress(address.to_string()))?;

    let Some(address) = addresses.first() else {
        return Err(TransportError::InvalidTransportAddress(address.to_string()));
    };

    let (cert, key) = load_certificate()?;
    let config = rustls::ServerConfig::builder_with_provider(CRYPTO_PROVIDER.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&address)
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e))?;

    let (tx, mut rx) = mpsc::channel::<Result<Vec<u8>, TransportError>>(16);

    tokio::spawn(async move {
        while let Ok((stream, peer_addr)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let tx = tx.clone();

            tokio::spawn(async move {
                let stream = acceptor
                    .accept(stream)
                    .await
                    .map_err(|e| TransportError::Connection(peer_addr.to_string(), e))?;

                let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

                while let Some(result) = framed.next().await {
                    let message = result
                        .map(|b| b.to_vec())
                        .map_err(|e| TransportError::Connection(peer_addr.to_string(), e));

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
    async fn test_tls_transport() {
        let allocator = TestPortAllocator::new();
        let url = Url::parse(&format!("tls://localhost:{}", allocator.allocate())).unwrap();

        let mut incoming_stream = receive_messages(&url).await.unwrap();

        // Send multiple messages to verify connection reuse and framing
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
