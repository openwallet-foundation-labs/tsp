use async_stream::stream;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use once_cell::sync::Lazy;
use rustls::{ClientConfig, RootCertStore, crypto::CryptoProvider};
use rustls_pki_types::{ServerName, pem::PemObject};
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::mpsc};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::codec::{BytesCodec, Framed};
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

    rustls::ClientConfig::builder_with_provider(CRYPTO_PROVIDER.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth()
}

pub(super) static CRYPTO_PROVIDER: Lazy<Arc<CryptoProvider>> =
    Lazy::new(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
pub(super) static TLS_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| Arc::new(create_tls_config()));

/// Send a message over TLS
/// Connects to the specified transport address and sends the message.
/// Note that a new connection is opened for each message.
pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), TransportError> {
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
        TransportError::InvalidTransportAddress(format!("could not resolve {url} to a server name"))
    })?;

    let connector = TlsConnector::from(TLS_CONFIG.clone());

    let mut stream = connector
        .connect(dns_name, tcp_stream)
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e))?;

    stream
        .write_all(tsp_message)
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e))?;

    stream
        .shutdown()
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e))?;

    Ok(())
}

/// Receive (multiple) messages over TLS
/// Listens on the specified transport port and yields messages as they arrive
/// This function handles multiple connections and messages and
/// combines them in a single stream. It uses an internal queue of 16 messages.
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

                let mut messages = Framed::new(stream, BytesCodec::new());

                while let Some(m) = messages.next().await {
                    tx.send(
                        m.map(|m| m.to_vec())
                            .map_err(|e| TransportError::Connection(peer_addr.to_string(), e)),
                    )
                    .await
                    .map_err(|_| TransportError::Internal)?;
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
    use futures::StreamExt;

    #[tokio::test]
    async fn test_tls_transport() {
        let url = Url::parse("tls://localhost:4242").unwrap();
        let message = b"Hello, world!";

        let mut incoming_stream = receive_messages(&url).await.unwrap();

        send_message(message, &url).await.unwrap();

        let received_message = incoming_stream.next().await.unwrap().unwrap();

        assert_eq!(message, received_message.iter().as_slice());
    }
}
