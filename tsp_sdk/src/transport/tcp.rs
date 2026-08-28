use async_stream::stream;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use url::Url;

use super::{TSPStream, TransportError};

pub(crate) const SCHEME: &str = "tcp";

/// Cached TCP connections keyed by URL string.
static TCP_CONNECTIONS: Lazy<TokioMutex<HashMap<String, Framed<TcpStream, LengthDelimitedCodec>>>> =
    Lazy::new(|| TokioMutex::new(HashMap::new()));

/// Connect to the first address that accepts the connection.
/// A host like `localhost` can resolve to both IPv6 and IPv4 addresses in
/// nondeterministic order, while the listener may be bound to only one of them.
pub(super) async fn connect_any(
    addresses: &[SocketAddr],
    url: &Url,
) -> Result<TcpStream, TransportError> {
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(TransportError::Connection(address.to_string(), e)),
        }
    }

    Err(last_error.unwrap_or_else(|| TransportError::InvalidTransportAddress(url.to_string())))
}

/// Check whether the peer has closed (or otherwise poisoned) a cached
/// connection. A healthy idle connection returns `WouldBlock`; EOF, an error,
/// or unexpected inbound data all mean the connection must not be reused.
/// This check must happen before sending: a write shortly after the peer
/// closed can be accepted by the kernel and reported as success even though
/// the message is lost, which would bypass the send retry path.
pub(super) fn peer_closed(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    !matches!(stream.try_read(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
}

/// Get an existing cached connection or create a new one.
async fn get_or_create_connection(
    url: &Url,
) -> Result<
    &'static TokioMutex<HashMap<String, Framed<TcpStream, LengthDelimitedCodec>>>,
    TransportError,
> {
    let key = url.to_string();
    let mut cache = TCP_CONNECTIONS.lock().await;

    if let Some(framed) = cache.get(&key)
        && peer_closed(framed.get_ref())
    {
        cache.remove(&key);
    }

    if let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(key) {
        let addresses = url
            .socket_addrs(|| None)
            .map_err(|_| TransportError::InvalidTransportAddress(url.to_string()))?;

        let stream = connect_any(&addresses, url).await?;

        let framed = Framed::new(stream, LengthDelimitedCodec::new());
        entry.insert(framed);
    }

    Ok(&TCP_CONNECTIONS)
}

/// Evict a cached connection so the next send will reconnect.
async fn invalidate_connection(url: &Url) {
    let key = url.to_string();
    let mut cache = TCP_CONNECTIONS.lock().await;
    cache.remove(&key);
}

/// Send a message over TCP.
/// Reuses a cached connection with length-delimited framing.
/// If the connection is stale, it reconnects automatically.
pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), TransportError> {
    let key = url.to_string();

    // First attempt
    {
        let _ = get_or_create_connection(url).await?;
        let mut cache = TCP_CONNECTIONS.lock().await;
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
        let _ = get_or_create_connection(url).await?;
        let mut cache = TCP_CONNECTIONS.lock().await;
        let framed = cache.get_mut(&key).ok_or(TransportError::Internal)?;
        framed
            .send(Bytes::copy_from_slice(tsp_message))
            .await
            .map_err(|e| TransportError::Connection(key, e))?;
    }

    Ok(())
}

/// Receive (multiple) messages over TCP.
/// Listens on the specified transport port and yields messages as they arrive.
/// Uses length-delimited framing to support multiple messages per connection.
pub(crate) async fn receive_messages(
    address: &Url,
) -> Result<TSPStream<BytesMut, TransportError>, TransportError> {
    let addresses = address
        .socket_addrs(|| None)
        .map_err(|_| TransportError::InvalidTransportAddress(address.to_string()))?;

    let Some(address) = addresses.into_iter().next() else {
        return Err(TransportError::InvalidTransportAddress(address.to_string()));
    };

    let listener = TcpListener::bind(&address)
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e))?;

    let (tx, mut rx) = mpsc::channel::<Result<Vec<u8>, TransportError>>(16);

    tokio::spawn(async move {
        while let Ok((stream, peer_addr)) = listener.accept().await {
            let tx = tx.clone();

            tokio::spawn(async move {
                let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

                while let Some(result) = framed.next().await {
                    let message = result
                        .map(|b| b.to_vec())
                        .map_err(|e| TransportError::Connection(peer_addr.to_string(), e));

                    if tx.send(message).await.is_err() {
                        break;
                    }
                }
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
mod test {
    use super::*;
    use crate::test_utils::TestPortAllocator;
    use futures::StreamExt;
    use url::Url;

    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn test_tcp_transport() {
        let allocator = TestPortAllocator::new();
        let url = Url::parse(&format!("tcp://localhost:{}", allocator.allocate())).unwrap();

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

    async fn accept_and_read_one(listener: TcpListener) -> Vec<u8> {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        framed.next().await.unwrap().unwrap().to_vec()
    }

    /// Regression test: a cached connection whose peer exited must not
    /// swallow the next message. The kernel can accept a write on a
    /// half-closed connection and report success, so the send has to detect
    /// the closed peer up front and reconnect to the new listener.
    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn test_tcp_reconnect_after_peer_close() {
        let allocator = TestPortAllocator::new();
        let port = allocator.allocate();
        let url = Url::parse(&format!("tcp://127.0.0.1:{port}")).unwrap();

        // First peer: accept one connection, read one message, then exit
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let first_peer = tokio::spawn(accept_and_read_one(listener));

        send_message(b"first message", &url).await.unwrap();
        assert_eq!(first_peer.await.unwrap(), b"first message");

        // Give the FIN from the exited peer time to reach the cached connection
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Second peer on the same port; the send must reach it promptly
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let second_peer = tokio::spawn(accept_and_read_one(listener));

        send_message(b"second message", &url).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), second_peer)
            .await
            .expect("message was lost on the stale cached connection")
            .unwrap();
        assert_eq!(received, b"second message");
    }

    /// Regression test: `localhost` resolves to both IPv6 and IPv4 addresses
    /// in nondeterministic order; a listener bound to only one address family
    /// must still be reachable by hostname.
    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn test_tcp_dual_stack_hostname() {
        let allocator = TestPortAllocator::new();

        for bind_address in ["::1", "127.0.0.1"] {
            let port = allocator.allocate();
            let url = Url::parse(&format!("tcp://localhost:{port}")).unwrap();

            let want_ipv6 = bind_address == "::1";
            let addresses = url.socket_addrs(|| None).unwrap();
            if !addresses.iter().any(|a| a.is_ipv6() == want_ipv6) {
                // localhost does not resolve to this address family here
                continue;
            }

            let listener = match TcpListener::bind((bind_address, port)).await {
                Ok(listener) => listener,
                // this address family is not available on this host
                Err(_) => continue,
            };
            let peer = tokio::spawn(accept_and_read_one(listener));

            send_message(b"hello", &url).await.unwrap();

            let received = tokio::time::timeout(std::time::Duration::from_secs(5), peer)
                .await
                .expect("connect went to the wrong address family")
                .unwrap();
            assert_eq!(received, b"hello");
        }
    }
}
