use async_stream::stream;
use bytes::{Bytes, BytesMut};
use futures::{FutureExt, SinkExt, StreamExt};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use url::Url;

use super::{TSPStream, TransportError};

pub(crate) const SCHEME: &str = "tcp";

type TcpFramed = Framed<TcpStream, LengthDelimitedCodec>;

/// One peer's cached connection, with the lock that serialises writes to it.
///
/// The map below is locked only to find or insert this handle, never while
/// sending. Holding a single global lock across the write serialised every
/// send in the process against every other, so throughput fell as senders were
/// added and one slow peer stalled traffic to every other peer. Writes to the
/// same peer still serialise, which they must: a `Framed` cannot be written
/// concurrently.
type Connection = Arc<TokioMutex<Option<TcpFramed>>>;

/// Cached TCP connections keyed by URL string.
static TCP_CONNECTIONS: Lazy<TokioMutex<HashMap<String, Connection>>> =
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
/// connection, without consuming any inbound bytes (MSG_PEEK): a healthy idle
/// connection is not readable, and inbound data — which a TLS session
/// legitimately receives, e.g. session tickets — does not poison anything.
/// This check must happen before sending: a write shortly after the peer
/// closed can be accepted by the kernel and reported as success even though
/// the message is lost, which would bypass the send retry path.
pub(super) async fn peer_closed(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    // Poll the peek exactly once. A timer must not be used here: tokio's timer
    // wheel is millisecond-granular, so even a zero-duration timeout costs a
    // tick per send — around 1.5 ms, which dominated small messages.
    match stream.peek(&mut buf).now_or_never() {
        // not readable: healthy idle connection
        None => false,
        // EOF or socket error: the peer is gone
        Some(Ok(0)) | Some(Err(_)) => true,
        // inbound data with the connection still open
        Some(Ok(_)) => false,
    }
}

/// The handle for a peer, empty if nothing is connected yet. Holds the map
/// lock only long enough to look up or insert.
async fn connection_for(url: &Url) -> Connection {
    let mut cache = TCP_CONNECTIONS.lock().await;
    cache.entry(url.to_string()).or_default().clone()
}

/// Open a fresh connection to `url`.
async fn connect(url: &Url) -> Result<TcpFramed, TransportError> {
    let addresses = url
        .socket_addrs(|| None)
        .map_err(|_| TransportError::InvalidTransportAddress(url.to_string()))?;
    let stream = connect_any(&addresses, url).await?;

    Ok(Framed::new(stream, LengthDelimitedCodec::new()))
}

/// Send a message over TCP.
/// Reuses a cached connection with length-delimited framing.
/// If the connection is stale, it reconnects automatically.
pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), TransportError> {
    let connection = connection_for(url).await;
    let mut cached = connection.lock().await;

    // Drop a connection whose peer has gone before writing to it: the kernel
    // can accept a write shortly after the peer closed and report success even
    // though the message is lost, which would bypass the retry below.
    if let Some(framed) = cached.as_ref()
        && peer_closed(framed.get_ref()).await
    {
        *cached = None;
    }

    if cached.is_none() {
        *cached = Some(connect(url).await?);
    }

    let framed = cached.as_mut().ok_or(TransportError::Internal)?;
    if framed
        .send(Bytes::copy_from_slice(tsp_message))
        .await
        .is_ok()
    {
        return Ok(());
    }

    // Retry once on a fresh connection, leaving nothing cached if that fails
    // too, so the next send starts over.
    *cached = None;
    let mut framed = connect(url).await?;
    framed
        .send(Bytes::copy_from_slice(tsp_message))
        .await
        .map_err(|e| TransportError::Connection(url.to_string(), e))?;
    *cached = Some(framed);

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

    /// Regression test: a peer that stops reading must not block sends to
    /// other peers. The connection cache is global, so an implementation that
    /// holds the map lock across the write serialises every send in the
    /// process: one unresponsive peer then stalls traffic to all of them.
    /// Measured at 4.7 seconds before the per-connection lock was introduced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial_test::serial(tcp)]
    async fn test_tcp_stalled_peer_does_not_block_other_peers() {
        let allocator = TestPortAllocator::new();

        // A peer that accepts the connection and then never reads a byte.
        let deaf_port = allocator.allocate();
        let deaf_url = Url::parse(&format!("tcp://127.0.0.1:{deaf_port}")).unwrap();
        let deaf = TcpListener::bind(("127.0.0.1", deaf_port)).await.unwrap();
        tokio::spawn(async move {
            let _accepted = deaf.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        // A healthy peer that drains what it is sent.
        let live_url = Url::parse(&format!("tcp://127.0.0.1:{}", allocator.allocate())).unwrap();
        let mut incoming = receive_messages(&live_url).await.unwrap();
        tokio::spawn(async move { while incoming.next().await.is_some() {} });

        // Fill the deaf peer's socket buffer so that its next send blocks.
        let big = vec![0x5Au8; 512 * 1024];
        let stalled = tokio::spawn({
            let url = deaf_url.clone();
            async move {
                for _ in 0..40 {
                    if tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        send_message(&big, &url),
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                }
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Sends to the healthy peer must still complete promptly.
        let small = vec![0x41u8; 256];
        let mut worst = std::time::Duration::ZERO;
        for _ in 0..10 {
            let started = std::time::Instant::now();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                send_message(&small, &live_url),
            )
            .await
            .expect("send to the healthy peer never returned")
            .expect("send to the healthy peer failed");
            worst = worst.max(started.elapsed());
        }
        stalled.abort();

        assert!(
            worst < std::time::Duration::from_millis(500),
            "a stalled peer blocked sends to an unrelated peer for {worst:?}"
        );
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
