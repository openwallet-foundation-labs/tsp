use async_stream::stream;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use url::Url;

use super::{TSPStream, TransportError};

pub(crate) const SCHEME: &str = "tcp";

/// Cached TCP connections keyed by URL string.
static TCP_CONNECTIONS: Lazy<TokioMutex<HashMap<String, Framed<TcpStream, LengthDelimitedCodec>>>> =
    Lazy::new(|| TokioMutex::new(HashMap::new()));

/// Get an existing cached connection or create a new one.
async fn get_or_create_connection(
    url: &Url,
) -> Result<
    &'static TokioMutex<HashMap<String, Framed<TcpStream, LengthDelimitedCodec>>>,
    TransportError,
> {
    let key = url.to_string();
    let mut cache = TCP_CONNECTIONS.lock().await;

    if let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(key) {
        let addresses = url
            .socket_addrs(|| None)
            .map_err(|_| TransportError::InvalidTransportAddress(url.to_string()))?;

        let Some(address) = addresses.first() else {
            return Err(TransportError::InvalidTransportAddress(url.to_string()));
        };

        let stream = TcpStream::connect(address)
            .await
            .map_err(|e| TransportError::Connection(address.to_string(), e))?;

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
}
