use async_stream::stream;
use bytes::BytesMut;
use futures::StreamExt;
use tokio::{io::AsyncWriteExt, net::TcpListener};
use tokio_util::codec::{BytesCodec, Framed};
use url::Url;

use super::{TSPStream, TransportError};

pub(crate) const SCHEME: &str = "tcp";

/// Send a single message over TCP
/// Note: this opens a new connection per message
pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), TransportError> {
    let addresses = url
        .socket_addrs(|| None)
        .map_err(|_| TransportError::InvalidTransportAddress(url.to_string()))?;

    let Some(address) = addresses.first() else {
        return Err(TransportError::InvalidTransportAddress(url.to_string()));
    };

    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e))?;

    stream
        .write_all(tsp_message)
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e))?;

    Ok(())
}

/// Receive (multiple) messages over TCP
/// Listens on the specified transport port and yields messages as they arrive
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

    Ok(Box::pin(stream! {
        while let Ok((stream, addr)) = listener.accept().await {
            let mut messages = Framed::new(stream, BytesCodec::new());

            while let Some(m) = messages.next().await {
                yield m.map_err(|e| TransportError::Connection(addr.to_string(), e));
            }
        }
    }))
}

#[cfg(test)]
mod test {
    use super::*;
    use url::Url;

    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn test_tcp_transport() {
        let url = Url::parse("tcp://localhost:12345").unwrap();
        let message = b"Hello, world!";

        let mut incoming_stream = receive_messages(&url).await.unwrap();

        send_message(message, &url).await.unwrap();
        let received_message = incoming_stream.next().await.unwrap().unwrap();

        assert_eq!(message, received_message.iter().as_slice());
    }
}
