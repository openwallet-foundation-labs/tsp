use async_stream::stream;
use futures::{SinkExt, StreamExt};
use std::{collections::HashMap, fmt::Display, io, net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::{mpsc, Mutex},
    task::JoinHandle,
};
use tokio_util::{
    bytes::BytesMut,
    codec::{BytesCodec, Framed},
};
use url::Url;

use super::{TSPStream, TransportError};

pub(crate) const SCHEME: &str = "tcp";

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

pub(crate) async fn receive_messages(
    address: &Url,
) -> Result<TSPStream<BytesMut, TransportError>, TransportError> {
    let addresses = address
        .socket_addrs(|| None)
        .map_err(|_| TransportError::InvalidTransportAddress(address.to_string()))?;

    let Some(address) = addresses.into_iter().next() else {
        return Err(TransportError::InvalidTransportAddress(address.to_string()));
    };

    let stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(|e| TransportError::Connection(address.to_string(), e))?;
    let mut messages = Framed::new(stream, BytesCodec::new());

    Ok(Box::pin(stream! {
        while let Some(m) = messages.next().await {
            yield m.map_err(|e| TransportError::Connection(address.to_string(), e));
        }
    }))
}

pub async fn start_broadcast_server(addr: &str) -> Result<JoinHandle<()>, TransportError> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|_| TransportError::InvalidTransportAddress(addr.to_string()))?;

    // start broadcast server
    let handle = tokio::spawn(async move {
        if let Err(e) = broadcast_server(addr).await {
            tracing::error!("tcp broadcast server error {e}");
        }
    });

    Ok(handle)
}

/// Start a broadcast server, that will forward all messages to all open tcp connections
pub async fn broadcast_server<A: ToSocketAddrs + Display>(addr: A) -> Result<(), TransportError> {
    let state = Arc::new(Mutex::new(Shared::new()));
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| TransportError::Connection(addr.to_string(), e))?;

    tracing::info!("server running on {}", addr);

    loop {
        if let Ok((stream, addr)) = listener.accept().await {
            let state = Arc::clone(&state);

            tokio::spawn(async move {
                tracing::debug!("accepted connection");
                if let Err(e) = process(state, stream, addr).await {
                    tracing::info!("an error occurred; error = {:?}", e);
                }
            });
        }
    }
}

type Tx = mpsc::UnboundedSender<BytesMut>;
type Rx = mpsc::UnboundedReceiver<BytesMut>;

struct Shared {
    peers: HashMap<SocketAddr, Tx>,
}

struct Peer {
    messages: Framed<TcpStream, BytesCodec>,
    rx: Rx,
}

impl Shared {
    fn new() -> Self {
        Shared {
            peers: HashMap::new(),
        }
    }

    async fn broadcast(&mut self, sender: SocketAddr, message: BytesMut) {
        for peer in self.peers.iter_mut() {
            if *peer.0 != sender {
                let _ = peer.1.send(message.clone());
            }
        }
    }
}

impl Peer {
    async fn new(
        state: Arc<Mutex<Shared>>,
        messages: Framed<TcpStream, BytesCodec>,
    ) -> io::Result<Peer> {
        let addr = messages.get_ref().peer_addr()?;
        let (tx, rx) = mpsc::unbounded_channel();

        state.lock().await.peers.insert(addr, tx);

        Ok(Peer { messages, rx })
    }
}

async fn process(
    state: Arc<Mutex<Shared>>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), TransportError> {
    let peer_id = addr.to_string();

    tracing::info!("{} connected", peer_id);

    let messages = Framed::new(stream, BytesCodec::new());
    let mut peer = Peer::new(state.clone(), messages)
        .await
        .map_err(|e| TransportError::Connection(addr.to_string(), e))?;

    loop {
        tokio::select! {
            Some(msg) = peer.rx.recv() => {
                tracing::info!("{} send a message ({} bytes)", peer_id, msg.len());
                peer.messages.send(msg).await
                    .map_err(|e| TransportError::Connection(addr.to_string(), e))?;
            }
            result = peer.messages.next() => match result {
                Some(Ok(msg)) => {
                    tracing::info!("{} broadcasting message ({} bytes)", peer_id, msg.len());
                    let mut state = state.lock().await;
                    state.broadcast(addr, msg).await;
                }
                Some(Err(e)) => {
                    tracing::error!(
                        "an error occurred while processing messages for {}; error = {:?}",
                        peer_id,
                        e
                    );
                }
                None => break,
            },
        }
    }

    {
        let mut state = state.lock().await;
        state.peers.remove(&addr);

        tracing::info!("{} has disconnected", peer_id);
    }

    Ok(())
}
