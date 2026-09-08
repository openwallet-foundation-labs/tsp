//! A minimal HTTP endpoint implementing the two things the SDK's HTTP
//! transport needs, so that HTTP can be benchmarked on loopback.
//!
//! The SDK's HTTP transport is a client only: `receive_messages` subscribes to
//! a remote server's event stream and `send_message` posts to it. The other
//! transports bind both ends inside the benchmark; HTTP cannot, so without
//! something like this it is the one transport that goes unmeasured.
//!
//! The contract is small. `GET` returns an event stream whose events carry the
//! message base64url-encoded, matching what the transport decodes. `POST`
//! carries the raw message bytes and answers 200. Written on tokio directly
//! rather than a web framework, to keep this out of the dependency graph.
use base64ct::{Base64UrlUnpadded, Encoding as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

/// Serve on an unused port, returning the URL to give the transport and a
/// count of connected event-stream subscribers.
///
/// The count matters: a broadcast drops messages sent before anyone is
/// subscribed, and the transport's GET connects asynchronously after
/// `receive_messages` returns. Posting before then would lose the message and
/// the benchmark would wait for something that never arrives.
pub async fn spawn() -> (url::Url, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local_addr");
    let (tx, _) = broadcast::channel::<Vec<u8>>(1024);
    let subscribers = Arc::new(AtomicUsize::new(0));
    let subscribers_for_server = Arc::clone(&subscribers);

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let tx = tx.clone();
            let subscribers = Arc::clone(&subscribers_for_server);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                // Read the request head one byte at a time: any buffered read
                // could swallow part of a POST body.
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte).await {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&head).to_string();

                if head.starts_with("GET") {
                    let mut rx = tx.subscribe();
                    if stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                              Cache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                    subscribers.fetch_add(1, Ordering::SeqCst);
                    let mut id = 0u64;
                    while let Ok(message) = rx.recv().await {
                        id += 1;
                        let event = format!(
                            "id: {id}\ndata: {}\n\n",
                            Base64UrlUnpadded::encode_string(&message)
                        );
                        if stream.write_all(event.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                } else if head.starts_with("POST") {
                    let length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    let mut body = vec![0u8; length];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let _ = tx.send(body);
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                }
            });
        }
    });

    (
        url::Url::parse(&format!("http://{address}")).expect("url"),
        subscribers,
    )
}

/// Whether the transport's event stream has connected yet.
pub fn is_ready(subscribers: &AtomicUsize) -> bool {
    subscribers.load(Ordering::SeqCst) > 0
}
