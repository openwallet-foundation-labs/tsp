use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use criterion::{Criterion, criterion_group, criterion_main};
use futures::{SinkExt as _, StreamExt as _};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::pem::PemObject;
use url::Url;

mod bench_utils;
#[path = "common/tokio_rt.rs"]
mod tokio_rt;

fn ensure_crypto_provider() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider());
    });
}

fn load_local_test_tls_material() -> (
    Vec<rustls_pki_types::CertificateDer<'static>>,
    rustls_pki_types::PrivateKeyDer<'static>,
    rustls::RootCertStore,
) {
    ensure_crypto_provider();

    let cert_path = "../examples/test/localhost.pem";
    let key_path = "../examples/test/localhost-key.pem";
    let ca_path = "../examples/test/root-ca.pem";

    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_file_iter(cert_path)
            .expect("could not find local test certificate")
            .collect::<Result<Vec<_>, _>>()
            .expect("could not read local test certificate");
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(key_path)
        .expect("could not read local test private key");

    let mut root = rustls::RootCertStore::empty();
    let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_file_iter(ca_path)
            .expect("could not find local root CA")
            .collect::<Result<Vec<_>, _>>()
            .expect("could not read local root CA");
    for cert in ca_certs {
        root.add(cert).expect("could not add local root CA");
    }

    (certs, key, root)
}

fn tls_acceptor_connector() -> (tokio_rustls::TlsAcceptor, tokio_rustls::TlsConnector) {
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    let (certs, key, root) = load_local_test_tls_material();

    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("invalid server cert/key");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    (acceptor, connector)
}

fn quic_server_client_configs() -> (quinn::ServerConfig, quinn::ClientConfig) {
    let (certs, key, root) = load_local_test_tls_material();

    let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("invalid server cert/key");
    server_tls.alpn_protocols = vec![b"hq-29".to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
            .expect("could not convert rustls to quic server config"),
    ));

    let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root)
    .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"hq-29".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls))
            .expect("could not convert rustls to quic client config"),
    ));

    (server_config, client_config)
}

async fn tls_oneway_deliver(payload: &[u8], iters: u64) -> Duration {
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
    };
    let (acceptor, connector) = tls_acceptor_connector();

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("tls tcp bind failed");
    let addr = listener.local_addr().expect("tls tcp local_addr failed");

    let payload_len = payload.len();
    let server = tokio::spawn(async move {
        let (socket, peer_addr) = listener.accept().await.expect("tls tcp accept failed");
        let mut stream = acceptor
            .accept(socket)
            .await
            .map_err(|e| (peer_addr, e))
            .expect("tls accept failed");

        let mut buf = vec![0u8; payload_len];
        for _ in 0..iters {
            stream
                .read_exact(buf.as_mut_slice())
                .await
                .expect("tls oneway recv failed");
            std::hint::black_box(buf[0]);
        }
    });

    let tcp = TcpStream::connect(addr)
        .await
        .expect("tls tcp connect failed");
    let dns_name =
        rustls_pki_types::ServerName::try_from("localhost").expect("invalid tls server name");
    let mut stream = connector
        .connect(dns_name, tcp)
        .await
        .expect("tls connect failed");

    let start = Instant::now();
    for _ in 0..iters {
        stream
            .write_all(payload)
            .await
            .expect("tls oneway send failed");
    }
    let elapsed = start.elapsed();

    let _ = stream.shutdown().await;
    server.await.expect("tls oneway server task failed");
    elapsed
}

async fn tls_roundtrip_echo(payload: &[u8], iters: u64) -> Duration {
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
    };
    let (acceptor, connector) = tls_acceptor_connector();

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("tls tcp bind failed");
    let addr = listener.local_addr().expect("tls tcp local_addr failed");

    let payload_len = payload.len();
    let server = tokio::spawn(async move {
        let (socket, peer_addr) = listener.accept().await.expect("tls tcp accept failed");
        let mut stream = acceptor
            .accept(socket)
            .await
            .map_err(|e| (peer_addr, e))
            .expect("tls accept failed");

        let mut buf = vec![0u8; payload_len];
        for _ in 0..iters {
            stream
                .read_exact(buf.as_mut_slice())
                .await
                .expect("tls roundtrip recv failed");
            stream
                .write_all(buf.as_slice())
                .await
                .expect("tls roundtrip send failed");
        }
    });

    let tcp = TcpStream::connect(addr)
        .await
        .expect("tls tcp connect failed");
    let dns_name =
        rustls_pki_types::ServerName::try_from("localhost").expect("invalid tls server name");
    let mut stream = connector
        .connect(dns_name, tcp)
        .await
        .expect("tls connect failed");

    let mut buf = vec![0u8; payload.len()];
    let start = Instant::now();
    for _ in 0..iters {
        stream
            .write_all(payload)
            .await
            .expect("tls roundtrip send failed");
        stream
            .read_exact(buf.as_mut_slice())
            .await
            .expect("tls roundtrip recv failed");
        std::hint::black_box(buf[0]);
    }
    let elapsed = start.elapsed();

    let _ = stream.shutdown().await;
    server.await.expect("tls roundtrip server task failed");
    elapsed
}

async fn quic_oneway_deliver(payload: &[u8], iters: u64) -> Duration {
    let (server_config, client_config) = quic_server_client_configs();

    let listen_address: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server_endpoint =
        quinn::Endpoint::server(server_config, listen_address).expect("quic server endpoint");
    let server_addr = server_endpoint
        .local_addr()
        .expect("quic server local_addr failed");

    let listen_address: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut client_endpoint =
        quinn::Endpoint::client(listen_address).expect("quic client endpoint");
    client_endpoint.set_default_client_config(client_config);

    let payload_len = payload.len();
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("quic accept returned none");
        let conn = incoming.await.expect("quic server handshake failed");
        let mut recv = conn.accept_uni().await.expect("quic accept_uni failed");

        let mut buf = vec![0u8; payload_len];
        for _ in 0..iters {
            recv.read_exact(buf.as_mut_slice())
                .await
                .expect("quic oneway recv failed");
            std::hint::black_box(buf[0]);
        }

        // Keep the connection alive until the client closes it.
        conn.closed().await;
    });

    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .expect("quic connect failed")
        .await
        .expect("quic client handshake failed");

    let mut send = connection.open_uni().await.expect("quic open_uni failed");

    let start = Instant::now();
    for _ in 0..iters {
        send.write_all(payload)
            .await
            .expect("quic oneway send failed");
    }
    let elapsed = start.elapsed();

    let _ = send.finish();
    let _ = send.stopped().await;
    connection.close(0u32.into(), b"done");
    server_task.await.expect("quic oneway server task failed");
    elapsed
}

async fn quic_roundtrip_echo(payload: &[u8], iters: u64) -> Duration {
    let (server_config, client_config) = quic_server_client_configs();

    let listen_address: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server_endpoint =
        quinn::Endpoint::server(server_config, listen_address).expect("quic server endpoint");
    let server_addr = server_endpoint
        .local_addr()
        .expect("quic server local_addr failed");

    let listen_address: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut client_endpoint =
        quinn::Endpoint::client(listen_address).expect("quic client endpoint");
    client_endpoint.set_default_client_config(client_config);

    let payload_len = payload.len();
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("quic accept returned none");
        let conn = incoming.await.expect("quic server handshake failed");
        let (mut send, mut recv) = conn.accept_bi().await.expect("quic accept_bi failed");

        let mut buf = vec![0u8; payload_len];
        for _ in 0..iters {
            recv.read_exact(buf.as_mut_slice())
                .await
                .expect("quic roundtrip recv failed");
            send.write_all(buf.as_slice())
                .await
                .expect("quic roundtrip send failed");
        }

        // Explicitly finish the server->client stream; dropping without `finish` can reset the stream.
        let _ = send.finish();

        // Keep the connection alive until the client closes it.
        conn.closed().await;
    });

    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .expect("quic connect failed")
        .await
        .expect("quic client handshake failed");

    let (mut send, mut recv) = connection.open_bi().await.expect("quic open_bi failed");

    let mut buf = vec![0u8; payload.len()];
    let start = Instant::now();
    for _ in 0..iters {
        send.write_all(payload)
            .await
            .expect("quic roundtrip send failed");
        recv.read_exact(buf.as_mut_slice())
            .await
            .expect("quic roundtrip recv failed");
        std::hint::black_box(buf[0]);
    }
    let elapsed = start.elapsed();

    let _ = send.finish();
    let _ = send.stopped().await;
    connection.close(0u32.into(), b"done");
    server_task
        .await
        .expect("quic roundtrip server task failed");
    elapsed
}

async fn tcp_oneway_deliver(payload: &[u8], iters: u64) -> Duration {
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("tcp bind failed");
    let addr = listener.local_addr().expect("tcp local_addr failed");

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("tcp accept failed");
        let mut framed = Framed::new(socket, LengthDelimitedCodec::new());
        for _ in 0..iters {
            let msg = framed
                .next()
                .await
                .expect("tcp oneway recv: stream ended")
                .expect("tcp oneway recv failed");
            std::hint::black_box(msg.len());
        }
    });

    let client = TcpStream::connect(addr).await.expect("tcp connect failed");
    let mut framed = Framed::new(client, LengthDelimitedCodec::new());

    let start = Instant::now();
    for _ in 0..iters {
        framed
            .send(payload.to_vec().into())
            .await
            .expect("tcp oneway send failed");
    }
    let elapsed = start.elapsed();

    server.await.expect("tcp oneway server task failed");
    elapsed
}

async fn tcp_roundtrip_echo(payload: &[u8], iters: u64) -> Duration {
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("tcp bind failed");
    let addr = listener.local_addr().expect("tcp local_addr failed");

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("tcp accept failed");
        let mut framed = Framed::new(socket, LengthDelimitedCodec::new());
        for _ in 0..iters {
            let msg = framed
                .next()
                .await
                .expect("tcp roundtrip recv: stream ended")
                .expect("tcp roundtrip recv failed");
            framed
                .send(msg.freeze())
                .await
                .expect("tcp roundtrip send failed");
        }
    });

    let client = TcpStream::connect(addr).await.expect("tcp connect failed");
    let mut framed = Framed::new(client, LengthDelimitedCodec::new());

    let start = Instant::now();
    for _ in 0..iters {
        framed
            .send(payload.to_vec().into())
            .await
            .expect("tcp roundtrip send failed");
        let resp = framed
            .next()
            .await
            .expect("tcp roundtrip recv: stream ended")
            .expect("tcp roundtrip recv failed");
        std::hint::black_box(resp.len());
    }
    let elapsed = start.elapsed();

    server.await.expect("tcp roundtrip server task failed");
    elapsed
}

fn pick_unused_tcp_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("failed to pick an unused tcp port")
}

fn pick_unused_udp_port() -> u16 {
    std::net::UdpSocket::bind(("127.0.0.1", 0))
        .and_then(|s| s.local_addr())
        .map(|a| a.port())
        .expect("failed to pick an unused udp port")
}

fn url(scheme: &str, host: &str, port: u16) -> Url {
    Url::parse(&format!("{scheme}://{host}:{port}")).expect("failed to parse url")
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .without_plots()
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20)
}

fn bench_oneway(c: &mut Criterion, scheme: &'static str, host: &'static str, payload_len: usize) {
    let benchmark_id = format!(
        "throughput.transport.{scheme}.oneway.deliver.{}",
        size_label(payload_len)
    );
    c.bench_function(&benchmark_id, |b| {
        let runtime = tokio_rt::current_thread();

        b.iter_custom(|iters| {
            runtime.block_on(async {
                if scheme == "tcp" {
                    let payload = bench_utils::seeded_bytes(
                        0x5452414E535F4F4Eu64 ^ payload_len as u64,
                        payload_len,
                    );
                    return tcp_oneway_deliver(payload.as_slice(), iters).await;
                }

                if scheme == "tls" {
                    let payload = bench_utils::seeded_bytes(
                        0x5452414E535F544Cu64 ^ payload_len as u64,
                        payload_len,
                    );
                    return tls_oneway_deliver(payload.as_slice(), iters).await;
                }

                if scheme == "quic" {
                    let payload = bench_utils::seeded_bytes(
                        0x5452414E535F5155u64 ^ payload_len as u64,
                        payload_len,
                    );
                    return quic_oneway_deliver(payload.as_slice(), iters).await;
                }

                let port = match scheme {
                    "quic" => pick_unused_udp_port(),
                    _ => pick_unused_tcp_port(),
                };
                let server = url(scheme, host, port);
                let mut incoming = tsp_sdk::transport::receive_messages(&server)
                    .await
                    .expect("receive_messages failed");

                let payload = bench_utils::seeded_bytes(
                    0x5452414E535F4F4Eu64 ^ payload_len as u64,
                    payload_len,
                );

                let start = Instant::now();
                for _ in 0..iters {
                    tsp_sdk::transport::send_message(&server, payload.as_slice())
                        .await
                        .expect("send_message failed");

                    let msg = incoming
                        .next()
                        .await
                        .expect("missing oneway recv item")
                        .expect("oneway recv failed");
                    std::hint::black_box(msg.len());
                }
                start.elapsed()
            })
        });
    });
}

fn bench_roundtrip(
    c: &mut Criterion,
    scheme: &'static str,
    host: &'static str,
    payload_len: usize,
) {
    let benchmark_id = format!(
        "throughput.transport.{scheme}.roundtrip.echo.{}",
        size_label(payload_len)
    );
    c.bench_function(&benchmark_id, |b| {
        let runtime = tokio_rt::current_thread();

        b.iter_custom(|iters| {
            runtime.block_on(async {
                if scheme == "tcp" {
                    let request = bench_utils::seeded_bytes(
                        0x5452414E535F5254u64 ^ payload_len as u64,
                        payload_len,
                    );
                    return tcp_roundtrip_echo(request.as_slice(), iters).await;
                }

                if scheme == "tls" {
                    let request = bench_utils::seeded_bytes(
                        0x5452414E535F544Cu64 ^ payload_len as u64,
                        payload_len,
                    );
                    return tls_roundtrip_echo(request.as_slice(), iters).await;
                }

                if scheme == "quic" {
                    let request = bench_utils::seeded_bytes(
                        0x5452414E535F5155u64 ^ payload_len as u64,
                        payload_len,
                    );
                    return quic_roundtrip_echo(request.as_slice(), iters).await;
                }

                let (server_port, client_port) = match scheme {
                    "quic" => (pick_unused_udp_port(), pick_unused_udp_port()),
                    _ => (pick_unused_tcp_port(), pick_unused_tcp_port()),
                };
                let server = url(scheme, host, server_port);
                let client = url(scheme, host, client_port);

                let mut server_incoming = tsp_sdk::transport::receive_messages(&server)
                    .await
                    .expect("server receive_messages failed");
                let mut client_incoming = tsp_sdk::transport::receive_messages(&client)
                    .await
                    .expect("client receive_messages failed");

                let request = bench_utils::seeded_bytes(
                    0x5452414E535F5254u64 ^ payload_len as u64,
                    payload_len,
                );

                let start = Instant::now();
                for _ in 0..iters {
                    tsp_sdk::transport::send_message(&server, request.as_slice())
                        .await
                        .expect("send_message(request) failed");

                    let msg = server_incoming
                        .next()
                        .await
                        .expect("missing server recv item")
                        .expect("server recv failed");

                    tsp_sdk::transport::send_message(&client, msg.as_ref())
                        .await
                        .expect("send_message(response) failed");

                    let resp = client_incoming
                        .next()
                        .await
                        .expect("missing client recv item")
                        .expect("client recv failed");
                    std::hint::black_box(resp.len());
                }
                start.elapsed()
            })
        });
    });
}

fn size_label(payload_len: usize) -> &'static str {
    match payload_len {
        1 => "1B",
        1024 => "1KiB",
        16_384 => "16KiB",
        _ => "custom",
    }
}

fn benches(c: &mut Criterion) {
    for payload_len in [1usize, 1024usize, 16 * 1024] {
        bench_oneway(c, "tcp", "127.0.0.1", payload_len);
        bench_roundtrip(c, "tcp", "127.0.0.1", payload_len);

        bench_oneway(c, "tls", "localhost", payload_len);
        bench_roundtrip(c, "tls", "localhost", payload_len);
    }

    // QUIC transport currently limits single-message size to 8KiB.
    for payload_len in [1usize, 1024usize] {
        bench_oneway(c, "quic", "localhost", payload_len);
        bench_roundtrip(c, "quic", "localhost", payload_len);
    }
}

criterion_group!(name = throughput_transport; config = criterion_config(); targets = benches);
criterion_main!(throughput_transport);
