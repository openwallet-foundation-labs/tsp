#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("fetching '{0}' failed: {1}")]
    Http(String, reqwest::Error),
    #[error("connection to '{0}' failed: {1}")]
    Connection(String, std::io::Error),
    #[error("connection to '{0}' failed: {1}")]
    QuicConnection(String, quinn::ConnectError),
    #[error("invalid address '{0}'")]
    InvalidTransportAddress(String),
    #[error("invalid transport scheme '{0}'")]
    InvalidTransportScheme(String),
    #[error("websocket '{0}' failed: {1}")]
    Websocket(String, Box<tokio_tungstenite::tungstenite::Error>),
    #[error("invalid message received '{0}'")]
    InvalidMessageReceived(String),
    #[error("missing TSP_TLS_CERT and TSP_TLS_KEY environment variables")]
    TLSConfiguration,
    #[error("missing TLS certificate or key file '{0}'")]
    TLSMissingFile(String),
    #[error("invalid TLS certificate")]
    TLSCertificate,
    #[error("invalid TLS key '{0}'")]
    TLSKey(String),
    #[error("{0}")]
    TLS(#[from] rustls::Error),
    #[error("internel error")]
    Internal,
    #[error("could not listen on random UDP port")]
    ListenPort,
}
