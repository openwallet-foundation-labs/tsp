/// Error originating from the TSP library
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error: {0}")]
    Encode(#[from] crate::cesr::error::EncodeError),
    #[error("Error: {0}")]
    Decode(#[from] crate::cesr::error::DecodeError),
    #[cfg(feature = "async")]
    #[error("Error: {0}")]
    Transport(#[from] crate::transport::TransportError),
    #[error("Error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("Error: {0}")]
    Vid(#[from] crate::vid::VidError),
    #[error("Error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Error: {0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error("Error: {0}")]
    InvalidRoute(String),
    #[error("Error: {0}")]
    Relationship(String),
    #[error("Error: missing private vid {0}")]
    MissingPrivateVid(String),
    #[error("Error: missing vid {0}")]
    MissingVid(String),
    #[error("Error: unresolved vid {0}")]
    UnverifiedVid(String),
    #[error("Error: no relation with sender {0}")]
    UnverifiedSource(String),
    #[error("Error: no relation with next hop {0}")]
    InvalidNextHop(String),
    #[error("Error: no relation established for {0}")]
    MissingDropOff(String),
    #[error("Internal error")]
    Internal,
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Self::Internal
    }
}
