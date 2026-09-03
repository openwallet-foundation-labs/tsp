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
    #[cfg(feature = "async")]
    Storage(#[from] aries_askar::Error),
    #[error("Error decoding persisted state: {0}")]
    DecodeState(&'static str),
    #[error("Invalid Route Error: {0}")]
    InvalidRoute(String),
    #[error("Relationship Error: {0}")]
    Relationship(String),
    #[error("Error: missing private vid {0}")]
    MissingPrivateVid(String),
    #[error("Error: missing vid {0}")]
    MissingVid(String),
    #[error("Error: unresolved vid {0}")]
    UnverifiedVid(String),
    #[cfg(feature = "async")]
    #[error("Error: no relation with sender {0}")]
    UnverifiedSource(String, Option<bytes::BytesMut>),
    #[cfg(not(feature = "async"))]
    #[error("Error: no relation with sender {0}")]
    UnverifiedSource(String),
    #[error("Error: unresolved next hop {0}")]
    UnresolvedNextHop(String),
    #[error("Error: no relation with next hop {0}")]
    InvalidNextHop(String),
    #[error("Error: no relation established for {0}")]
    MissingDropOff(String),
    #[error("Error: no relationship from {0} to {1}; the message is dropped")]
    UnestablishedRelationship(String, String),
    #[error(
        "Error: the key state obtained for {0} conflicts with the key state held; reliance on it is suspended"
    )]
    ConflictingKeyState(String),
    #[error("Error: not acting on a message from {0}: {1}")]
    UnconfirmedKeyState(String, String),
    #[error("Internal error")]
    Internal,
}

impl Error {
    /// Whether this error describes the message stream itself failing, rather
    /// than a single message that was discarded. Discarding one message does
    /// not end a stream, so a caller can distinguish the two and go on
    /// listening after the first.
    pub fn ends_stream(&self) -> bool {
        #[cfg(feature = "async")]
        let ends_stream = matches!(self, Error::Transport(_));
        #[cfg(not(feature = "async"))]
        let ends_stream = false;

        ends_stream
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Self::Internal
    }
}
