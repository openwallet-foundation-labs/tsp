/// An error type to indicate something went wrong with encoding
#[derive(thiserror::Error, Clone, Copy, Debug)]
pub enum EncodeError {
    #[error("field size exceeds maximum CESR encoding limit")]
    ExcessiveFieldSize,
    #[error("hops field is required but missing")]
    MissingHops,
    #[error("VID is not valid for CESR encoding")]
    InvalidVid,
    #[error("invalid signature type")]
    InvalidSignatureType,
    #[error("a nested message must be CESR data (a multiple of 3 bytes long)")]
    MisalignedNestedMessage,
    #[error("this payload type does not carry a self-referencing digest")]
    NoDigestSlot,
}

/// An error type to indicate something went wrong with decoding
#[derive(thiserror::Error, Clone, Copy, Debug)]
pub enum DecodeError {
    #[error("unexpected data encountered while decoding")]
    UnexpectedData,
    #[error("unexpected message type")]
    UnexpectedMsgType,
    #[error("trailing garbage after decoded message")]
    TrailingGarbage,
    #[error("signature verification failed")]
    SignatureError,
    #[error("VID error while decoding")]
    VidError,
    #[error("not a TSP message")]
    NotTsp,
    #[error("unsupported TSP version")]
    VersionMismatch,
    #[error("frame count does not match the framed content")]
    InvalidFrameCount,
    #[error("invalid crypto type")]
    InvalidCryptoType,
    #[error("invalid signature type")]
    InvalidSignatureType,
    #[error("hops field is required but missing")]
    MissingHops,
    #[error("unknown crypto algorithm")]
    UnknownCrypto,
    #[error("invalid crypto payload")]
    InvalidCrypto,
}
