#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("failed to encode message {0}")]
    Encode(#[from] crate::cesr::error::EncodeError),
    #[error("failed to decode message {0}")]
    Decode(#[from] crate::cesr::error::DecodeError),
    #[cfg(not(feature = "nacl"))]
    #[error("encryption or decryption failed: {0}")]
    Cryptographic(#[from] hpke::HpkeError),
    #[cfg(feature = "nacl")]
    #[error("encryption or decryption failed")]
    Cryptographic(#[from] crypto_box::aead::Error),
    #[error("could not verify signature: {0}")]
    Verify(#[from] ed25519_dalek::ed25519::Error),
    #[error("unexpected recipient")]
    UnexpectedRecipient,
    #[error("no ciphertext found in encrypted message")]
    MissingCiphertext,
    #[error("invalid sender identity found in encrypted message")]
    UnexpectedSender,
    #[error("no sender identity found in encrypted message")]
    MissingSender,
}
