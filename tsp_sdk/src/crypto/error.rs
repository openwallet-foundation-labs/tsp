#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("failed to encode message {0}")]
    Encode(#[from] crate::cesr::error::EncodeError),
    #[error("failed to decode message {0}")]
    Decode(#[from] crate::cesr::error::DecodeError),
    #[cfg(feature = "pq")]
    #[error("encryption or decryption failed: {0}")]
    CryptographicHpkePq(#[from] hpke_pq::HpkeError),
    #[error("encryption or decryption failed: {0}")]
    CryptographicHpke(#[from] hpke::HpkeError),
    #[error("encryption or decryption failed")]
    CryptographicNacl(#[from] crypto_box::aead::Error),
    #[error("could not verify signature for sender VID {0}: {1}")]
    Verify(String, ed25519_dalek::ed25519::Error),
    #[error("unexpected recipient")]
    UnexpectedRecipient,
    #[error("no ciphertext found in encrypted message")]
    MissingCiphertext,
    #[error("invalid sender identity found in encrypted message")]
    UnexpectedSender,
    #[error("no sender identity found in encrypted message")]
    MissingSender,
}
