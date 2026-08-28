use std::array::TryFromSliceError;

use crate::{cesr::CryptoType, definitions::VidEncryptionKeyType};

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("failed to encode message {0}")]
    Encode(#[from] crate::cesr::error::EncodeError),
    #[error("failed to decode message {0}")]
    Decode(#[from] crate::cesr::error::DecodeError),
    #[error("encryption or decryption failed: {0}")]
    CryptographicHpke(#[from] hpke::HpkeError),
    #[error("encryption or decryption failed")]
    CryptographicNacl(#[from] crypto_box::aead::Error),
    #[error("Wrong key length")]
    Key(#[from] TryFromSliceError),
    #[error("could not verify signature for sender VID {0}: {1}")]
    Verify(String, String),
    #[error("unexpected recipient")]
    UnexpectedRecipient,
    #[error("no ciphertext found in encrypted message")]
    MissingCiphertext,
    #[error("payload type is not supported by this implementation")]
    UnsupportedPayload,
    #[error("invalid sender identity found in encrypted message")]
    UnexpectedSender,
    #[error("no sender identity found in encrypted message")]
    MissingSender,
    #[error("embedded digest does not match the message contents")]
    DigestMismatch,
    #[error("invalid outbound crypto selection {0:?}")]
    InvalidCryptoSelection(CryptoType),
    #[error(
        "outbound crypto selection {crypto_type:?} is incompatible with receiver encryption key type {key_type:?}"
    )]
    IncompatibleCryptoSelection {
        crypto_type: CryptoType,
        key_type: VidEncryptionKeyType,
    },
    #[error(
        "outbound crypto selection {crypto_type:?} is incompatible with sender encryption key type {key_type:?}"
    )]
    IncompatibleSenderCryptoSelection {
        crypto_type: CryptoType,
        key_type: VidEncryptionKeyType,
    },
}
