use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::BytesMut;
use core::fmt;
use std::{
    fmt::{Debug, Display},
    ops::Deref,
};
use zeroize::Zeroize;

#[cfg(feature = "async")]
use futures::Stream;

#[cfg(feature = "pq")]
use crate::vid::did::web::Algorithm;
use crate::vid::did::web::{Curve, KeyType};
#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

pub type Digest = [u8; 32];

#[derive(Clone, Zeroize)]
pub struct PrivateKeyData(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyData(Vec<u8>);

#[derive(Clone, Zeroize)]
pub struct PrivateSigningKeyData(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicVerificationKeyData(Vec<u8>);

pub type VidData<'a> = &'a [u8];
pub type NonConfidentialData<'a> = &'a [u8];
pub type TSPMessage = Vec<u8>;

#[cfg(feature = "async")]
pub type TSPStream<D, E> = std::pin::Pin<Box<dyn Stream<Item = Result<D, E>> + Send>>;

#[derive(Debug)]
pub struct MessageType {
    pub crypto_type: crate::cesr::CryptoType,
    pub signature_type: crate::cesr::SignatureType,
}

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingNestedRelationship {
    pub thread_id: Digest,
    pub local_nested_vid: String,
}

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingParallelRelationship {
    pub thread_id: Digest,
    pub local_parallel_vid: String,
    pub outer_receiver: String,
}

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingIncomingParallelRelationship {
    pub thread_id: Digest,
    pub local_outer_vid: String,
}

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub enum RelationshipStatus {
    _Controlled,
    Bidirectional {
        thread_id: Digest,
        remote_thread_id: Digest,
        outstanding_nested_requests: Vec<PendingNestedRelationship>,
    },
    Unidirectional {
        thread_id: Digest,
    },
    ReverseUnidirectional {
        thread_id: Digest,
    },
    Unrelated,
}

impl RelationshipStatus {
    pub(crate) fn bi(thread_id: Digest, remote_thread_id: Digest) -> Self {
        RelationshipStatus::Bidirectional {
            thread_id,
            remote_thread_id,
            outstanding_nested_requests: vec![],
        }
    }
}

impl Display for RelationshipStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelationshipStatus::_Controlled => write!(f, "Controlled"),
            RelationshipStatus::Bidirectional { .. } => write!(f, "Bidirectional"),
            RelationshipStatus::Unidirectional { .. } => write!(f, "Unidirectional"),
            RelationshipStatus::ReverseUnidirectional { .. } => write!(f, "ReverseUnidirectional"),
            RelationshipStatus::Unrelated => write!(f, "Unrelated"),
        }
    }
}

#[derive(Debug)]
pub enum ReceivedRelationshipForm<Data: AsRef<[u8]> = BytesMut> {
    Direct,
    Parallel { new_vid: String, sig_new_vid: Data },
}

#[derive(Debug)]
pub enum ReceivedRelationshipDelivery {
    Direct,
    Nested { nested_vid: String },
    Routed,
}

#[derive(Debug)]
pub enum ReceivedTspMessage<Data: AsRef<[u8]> = BytesMut> {
    GenericMessage {
        sender: String,
        receiver: Option<String>,
        nonconfidential_data: Option<Data>,
        message: Data,
        message_type: MessageType,
    },
    RequestRelationship {
        sender: String,
        receiver: String,
        thread_id: Digest,
        form: ReceivedRelationshipForm<Data>,
        delivery: ReceivedRelationshipDelivery,
    },
    AcceptRelationship {
        sender: String,
        receiver: String,
        thread_id: Digest,
        reply_thread_id: Digest,
        form: ReceivedRelationshipForm<Data>,
        delivery: ReceivedRelationshipDelivery,
    },
    CancelRelationship {
        sender: String,
        receiver: String,
    },
    ForwardRequest {
        sender: String,
        receiver: String,
        next_hop: String,
        route: Vec<BytesMut>,
        opaque_payload: BytesMut,
    },
    #[cfg(feature = "async")]
    PendingMessage {
        unknown_vid: String,
        payload: BytesMut,
    },
}

impl<Data: AsRef<[u8]>> ReceivedTspMessage<Data> {
    pub fn pending_message_parts(&self) -> Option<(&str, &[u8])> {
        #[cfg(feature = "async")]
        {
            match self {
                Self::PendingMessage {
                    unknown_vid,
                    payload,
                } => Some((unknown_vid.as_str(), payload.as_ref())),
                _ => None,
            }
        }

        #[cfg(not(feature = "async"))]
        {
            None
        }
    }
}

mod conversions;

#[derive(Debug, PartialEq, Eq)]
pub enum RelationshipForm<'a, Bytes: AsRef<[u8]>> {
    Direct,
    Parallel {
        new_vid: VidData<'a>,
        sig_new_vid: Bytes,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Payload<'a, Bytes: AsRef<[u8]>, MaybeMutBytes: AsRef<[u8]> = Bytes> {
    Content(Bytes),
    NestedMessage(MaybeMutBytes),
    RoutedMessage(Vec<VidData<'a>>, Bytes),
    CancelRelationship {
        thread_id: Digest,
    },
    RequestRelationship {
        thread_id: Digest,
        form: RelationshipForm<'a, Bytes>,
    },
    AcceptRelationship {
        thread_id: Digest,
        reply_thread_id: Digest,
        form: RelationshipForm<'a, Bytes>,
    },
}

impl<Bytes: AsRef<[u8]>, MaybeMutBytes: AsRef<[u8]>> Payload<'_, Bytes, MaybeMutBytes> {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Payload::Content(bytes) => bytes.as_ref(),
            Payload::NestedMessage(bytes) => bytes.as_ref(),
            Payload::RoutedMessage(_, bytes) => bytes.as_ref(),
            Payload::CancelRelationship { .. } => &[],
            Payload::RequestRelationship { .. } => &[],
            Payload::AcceptRelationship { .. } => &[],
        }
    }
}

impl<Bytes: AsRef<[u8]>> fmt::Display for Payload<'_, Bytes> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Payload::Content(bytes) => {
                write!(f, "Content: {}", String::from_utf8_lossy(bytes.as_ref()))
            }
            Payload::NestedMessage(bytes) => write!(
                f,
                "Nested Message: {}",
                String::from_utf8_lossy(bytes.as_ref())
            ),
            Payload::RoutedMessage(hops, bytes) => {
                write!(
                    f,
                    "Routed Message: {}, route: [",
                    String::from_utf8_lossy(bytes.as_ref())
                )?;
                for vid in hops {
                    write!(f, "{:?}", &vid[..])?
                }
                write!(f, "]")
            }
            Payload::CancelRelationship { .. } => write!(f, "Cancel Relationship"),
            Payload::RequestRelationship { .. } => write!(f, "Request Relationship"),
            Payload::AcceptRelationship { .. } => write!(f, "Accept Relationship"),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize, Default)]
pub enum VidEncryptionKeyType {
    #[default]
    X25519,
    #[cfg(feature = "pq")]
    X25519Kyber768Draft00,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize, Default)]
pub enum VidSignatureKeyType {
    #[default]
    Ed25519,
    #[cfg(feature = "pq")]
    MlDsa65,
}

// ANCHOR: custom-vid-mbBook
pub trait VerifiedVid: Send + Sync {
    /// A identifier of the Vid as bytes (for inclusion in TSP packets)
    fn identifier(&self) -> &str;

    /// The transport layer endpoint in the transport layer associated with this Vid
    fn endpoint(&self) -> &url::Url;

    /// The verification key that can check signatures made by this Vid
    fn verifying_key(&self) -> &PublicVerificationKeyData;

    /// The encryption key associated with this Vid
    fn encryption_key(&self) -> &PublicKeyData;

    /// The encryption key type associated with this Vid
    fn encryption_key_type(&self) -> VidEncryptionKeyType;

    /// The signature key type associated with this Vid
    fn signature_key_type(&self) -> VidSignatureKeyType;

    fn encryption_key_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": Into::<KeyType>::into(self.encryption_key_type()),
            "crv": Into::<Curve>::into(self.encryption_key_type()),
            "use": "enc",
            "x": Base64UrlUnpadded::encode_string(self.encryption_key().as_ref()),
        })
    }

    fn signature_key_jwk(&self) -> serde_json::Value {
        match self.signature_key_type() {
            VidSignatureKeyType::Ed25519 => {
                serde_json::json!({
                    "kty": Into::<KeyType>::into(self.signature_key_type()),
                    "crv": Into::<Option<Curve>>::into(self.signature_key_type()),
                    "use": "sig",
                    "x": Base64UrlUnpadded::encode_string(self.verifying_key().as_ref()),
                })
            }
            #[cfg(feature = "pq")]
            VidSignatureKeyType::MlDsa65 => {
                serde_json::json!({
                    "kty": Into::<KeyType>::into(self.signature_key_type()),
                    "alg": Into::<Option<Algorithm>>::into(self.signature_key_type()),
                    "use": "sig",
                    "pub": Base64UrlUnpadded::encode_string(self.verifying_key().as_ref()),
                })
            }
        }
    }
}

pub trait PrivateVid: VerifiedVid + Send + Sync {
    /// The PRIVATE key used to decrypt data
    fn decryption_key(&self) -> &PrivateKeyData;

    /// The PRIVATE key used to sign data
    fn signing_key(&self) -> &PrivateSigningKeyData;

    fn private_encryption_key_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": Into::<KeyType>::into(self.encryption_key_type()),
            "crv": Into::<Curve>::into(self.encryption_key_type()),
            "use": "enc",
            "x": Base64UrlUnpadded::encode_string(self.encryption_key().as_ref()),
            "d": Base64UrlUnpadded::encode_string(self.decryption_key().as_ref()),
        })
    }
}
// ANCHOR_END: custom-vid-mbBook

impl Debug for PrivateKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKeyData([redacted])")
    }
}

impl AsRef<[u8]> for PrivateKeyData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKeyData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PrivateSigningKeyData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PublicVerificationKeyData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for PrivateSigningKeyData {
    fn from(data: Vec<u8>) -> PrivateSigningKeyData {
        PrivateSigningKeyData(data)
    }
}

impl From<Vec<u8>> for PublicVerificationKeyData {
    fn from(data: Vec<u8>) -> PublicVerificationKeyData {
        PublicVerificationKeyData(data)
    }
}

impl From<Vec<u8>> for PrivateKeyData {
    fn from(data: Vec<u8>) -> PrivateKeyData {
        PrivateKeyData(data)
    }
}

impl From<Vec<u8>> for PublicKeyData {
    fn from(data: Vec<u8>) -> PublicKeyData {
        PublicKeyData(data)
    }
}

impl Deref for PublicKeyData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for PrivateKeyData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for PublicVerificationKeyData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for PrivateSigningKeyData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
