use bytes::BytesMut;
use core::fmt;
use std::{fmt::Debug, ops::Deref};
use zeroize::Zeroize;

#[cfg(feature = "async")]
use futures::Stream;

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

pub type Digest = [u8; 32];

#[cfg(feature = "pq")]
pub const PRIVATE_KEY_SIZE: usize = 2432;

#[cfg(feature = "pq")]
pub const PUBLIC_KEY_SIZE: usize = 1216;

#[cfg(not(feature = "pq"))]
pub const PRIVATE_KEY_SIZE: usize = 32;

#[cfg(not(feature = "pq"))]
pub const PUBLIC_KEY_SIZE: usize = 32;

#[derive(Clone, Zeroize)]
pub struct PrivateKeyData([u8; PRIVATE_KEY_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyData([u8; PUBLIC_KEY_SIZE]);

pub const PRIVATE_SIGNING_KEY_SIZE: usize = 32;

pub const PUBLIC_VERIFICATION_KEY_SIZE: usize = 32;

#[derive(Clone, Zeroize)]
pub struct PrivateSigningKeyData([u8; PRIVATE_SIGNING_KEY_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicVerificationKeyData([u8; PUBLIC_VERIFICATION_KEY_SIZE]);

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
#[derive(Clone, Debug)]
pub enum RelationshipStatus {
    _Controlled,
    Bidirectional {
        thread_id: Digest,
        outstanding_nested_thread_ids: Vec<Digest>,
    },
    Unidirectional {
        thread_id: Digest,
    },
    Unrelated,
}

#[derive(Debug)]
pub enum ReceivedTspMessage<Data: AsRef<[u8]> = BytesMut> {
    GenericMessage {
        sender: String,
        nonconfidential_data: Option<Data>,
        message: Data,
        message_type: MessageType,
    },
    RequestRelationship {
        sender: String,
        route: Option<Vec<Vec<u8>>>,
        nested_vid: Option<String>,
        thread_id: Digest,
    },
    AcceptRelationship {
        sender: String,
        nested_vid: Option<String>,
    },
    CancelRelationship {
        sender: String,
    },
    ForwardRequest {
        sender: String,
        next_hop: String,
        route: Vec<BytesMut>,
        opaque_payload: BytesMut,
    },
    NewIdentifier {
        sender: String,
        new_vid: String,
    },
    Referral {
        sender: String,
        referred_vid: String,
    },
    #[cfg(feature = "async")]
    PendingMessage {
        unknown_vid: String,
        payload: BytesMut,
    },
}

mod conversions;

#[derive(Debug, PartialEq, Eq)]
pub enum Payload<'a, Bytes: AsRef<[u8]>, MaybeMutBytes: AsRef<[u8]> = Bytes> {
    Content(Bytes),
    NestedMessage(MaybeMutBytes),
    RoutedMessage(Vec<VidData<'a>>, Bytes),
    CancelRelationship {
        thread_id: Digest,
    },
    RequestRelationship {
        route: Option<Vec<VidData<'a>>>,
        thread_id: Digest,
    },
    AcceptRelationship {
        thread_id: Digest,
    },
    RequestNestedRelationship {
        inner: MaybeMutBytes,
        thread_id: Digest,
    },
    AcceptNestedRelationship {
        inner: MaybeMutBytes,
        thread_id: Digest,
    },
    NewIdentifier {
        thread_id: Digest,
        new_vid: VidData<'a>,
    },
    Referral {
        referred_vid: VidData<'a>,
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
            Payload::RequestNestedRelationship { .. } => &[],
            Payload::AcceptNestedRelationship { .. } => &[],
            Payload::NewIdentifier { .. } => &[],
            Payload::Referral { .. } => &[],
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
            Payload::RequestNestedRelationship { .. } => write!(f, "Request Nested Relationship"),
            Payload::AcceptNestedRelationship { .. } => write!(f, "Accept Nested Relationship"),
            Payload::NewIdentifier { .. } => write!(f, "Request Identifier Change"),
            Payload::Referral { .. } => write!(f, "Relationship Referral"),
        }
    }
}

pub trait VerifiedVid: Send + Sync {
    /// A identifier of the Vid as bytes (for inclusion in TSP packets)
    fn identifier(&self) -> &str;

    /// The transport layer endpoint in the transport layer associated with this Vid
    fn endpoint(&self) -> &url::Url;

    /// The verification key that can check signatures made by this Vid
    fn verifying_key(&self) -> &PublicVerificationKeyData;

    /// The encryption key associated with this Vid
    fn encryption_key(&self) -> &PublicKeyData;
}

pub trait PrivateVid: VerifiedVid + Send + Sync {
    /// The PRIVATE key used to decrypt data
    fn decryption_key(&self) -> &PrivateKeyData;

    /// The PRIVATE key used to sign data
    fn signing_key(&self) -> &PrivateSigningKeyData;
}

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

impl From<[u8; PRIVATE_SIGNING_KEY_SIZE]> for PrivateSigningKeyData {
    fn from(data: [u8; PRIVATE_SIGNING_KEY_SIZE]) -> PrivateSigningKeyData {
        PrivateSigningKeyData(data)
    }
}

impl From<[u8; PUBLIC_VERIFICATION_KEY_SIZE]> for PublicVerificationKeyData {
    fn from(data: [u8; PUBLIC_VERIFICATION_KEY_SIZE]) -> PublicVerificationKeyData {
        PublicVerificationKeyData(data)
    }
}

impl From<[u8; PRIVATE_KEY_SIZE]> for PrivateKeyData {
    fn from(data: [u8; PRIVATE_KEY_SIZE]) -> PrivateKeyData {
        PrivateKeyData(data)
    }
}

impl From<[u8; PUBLIC_KEY_SIZE]> for PublicKeyData {
    fn from(data: [u8; PUBLIC_KEY_SIZE]) -> PublicKeyData {
        PublicKeyData(data)
    }
}

impl Deref for PublicKeyData {
    type Target = [u8; PUBLIC_KEY_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for PrivateKeyData {
    type Target = [u8; PRIVATE_KEY_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for PublicVerificationKeyData {
    type Target = [u8; PUBLIC_VERIFICATION_KEY_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for PrivateSigningKeyData {
    type Target = [u8; PRIVATE_SIGNING_KEY_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
