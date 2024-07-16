use core::fmt;
use std::{fmt::Debug, ops::Deref};
use zeroize::Zeroize;

#[cfg(feature = "async")]
use futures::Stream;

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

pub type Digest = [u8; 32];

#[derive(Clone, Zeroize)]
pub struct PrivateKeyData([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyData([u8; 32]);

pub type VidData<'a> = &'a [u8];
pub type NonConfidentialData<'a> = &'a [u8];
pub type TSPMessage = Vec<u8>;

#[cfg(feature = "async")]
pub type TSPStream<D, E> = std::pin::Pin<Box<dyn Stream<Item = Result<D, E>> + Send>>;

#[derive(Debug, PartialEq, Eq)]
pub enum MessageType {
    Signed,
    SignedAndEncrypted,
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
pub enum ReceivedTspMessage {
    GenericMessage {
        sender: String,
        nonconfidential_data: Option<Vec<u8>>,
        message: Vec<u8>,
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
        route: Vec<Vec<u8>>,
        opaque_payload: Vec<u8>,
    },
    Referral {
        sender: String,
        referred_vid: String,
    },
    #[cfg(feature = "async")]
    PendingMessage {
        unknown_vid: String,
        payload: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload<'a, Bytes: AsRef<[u8]>> {
    Content(Bytes),
    NestedMessage(Bytes),
    RoutedMessage(Vec<VidData<'a>>, Bytes),
    CancelRelationship {
        thread_id: Digest,
    },
    RequestRelationship {
        route: Option<Vec<VidData<'a>>>,
    },
    AcceptRelationship {
        thread_id: Digest,
    },
    RequestNestedRelationship {
        vid: VidData<'a>,
    },
    AcceptNestedRelationship {
        thread_id: Digest,
        vid: VidData<'a>,
        connect_to_vid: VidData<'a>,
    },
    Referral {
        referred_vid: VidData<'a>,
    },
}

impl<'a, Bytes: AsRef<[u8]>> Payload<'a, Bytes> {
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
            Payload::Referral { .. } => &[],
        }
    }
}

impl<'a, Bytes: AsRef<[u8]>> fmt::Display for Payload<'a, Bytes> {
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
    fn verifying_key(&self) -> &PublicKeyData;

    /// The encryption key associated with this Vid
    fn encryption_key(&self) -> &PublicKeyData;
}

pub trait PrivateVid: VerifiedVid + Send + Sync {
    /// The PRIVATE key used to decrypt data
    fn decryption_key(&self) -> &PrivateKeyData;

    /// The PRIVATE key used to sign data
    fn signing_key(&self) -> &PrivateKeyData;
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

impl From<[u8; 32]> for PrivateKeyData {
    fn from(data: [u8; 32]) -> PrivateKeyData {
        PrivateKeyData(data)
    }
}

impl From<[u8; 32]> for PublicKeyData {
    fn from(data: [u8; 32]) -> PublicKeyData {
        PublicKeyData(data)
    }
}

impl Deref for PublicKeyData {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for PrivateKeyData {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
