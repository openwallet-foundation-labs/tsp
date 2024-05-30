use core::fmt;
use std::fmt::Debug;

#[cfg(feature = "async")]
use futures::Stream;

pub type KeyData = [u8; 32];
pub type Digest = [u8; 32];
pub type PrivateKeyData<'a> = &'a KeyData;
pub type PublicKeyData<'a> = &'a KeyData;
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
        thread_id: Digest,
    },
    AcceptRelationship {
        sender: String,
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
    #[cfg(feature = "async")]
    PendingMessage {
        unknown_vid: String,
        payload: tokio_util::bytes::BytesMut,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload<'a, Bytes: AsRef<[u8]>> {
    Content(Bytes),
    NestedMessage(Bytes),
    RoutedMessage(Vec<VidData<'a>>, Bytes),
    CancelRelationship { thread_id: Digest },
    RequestRelationship { route: Option<Vec<VidData<'a>>> },
    AcceptRelationship { thread_id: Digest },
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
            Payload::CancelRelationship { thread_id: _ } => write!(f, "Cancel Relationship"),
            Payload::RequestRelationship { route: _ } => write!(f, "Request Relationship"),
            Payload::AcceptRelationship { thread_id: _ } => write!(f, "Accept Relationship"),
        }
    }
}

pub trait VerifiedVid: Send + Sync {
    /// A identifier of the Vid as bytes (for inclusion in TSP packets)
    fn identifier(&self) -> &str;

    /// The transport layer endpoint in the transport layer associated with this Vid
    fn endpoint(&self) -> &url::Url;

    /// The verification key that can check signatures made by this Vid
    fn verifying_key(&self) -> PublicKeyData;

    /// The encryption key associated with this Vid
    fn encryption_key(&self) -> PublicKeyData;
}

pub trait PrivateVid: VerifiedVid + Send + Sync {
    /// The PRIVATE key used to decrypt data
    fn decryption_key(&self) -> PrivateKeyData;

    /// The PRIVATE key used to sign data
    fn signing_key(&self) -> PrivateKeyData;
}
