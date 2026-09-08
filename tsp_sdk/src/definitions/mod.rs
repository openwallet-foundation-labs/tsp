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
pub type TSPMessage = Vec<u8>;

#[cfg(feature = "async")]
pub type TSPStream<D, E> = std::pin::Pin<Box<dyn Stream<Item = Result<D, E>> + Send>>;

#[derive(Debug)]
pub struct MessageType {
    /// How this message itself was encrypted. For a nested message this is the
    /// *inner* message's own encoding, which may be `Plaintext`: section 4
    /// permits a signed-only inner message, since the enclosing envelope
    /// conceals it in transit. See [`Self::enclosing_crypto_type`].
    pub crypto_type: crate::cesr::CryptoType,
    pub signature_type: crate::cesr::SignatureType,
    /// When this message arrived inside another message's ciphertext, how that
    /// enclosing message was encrypted; `None` when it was not nested.
    ///
    /// A message with `crypto_type: Plaintext` and an enclosing type was still
    /// confidential on the wire — but under the enclosing relationship's keys,
    /// not its own. Section 4 asks applications to notice that difference,
    /// which is why the two are reported separately rather than merged.
    pub enclosing_crypto_type: Option<crate::cesr::CryptoType>,
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
        message: Data,
        message_type: MessageType,
    },
    /// An upper layer's own control payload (`XCTL`). Carried opaquely, exactly
    /// as [`ReceivedTspMessage::GenericMessage`] is; it arrives as its own
    /// variant so that an upper layer can route its control plane separately
    /// from its data plane (spec 9.3).
    ControlMessage {
        sender: String,
        receiver: Option<String>,
        message: Data,
        message_type: MessageType,
    },
    /// A padding message (`XPAD`). It carries nothing: it exists so that
    /// traffic analysis sees messages that mean nothing. The specification says
    /// the receiver SHOULD silently discard it — silence being about what goes
    /// back on the wire, which is nothing. It is reported rather than swallowed
    /// so that an application can account for what it received; there is simply
    /// nothing in it to act on.
    PaddingMessage {
        sender: String,
        receiver: Option<String>,
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
        /// The digest the cancellation named, which is one of the two the
        /// relationship was formed with. A reply echoes it (spec 7.3).
        thread_id: Digest,
        /// Whether the specification expects a `TSP_RFD` in reply: it does when
        /// the cancelled relationship was bidirectional, and does not when it
        /// was one-way (spec 7.3). The relationship has already been removed
        /// either way, so the reply goes out with
        /// [`crate::SecureStore::make_relationship_cancel_reply`].
        reply_expected: bool,
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
    /// The VID that sent this message, where the message names one. A pending
    /// message names a VID that could not be resolved, so it has no sender.
    pub fn sender(&self) -> Option<&str> {
        match self {
            ReceivedTspMessage::GenericMessage { sender, .. }
            | ReceivedTspMessage::ControlMessage { sender, .. }
            | ReceivedTspMessage::PaddingMessage { sender, .. }
            | ReceivedTspMessage::RequestRelationship { sender, .. }
            | ReceivedTspMessage::AcceptRelationship { sender, .. }
            | ReceivedTspMessage::CancelRelationship { sender, .. }
            | ReceivedTspMessage::ForwardRequest { sender, .. } => Some(sender),
            #[cfg(feature = "async")]
            ReceivedTspMessage::PendingMessage { .. } => None,
        }
    }
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
    /// An upper layer's own control payload (`XCTL`). TSP carries it opaquely,
    /// exactly as it carries [`Payload::Content`]; the separate type exists so
    /// that an upper layer can tell its control plane from its data plane
    /// without reserving part of its own format for the distinction (spec 9.3).
    ControlMessage(Bytes),
    /// A padding message (`XPAD`), which carries no information at all — it
    /// exists so that traffic analysis sees messages that mean nothing. The
    /// receiver discards it (spec 7.5).
    Padding,
    NestedMessage(MaybeMutBytes),
    RoutedMessage(Vec<VidData<'a>>, Bytes),
    CancelRelationship {
        thread_id: Digest,
    },
    RequestRelationship {
        thread_id: Digest,
        form: RelationshipForm<'a, Bytes>,
        /// The route the replying endpoint is to use to reach this sender
        /// (spec 7.2.4). Empty when the reply is to come back directly.
        reply_path: Vec<VidData<'a>>,
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
            Payload::ControlMessage(bytes) => bytes.as_ref(),
            Payload::Padding => &[],
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
            Payload::ControlMessage(bytes) => {
                write!(f, "Control: {}", String::from_utf8_lossy(bytes.as_ref()))
            }
            Payload::Padding => write!(f, "Padding"),
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

#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum VidEncryptionKeyType {
    #[default]
    X25519,
    X25519MlKem768,
}

#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum VidSignatureKeyType {
    #[default]
    Ed25519,
    MlDsa65,
}

impl VidEncryptionKeyType {
    fn jwk_key_type(self) -> &'static str {
        match self {
            VidEncryptionKeyType::X25519 => "OKP",
            VidEncryptionKeyType::X25519MlKem768 => "X25519MlKem768",
        }
    }

    fn jwk_curve(self) -> &'static str {
        match self {
            VidEncryptionKeyType::X25519 | VidEncryptionKeyType::X25519MlKem768 => "X25519",
        }
    }
}

impl VidSignatureKeyType {
    fn jwk_key_type(self) -> &'static str {
        match self {
            VidSignatureKeyType::Ed25519 => "OKP",
            VidSignatureKeyType::MlDsa65 => "APK",
        }
    }

    fn jwk_curve(self) -> Option<&'static str> {
        match self {
            VidSignatureKeyType::Ed25519 => Some("Ed25519"),
            VidSignatureKeyType::MlDsa65 => None,
        }
    }

    fn jwk_algorithm(self) -> Option<&'static str> {
        match self {
            VidSignatureKeyType::Ed25519 => None,
            VidSignatureKeyType::MlDsa65 => Some("ML-DSA-65"),
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

    /// The encryption key type associated with this Vid
    fn encryption_key_type(&self) -> VidEncryptionKeyType;

    /// The signature key type associated with this Vid
    fn signature_key_type(&self) -> VidSignatureKeyType;

    fn encryption_key_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": self.encryption_key_type().jwk_key_type(),
            "crv": self.encryption_key_type().jwk_curve(),
            "use": "enc",
            "x": Base64UrlUnpadded::encode_string(self.encryption_key().as_ref()),
        })
    }

    fn signature_key_jwk(&self) -> serde_json::Value {
        match self.signature_key_type() {
            VidSignatureKeyType::Ed25519 => {
                serde_json::json!({
                    "kty": self.signature_key_type().jwk_key_type(),
                    "crv": self.signature_key_type().jwk_curve(),
                    "use": "sig",
                    "x": Base64UrlUnpadded::encode_string(self.verifying_key().as_ref()),
                })
            }
            VidSignatureKeyType::MlDsa65 => {
                serde_json::json!({
                    "kty": self.signature_key_type().jwk_key_type(),
                    "alg": self.signature_key_type().jwk_algorithm(),
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
            "kty": self.encryption_key_type().jwk_key_type(),
            "crv": self.encryption_key_type().jwk_curve(),
            "use": "enc",
            "x": Base64UrlUnpadded::encode_string(self.encryption_key().as_ref()),
            "d": Base64UrlUnpadded::encode_string(self.decryption_key().as_ref()),
        })
    }
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
