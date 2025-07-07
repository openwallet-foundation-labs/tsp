/// Constants that determine the specific CESR types for "variable length data"
const TSP_PLAINTEXT: u32 = (b'B' - b'A') as u32;
const TSP_CIPHERTEXT: u32 = (b'C' - b'A') as u32;
const TSP_DEVELOPMENT_VID: u32 = (((21 << 6) | 8) << 6) | 3; // "VID"

/// Constants that determine the specific CESR types for "fixed length data"
const TSP_TYPECODE: u32 = (b'X' - b'A') as u32;
const ED25519_SIGNATURE: u32 = (b'B' - b'A') as u32;
#[allow(clippy::eq_op)]
const TSP_NONCE: u32 = (b'A' - b'A') as u32;
const TSP_SHA256: u32 = (b'I' - b'A') as u32;
#[allow(dead_code)]
const TSP_BLAKE2B256: u32 = (b'F' - b'A') as u32;

/// Constants that determine the specific CESR types for the framing codes
const TSP_ETS_WRAPPER: u16 = (b'E' - b'A') as u16;
const TSP_S_WRAPPER: u16 = (b'S' - b'A') as u16;
const TSP_HOP_LIST: u16 = (b'I' - b'A') as u16;
const TSP_PAYLOAD: u16 = (b'Z' - b'A') as u16;

/// Constants to encode message types
mod msgtype {
    pub(super) const GEN_MSG: [u8; 2] = [0, 0];
    pub(super) const NEST_MSG: [u8; 2] = [0, 1];
    pub(super) const NEW_REL: [u8; 2] = [1, 0];
    pub(super) const NEW_REL_REPLY: [u8; 2] = [1, 1];
    pub(super) const NEW_NEST_REL: [u8; 2] = [1, 2];
    pub(super) const NEW_NEST_REL_REPLY: [u8; 2] = [1, 3];
    pub(super) const NEW_REFER_REL: [u8; 2] = [1, 4];
    pub(super) const THIRDP_REFER_REL: [u8; 2] = [1, 5];
    pub(super) const REL_CANCEL: [u8; 2] = [1, 255];
}

use super::{
    decode::{
        decode_count, decode_count_mut, decode_fixed_data, decode_fixed_data_mut,
        decode_variable_data, decode_variable_data_index, decode_variable_data_mut,
    },
    encode::{encode_count, encode_fixed_data},
    error::{DecodeError, EncodeError},
};
#[cfg(not(feature = "pq"))]
use hpke::kem;
use std::fmt::Debug;

/// A type to enforce that a random nonce contains enough bits of security
/// (128bits via a birthday attack -> 256bits needed)
/// This explicitly does not implement Clone or Copy to make sure nonces are not reused
#[derive(Debug)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(PartialEq, Eq, Clone))]
pub struct Nonce([u8; 32]);

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum Digest<'a> {
    Sha2_256(&'a [u8; 32]),
    Blake2b256(&'a [u8; 32]),
}

impl Digest<'_> {
    pub fn as_bytes(&self) -> &[u8; 32] {
        match self {
            Digest::Sha2_256(bytes) => bytes,
            Digest::Blake2b256(bytes) => bytes,
        }
    }
}

impl Nonce {
    pub fn generate(g: impl FnOnce(&mut [u8; 32])) -> Nonce {
        let mut bytes = Default::default();
        g(&mut bytes);

        Nonce(bytes)
    }
}

/// A type to distinguish "normal" TSP messages from "control" messages
#[repr(u32)]
#[derive(Debug)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(PartialEq, Eq, Clone))]
pub enum Payload<'a, Bytes, Vid> {
    /// A TSP message which consists only of a message which will be protected using HPKE
    GenericMessage(Bytes),
    /// A payload that consists of a TSP Envelope+Message
    NestedMessage(Bytes),
    /// A routed payload; same as above but with routing information attached
    RoutedMessage(Vec<Vid>, Bytes),
    /// A TSP message requesting a relationship
    DirectRelationProposal { nonce: Nonce, hops: Vec<Vid> },
    /// A TSP message confirming a relationship
    DirectRelationAffirm { reply: Digest<'a> },
    /// A TSP message requesting a nested relationship
    NestedRelationProposal { nonce: Nonce, message: Bytes },
    /// A TSP message confirming a relationship
    NestedRelationAffirm { message: Bytes, reply: Digest<'a> },
    /// A TSP Message establishing a secondary relationship (parallel relationship forming)
    NewIdentifierProposal { thread_id: Digest<'a>, new_vid: Vid },
    /// A TSP Message revealing a third party
    RelationshipReferral { referred_vid: Vid },
    /// A TSP cancellation message
    RelationshipCancel { reply: Digest<'a> },
}

impl<Bytes: AsRef<[u8]>, Vid: AsRef<[u8]>> Payload<'_, Bytes, Vid> {
    pub fn calculate_size(&self, sender_identity: Option<&[u8]>) -> usize {
        struct Count(usize);
        impl<'a> std::iter::Extend<&'a u8> for Count {
            fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
                self.0 += iter.into_iter().count()
            }
        }

        let mut count = Count(0);
        let _ignore = encode_payload(self, sender_identity, &mut count);

        count.0
    }
}

// helpers for generating and comparing arbitrary `Payload`s
#[cfg(feature = "fuzzing")]
pub mod fuzzing;

#[derive(Debug, Clone, PartialEq)]
#[repr(u8)]
pub enum CryptoType {
    Plaintext = 0,
    HpkeAuth = 1,
    HpkeEssr = 2,
    NaclAuth = 3,
    NaclEssr = 4,
    #[cfg(feature = "pq")]
    X25519Kyber768Draft00 = 5,
}

pub trait AsCryptoType {
    fn crypto_type() -> CryptoType;
}

#[cfg(feature = "pq")]
impl AsCryptoType for kem::X25519Kyber768Draft00 {
    fn crypto_type() -> CryptoType {
        CryptoType::X25519Kyber768Draft00
    }
}

impl AsCryptoType for kem::X25519HkdfSha256 {
    fn crypto_type() -> CryptoType {
        CryptoType::HpkeAuth
    }
}

impl TryFrom<u8> for CryptoType {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CryptoType::Plaintext),
            1 => Ok(CryptoType::HpkeAuth),
            2 => Ok(CryptoType::HpkeEssr),
            3 => Ok(CryptoType::NaclAuth),
            4 => Ok(CryptoType::NaclEssr),
            #[cfg(feature = "pq")]
            5 => Ok(CryptoType::X25519Kyber768Draft00),
            _ => Err(DecodeError::InvalidCryptoType),
        }
    }
}

impl CryptoType {
    pub(crate) fn is_encrypted(&self) -> bool {
        !matches!(self, CryptoType::Plaintext)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[repr(u8)]
pub enum SignatureType {
    NoSignature = 0,
    Ed25519 = 1,
}

impl TryFrom<u8> for SignatureType {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SignatureType::NoSignature),
            1 => Ok(SignatureType::Ed25519),
            _ => Err(DecodeError::InvalidSignatureType),
        }
    }
}

/// Type representing a TSP Envelope
#[derive(Debug, Clone)]
pub struct Envelope<'a, Vid> {
    pub crypto_type: CryptoType,
    pub signature_type: SignatureType,
    pub sender: Vid,
    pub receiver: Option<Vid>,
    pub nonconfidential_data: Option<&'a [u8]>,
}

pub struct DecodedEnvelope<'a, Vid, Bytes> {
    pub envelope: Envelope<'a, Vid>,
    pub raw_header: &'a [u8], // for associated data purposes
    pub ciphertext: Option<Bytes>,
}

type Signature = [u8; 64];

/// Safely encode variable data, returning a soft error in case the size limit is exceeded
fn checked_encode_variable_data(
    identifier: u32,
    payload: &[u8],
    stream: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    const DATA_LIMIT: usize = 3 * (1 << 24);

    if payload.len() >= DATA_LIMIT {
        // since blobs have no identifier, that information is lost on large payloads and a "blob" can only be used
        // for TSP_PLAINTEXT or TSP_CIPHERTEXT.
        if identifier == TSP_PLAINTEXT || identifier == TSP_CIPHERTEXT {
            super::encode::encode_large_blob(payload, stream);
        } else {
            return Err(EncodeError::ExcessiveFieldSize);
        }
    } else {
        super::encode::encode_variable_data(identifier, payload, stream);
    }

    Ok(())
}

/// Safely decode variable data, detecting blobs
fn checked_decode_variable_data_mut(
    identifier: u32,
    stream: &mut [u8],
) -> Option<(&mut [u8], &mut [u8])> {
    let range = checked_decode_variable_data_index(identifier, stream, &mut 0)?;
    let (prefix, stream) = stream.split_at_mut(range.end);
    let slice = &mut prefix[range.start..];

    Some((slice, stream))
}

/// Safely decode variable data, detecting blobs
fn checked_decode_variable_data_index(
    identifier: u32,
    stream: &[u8],
    pos: &mut usize,
) -> Option<std::ops::Range<usize>> {
    if let Some(result) = decode_variable_data_index(identifier, stream, pos) {
        Some(result)
    } else {
        // since blobs have no identifier, that information is lost on large payloads and a "blob" can only be used
        // for TSP_PLAINTEXT or TSP_CIPHERTEXT.
        if identifier == TSP_PLAINTEXT || identifier == TSP_CIPHERTEXT {
            let mut range = super::decode::decode_large_blob_index(&stream[*pos..])?;
            range.start += *pos;
            range.end += *pos;
            *pos = range.end;

            Some(range)
        } else {
            None
        }
    }
}

/// Encode a TSP Payload into CESR for encryption
pub fn encode_payload(
    payload: &Payload<impl AsRef<[u8]>, impl AsRef<[u8]>>,
    sender_identity: Option<&[u8]>,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    if let Some(sender_identity) = sender_identity {
        encode_count(TSP_PAYLOAD, 2, output);
        checked_encode_variable_data(TSP_DEVELOPMENT_VID, sender_identity, output)?;
    } else {
        encode_count(TSP_PAYLOAD, 1, output);
    }

    match payload {
        Payload::GenericMessage(data) => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::GEN_MSG, output);
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), output)?;
        }
        Payload::NestedMessage(data) => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEST_MSG, output);
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), output)?;
        }
        Payload::RoutedMessage(hops, data) => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::GEN_MSG, output);
            if hops.is_empty() {
                return Err(EncodeError::MissingHops);
            }
            encode_hops(hops, output)?;
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), output)?;
        }
        Payload::DirectRelationProposal { nonce, hops } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_REL, output);
            encode_hops(hops, output)?;
            encode_fixed_data(TSP_NONCE, &nonce.0, output);
        }
        Payload::DirectRelationAffirm { reply } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_REL_REPLY, output);
            encode_digest(reply, output);
        }
        Payload::NestedRelationProposal {
            message: data,
            nonce,
        } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_NEST_REL, output);
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), output)?;
            encode_fixed_data(TSP_NONCE, &nonce.0, output);
        }
        Payload::NestedRelationAffirm {
            message: data,
            reply,
        } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_NEST_REL_REPLY, output);
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), output)?;
            encode_digest(reply, output);
        }
        Payload::NewIdentifierProposal { thread_id, new_vid } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_REFER_REL, output);
            encode_digest(thread_id, output);
            checked_encode_variable_data(TSP_DEVELOPMENT_VID, new_vid.as_ref(), output)?;
        }
        Payload::RelationshipReferral { referred_vid } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::THIRDP_REFER_REL, output);
            checked_encode_variable_data(TSP_DEVELOPMENT_VID, referred_vid.as_ref(), output)?;
        }
        Payload::RelationshipCancel { reply } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::REL_CANCEL, output);
            encode_digest(reply, output);
        }
    }

    Ok(())
}

/// Encode a hops list
pub fn encode_hops(
    hops: &[impl AsRef<[u8]>],
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    if !hops.is_empty() {
        encode_count(TSP_HOP_LIST, hops.len() as u16, output);
        for hop in hops {
            checked_encode_variable_data(TSP_DEVELOPMENT_VID, hop.as_ref(), output)?;
        }
    }

    Ok(())
}

/// Decode a hops list
fn decode_hops<'a, Vid: TryFrom<&'a [u8]>>(
    stream: &'a mut [u8],
) -> Result<(Vec<Vid>, &'a mut [u8]), DecodeError> {
    // a rare case of Rust's borrow checker not being able to figure out
    // that a "None" isn't borrowing from anybody; so we have to call
    // the referentially transparent decode_count_mut twice...
    if decode_count_mut(TSP_HOP_LIST, stream).is_none() {
        return Ok((Vec::new(), stream));
    }

    let (hop_length, mut stream) = decode_count_mut(TSP_HOP_LIST, stream).unwrap();

    let mut hop_list = Vec::with_capacity(hop_length as usize);
    for _ in 0..hop_length {
        let hop: &[u8];
        (hop, stream) = decode_variable_data_mut(TSP_DEVELOPMENT_VID, stream)
            .ok_or(DecodeError::UnexpectedData)?;

        hop_list.push(hop.try_into().map_err(|_| DecodeError::VidError)?);
    }

    Ok((hop_list, stream))
}

// "NestedBytes" to support both mutable and non-mutable data
/// A decoded payload + optional ESSR data
pub struct DecodedPayload<'a> {
    pub payload: Payload<'a, &'a mut [u8], &'a [u8]>,
    pub sender_identity: Option<&'a [u8]>,
}

/// Decode a TSP Digest
fn decode_digest(stream: &mut [u8]) -> Result<(Digest, &mut [u8]), DecodeError> {
    let result = if decode_fixed_data::<32>(TSP_SHA256, &mut (stream as &[u8])).is_some() {
        decode_fixed_data_mut(TSP_SHA256, stream)
            .map(|(digest, stream)| (Digest::Sha2_256(digest), stream))
    } else if decode_fixed_data::<32>(TSP_BLAKE2B256, &mut (stream as &[u8])).is_some() {
        decode_fixed_data_mut(TSP_BLAKE2B256, stream)
            .map(|(digest, stream)| (Digest::Blake2b256(digest), stream))
    } else {
        None
    };

    result.ok_or(DecodeError::UnexpectedData)
}

/// Encode a TSP Digest
pub fn encode_digest(digest: &Digest, output: &mut impl for<'a> Extend<&'a u8>) {
    match digest {
        Digest::Sha2_256(digest) => encode_fixed_data(TSP_SHA256, digest.as_slice(), output),
        Digest::Blake2b256(digest) => encode_fixed_data(TSP_BLAKE2B256, digest.as_slice(), output),
    }
}

/// Decode a TSP Payload
pub fn decode_payload(mut stream: &mut [u8]) -> Result<DecodedPayload, DecodeError> {
    let sender_identity = match decode_count_mut(TSP_PAYLOAD, stream) {
        Some((2, upd_stream)) => {
            let essr_prefix: &[u8];
            (essr_prefix, stream) = decode_variable_data_mut(TSP_DEVELOPMENT_VID, upd_stream)
                .ok_or(DecodeError::UnexpectedData)?;

            Some(essr_prefix)
        }
        Some((1, upd_stream)) => {
            stream = upd_stream;

            None
        }
        _ => return Err(DecodeError::VersionMismatch),
    };

    let (&mut msgtype, mut stream) =
        decode_fixed_data_mut(TSP_TYPECODE, stream).ok_or(DecodeError::UnexpectedData)?;

    let payload = match msgtype {
        msgtype::GEN_MSG => {
            let (hop_list, upd_stream) = decode_hops(stream)?;
            let msg;
            if hop_list.is_empty() {
                (msg, stream) = checked_decode_variable_data_mut(TSP_PLAINTEXT, upd_stream)
                    .ok_or(DecodeError::UnexpectedData)?;

                Payload::GenericMessage(msg)
            } else {
                (msg, stream) = checked_decode_variable_data_mut(TSP_PLAINTEXT, upd_stream)
                    .ok_or(DecodeError::UnexpectedData)?;

                Payload::RoutedMessage(hop_list, msg)
            }
        }
        msgtype::NEW_REL => {
            let (hop_list, upd_stream) = decode_hops(stream)?;

            let nonce;
            (nonce, stream) =
                decode_fixed_data_mut(TSP_NONCE, upd_stream).ok_or(DecodeError::UnexpectedData)?;

            Payload::DirectRelationProposal {
                nonce: Nonce(*nonce),
                hops: hop_list,
            }
        }
        msgtype::NEST_MSG => {
            let msg;
            (msg, stream) = checked_decode_variable_data_mut(TSP_PLAINTEXT, stream)
                .ok_or(DecodeError::UnexpectedData)?;

            Payload::NestedMessage(msg)
        }
        msgtype::NEW_REL_REPLY => {
            let reply;
            (reply, stream) = decode_digest(stream)?;

            Payload::DirectRelationAffirm { reply }
        }
        msgtype::NEW_NEST_REL => {
            let data: &mut [u8];
            (data, stream) = decode_variable_data_mut(TSP_PLAINTEXT, stream)
                .ok_or(DecodeError::UnexpectedData)?;

            let nonce;
            (nonce, stream) =
                decode_fixed_data_mut(TSP_NONCE, stream).ok_or(DecodeError::UnexpectedData)?;

            Payload::NestedRelationProposal {
                message: data,
                nonce: Nonce(*nonce),
            }
        }
        msgtype::NEW_NEST_REL_REPLY => {
            let data: &mut [u8];
            let reply;
            (data, stream) = decode_variable_data_mut(TSP_PLAINTEXT, stream)
                .ok_or(DecodeError::UnexpectedData)?;
            (reply, stream) = decode_digest(stream)?;

            Payload::NestedRelationAffirm {
                message: data,
                reply,
            }
        }
        msgtype::NEW_REFER_REL => {
            let (thread_id, upd_stream) = decode_digest(stream)?;
            let new_vid: &[u8];
            (new_vid, stream) = decode_variable_data_mut(TSP_DEVELOPMENT_VID, upd_stream)
                .ok_or(DecodeError::UnexpectedData)?;

            Payload::NewIdentifierProposal { thread_id, new_vid }
        }
        msgtype::THIRDP_REFER_REL => {
            let referred_vid: &[u8];
            (referred_vid, stream) = decode_variable_data_mut(TSP_DEVELOPMENT_VID, stream)
                .ok_or(DecodeError::UnexpectedData)?;

            Payload::RelationshipReferral { referred_vid }
        }
        msgtype::REL_CANCEL => {
            let reply;
            (reply, stream) = decode_digest(stream)?;

            Payload::RelationshipCancel { reply }
        }
        _ => return Err(DecodeError::UnexpectedMsgType),
    };

    if !stream.is_empty() {
        Err(DecodeError::TrailingGarbage)
    } else {
        Ok(DecodedPayload {
            payload,
            sender_identity,
        })
    }
}

/// Encode a encrypted TSP message plus Envelope into CESR
pub fn encode_ets_envelope<'a, Vid: AsRef<[u8]>>(
    envelope: Envelope<'a, Vid>,
    output: &mut impl for<'b> Extend<&'b u8>,
) -> Result<(), EncodeError> {
    encode_count(TSP_ETS_WRAPPER, 1, output);
    encode_envelope_fields(envelope, output)
}

/// Encode a encrypted TSP message plus Envelope into CESR
pub fn encode_s_envelope<'a, Vid: AsRef<[u8]>>(
    envelope: Envelope<'a, Vid>,
    output: &mut impl for<'b> Extend<&'b u8>,
) -> Result<(), EncodeError> {
    encode_count(TSP_S_WRAPPER, 1, output);

    encode_envelope_fields(envelope, output)
}

/// Encode the envelope fields; the only difference between ETS and S envelopes
/// is whether there is ciphertext between the header and signature, and this function
/// doesn't need to know that.
fn encode_envelope_fields<'a, Vid: AsRef<[u8]>>(
    envelope: Envelope<'a, Vid>,
    output: &mut impl for<'b> Extend<&'b u8>,
) -> Result<(), EncodeError> {
    encode_fixed_data(TSP_TYPECODE, &[0, 0], output);
    encode_fixed_data(
        TSP_TYPECODE,
        &[envelope.crypto_type as u8, envelope.signature_type as u8],
        output,
    );
    checked_encode_variable_data(TSP_DEVELOPMENT_VID, envelope.sender.as_ref(), output)?;

    if let Some(rec) = envelope.receiver {
        checked_encode_variable_data(TSP_DEVELOPMENT_VID, rec.as_ref(), output)?;
    }

    if let Some(data) = envelope.nonconfidential_data {
        checked_encode_variable_data(TSP_PLAINTEXT, data, output)?;
    }

    Ok(())
}

/// Encode a Ed25519 signature into CESR
pub fn encode_signature(signature: &Signature, output: &mut impl for<'a> Extend<&'a u8>) {
    encode_fixed_data(ED25519_SIGNATURE, signature, output);
}

/// Encode a encrypted ciphertext into CESR
pub fn encode_ciphertext(
    ciphertext: &[u8],
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    checked_encode_variable_data(TSP_CIPHERTEXT, ciphertext, output)
}

/// Checks whether the expected TSP header is present and returns its size and whether it
/// is a "ETS" or "S" envelope
pub(super) fn detected_tsp_header_size_and_confidentiality(
    stream: &mut &[u8],
) -> Result<(usize, CryptoType, SignatureType), DecodeError> {
    let origin = stream as &[u8];
    let encrypted = if let Some(1) = decode_count(TSP_ETS_WRAPPER, stream) {
        true
    } else if let Some(1) = decode_count(TSP_S_WRAPPER, stream) {
        false
    } else {
        return Err(DecodeError::VersionMismatch);
    };

    match decode_fixed_data(TSP_TYPECODE, stream) {
        Some([0, 0]) => {}
        _ => return Err(DecodeError::VersionMismatch),
    }

    let (crypto_type, signature_type) = match decode_fixed_data(TSP_TYPECODE, stream) {
        Some([crypto, signature]) => {
            let crypto_type = CryptoType::try_from(*crypto)?;

            if crypto_type.is_encrypted() != encrypted {
                return Err(DecodeError::VersionMismatch);
            }

            (crypto_type, SignatureType::try_from(*signature)?)
        }
        _ => return Err(DecodeError::VersionMismatch),
    };

    debug_assert_eq!(origin.len() - stream.len(), 9);

    Ok((9, crypto_type, signature_type))
}

/// A structure representing a siganture + data that needs to be verified.
/// The `signature` must authenticate the `signed_data`.
#[derive(Clone, Debug)]
#[must_use]
pub struct VerificationChallenge<'a> {
    pub signed_data: &'a [u8],
    pub signature: &'a Signature,
}

/// Decode the type, sender and receiver of an encrypted TSP message
pub fn decode_sender_receiver<'a, Vid: TryFrom<&'a [u8]>>(
    stream: &mut &'a [u8],
) -> Result<(Vid, Option<Vid>, CryptoType, SignatureType), DecodeError> {
    let (_, crypto_type, signature_type) = detected_tsp_header_size_and_confidentiality(stream)?;

    let sender = decode_variable_data(TSP_DEVELOPMENT_VID, stream)
        .ok_or(DecodeError::UnexpectedData)?
        .try_into()
        .map_err(|_| DecodeError::VidError)?;

    let receiver = decode_variable_data(TSP_DEVELOPMENT_VID, stream)
        .map(|r| r.try_into().map_err(|_| DecodeError::VidError))
        .transpose()?;

    Ok((sender, receiver, crypto_type, signature_type))
}

#[cfg(feature = "pq")]
use hpke_pq::kem;
use std::ops::Range;

#[derive(Debug)]
/// A CipherView is an intermediary representation of an "opened envelope", but whose signature still needs
/// to be checked.
// An opened envelope has the capability of in-place mutations: since the original data is still present
// 'in memory' (guaranteed by CESR encoding), this saves a needless copy (which is good from a
// security point-of-view)
//
// At the same time, to check the signature on the entire CESR message, we need a immutable
// reference to the parts of memory that we want to mutate soon after checking the signature, so we
// cannot use slices in this structure but instead use a mutable reference to the entire data plus
// ranges so we can produce both "views" of this data.
pub struct CipherView<'a> {
    data: &'a mut [u8],

    crypto_type: CryptoType,
    signature_type: SignatureType,

    sender: Range<usize>,
    receiver: Option<Range<usize>>,
    nonconfidential_data: Option<Range<usize>>,

    associated_data: Range<usize>,
    signature: &'a Signature,

    signed_data: Range<usize>,
    ciphertext: Option<Range<usize>>,
}

impl<'a> CipherView<'a> {
    /// Produce the "opened envelope", consuming this 'CipherView'.
    pub fn into_opened<Vid: TryFrom<&'a [u8]>>(
        self,
    ) -> Result<DecodedEnvelope<'a, Vid, &'a mut [u8]>, Vid::Error> {
        let plaintext_end = self
            .ciphertext
            .as_ref()
            .map(|r| r.start)
            .unwrap_or(self.data.len());
        let (header, cipherdata) = self.data.split_at_mut(plaintext_end);

        let ciphertext = self.ciphertext.map(|r| &mut cipherdata[..r.len()]);

        let raw_header = &header[self.associated_data.clone()];

        let envelope = Envelope {
            crypto_type: self.crypto_type,
            signature_type: self.signature_type,
            sender: header[self.sender.clone()].try_into()?,
            receiver: self
                .receiver
                .map(|r| header[r.clone()].try_into())
                .transpose()?,
            nonconfidential_data: self
                .nonconfidential_data
                .as_ref()
                .map(|range| &header[range.clone()]),
        };

        Ok(DecodedEnvelope {
            envelope,
            raw_header,
            ciphertext,
        })
    }

    /// Obtain the VerificationChallenge of this CipherView
    pub fn as_challenge(&self) -> VerificationChallenge {
        VerificationChallenge {
            signed_data: &self.data[self.signed_data.clone()],
            signature: self.signature,
        }
    }
}

/// Decode an encrypted TSP message plus Envelope & Signature
/// Produces the ciphertext as a mutable stream.
pub fn decode_envelope<'a>(stream: &'a mut [u8]) -> Result<CipherView<'a>, DecodeError> {
    let (mut pos, crypto_type, signature_type) =
        detected_tsp_header_size_and_confidentiality(&mut (stream as &[u8]))?;

    let sender = decode_variable_data_index(TSP_DEVELOPMENT_VID, stream, &mut pos)
        .ok_or(DecodeError::UnexpectedData)?;

    let receiver = decode_variable_data_index(TSP_DEVELOPMENT_VID, stream, &mut pos);

    let nonconfidential_data = decode_variable_data_index(TSP_PLAINTEXT, stream, &mut pos);

    let associated_data = 0..pos;

    let ciphertext = if crypto_type.is_encrypted() {
        Some(
            checked_decode_variable_data_index(TSP_CIPHERTEXT, stream, &mut pos)
                .ok_or(DecodeError::UnexpectedData)?,
        )
    } else {
        None
    };

    let signed_data = 0..pos;

    let data: &'a mut [u8];
    let mut sigdata: &[u8];
    (data, sigdata) = stream.split_at_mut(signed_data.end);

    let signature =
        decode_fixed_data(ED25519_SIGNATURE, &mut sigdata).ok_or(DecodeError::UnexpectedData)?;

    if !sigdata.is_empty() {
        return Err(DecodeError::TrailingGarbage);
    }

    Ok(CipherView {
        data,

        crypto_type,
        signature_type,

        sender,
        receiver,
        nonconfidential_data,

        associated_data,
        signature,

        signed_data,
        ciphertext,
    })
}

/// Allocating variant of [encode_payload]
#[cfg(test)]
pub fn encode_payload_vec(
    payload: &Payload<impl AsRef<[u8]>, impl AsRef<[u8]>>,
) -> Result<Vec<u8>, EncodeError> {
    let mut data = vec![];
    encode_payload(payload, None, &mut data)?;

    Ok(data)
}

/// Allocating variant of [encode_ets_envelope]
#[cfg(test)]
pub fn encode_ets_envelope_vec<Vid: AsRef<[u8]>>(
    envelope: Envelope<Vid>,
) -> Result<Vec<u8>, EncodeError> {
    let mut data = vec![];
    encode_ets_envelope(envelope, &mut data)?;

    Ok(data)
}

/// Allocating variant of [encode_ets_envelope]
#[cfg(test)]
pub fn encode_s_envelope_vec<Vid: AsRef<[u8]>>(
    envelope: Envelope<Vid>,
) -> Result<Vec<u8>, EncodeError> {
    let mut data = vec![];
    encode_s_envelope(envelope, &mut data)?;

    Ok(data)
}

/// Describes the bytes in a CESR-encoded message part
#[derive(Default, Debug)]
pub struct Part<'a> {
    pub prefix: &'a [u8],
    pub data: &'a [u8],
}

/// Decode a CESR-encoded data into a Part
impl<'a> Part<'a> {
    fn decode(identifier: u32, data: &'a [u8], pos: &mut usize) -> Option<Part<'a>> {
        let begin_pos = *pos;
        match checked_decode_variable_data_index(identifier, data, pos) {
            Some(range) => {
                let part = Part {
                    prefix: &data[begin_pos..range.start],
                    data: &data[range.start..range.end],
                };

                Some(part)
            }
            None => None,
        }
    }
}

/// Describes the CESR-encoded parts of a TSP message
#[derive(Debug)]
pub struct MessageParts<'a> {
    pub prefix: Part<'a>,
    pub sender: Part<'a>,
    pub receiver: Option<Part<'a>>,
    pub nonconfidential_data: Option<Part<'a>>,
    pub ciphertext: Option<Part<'a>>,
    pub signature: Part<'a>,
    pub crypto_type: CryptoType,
    pub signature_type: SignatureType,
}

/// Decode a CESR-encoded message into its CESR-encoded parts
pub fn open_message_into_parts(data: &[u8]) -> Result<MessageParts, DecodeError> {
    let (mut pos, crypto_type, signature_type) =
        detected_tsp_header_size_and_confidentiality(&mut (data as &[u8]))?;

    let prefix = Part {
        prefix: &data[..pos],
        data: &[],
    };

    let sender = Part::decode(TSP_DEVELOPMENT_VID, data, &mut pos).ok_or(DecodeError::VidError)?;
    let receiver = Part::decode(TSP_DEVELOPMENT_VID, data, &mut pos);
    let nonconfidential_data = Part::decode(TSP_PLAINTEXT, data, &mut pos);
    let ciphertext = Part::decode(TSP_CIPHERTEXT, data, &mut pos);

    let signature: &[u8; 64] = decode_fixed_data(ED25519_SIGNATURE, &mut &data[pos..])
        .ok_or(DecodeError::SignatureError)?;

    let signature = Part {
        prefix: &data[pos..(data.len() - signature.len())],
        data: signature,
    };

    Ok(MessageParts {
        prefix,
        sender,
        receiver,
        nonconfidential_data,
        ciphertext,
        signature,
        crypto_type,
        signature_type,
    })
}

/// Convenience interface: this struct is isomorphic to [Envelope] but represents
/// a "opened" envelope, i.e. message.
#[cfg(all(feature = "demo", test))]
#[derive(Debug, Clone)]
pub struct Message<'a, Vid, Bytes: AsRef<[u8]>> {
    pub sender: Vid,
    pub receiver: Vid,
    pub nonconfidential_data: Option<&'a [u8]>,
    pub message: Payload<'a, Bytes, Vid>,
}

/// Convenience interface which illustrates encoding as a single operation
#[cfg(all(feature = "demo", test))]
pub fn encode_tsp_message<Vid: AsRef<[u8]>>(
    Message {
        ref sender,
        ref receiver,
        nonconfidential_data,
        message,
    }: Message<Vid, impl AsRef<[u8]>>,
    encrypt: impl FnOnce(&Vid, Vec<u8>) -> Vec<u8>,
    sign: impl FnOnce(&Vid, &[u8]) -> Signature,
) -> Result<Vec<u8>, EncodeError> {
    let mut cesr = encode_ets_envelope_vec(Envelope {
        crypto_type: CryptoType::HpkeAuth,
        signature_type: SignatureType::Ed25519,
        sender,
        receiver: Some(receiver),
        nonconfidential_data,
    })?;

    let ciphertext = &encrypt(receiver, encode_payload_vec(&message)?);

    encode_ciphertext(ciphertext, &mut cesr)?;
    encode_signature(&sign(sender, &cesr), &mut cesr);

    Ok(cesr)
}

/// A convenience interface which illustrates decoding as a single operation
#[cfg(all(feature = "demo", test))]
pub fn decode_tsp_message<'a, Vid: TryFrom<&'a [u8]>>(
    data: &'a mut [u8],
    decrypt: impl FnOnce(&Vid, &[u8]) -> Vec<u8>,
    verify: impl FnOnce(&[u8], &Vid, &Signature) -> bool,
) -> Result<Message<'a, Vid, Vec<u8>>, DecodeError>
where
    <Vid as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    let CipherView {
        data,
        sender,
        receiver,
        nonconfidential_data,
        signature,
        signed_data,
        ciphertext,
        ..
    } = decode_envelope(data)?;

    if !verify(
        &data[signed_data],
        &data[sender.clone()].try_into().unwrap(),
        signature,
    ) {
        return Err(DecodeError::SignatureError);
    }

    let mut decrypted = decrypt(
        &data[receiver.clone().unwrap()].try_into().unwrap(),
        &data[ciphertext.unwrap()],
    );

    // This illustrates a challenge: unless decryption happens in place, either a needless
    // allocation or at the very least moving the contents of the payload around must occur.
    let DecodedPayload {
        payload: Payload::GenericMessage(message),
        ..
    } = decode_payload(&mut decrypted)?
    else {
        panic!("Expected GenericMessage");
    };
    let message = Payload::GenericMessage(message.to_owned());

    Ok(Message {
        sender: data[sender].try_into().unwrap(),
        receiver: data[receiver.unwrap()].try_into().unwrap(),
        nonconfidential_data: nonconfidential_data.map(|ncd| data[ncd].try_into().unwrap()),
        message,
    })
}

#[cfg(test)]
mod test {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[test]
    #[wasm_bindgen_test]
    fn envelope_without_nonconfidential_data() {
        fn dummy_crypt(data: &mut [u8]) -> &mut [u8] {
            data
        }
        let fixed_sig = [1; 64];

        let mut cesr_payload =
            { encode_payload_vec(&Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_ets_envelope_vec(Envelope {
            crypto_type: CryptoType::HpkeAuth,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: None,
        })
        .unwrap();
        let ciphertext = dummy_crypt(&mut cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let view = decode_envelope(&mut outer).unwrap();
        let ver = view.as_challenge();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        let DecodedEnvelope {
            envelope: env,
            ciphertext,
            ..
        } = view.into_opened().unwrap();
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));
        assert_eq!(env.nonconfidential_data, None);

        let DecodedPayload {
            payload: Payload::GenericMessage(data),
            ..
        } = decode_payload(dummy_crypt(ciphertext.unwrap())).unwrap()
        else {
            unreachable!();
        };
        assert_eq!(data, b"Hello TSP!");
    }

    #[test]
    #[wasm_bindgen_test]
    fn envelope_with_nonconfidential_data() {
        fn dummy_crypt(data: &mut [u8]) -> &mut [u8] {
            data
        }
        let fixed_sig = [1; 64];

        let mut cesr_payload =
            { encode_payload_vec(&Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_ets_envelope_vec(Envelope {
            crypto_type: CryptoType::HpkeAuth,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&mut cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let view = decode_envelope(&mut outer).unwrap();
        let ver = view.as_challenge();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        let DecodedEnvelope {
            envelope: env,
            ciphertext,
            ..
        } = view.into_opened().unwrap();
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));
        assert_eq!(env.nonconfidential_data, Some(&b"treasure"[..]));

        let DecodedPayload {
            payload: Payload::GenericMessage(data),
            ..
        } = decode_payload(dummy_crypt(ciphertext.unwrap())).unwrap()
        else {
            unreachable!();
        };
        assert_eq!(data, b"Hello TSP!");
    }

    #[test]
    #[wasm_bindgen_test]
    fn envelope_without_confidential_data() {
        let fixed_sig = [1; 64];

        let mut outer = encode_s_envelope_vec(Envelope {
            crypto_type: CryptoType::Plaintext,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let view = decode_envelope(&mut outer).unwrap();
        let ver = view.as_challenge();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        let DecodedEnvelope {
            envelope: env,
            ciphertext,
            ..
        } = view.into_opened().unwrap();
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));
        assert_eq!(env.nonconfidential_data, Some(&b"treasure"[..]));

        assert!(ciphertext.is_none());
    }

    #[test]
    #[wasm_bindgen_test]
    fn s_envelope_with_confidential_data_failure() {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload =
            { encode_payload_vec(&Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_s_envelope_vec(Envelope {
            crypto_type: CryptoType::Plaintext,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload); // this is wrong
        encode_ciphertext(ciphertext, &mut outer).unwrap();
        encode_signature(&fixed_sig, &mut outer);

        assert!(decode_envelope(&mut outer).is_err());
    }

    #[test]
    #[wasm_bindgen_test]
    fn envelope_failure() {
        let fixed_sig = [1; 64];

        let mut outer = vec![];
        encode_ets_envelope(
            Envelope {
                crypto_type: CryptoType::HpkeAuth,
                signature_type: SignatureType::Ed25519,
                sender: &b"Alister"[..],
                receiver: Some(&b"Bobbi"[..]),
                nonconfidential_data: Some(b"treasure"),
            },
            &mut outer,
        )
        .unwrap();
        encode_signature(&fixed_sig, &mut outer);
        encode_ciphertext(&[], &mut outer).unwrap();

        assert!(decode_envelope(&mut outer).is_err());
    }

    #[test]
    #[wasm_bindgen_test]
    fn trailing_data() {
        let fixed_sig = [1; 64];

        let mut outer = encode_ets_envelope_vec(Envelope {
            crypto_type: CryptoType::HpkeAuth,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        encode_ciphertext(&[], &mut outer).unwrap();
        encode_signature(&fixed_sig, &mut outer);
        outer.push(b'-');

        assert!(decode_envelope(&mut outer).is_err());
    }

    #[cfg(all(feature = "demo", test))]
    #[test]
    fn convenience() {
        let sender = b"Alister".as_slice();
        let receiver = b"Bobbi".as_slice();
        let payload = b"Hello TSP!";
        let mut data = encode_tsp_message(
            Message {
                sender,
                receiver,
                nonconfidential_data: None,
                message: Payload::GenericMessage(payload),
            },
            |_, vec| vec,
            |_, _| [5; 64],
        )
        .unwrap();

        let tsp = decode_tsp_message(
            &mut data,
            |_: &&[u8], x| x.to_vec(),
            |_, _, sig| sig == &[5u8; 64],
        )
        .unwrap();

        assert_eq!(tsp.sender, b"Alister".as_slice());
        assert_eq!(tsp.receiver, b"Bobbi");

        let Payload::GenericMessage(content) = tsp.message else {
            panic!("Expected Payload::GenericMessage");
        };
        assert_eq!(&content[..], b"Hello TSP!");
    }

    #[test]
    #[wasm_bindgen_test]
    fn mut_envelope_with_nonconfidential_data() {
        test_turn_around(Payload::GenericMessage(&mut b"Hello TSP!".to_owned()));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_nested_msg() {
        test_turn_around(Payload::NestedMessage(&mut b"Hello TSP!".to_owned()));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_routed_msg() {
        test_turn_around(Payload::RoutedMessage(
            vec![b"foo", b"bar"],
            &mut b"Hello TSP!".to_owned(),
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_par_refer_rel() {
        test_turn_around(Payload::NewIdentifierProposal {
            thread_id: Digest::Sha2_256(&Default::default()),
            new_vid: b"Charlie",
        });
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_3p_refer_rel() {
        test_turn_around(Payload::RelationshipReferral {
            referred_vid: b"Charlie",
        });
    }

    fn test_turn_around(payload: Payload<&mut [u8], &[u8]>) {
        fn dummy_crypt(data: &mut [u8]) -> &mut [u8] {
            data
        }
        let fixed_sig = [1; 64];

        let mut cesr_payload = encode_payload_vec(&payload).unwrap();

        let mut outer = encode_ets_envelope_vec(Envelope {
            crypto_type: CryptoType::HpkeAuth,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&mut cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let view = decode_envelope(&mut outer).unwrap();
        assert_eq!(view.as_challenge().signed_data, signed_data);
        assert_eq!(view.as_challenge().signature, &fixed_sig);
        let DecodedEnvelope {
            envelope: env,
            ciphertext,
            ..
        } = view.into_opened::<&[u8]>().unwrap();

        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));
        assert_eq!(env.nonconfidential_data, Some(&b"treasure"[..]));

        assert_eq!(
            decode_payload(dummy_crypt(ciphertext.unwrap()))
                .unwrap()
                .payload,
            payload
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_relation_forming() {
        let temp = (1u8..33).collect::<Vec<u8>>();
        let nonce: &[u8; 32] = temp.as_slice().try_into().unwrap();
        test_turn_around(Payload::DirectRelationProposal {
            nonce: Nonce(*nonce),
            hops: vec![],
        });
        test_turn_around(Payload::DirectRelationAffirm {
            reply: Digest::Sha2_256(nonce),
        });
        test_turn_around(Payload::DirectRelationAffirm {
            reply: Digest::Blake2b256(nonce),
        });
        test_turn_around(Payload::NestedRelationProposal {
            message: &mut temp.clone(),
            nonce: Nonce(*nonce),
        });
        test_turn_around(Payload::NestedRelationAffirm {
            message: &mut temp.clone(),
            reply: Digest::Sha2_256(nonce),
        });
        test_turn_around(Payload::NestedRelationAffirm {
            message: &mut temp.clone(),
            reply: Digest::Blake2b256(nonce),
        });

        test_turn_around(Payload::RelationshipCancel {
            reply: Digest::Sha2_256(nonce),
        });
        test_turn_around(Payload::RelationshipCancel {
            reply: Digest::Blake2b256(nonce),
        });
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_message_to_parts() {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let message = Base64UrlUnpadded::decode_vec("-EABXAAAXAEB9VIDAAAEZGlkOnRlc3Q6Ym9i8VIDAAAFAGRpZDp0ZXN0OmFsaWNl6BAEAABleHRyYSBkYXRh4CAXScvzIiBCgfOu9jHtGwd1qN-KlMB7uhFbE9YOSyTmnp9yziA1LVPdQmST27yjuDRTlxeRo7H7gfuaGFY4iyf2EsfiqvEg0BBNDbKoW0DDczGxj7rNWKH_suyj18HCUxMZ6-mDymZdNhHZIS8zIstC9Kxv5Q-GxmI-1v4SNbeCemuCMBzMPogK").unwrap();
        let parts = open_message_into_parts(&message).unwrap();

        assert_eq!(parts.prefix.prefix.len(), 9);
        assert_eq!(parts.sender.data.len(), 10);
        assert_eq!(parts.receiver.unwrap().data.len(), 14);
        assert_eq!(parts.ciphertext.unwrap().data.len(), 69);
    }

    #[test]
    fn test_blob() {
        let payload = vec![b'M'; 50];
        let mut data = vec![];
        checked_encode_variable_data(TSP_PLAINTEXT, &payload, &mut data).unwrap();
        let input = &mut data[..];
        let (source, _) = decode_variable_data_mut(TSP_PLAINTEXT, input).unwrap();
        assert!(source.len() == 50);
        let (source, _) = checked_decode_variable_data_mut(TSP_PLAINTEXT, input).unwrap();
        assert!(source.len() == 50);

        let payload = vec![b'M'; 60_000_000];
        let mut data = vec![];
        checked_encode_variable_data(TSP_PLAINTEXT, &payload, &mut data).unwrap();
        let input = &mut data[..];
        assert!(decode_variable_data_mut(TSP_PLAINTEXT, input).is_none());
        let (source, _) = checked_decode_variable_data_mut(TSP_PLAINTEXT, input).unwrap();
        assert!(source.len() == 60_000_000);
    }
}
