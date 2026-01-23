use super::consts::{cesr, cesr_data};

/// The TSP version supported by this spec
const TSP_VERSION: (u16, u8, u8) = (0, 0, 1);

/// Constants that determine the specific CESR types for "variable length data"
const TSP_PLAINTEXT: u32 = cesr!("B");
const TSP_NACL_CIPHERTEXT: u32 = cesr!("C");
const TSP_NACLAUTH_CIPHERTEXT: u32 = cesr!("NCL");
const TSP_HPKEBASE_CIPHERTEXT: u32 = cesr!("F");
const TSP_HPKEAUTH_CIPHERTEXT: u32 = cesr!("G");
#[cfg(feature = "pq")]
const TSP_HPKEPQ_CIPHERTEXT: u32 = cesr!("PQC");
const TSP_VID: u32 = cesr!("B");

/// Constants that determine the specific CESR types for "fixed length data"
const ED25519_SIGNATURE: u32 = cesr!("B");
#[cfg(feature = "pq")]
const ML_DSA_65_SIGNATURE: u32 = cesr!("QDM");
#[allow(clippy::eq_op)]
const TSP_NONCE: u32 = cesr!("A");
const TSP_SHA256: u32 = cesr!("I");
#[allow(dead_code)]
const TSP_BLAKE2B256: u32 = cesr!("F");

/// Constants that determine the specific CESR types for the framing codes
const TSP_ETS_WRAPPER: u16 = cesr!("E");
const TSP_S_WRAPPER: u16 = cesr!("S");
const TSP_HOP_LIST: u16 = cesr!("J");
const TSP_PAYLOAD: u16 = cesr!("Z");
const TSP_ATTACH_GRP: u16 = cesr!("C");
const TSP_INDEX_SIG_GRP: u16 = cesr!("K");

const TSP_TMP: u32 = cesr!("X");

/// Constants for payload field types
// NOTE: this is for future extensibility
#[allow(unused)]
const XCTL: [u8; 3] = cesr_data("XCTL");
const XSCS: [u8; 3] = cesr_data("XSCS");
const XHOP: [u8; 3] = cesr_data("XHOP");
#[allow(unused)]
const XPAD: [u8; 3] = cesr_data("XPAD");
const XRFI: [u8; 3] = cesr_data("XRFI");
const XRFA: [u8; 3] = cesr_data("XRFA");
const XRFD: [u8; 3] = cesr_data("XRFD");
const YTSP: [u8; 3] = cesr_data("YTSP");

// FIXME: a temporary code for third party referrals
const X3RR: [u8; 3] = cesr_data("X3RR");

// FIXME: a temporary code for nested relationships
const XRNI: [u8; 3] = cesr_data("XRNI");
const XRNA: [u8; 3] = cesr_data("XRNA");

use super::{
    decode::{
        decode_count, decode_count_mut, decode_fixed_data, decode_fixed_data_mut,
        decode_variable_data, decode_variable_data_index, decode_variable_data_mut,
        opt_decode_variable_data_mut,
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
    NewIdentifierProposal {
        thread_id: Digest<'a>,
        sig_thread_id: &'a Signature,
        new_vid: Vid,
    },
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

#[derive(Debug, Clone, PartialEq, Copy)]
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
        if cfg!(feature = "essr") {
            CryptoType::HpkeEssr
        } else {
            CryptoType::HpkeAuth
        }
    }
}

impl CryptoType {
    pub(crate) fn is_encrypted(&self) -> bool {
        !matches!(self, CryptoType::Plaintext)
    }
}

#[derive(Debug, Clone, PartialEq, Copy)]
#[repr(u8)]
pub enum SignatureType {
    NoSignature = 0,
    Ed25519 = 1,
    #[cfg(feature = "pq")]
    MlDsa65 = 2,
}

impl SignatureType {
    #[allow(unused)]
    pub(crate) fn is_signed(&self) -> bool {
        !matches!(self, SignatureType::NoSignature)
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

type Signature = [u8];

/// Safely encode variable data, returning a soft error in case the size limit is exceeded
fn checked_encode_variable_data(
    identifier: u32,
    payload: &[u8],
    stream: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    const DATA_LIMIT: usize = 3 * (1 << 24);

    if payload.len() >= DATA_LIMIT {
        return Err(EncodeError::ExcessiveFieldSize);
    } else {
        super::encode::encode_variable_data(identifier, payload, stream);
    }

    Ok(())
}

/// Safely decode variable data
fn checked_decode_variable_data_mut(
    identifier: u32,
    stream: &mut [u8],
) -> Option<(&mut [u8], &mut [u8])> {
    let range = checked_decode_variable_data_index(identifier, stream, &mut 0)?;
    let (prefix, stream) = stream.split_at_mut(range.end);
    let slice = &mut prefix[range.start..];

    Some((slice, stream))
}

/// Safely decode variable data
fn checked_decode_variable_data_index(
    identifier: u32,
    stream: &[u8],
    pos: &mut usize,
) -> Option<std::ops::Range<usize>> {
    decode_variable_data_index(identifier, stream, pos)
}

/// Encode a TSP Payload into CESR for encryption
pub fn encode_payload(
    payload: &Payload<impl AsRef<[u8]>, impl AsRef<[u8]>>,
    sender_identity: Option<&[u8]>,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    let mut temp = Vec::new(); // temporary buffer to count the size

    if let Some(sender_identity) = sender_identity {
        checked_encode_variable_data(TSP_VID, sender_identity, &mut temp)?;
    }

    match payload {
        Payload::GenericMessage(data) => {
            temp.extend(&XSCS);
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), &mut temp)?;
        }
        Payload::NestedMessage(data) => {
            temp.extend(&XHOP);
            let no_hops: [&[u8]; 0] = [];
            encode_hops(&no_hops, &mut temp)?;
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), &mut temp)?;
        }
        Payload::RoutedMessage(hops, data) => {
            temp.extend(&XHOP);
            if hops.is_empty() {
                return Err(EncodeError::MissingHops);
            }
            encode_hops(hops, &mut temp)?;
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), &mut temp)?;
        }
        Payload::DirectRelationProposal { nonce, hops } => {
            temp.extend(&XRFI);
            encode_hops(hops, &mut temp)?;
            encode_fixed_data(TSP_NONCE, &nonce.0, &mut temp);
            checked_encode_variable_data(TSP_VID, &[], &mut temp)?;
        }
        Payload::DirectRelationAffirm { reply } => {
            temp.extend(&XRFA);
            encode_digest(reply, &mut temp);
        }
        Payload::NestedRelationProposal {
            message: data,
            nonce,
        } => {
            temp.extend(&XRNI);
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), &mut temp)?;
            encode_fixed_data(TSP_NONCE, &nonce.0, &mut temp);
        }
        Payload::NestedRelationAffirm {
            message: data,
            reply,
        } => {
            temp.extend(&XRNA);
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), &mut temp)?;
            encode_digest(reply, &mut temp);
        }
        Payload::NewIdentifierProposal {
            thread_id,
            sig_thread_id,
            new_vid,
        } => {
            if new_vid.as_ref().is_empty() {
                return Err(EncodeError::InvalidVid);
            }
            temp.extend(&XRFI);
            let no_hops: [&[u8]; 0] = [];
            encode_hops(&no_hops, &mut temp)?;
            encode_fixed_data(TSP_NONCE, &[0; 32], &mut temp); // this does not need to be a secure nonce
            checked_encode_variable_data(TSP_VID, new_vid.as_ref(), &mut temp)?;
            encode_digest(thread_id, &mut temp);
            encode_fixed_data(ED25519_SIGNATURE, sig_thread_id, &mut temp);
        }
        Payload::RelationshipReferral { referred_vid } => {
            temp.extend(&X3RR);
            checked_encode_variable_data(TSP_VID, referred_vid.as_ref(), &mut temp)?;
        }
        Payload::RelationshipCancel { reply } => {
            temp.extend(&XRFD);
            encode_digest(reply, &mut temp);
        }
    }

    encode_count(TSP_PAYLOAD, temp.len() / 3, output);
    output.extend(temp.iter());

    Ok(())
}

/// Encode a hops list
pub fn encode_hops(
    hops: &[impl AsRef<[u8]>],
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    encode_count(TSP_HOP_LIST, hops.len() as u16, output);
    for hop in hops {
        checked_encode_variable_data(TSP_VID, hop.as_ref(), output)?;
    }

    Ok(())
}

/// Decode a hops list
fn decode_hops<'a, Vid: TryFrom<&'a [u8]>>(
    stream: &'a mut [u8],
) -> Result<(Vec<Vid>, &'a mut [u8]), DecodeError> {
    let (hop_length, mut stream) =
        decode_count_mut(TSP_HOP_LIST, stream).ok_or(DecodeError::MissingHops)?;

    let mut hop_list = Vec::with_capacity(hop_length as usize);
    for _ in 0..hop_length {
        let hop: &[u8];
        (hop, stream) = decode_variable_data_mut(TSP_VID, stream).ok_or(DecodeError::VidError)?;

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
fn decode_digest(stream: &mut [u8]) -> Result<(Digest<'_>, &mut [u8]), DecodeError> {
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
pub fn decode_payload(mut stream: &mut [u8]) -> Result<DecodedPayload<'_>, DecodeError> {
    //NOTE: we do not need the quadlet count
    let _count;
    (_count, stream) = decode_count_mut(TSP_PAYLOAD, stream).ok_or(DecodeError::UnexpectedData)?;

    let sender_identity;
    (sender_identity, stream) = opt_decode_variable_data_mut(TSP_VID, stream);

    let (msgtype, mut stream) = stream
        .split_at_mut_checked(3)
        .ok_or(DecodeError::UnexpectedData)?;

    let payload = match *<&[u8; 3]>::try_from(msgtype as &[u8]).unwrap() {
        XSCS => {
            let msg;
            (msg, stream) = checked_decode_variable_data_mut(TSP_PLAINTEXT, stream)
                .ok_or(DecodeError::UnexpectedData)?;

            Payload::GenericMessage(msg)
        }
        XHOP => {
            let (hop_list, msg);
            (hop_list, stream) = decode_hops(stream)?;
            if hop_list.is_empty() {
                (msg, stream) = checked_decode_variable_data_mut(TSP_PLAINTEXT, stream)
                    .ok_or(DecodeError::UnexpectedData)?;

                Payload::NestedMessage(msg)
            } else {
                (msg, stream) = checked_decode_variable_data_mut(TSP_PLAINTEXT, stream)
                    .ok_or(DecodeError::UnexpectedData)?;

                Payload::RoutedMessage(hop_list, msg)
            }
        }
        XRFI => {
            let hop_list;
            (hop_list, stream) = decode_hops(stream)?;

            let nonce;
            (nonce, stream) =
                decode_fixed_data_mut(TSP_NONCE, stream).ok_or(DecodeError::UnexpectedData)?;

            let new_vid: &[u8];
            (new_vid, stream) =
                decode_variable_data_mut(TSP_VID, stream).ok_or(DecodeError::UnexpectedData)?;

            if new_vid.is_empty() {
                Payload::DirectRelationProposal {
                    nonce: Nonce(*nonce),
                    hops: hop_list,
                }
            } else {
                let (thread_id, sig_thread_id);
                (thread_id, stream) = decode_digest(stream)?;
                (sig_thread_id, stream) = decode_fixed_data_mut::<64>(ED25519_SIGNATURE, stream)
                    .ok_or(DecodeError::UnexpectedData)?;

                Payload::NewIdentifierProposal {
                    thread_id,
                    sig_thread_id,
                    new_vid,
                }
            }
        }
        XRFA => {
            let reply;
            (reply, stream) = decode_digest(stream)?;

            Payload::DirectRelationAffirm { reply }
        }
        XRNI => {
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
        XRNA => {
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
        X3RR => {
            let referred_vid: &[u8];
            (referred_vid, stream) =
                decode_variable_data_mut(TSP_VID, stream).ok_or(DecodeError::UnexpectedData)?;

            Payload::RelationshipReferral { referred_vid }
        }
        XRFD => {
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

const fn encoded_version() -> u16 {
    (TSP_VERSION.1 as u16) << 6 | (TSP_VERSION.2 as u16)
}

/// Encode a TSP version marker
pub fn encode_version(output: &mut impl for<'b> Extend<&'b u8>) {
    output.extend(&YTSP);
    encode_count(TSP_VERSION.0, encoded_version(), output);
}

fn decode_version(stream: &mut &[u8]) -> Result<(), DecodeError> {
    // See above: this is hopefully rare case of pseudo-CESR encoding
    let Some((hdr, new_stream)) = stream.split_at_checked(YTSP.len()) else {
        return Err(DecodeError::VersionMismatch);
    };

    if hdr != YTSP {
        return Err(DecodeError::VersionMismatch);
    }

    *stream = new_stream;

    let _version = decode_count(TSP_VERSION.0, stream).ok_or(DecodeError::VersionMismatch)?;

    // NOTE: can we simply ignore the minor and path parts of the version?

    Ok(())
}

/// Encode a encrypted TSP message plus Envelope into CESR
pub fn encode_ets_envelope<'a, Vid: AsRef<[u8]>>(
    envelope: Envelope<'a, Vid>,
    output: &mut impl for<'b> Extend<&'b u8>,
) -> Result<(), EncodeError> {
    let mut temp = Vec::new(); // temporary buffer to count the size
    encode_envelope_fields(envelope, &mut temp)?;

    encode_count(TSP_ETS_WRAPPER, temp.len() / 3, output);
    output.extend(temp.iter());
    Ok(())
}

/// Encode a encrypted TSP message plus Envelope into CESR
pub fn encode_s_envelope<'a, Vid: AsRef<[u8]>>(
    envelope: Envelope<'a, Vid>,
    output: &mut impl for<'b> Extend<&'b u8>,
) -> Result<(), EncodeError> {
    let mut temp = Vec::new(); // temporary buffer to count the size
    encode_envelope_fields(envelope, &mut temp)?;

    encode_count(TSP_S_WRAPPER, temp.len() / 3, output);
    output.extend(temp.iter());
    Ok(())
}

/// Encode the envelope fields; the only difference between ETS and S envelopes
/// is whether there is ciphertext between the header and signature, and this function
/// doesn't need to know that.
fn encode_envelope_fields<'a, Vid: AsRef<[u8]>>(
    envelope: Envelope<'a, Vid>,
    output: &mut impl for<'b> Extend<&'b u8>,
) -> Result<(), EncodeError> {
    encode_version(output);
    checked_encode_variable_data(TSP_VID, envelope.sender.as_ref(), output)?;

    if let Some(rec) = envelope.receiver {
        checked_encode_variable_data(TSP_VID, rec.as_ref(), output)?;
    }

    // FIXME: without this parsing errors seem to occur -- maybe there is am ambiguity
    encode_fixed_data(TSP_TMP, &[0u8, 0u8], output);

    if let Some(data) = envelope.nonconfidential_data {
        checked_encode_variable_data(TSP_PLAINTEXT, data, output)?;
    }

    Ok(())
}

enum EncodedSignature<'a> {
    NoSignature,
    Ed25519(&'a [u8; 64]),
    #[cfg(feature = "pq")]
    MlDsa65(&'a [u8; 3309]),
}

impl<'a> EncodedSignature<'a> {
    fn encode(&self, output: &mut impl for<'b> Extend<&'b u8>) {
        match self {
            EncodedSignature::NoSignature => {}
            EncodedSignature::Ed25519(signature) => {
                encode_count(
                    TSP_ATTACH_GRP,
                    signature.len().next_multiple_of(3) / 3,
                    output,
                );
                encode_count(
                    TSP_INDEX_SIG_GRP,
                    signature.len().next_multiple_of(3) / 3,
                    output,
                );
                encode_fixed_data(ED25519_SIGNATURE, signature.as_slice(), output);
            }
            #[cfg(feature = "pq")]
            EncodedSignature::MlDsa65(signature) => {
                encode_count(
                    TSP_ATTACH_GRP,
                    signature.len().next_multiple_of(3) / 3,
                    output,
                );
                encode_count(
                    TSP_INDEX_SIG_GRP,
                    signature.len().next_multiple_of(3) / 3,
                    output,
                );
                encode_fixed_data(ML_DSA_65_SIGNATURE, signature.as_slice(), output);
            }
        }
    }

    fn decode(stream: &mut &'a [u8]) -> Result<Self, DecodeError> {
        let a_size = decode_count(TSP_ATTACH_GRP, stream).ok_or(DecodeError::UnexpectedData)?;
        let i_size = decode_count(TSP_INDEX_SIG_GRP, stream).ok_or(DecodeError::UnexpectedData)?;
        if let Some(sig) = decode_fixed_data(ED25519_SIGNATURE, stream) {
            if a_size != (sig.len() as u32).next_multiple_of(3) / 3 {
                return Err(DecodeError::InvalidSignatureType);
            }
            if i_size != (sig.len() as u32).next_multiple_of(3) / 3 {
                return Err(DecodeError::InvalidSignatureType);
            }
            Ok(EncodedSignature::Ed25519(sig))
        } else {
            #[cfg(feature = "pq")]
            if let Some(sig) = decode_fixed_data(ML_DSA_65_SIGNATURE, stream) {
                if a_size != (sig.len() as u32).next_multiple_of(3) / 3 {
                    return Err(DecodeError::InvalidSignatureType);
                }
                if i_size != (sig.len() as u32).next_multiple_of(3) / 3 {
                    return Err(DecodeError::InvalidSignatureType);
                }
                Ok(EncodedSignature::MlDsa65(sig))
            } else {
                return Err(DecodeError::InvalidSignatureType);
            }
            #[cfg(not(feature = "pq"))]
            return Err(DecodeError::InvalidSignatureType);
        }
    }
}

/// Encode a Ed25519 or MlDsa signature into CESR
pub fn encode_signature(
    signature: &Signature,
    output: &mut impl for<'a> Extend<&'a u8>,
    sig_type: SignatureType,
) {
    match sig_type {
        SignatureType::NoSignature => EncodedSignature::NoSignature,
        SignatureType::Ed25519 => {
            EncodedSignature::Ed25519(signature.try_into().expect("signature has incorrect size"))
        }
        #[cfg(feature = "pq")]
        SignatureType::MlDsa65 => {
            EncodedSignature::MlDsa65(signature.try_into().expect("signature has incorrect size"))
        }
    }
    .encode(output)
}

impl CryptoType {
    fn cesr_code(&self) -> Result<u32, DecodeError> {
        Ok(match self {
            CryptoType::NaclEssr => TSP_NACL_CIPHERTEXT,
            CryptoType::HpkeEssr => TSP_HPKEBASE_CIPHERTEXT,
            CryptoType::HpkeAuth => TSP_HPKEAUTH_CIPHERTEXT,
            CryptoType::NaclAuth => TSP_NACLAUTH_CIPHERTEXT,
            #[cfg(feature = "pq")]
            CryptoType::X25519Kyber768Draft00 => TSP_HPKEPQ_CIPHERTEXT,
            _ => return Err(DecodeError::InvalidCrypto),
        })
    }
}

/// Encode a encrypted ciphertext into CESR
pub fn encode_ciphertext(
    ciphertext: &[u8],
    crypto: CryptoType,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    checked_encode_variable_data(crypto.cesr_code().unwrap(), ciphertext, output)
}

/// Checks whether the expected TSP header is present and returns its size and whether it
/// is a "ETS" or "S" envelope
#[allow(clippy::type_complexity)]
pub(super) fn detected_tsp_header_size_and_confidentiality(
    stream: &[u8],
    pos: &mut usize,
) -> Result<
    (
        Range<usize>,
        Option<Range<usize>>,
        CryptoType,
        SignatureType,
    ),
    DecodeError,
> {
    let origin = stream;
    let mut stream = &origin[*pos..];
    //NOTE: we don't need this quadlet count
    let encrypted = if let Some(_quadlet_count) = decode_count(TSP_ETS_WRAPPER, &mut stream) {
        true
    } else if let Some(_quadlet_count) = decode_count(TSP_S_WRAPPER, &mut stream) {
        false
    } else {
        return Err(DecodeError::VersionMismatch);
    };

    decode_version(&mut stream)?;
    let mut mid_pos = *pos + origin.len() - stream.len();

    let sender = decode_variable_data_index(TSP_VID, origin, &mut mid_pos)
        .ok_or(DecodeError::UnexpectedData)?;

    let receiver = decode_variable_data_index(TSP_VID, origin, &mut mid_pos);

    let mut stream = &origin[mid_pos..];

    if let Some([_crypto_type, _signature_type]) = decode_fixed_data(TSP_TMP, &mut stream) {}

    *pos += origin.len() - stream.len();

    /* look ahead to determine the crypto and signature types */
    let _nonconf_data = decode_variable_data(TSP_PLAINTEXT, &mut stream);

    let crypto_type = if decode_variable_data(TSP_HPKEAUTH_CIPHERTEXT, &mut stream).is_some() {
        CryptoType::HpkeAuth
    } else if decode_variable_data(TSP_HPKEBASE_CIPHERTEXT, &mut stream).is_some() {
        CryptoType::HpkeEssr
    } else if decode_variable_data(TSP_NACL_CIPHERTEXT, &mut stream).is_some() {
        CryptoType::NaclEssr
    } else if decode_variable_data(TSP_NACLAUTH_CIPHERTEXT, &mut stream).is_some() {
        CryptoType::NaclAuth
    } else {
        #[cfg(feature = "pq")]
        if decode_variable_data(TSP_HPKEPQ_CIPHERTEXT, &mut stream).is_some() {
            CryptoType::X25519Kyber768Draft00
        } else if encrypted {
            return Err(DecodeError::UnknownCrypto);
        } else {
            CryptoType::Plaintext
        }
        #[cfg(not(feature = "pq"))]
        if encrypted {
            return Err(DecodeError::UnknownCrypto);
        } else {
            CryptoType::Plaintext
        }
    };

    if encrypted != crypto_type.is_encrypted() {
        return Err(DecodeError::InvalidCrypto);
    }

    let signature_type = match EncodedSignature::decode(&mut stream) {
        Ok(EncodedSignature::Ed25519(_)) => SignatureType::Ed25519,
        #[cfg(feature = "pq")]
        Ok(EncodedSignature::MlDsa65(_)) => SignatureType::MlDsa65,
        _ => SignatureType::NoSignature,
    };

    Ok((sender, receiver, crypto_type, signature_type))
}

/// A structure representing a signature + data that needs to be verified.
/// The `signature` must authenticate the `signed_data`.
#[derive(Clone, Debug)]
#[must_use]
pub struct VerificationChallenge<'a> {
    pub signed_data: &'a [u8],
    pub signature: &'a Signature,
}

/// Decode the type, sender and receiver of an encrypted TSP message
pub fn decode_sender_receiver<'a, Vid: TryFrom<&'a [u8]>>(
    stream: &'a [u8],
) -> Result<(Vid, Option<Vid>, CryptoType, SignatureType), DecodeError> {
    let mut pos = 0;
    let (sender, receiver, crypto_type, signature_type) =
        detected_tsp_header_size_and_confidentiality(stream, &mut pos)?;

    let sender = stream[sender]
        .try_into()
        .map_err(|_| DecodeError::VidError)?;

    let receiver = receiver
        .map(|r| stream[r].try_into().map_err(|_| DecodeError::VidError))
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
    pub fn as_challenge(&self) -> VerificationChallenge<'_> {
        VerificationChallenge {
            signed_data: &self.data[self.signed_data.clone()],
            signature: self.signature,
        }
    }

    pub(crate) fn signature_type(&self) -> SignatureType {
        self.signature_type
    }
}

/// Decode an encrypted TSP message plus Envelope & Signature
/// Produces the ciphertext as a mutable stream.
pub fn decode_envelope<'a>(stream: &'a mut [u8]) -> Result<CipherView<'a>, DecodeError> {
    let mut pos = 0;
    let (sender, receiver, crypto_type, signature_type) =
        detected_tsp_header_size_and_confidentiality(stream, &mut pos)?;

    let nonconfidential_data = decode_variable_data_index(TSP_PLAINTEXT, stream, &mut pos);

    let associated_data = 0..pos;

    let ciphertext = if crypto_type.is_encrypted() {
        Some(
            checked_decode_variable_data_index(crypto_type.cesr_code()?, stream, &mut pos)
                .ok_or(DecodeError::UnexpectedData)?,
        )
    } else {
        None
    };

    let signed_data = 0..pos;

    let data: &'a mut [u8];
    let mut sigdata: &[u8];
    (data, sigdata) = stream.split_at_mut(signed_data.end);

    //FIXME: just decode it fully with EncodedSignature
    let signature = match signature_type {
        SignatureType::NoSignature => [].as_slice(),
        _ => match EncodedSignature::decode(&mut sigdata)? {
            EncodedSignature::Ed25519(sig) => sig.as_slice(),
            #[cfg(feature = "pq")]
            EncodedSignature::MlDsa65(sig) => sig.as_slice(),
            _ => [].as_slice(),
        },
    };

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
        checked_decode_variable_data_index(identifier, data, pos).map(|range| Part {
            prefix: &data[begin_pos..range.start],
            data: &data[range.start..range.end],
        })
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
pub fn open_message_into_parts(data: &[u8]) -> Result<MessageParts<'_>, DecodeError> {
    let fix_start = |r: Range<usize>| {
        let start = if r.start.is_multiple_of(3) {
            r.start
        } else {
            (r.start).next_multiple_of(3) - 3
        };
        start..r.end
    };

    let mut pos = 0;
    let (sender, receiver, crypto_type, signature_type) =
        detected_tsp_header_size_and_confidentiality(data, &mut pos)?;

    let prefix = Part {
        prefix: &data[..9],
        data: &[],
    };

    let sender_prefix_len = if sender.len() > 3 * 0xFFFFFF { 6 } else { 3 };
    let sender = fix_start(sender);
    let sender = Part {
        prefix: &data[sender.start - sender_prefix_len..sender.start],
        data: &data[sender],
    };

    let receiver = receiver.map(|r| {
        let receiver_prefix_len = if r.len() > 3 * 0xFFFFFF { 6 } else { 3 };
        let r = fix_start(r);
        Part {
            prefix: &data[r.start - receiver_prefix_len..r.start],
            data: &data[r.start..r.end],
        }
    });

    let nonconfidential_data = Part::decode(TSP_PLAINTEXT, data, &mut pos);

    let cipher_code = crypto_type.cesr_code()?;
    let ciphertext = Part::decode(cipher_code, data, &mut pos);

    let signature = match EncodedSignature::decode(&mut &data[pos..])? {
        EncodedSignature::NoSignature => &[],
        EncodedSignature::Ed25519(sig) => sig.as_slice(),
        #[cfg(feature = "pq")]
        EncodedSignature::MlDsa65(sig) => sig.as_slice(),
    };

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
    encode_signature(&sign(sender, &cesr), &mut cesr, SignatureType::Ed25519);

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
        encode_ciphertext(ciphertext, CryptoType::HpkeAuth, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

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
        encode_ciphertext(ciphertext, CryptoType::HpkeAuth, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

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
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

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
        encode_ciphertext(ciphertext, CryptoType::HpkeAuth, &mut outer).unwrap();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

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
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);
        encode_ciphertext(&[], CryptoType::HpkeAuth, &mut outer).unwrap();

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
        encode_ciphertext(&[], CryptoType::HpkeAuth, &mut outer).unwrap();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);
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
            sig_thread_id: &[5; 64],
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
        encode_ciphertext(ciphertext, CryptoType::HpkeAuth, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

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

    #[ignore]
    #[test]
    #[wasm_bindgen_test]
    fn test_message_to_parts() {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let message = Base64UrlUnpadded::decode_vec("-EABYTSP-AABXAAAXAEB6VAEZGlkOnRlc3Q6Ym9i8VIDAAAFAGRpZDp0ZXN0OmFsaWNl6BAEAABleHRyYSBkYXRh4CAXScvzIiBCgfOu9jHtGwd1qN-KlMB7uhFbE9YOSyTmnp9yziA1LVPdQmST27yjuDRTlxeRo7H7gfuaGFY4iyf2EsfiqvEg0BBNDbKoW0DDczGxj7rNWKH_suyj18HCUxMZ6-mDymZdNhHZIS8zIstC9Kxv5Q-GxmI-1v4SNbeCemuCMBzMPogK").unwrap();
        let parts = open_message_into_parts(&message).unwrap();

        assert_eq!(parts.prefix.prefix.len(), 15);
        assert_eq!(parts.sender.data.len(), 10);
        assert_eq!(parts.receiver.unwrap().data.len(), 14);
        assert_eq!(parts.ciphertext.unwrap().data.len(), 69);
    }

    #[test]
    fn test_decode_send_recv() {
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
        encode_ciphertext(ciphertext, CryptoType::HpkeAuth, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

        let outer2 = outer.clone();
        let view = decode_envelope(&mut outer).unwrap();
        let ver = view.as_challenge();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        let DecodedEnvelope { envelope: env, .. } = view.into_opened().unwrap();
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));
        assert_eq!(env.nonconfidential_data, None);

        let (sender, receiver, _, _) = decode_sender_receiver(&outer2).unwrap();
        assert_eq!(env.sender, sender);
        assert_eq!(env.receiver, receiver);
    }
}
