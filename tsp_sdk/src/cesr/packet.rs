use super::consts::{cesr, cesr_data};

/// The TSP version supported by this spec
const TSP_VERSION: (u16, u8, u8) = (0, 0, 1);

/// The CESR code table this implementation follows: genus `AAA`, version 2.00,
/// identified by the genus/version code `-_AAACAA` (not emitted per message).
#[allow(dead_code)]
pub const TSP_CESR_GENUS: ([u8; 3], (u8, u8, u8)) = (cesr_data("AAA"), (2, 0, 0));

/// Constants that determine the specific CESR types for "variable length data"
const TSP_PLAINTEXT: u32 = cesr!("B");
const TSP_SEALEDBOX_CIPHERTEXT: u32 = cesr!("C");
const TSP_HPKEBASE_CIPHERTEXT: u32 = cesr!("F");
const TSP_VID: u32 = cesr!("B");

/// Constants that determine the specific CESR types for "fixed length data"
/// The Ed25519 signature is an indexed primitive `B#` (index = position of the
/// signing key in the VID's key list); ML-DSA-65 uses the fixed code `1AAQ`.
const ED25519_SIGNATURE: u32 = cesr!("B");
const ML_DSA_65_SIGNATURE: u32 = cesr!("AAQ");
#[allow(clippy::eq_op)]
const TSP_NONCE: u32 = cesr!("A");
const TSP_SHA256: u32 = cesr!("I");
const TSP_BLAKE2B256: u32 = cesr!("F");

/// Constants that determine the specific CESR types for the framing codes
const TSP_WRAPPER: u16 = cesr!("E");
const TSP_HOP_LIST: u16 = cesr!("J");
const TSP_PAYLOAD: u16 = cesr!("Z");
const TSP_ATTACH_GRP: u16 = cesr!("C");
const TSP_INDEX_SIG_GRP: u16 = cesr!("K");
const TSP_GENERIC_STREAM: u16 = cesr!("A");

/// Constants for payload field types
const XCTL: [u8; 3] = cesr_data("XCTL");
const XSCS: [u8; 3] = cesr_data("XSCS");
const XHOP: [u8; 3] = cesr_data("XHOP");
const XPAD: [u8; 3] = cesr_data("XPAD");
const XRFI: [u8; 3] = cesr_data("XRFI");
const XRFA: [u8; 3] = cesr_data("XRFA");
const XRFD: [u8; 3] = cesr_data("XRFD");
const YTSP: [u8; 3] = cesr_data("YTSP");

use super::{
    decode::{
        decode_count, decode_count_mut, decode_fixed_data, decode_fixed_data_mut,
        decode_indexed_data, decode_variable_data, decode_variable_data_index,
        decode_variable_data_mut,
    },
    encode::{encode_count, encode_fixed_data},
    error::{DecodeError, EncodeError},
};
use std::fmt::Debug;

/// A 128-bit nonce, encoded on the wire with the CESR code `0A`.
/// This explicitly does not implement Clone or Copy to make sure nonces are not reused
#[derive(Debug)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(PartialEq, Eq, Clone))]
pub struct Nonce(pub(crate) [u8; 16]);

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
    pub fn generate(g: impl FnOnce(&mut [u8; 16])) -> Nonce {
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
    /// An upper-layer control-plane message (`XCTL`); same shape as a generic message
    ControlMessage(Bytes),
    /// A padding message (`XPAD`), carrying no information; receivers discard it
    Padding { nonce: Nonce },
    /// A payload that consists of a TSP Envelope+Message
    NestedMessage(Bytes),
    /// A routed payload; same as above but with routing information attached
    RoutedMessage(Vec<Vid>, Bytes),
    /// A TSP message requesting a relationship
    DirectRelationProposal {
        nonce: Nonce,
        request_digest: Digest<'a>,
    },
    /// A TSP message confirming a relationship
    DirectRelationAffirm {
        request_digest: Digest<'a>,
        reply_digest: Digest<'a>,
    },
    /// A TSP message requesting a secondary relationship alongside an existing one.
    ParallelRelationProposal {
        nonce: Nonce,
        request_digest: Digest<'a>,
        sig_new_vid: &'a Signature,
        new_vid: Vid,
    },
    /// A TSP message accepting a secondary relationship request.
    ParallelRelationAffirm {
        request_digest: Digest<'a>,
        reply_digest: Digest<'a>,
        sig_new_vid: &'a Signature,
        new_vid: Vid,
    },
    /// A TSP cancellation message, naming the relationship it ends
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
        let _ignore = encode_payload(self, sender_identity, None, &mut count);

        count.0
    }
}

// helpers for generating and comparing arbitrary `Payload`s
#[cfg(feature = "fuzzing")]
pub mod fuzzing;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[repr(u8)]
pub enum CryptoType {
    Plaintext = 0,
    /// HPKE-Base; the KEM (X25519 or X25519MLKEM768) is selected by the
    /// recipient VID's encryption key type, with no separate code point
    HpkeBase = 1,
    /// The libsodium anonymous sealed box
    SealedBox = 2,
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
pub struct Envelope<Vid> {
    pub crypto_type: CryptoType,
    pub signature_type: SignatureType,
    pub sender: Vid,
    pub receiver: Option<Vid>,
}

pub struct DecodedEnvelope<'a, Vid, Bytes> {
    pub envelope: Envelope<Vid>,
    pub raw_header: &'a [u8], // for associated data purposes
    /// The payload position: the ciphertext of a confidential message, or the
    /// cleartext `-Z##` payload of a non-confidential (signed-only) message
    pub payload_position: Option<Bytes>,
}

type Signature = [u8];

fn encoded_signature_from_raw<'a>(
    signature: &'a Signature,
) -> Result<EncodedSignature<'a>, EncodeError> {
    if let Ok(signature) = <&[u8; 64]>::try_from(signature) {
        return Ok(EncodedSignature::Ed25519(signature));
    }

    if let Ok(signature) = <&[u8; 3309]>::try_from(signature) {
        return Ok(EncodedSignature::MlDsa65(signature));
    }

    Err(EncodeError::InvalidSignatureType)
}

fn encode_embedded_signature(
    signature: &Signature,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    encoded_signature_from_raw(signature)?.encode(output);
    Ok(())
}

fn decoded_signature_from_stream(
    stream: &mut [u8],
) -> Result<(&Signature, &mut [u8]), DecodeError> {
    let mut immutable_stream: &[u8] = stream;
    let original_len = immutable_stream.len();
    let (signature, rest) = EncodedSignature::decode_with_rest(&mut immutable_stream)?;
    let signature_len = match signature {
        EncodedSignature::NoSignature => return Err(DecodeError::InvalidSignatureType),
        EncodedSignature::Ed25519(signature) => signature.len(),
        EncodedSignature::MlDsa65(signature) => signature.len(),
    };

    // an embedded signature field holds exactly one signature
    if rest != 0 {
        return Err(DecodeError::InvalidSignatureType);
    }

    let consumed = original_len - immutable_stream.len();
    let (prefix, remaining) = stream.split_at_mut(consumed);
    let signature = &prefix[prefix.len() - signature_len..];

    Ok((signature, remaining))
}

/// The signable fields of a parallel (referral) relationship request:
/// {XRFI, VID_sndr, Digest, Nonce, VID_new}, in the unified field order.
pub(crate) fn encode_parallel_relation_proposal_challenge(
    sender_identity: Option<&[u8]>,
    nonce: &Nonce,
    request_digest: Digest<'_>,
    new_vid: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    let mut temp = Vec::new();
    temp.extend(&XRFI);
    checked_encode_variable_data(TSP_VID, sender_identity.unwrap_or(&[]), &mut temp)?;
    encode_digest(&request_digest, &mut temp);
    encode_fixed_data(TSP_NONCE, &nonce.0, &mut temp);
    checked_encode_variable_data(TSP_VID, new_vid, &mut temp)?;
    Ok(temp)
}

/// The signable fields of a parallel (referral) relationship accept:
/// {XRFA, VID_sndr, Digest, Reply_Digest, VID_new}, in the unified field order.
pub(crate) fn encode_parallel_relation_affirm_challenge(
    sender_identity: Option<&[u8]>,
    request_digest: Digest<'_>,
    reply_digest: Digest<'_>,
    new_vid: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    let mut temp = Vec::new();
    temp.extend(&XRFA);
    checked_encode_variable_data(TSP_VID, sender_identity.unwrap_or(&[]), &mut temp)?;
    encode_digest(&request_digest, &mut temp);
    encode_digest(&reply_digest, &mut temp);
    checked_encode_variable_data(TSP_VID, new_vid, &mut temp)?;
    Ok(temp)
}

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

/// Safely decode variable data, refusing fields beyond the receive-side size limit.
/// The limit matches the send-side limit in [checked_encode_variable_data]; a receiver
/// should not accept a field larger than anything a conformant sender can produce.
fn checked_decode_variable_data_index(
    identifier: u32,
    stream: &[u8],
    pos: &mut usize,
) -> Option<std::ops::Range<usize>> {
    const DATA_LIMIT: usize = 3 * (1 << 24);

    decode_variable_data_index(identifier, stream, pos).filter(|range| range.len() < DATA_LIMIT)
}

/// Encode the padding field that terminates every payload layout. The pad's
/// content is caller-chosen and carries no information (the receiver discards
/// it); when the caller supplies none, the empty pad `4BAA` is emitted.
fn encode_padding(
    padding: Option<&[u8]>,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    checked_encode_variable_data(TSP_PLAINTEXT, padding.unwrap_or(&[]), output)
}

/// Encode the sender VID payload field (a NULL VID `4BAA` when absent)
fn encode_sender_identity(
    sender_identity: Option<&[u8]>,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    checked_encode_variable_data(TSP_VID, sender_identity.unwrap_or(&[]), output)
}

/// Encode opaque upper-layer data as a `-A##` generic CESR stream holding a bare
/// Bytes primitive, which is native CESR. The `-A##` stream frame is always
/// present; its contents are the upper layer's. A caller that interleaves
/// non-native serializations (JSON, CBOR, MsgPak) encloses each in a `-H##`
/// group inside the stream; TSP carries the stream contents opaquely.
fn encode_opaque_data(
    data: &[u8],
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    let mut primitive = Vec::with_capacity(data.len() + 8);
    checked_encode_variable_data(TSP_PLAINTEXT, data, &mut primitive)?;

    encode_count(TSP_GENERIC_STREAM, primitive.len() / 3, output);
    output.extend(primitive.iter());
    Ok(())
}

/// Encode a TSP Payload into CESR for encryption.
///
/// All layouts follow the unified field order of the spec (section 9.4):
/// the payload type code first, then the sender VID field, the type-specific
/// fields, and a (currently empty) padding field last.
pub fn encode_payload(
    payload: &Payload<impl AsRef<[u8]>, impl AsRef<[u8]>>,
    sender_identity: Option<&[u8]>,
    padding: Option<&[u8]>,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    let mut temp = Vec::new(); // temporary buffer to count the size

    match payload {
        Payload::GenericMessage(data) => {
            temp.extend(&XSCS);
            encode_sender_identity(sender_identity, &mut temp)?;
            encode_padding(padding, &mut temp)?;
            encode_opaque_data(data.as_ref(), &mut temp)?;
        }
        Payload::ControlMessage(data) => {
            temp.extend(&XCTL);
            encode_sender_identity(sender_identity, &mut temp)?;
            encode_padding(padding, &mut temp)?;
            encode_opaque_data(data.as_ref(), &mut temp)?;
        }
        Payload::Padding { nonce } => {
            temp.extend(&XPAD);
            encode_sender_identity(sender_identity, &mut temp)?;
            encode_fixed_data(TSP_NONCE, &nonce.0, &mut temp);
            encode_padding(padding, &mut temp)?;
        }
        Payload::NestedMessage(data) => {
            if !data.as_ref().len().is_multiple_of(3) {
                return Err(EncodeError::MisalignedNestedMessage);
            }
            temp.extend(&XHOP);
            encode_sender_identity(sender_identity, &mut temp)?;
            let no_hops: [&[u8]; 0] = [];
            encode_hops(&no_hops, &mut temp)?;
            encode_padding(padding, &mut temp)?;
            // the nested message is a complete TSP message; it is self-framing
            temp.extend(data.as_ref());
        }
        Payload::RoutedMessage(hops, data) => {
            if !data.as_ref().len().is_multiple_of(3) {
                return Err(EncodeError::MisalignedNestedMessage);
            }
            temp.extend(&XHOP);
            encode_sender_identity(sender_identity, &mut temp)?;
            if hops.is_empty() {
                return Err(EncodeError::MissingHops);
            }
            encode_hops(hops, &mut temp)?;
            encode_padding(padding, &mut temp)?;
            temp.extend(data.as_ref());
        }
        Payload::DirectRelationProposal {
            nonce,
            request_digest,
        } => {
            temp.extend(&XRFI);
            encode_sender_identity(sender_identity, &mut temp)?;
            encode_digest(request_digest, &mut temp);
            encode_fixed_data(TSP_NONCE, &nonce.0, &mut temp);
            checked_encode_variable_data(TSP_VID, &[], &mut temp)?; // NULL new-VID field
            encode_padding(padding, &mut temp)?;
        }
        Payload::DirectRelationAffirm {
            request_digest,
            reply_digest,
        } => {
            temp.extend(&XRFA);
            encode_sender_identity(sender_identity, &mut temp)?;
            encode_digest(request_digest, &mut temp);
            encode_digest(reply_digest, &mut temp);
            encode_padding(padding, &mut temp)?;
        }
        Payload::ParallelRelationProposal {
            nonce,
            request_digest,
            sig_new_vid,
            new_vid,
        } => {
            if new_vid.as_ref().is_empty() {
                return Err(EncodeError::InvalidVid);
            }
            temp.extend(&XRFI);
            encode_sender_identity(sender_identity, &mut temp)?;
            encode_digest(request_digest, &mut temp);
            encode_fixed_data(TSP_NONCE, &nonce.0, &mut temp);
            checked_encode_variable_data(TSP_VID, new_vid.as_ref(), &mut temp)?;
            encode_embedded_signature(sig_new_vid, &mut temp)?;
            encode_padding(padding, &mut temp)?;
        }
        Payload::ParallelRelationAffirm {
            request_digest,
            reply_digest,
            sig_new_vid,
            new_vid,
        } => {
            if new_vid.as_ref().is_empty() {
                return Err(EncodeError::InvalidVid);
            }
            temp.extend(&XRFA);
            encode_sender_identity(sender_identity, &mut temp)?;
            encode_digest(request_digest, &mut temp);
            encode_digest(reply_digest, &mut temp);
            checked_encode_variable_data(TSP_VID, new_vid.as_ref(), &mut temp)?;
            encode_embedded_signature(sig_new_vid, &mut temp)?;
            encode_padding(padding, &mut temp)?;
        }
        Payload::RelationshipCancel { reply } => {
            temp.extend(&XRFD);
            encode_sender_identity(sender_identity, &mut temp)?;
            encode_digest(reply, &mut temp);
            encode_padding(padding, &mut temp)?;
        }
    }

    encode_count(TSP_PAYLOAD, temp.len() / 3, output);
    output.extend(temp.iter());

    Ok(())
}

/// Encode a hops list; the count is the length in quadlets/triplets of the
/// concatenated VID encodings, not the number of VIDs
pub fn encode_hops(
    hops: &[impl AsRef<[u8]>],
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    let mut temp = Vec::new();
    for hop in hops {
        checked_encode_variable_data(TSP_VID, hop.as_ref(), &mut temp)?;
    }

    encode_count(TSP_HOP_LIST, temp.len() / 3, output);
    output.extend(temp.iter());

    Ok(())
}

/// Decode a hops list; the count delimits the byte length of the list
fn decode_hops<'a, Vid: TryFrom<&'a [u8]>>(
    stream: &'a mut [u8],
) -> Result<(Vec<Vid>, &'a mut [u8]), DecodeError> {
    let (hop_length, stream) =
        decode_count_mut(TSP_HOP_LIST, stream).ok_or(DecodeError::MissingHops)?;

    let hop_bytes = (hop_length as usize)
        .checked_mul(3)
        .ok_or(DecodeError::UnexpectedData)?;
    if hop_bytes > stream.len() {
        return Err(DecodeError::UnexpectedData);
    }
    let (mut hop_stream, stream) = stream.split_at_mut(hop_bytes);

    let mut hop_list = Vec::new();
    while !hop_stream.is_empty() {
        let hop: &[u8];
        (hop, hop_stream) =
            decode_variable_data_mut(TSP_VID, hop_stream).ok_or(DecodeError::VidError)?;

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

/// Decode the trailing padding field of a payload; its contents are discarded
fn decode_padding(stream: &mut [u8]) -> Result<&mut [u8], DecodeError> {
    let (_pad, stream) =
        decode_variable_data_mut(TSP_PLAINTEXT, stream).ok_or(DecodeError::UnexpectedData)?;
    Ok(stream)
}

/// Decode the sender VID payload field; a NULL VID (`4BAA`) means absent
fn decode_sender_identity(stream: &mut [u8]) -> Result<(Option<&[u8]>, &mut [u8]), DecodeError> {
    let (vid, stream) =
        decode_variable_data_mut(TSP_VID, stream).ok_or(DecodeError::UnexpectedData)?;
    let vid = if vid.is_empty() {
        None
    } else {
        Some(vid as &[u8])
    };
    Ok((vid, stream))
}

/// Decode opaque upper-layer data (see [encode_opaque_data])
fn decode_opaque_data(stream: &mut [u8]) -> Result<(&mut [u8], &mut [u8]), DecodeError> {
    let (stream_quadlets, stream) =
        decode_count_mut(TSP_GENERIC_STREAM, stream).ok_or(DecodeError::UnexpectedData)?;
    let stream_bytes = (stream_quadlets as usize)
        .checked_mul(3)
        .ok_or(DecodeError::InvalidFrameCount)?;
    if stream_bytes != stream.len() {
        return Err(DecodeError::InvalidFrameCount);
    }

    let (data, rest) =
        decode_variable_data_mut(TSP_PLAINTEXT, stream).ok_or(DecodeError::UnexpectedData)?;
    if !rest.is_empty() {
        return Err(DecodeError::UnexpectedData);
    }
    Ok((data, rest))
}

/// Decode a TSP Payload
pub fn decode_payload(stream: &mut [u8]) -> Result<DecodedPayload<'_>, DecodeError> {
    let (count, stream) =
        decode_count_mut(TSP_PAYLOAD, stream).ok_or(DecodeError::UnexpectedData)?;

    // the count delimits the payload; validate it against the stream
    let payload_bytes = (count as usize)
        .checked_mul(3)
        .ok_or(DecodeError::UnexpectedData)?;
    if payload_bytes != stream.len() {
        return Err(DecodeError::UnexpectedData);
    }

    let (msgtype, stream) = stream
        .split_at_mut_checked(3)
        .ok_or(DecodeError::UnexpectedData)?;

    let (sender_identity, mut stream) = decode_sender_identity(stream)?;

    let payload = match *<&[u8; 3]>::try_from(msgtype as &[u8]).unwrap() {
        XSCS => {
            let msg;
            stream = decode_padding(stream)?;
            (msg, stream) = decode_opaque_data(stream)?;

            Payload::GenericMessage(msg)
        }
        XCTL => {
            let msg;
            stream = decode_padding(stream)?;
            (msg, stream) = decode_opaque_data(stream)?;

            Payload::ControlMessage(msg)
        }
        XPAD => {
            let nonce;
            (nonce, stream) =
                decode_fixed_data_mut(TSP_NONCE, stream).ok_or(DecodeError::UnexpectedData)?;
            let nonce = Nonce(*nonce);
            stream = decode_padding(stream)?;

            Payload::Padding { nonce }
        }
        XHOP => {
            let hop_list;
            (hop_list, stream) = decode_hops(stream)?;
            stream = decode_padding(stream)?;

            // the rest of the payload is the nested message, which is self-framing
            let msg = std::mem::take(&mut stream);

            if hop_list.is_empty() {
                Payload::NestedMessage(msg)
            } else {
                Payload::RoutedMessage(hop_list, msg)
            }
        }
        XRFI => {
            let request_digest;
            (request_digest, stream) = decode_digest(stream)?;

            let nonce;
            (nonce, stream) =
                decode_fixed_data_mut(TSP_NONCE, stream).ok_or(DecodeError::UnexpectedData)?;

            let new_vid: &[u8];
            (new_vid, stream) =
                decode_variable_data_mut(TSP_VID, stream).ok_or(DecodeError::UnexpectedData)?;

            if new_vid.is_empty() {
                stream = decode_padding(stream)?;
                Payload::DirectRelationProposal {
                    nonce: Nonce(*nonce),
                    request_digest,
                }
            } else {
                let sig_new_vid;
                (sig_new_vid, stream) = decoded_signature_from_stream(stream)?;
                stream = decode_padding(stream)?;

                Payload::ParallelRelationProposal {
                    nonce: Nonce(*nonce),
                    request_digest,
                    sig_new_vid,
                    new_vid,
                }
            }
        }
        XRFA => {
            let request_digest;
            (request_digest, stream) = decode_digest(stream)?;

            let reply_digest;
            (reply_digest, stream) = decode_digest(stream)?;

            // the next field is either the padding (direct form, ending the payload)
            // or the new VID of the parallel (referral) form, followed by a signature
            let vid_or_pad_mut;
            (vid_or_pad_mut, stream) =
                decode_variable_data_mut(TSP_VID, stream).ok_or(DecodeError::UnexpectedData)?;
            let vid_or_pad: &[u8] = vid_or_pad_mut;

            if stream.is_empty() {
                Payload::DirectRelationAffirm {
                    request_digest,
                    reply_digest,
                }
            } else {
                let new_vid = vid_or_pad;
                if new_vid.is_empty() {
                    return Err(DecodeError::UnexpectedData);
                }
                let sig_new_vid;
                (sig_new_vid, stream) = decoded_signature_from_stream(stream)?;
                stream = decode_padding(stream)?;

                Payload::ParallelRelationAffirm {
                    request_digest,
                    reply_digest,
                    sig_new_vid,
                    new_vid,
                }
            }
        }
        XRFD => {
            let reply;
            (reply, stream) = decode_digest(stream)?;
            stream = decode_padding(stream)?;

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
        return Err(DecodeError::NotTsp);
    };

    if hdr != YTSP {
        return Err(DecodeError::NotTsp);
    }

    *stream = new_stream;

    // the count identifier is the MAJOR version: a different MAJOR fails to decode,
    // and per semver a message with a different MAJOR cannot be assumed processable.
    // The count value carries MINOR and PATCH, which do not affect processability.
    let _minor_patch = decode_count(TSP_VERSION.0, stream).ok_or(DecodeError::VersionMismatch)?;

    Ok(())
}

/// Encode the envelope fields of a TSP message: the version, sender VID,
/// receiver VID (the NULL VID `4BAA` when absent) and optional non-confidential data.
///
/// The `-E##` frame is prepended later by [finalize_envelope_frame], after the
/// ciphertext (if any) has been appended, since its count covers both.
pub fn encode_envelope<Vid: AsRef<[u8]>>(
    envelope: Envelope<Vid>,
    output: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    encode_envelope_prefix(
        envelope.sender.as_ref(),
        envelope.receiver.as_ref().map(AsRef::as_ref),
        output,
    )
}

/// Encode the envelope prefix: the version, sender VID and receiver VID
/// (the NULL VID `4BAA` when absent). These bytes are the HPKE associated
/// data and the leading input of the TSP digest (spec 7.2.1, 8.2.2).
pub fn encode_envelope_prefix(
    sender: &[u8],
    receiver: Option<&[u8]>,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    encode_version(output);

    if sender.is_empty() {
        return Err(EncodeError::InvalidVid);
    }
    checked_encode_variable_data(TSP_VID, sender, output)?;

    checked_encode_variable_data(TSP_VID, receiver.unwrap_or(&[]), output)?;

    Ok(())
}

/// The dummy filling the digest's own slot during SAID derivation (spec 7.2.1):
/// 0x23 over the full encoded length of the digest primitive (code + 32 bytes)
const DIGEST_DUMMY: [u8; 33] = [0x23; 33];

/// Encode the input of the self-referencing TSP digest (spec 7.2.1) for a
/// relationship-forming payload: the envelope prefix (version and VIDs)
/// followed by the payload fields, with the digest's own slot (the Digest of
/// an invite, the Reply_Digest of an accept) filled with the 0x23 dummy.
/// The -E## and -Z## framing tags, the padding field, and the new-VID
/// signature field (which is produced after the digest) are excluded.
pub fn encode_digest_input(
    payload: &Payload<impl AsRef<[u8]>, impl AsRef<[u8]>>,
    sender_identity: Option<&[u8]>,
    envelope_prefix: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    output.extend(envelope_prefix);

    match payload {
        Payload::DirectRelationProposal { nonce, .. } => {
            output.extend(&XRFI);
            encode_sender_identity(sender_identity, output)?;
            output.extend(&DIGEST_DUMMY);
            encode_fixed_data(TSP_NONCE, &nonce.0, output);
            checked_encode_variable_data(TSP_VID, &[], output)?;
        }
        Payload::ParallelRelationProposal { nonce, new_vid, .. } => {
            output.extend(&XRFI);
            encode_sender_identity(sender_identity, output)?;
            output.extend(&DIGEST_DUMMY);
            encode_fixed_data(TSP_NONCE, &nonce.0, output);
            checked_encode_variable_data(TSP_VID, new_vid.as_ref(), output)?;
        }
        Payload::DirectRelationAffirm { request_digest, .. } => {
            output.extend(&XRFA);
            encode_sender_identity(sender_identity, output)?;
            encode_digest(request_digest, output);
            output.extend(&DIGEST_DUMMY);
        }
        Payload::ParallelRelationAffirm {
            request_digest,
            new_vid,
            ..
        } => {
            output.extend(&XRFA);
            encode_sender_identity(sender_identity, output)?;
            encode_digest(request_digest, output);
            output.extend(&DIGEST_DUMMY);
            checked_encode_variable_data(TSP_VID, new_vid.as_ref(), output)?;
        }
        _ => return Err(EncodeError::NoDigestSlot),
    }

    Ok(())
}

/// Prepend the `-E##`/`-0E#####` frame to the signable content built so far
/// (envelope fields plus ciphertext, if any). The count covers everything after
/// the frame code up to, but excluding, the signature attachment.
pub fn finalize_envelope_frame(data: &mut Vec<u8>) {
    let mut frame = Vec::with_capacity(6);
    encode_count(TSP_WRAPPER, data.len() / 3, &mut frame);
    data.splice(0..0, frame);
}

enum EncodedSignature<'a> {
    NoSignature,
    Ed25519(&'a [u8; 64]),
    MlDsa65(&'a [u8; 3309]),
}

impl<'a> EncodedSignature<'a> {
    fn encode(&self, output: &mut impl for<'b> Extend<&'b u8>) {
        // the group counts are lengths in quadlets/triplets: the indexed signature
        // group covers the signature primitive(s); the attachment group additionally
        // covers the indexed signature group's own code (one quadlet)
        match self {
            EncodedSignature::NoSignature => {}
            EncodedSignature::Ed25519(signature) => {
                let primitive_quadlets = (signature.len() + 2).div_ceil(3);
                encode_count(TSP_ATTACH_GRP, primitive_quadlets + 1, output);
                encode_count(TSP_INDEX_SIG_GRP, primitive_quadlets, output);
                // this implementation signs with a single key, so the index is 0
                super::encode::encode_indexed_data(
                    ED25519_SIGNATURE,
                    0,
                    signature.as_slice(),
                    output,
                );
            }
            EncodedSignature::MlDsa65(signature) => {
                let primitive_quadlets = (signature.len() + 3).div_ceil(3);
                encode_count(TSP_ATTACH_GRP, primitive_quadlets + 1, output);
                encode_count(TSP_INDEX_SIG_GRP, primitive_quadlets, output);
                encode_fixed_data(ML_DSA_65_SIGNATURE, signature.as_slice(), output);
            }
        }
    }

    /// Decode a signature attachment. Returns the first signature and the number of
    /// bytes remaining in the attachment group after it (additional signatures are
    /// tolerated but not verified by this implementation; key selection by signature
    /// index is left to the VID type).
    fn decode_with_rest(stream: &mut &'a [u8]) -> Result<(Self, usize), DecodeError> {
        let a_size = decode_count(TSP_ATTACH_GRP, stream).ok_or(DecodeError::UnexpectedData)?;
        let region_len = (a_size as usize)
            .checked_mul(3)
            .ok_or(DecodeError::InvalidFrameCount)?;
        let (mut region, rest) = stream
            .split_at_checked(region_len)
            .ok_or(DecodeError::InvalidFrameCount)?;

        let i_size = decode_count(TSP_INDEX_SIG_GRP, &mut region)
            .ok_or(DecodeError::InvalidSignatureType)?;
        // the indexed signature group covers the rest of the attachment group
        if (i_size as usize).checked_mul(3) != Some(region.len()) {
            return Err(DecodeError::InvalidFrameCount);
        }

        let signature =
            if let Some((index, sig)) = decode_indexed_data(ED25519_SIGNATURE, &mut region) {
                // the index selects the signing key in the VID's key list; this
                // implementation supports single-key VIDs, whose only valid index is 0
                if index != 0 {
                    return Err(DecodeError::InvalidSignatureType);
                }
                EncodedSignature::Ed25519(sig)
            } else if let Some(sig) = decode_fixed_data(ML_DSA_65_SIGNATURE, &mut region) {
                EncodedSignature::MlDsa65(sig)
            } else {
                return Err(DecodeError::InvalidSignatureType);
            };

        *stream = rest;
        Ok((signature, region.len()))
    }

    fn decode(stream: &mut &'a [u8]) -> Result<Self, DecodeError> {
        let (signature, _rest) = Self::decode_with_rest(stream)?;
        Ok(signature)
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
        SignatureType::MlDsa65 => {
            EncodedSignature::MlDsa65(signature.try_into().expect("signature has incorrect size"))
        }
    }
    .encode(output)
}

impl CryptoType {
    fn cesr_code(&self) -> Result<u32, DecodeError> {
        Ok(match self {
            CryptoType::SealedBox => TSP_SEALEDBOX_CIPHERTEXT,
            CryptoType::HpkeBase => TSP_HPKEBASE_CIPHERTEXT,
            CryptoType::Plaintext => return Err(DecodeError::InvalidCrypto),
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

/// Checks whether the expected TSP header is present; parses and validates the
/// `-E##` frame (whose count covers the version, VIDs, non-confidential data and
/// ciphertext) and determines the crypto type from the ciphertext code point.
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

    let frame_quadlets = decode_count(TSP_WRAPPER, &mut stream).ok_or(DecodeError::NotTsp)?;
    let content_start = origin.len() - stream.len();
    let content_len = (frame_quadlets as usize)
        .checked_mul(3)
        .ok_or(DecodeError::InvalidFrameCount)?;
    let content_end = content_start
        .checked_add(content_len)
        .filter(|&end| end <= origin.len())
        .ok_or(DecodeError::InvalidFrameCount)?;

    decode_version(&mut stream)?;
    let mut mid_pos = origin.len() - stream.len();

    let sender = decode_variable_data_index(TSP_VID, origin, &mut mid_pos)
        .ok_or(DecodeError::UnexpectedData)?;
    if sender.is_empty() {
        return Err(DecodeError::VidError);
    }

    // the receiver VID field is always present; the NULL VID `4BAA` means absent
    let receiver = decode_variable_data_index(TSP_VID, origin, &mut mid_pos)
        .ok_or(DecodeError::UnexpectedData)?;
    let receiver = if receiver.is_empty() {
        None
    } else {
        Some(receiver)
    };

    *pos = mid_pos;
    let mut stream = &origin[mid_pos..];

    /* look ahead to determine the crypto and signature types; the payload
    position holds either a ciphertext primitive (confidential message) or a
    cleartext -Z## payload (non-confidential, signed-only message) */
    let crypto_type = if decode_variable_data(TSP_HPKEBASE_CIPHERTEXT, &mut stream).is_some() {
        CryptoType::HpkeBase
    } else if decode_variable_data(TSP_SEALEDBOX_CIPHERTEXT, &mut stream).is_some() {
        CryptoType::SealedBox
    } else if let Some(quadlets) = decode_count(TSP_PAYLOAD, &mut stream) {
        let payload_bytes = (quadlets as usize)
            .checked_mul(3)
            .ok_or(DecodeError::InvalidFrameCount)?;
        stream = stream
            .get(payload_bytes..)
            .ok_or(DecodeError::InvalidFrameCount)?;
        CryptoType::Plaintext
    } else {
        return Err(DecodeError::UnexpectedData);
    };

    // validate the frame count: the envelope fields and ciphertext must end
    // exactly at the frame boundary (the signature attachment follows it)
    if origin.len() - stream.len() != content_end {
        return Err(DecodeError::InvalidFrameCount);
    }

    // every TSP message carries a signature attachment; a message without a
    // parseable one is rejected rather than treated as unsigned
    let signature_type = match EncodedSignature::decode(&mut stream)? {
        EncodedSignature::Ed25519(_) => SignatureType::Ed25519,
        EncodedSignature::MlDsa65(_) => SignatureType::MlDsa65,
        EncodedSignature::NoSignature => return Err(DecodeError::InvalidSignatureType),
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
        };

        Ok(DecodedEnvelope {
            envelope,
            raw_header,
            payload_position: ciphertext,
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

    // the associated data binds the envelope fields: everything after the `-E##`
    // frame code (which is excluded, matching the seal side where the frame is
    // prepended only after encryption) up to the payload position
    let frame_len = {
        let mut s = &stream[..];
        decode_count(TSP_WRAPPER, &mut s).ok_or(DecodeError::NotTsp)?;
        stream.len() - s.len()
    };
    let associated_data = frame_len..pos;

    // the payload position: a ciphertext primitive, or the cleartext -Z## payload
    let ciphertext = if crypto_type.is_encrypted() {
        Some(
            checked_decode_variable_data_index(crypto_type.cesr_code()?, stream, &mut pos)
                .ok_or(DecodeError::UnexpectedData)?,
        )
    } else {
        let start = pos;
        let mut s = &stream[pos..];
        let quadlets = decode_count(TSP_PAYLOAD, &mut s).ok_or(DecodeError::UnexpectedData)?;
        let code_len = stream.len() - pos - s.len();
        let payload_bytes = (quadlets as usize)
            .checked_mul(3)
            .ok_or(DecodeError::InvalidFrameCount)?;
        pos = start
            .checked_add(code_len + payload_bytes)
            .filter(|&end| end <= stream.len())
            .ok_or(DecodeError::InvalidFrameCount)?;
        Some(start..pos)
    };

    let signed_data = 0..pos;

    let data: &'a mut [u8];
    let mut sigdata: &[u8];
    (data, sigdata) = stream.split_at_mut(signed_data.end);

    let signature = match signature_type {
        SignatureType::NoSignature => [].as_slice(),
        _ => match EncodedSignature::decode(&mut sigdata)? {
            EncodedSignature::Ed25519(sig) => sig.as_slice(),
            EncodedSignature::MlDsa65(sig) => sig.as_slice(),
            _ => [].as_slice(),
        },
    };

    // any data after the signature attachment is not part of this message
    // (a transport may deliver several messages back-to-back) and is ignored

    Ok(CipherView {
        data,

        crypto_type,
        signature_type,

        sender,
        receiver,

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
    encode_payload(payload, None, None, &mut data)?;

    Ok(data)
}

/// Allocating variant of [encode_envelope]; the returned data still needs
/// [finalize_envelope_frame] applied after any ciphertext is appended
#[cfg(test)]
pub fn encode_envelope_vec<Vid: AsRef<[u8]>>(
    envelope: Envelope<Vid>,
) -> Result<Vec<u8>, EncodeError> {
    let mut data = vec![];
    encode_envelope(envelope, &mut data)?;

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

    // the message prefix: the `-E##`/`-0E#####` frame code plus the version
    let frame_len = {
        let mut stream = data;
        decode_count(TSP_WRAPPER, &mut stream).ok_or(DecodeError::NotTsp)?;
        data.len() - stream.len()
    };
    let prefix = Part {
        prefix: &data[..frame_len + 6],
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

    let ciphertext = if crypto_type.is_encrypted() {
        let cipher_code = crypto_type.cesr_code()?;
        Part::decode(cipher_code, data, &mut pos)
    } else {
        // the payload position holds the cleartext -Z## payload
        let start = pos;
        let mut s = &data[pos..];
        let quadlets = decode_count(TSP_PAYLOAD, &mut s).ok_or(DecodeError::UnexpectedData)?;
        let code_len = data.len() - pos - s.len();
        let end = start
            .checked_add(code_len + (quadlets as usize) * 3)
            .filter(|&end| end <= data.len())
            .ok_or(DecodeError::InvalidFrameCount)?;
        pos = end;
        Some(Part {
            prefix: &data[start..start + code_len],
            data: &data[start + code_len..end],
        })
    };

    let signature = match EncodedSignature::decode(&mut &data[pos..])? {
        EncodedSignature::NoSignature => &[],
        EncodedSignature::Ed25519(sig) => sig.as_slice(),
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
    pub message: Payload<'a, Bytes, Vid>,
}

/// Convenience interface which illustrates encoding as a single operation
#[cfg(all(feature = "demo", test))]
pub fn encode_tsp_message<Vid: AsRef<[u8]>, Sig: AsRef<[u8]>>(
    Message {
        ref sender,
        ref receiver,
        message,
    }: Message<Vid, impl AsRef<[u8]>>,
    encrypt: impl FnOnce(&Vid, Vec<u8>) -> Vec<u8>,
    sign: impl FnOnce(&Vid, &[u8]) -> Sig,
) -> Result<Vec<u8>, EncodeError> {
    let mut cesr = encode_envelope_vec(Envelope {
        crypto_type: CryptoType::HpkeBase,
        signature_type: SignatureType::Ed25519,
        sender,
        receiver: Some(receiver),
    })?;

    let ciphertext = &encrypt(receiver, encode_payload_vec(&message)?);

    encode_ciphertext(ciphertext, CryptoType::HpkeBase, &mut cesr)?;
    finalize_envelope_frame(&mut cesr);
    let signature = sign(sender, &cesr);
    encode_signature(signature.as_ref(), &mut cesr, SignatureType::Ed25519);

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
        message,
    })
}

#[cfg(test)]
mod test {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[test]
    #[wasm_bindgen_test]
    fn envelope_roundtrip() {
        fn dummy_crypt(data: &mut [u8]) -> &mut [u8] {
            data
        }
        let fixed_sig = [1; 64];

        let mut cesr_payload =
            { encode_payload_vec(&Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_envelope_vec(Envelope {
            crypto_type: CryptoType::HpkeBase,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&mut cesr_payload);
        encode_ciphertext(ciphertext, CryptoType::HpkeBase, &mut outer).unwrap();
        finalize_envelope_frame(&mut outer);

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

        let view = decode_envelope(&mut outer).unwrap();
        let ver = view.as_challenge();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        let DecodedEnvelope {
            envelope: env,
            payload_position: ciphertext,
            ..
        } = view.into_opened().unwrap();
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));

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
    fn envelope_roundtrip_second() {
        fn dummy_crypt(data: &mut [u8]) -> &mut [u8] {
            data
        }
        let fixed_sig = [1; 64];

        let mut cesr_payload =
            { encode_payload_vec(&Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_envelope_vec(Envelope {
            crypto_type: CryptoType::HpkeBase,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&mut cesr_payload);
        encode_ciphertext(ciphertext, CryptoType::HpkeBase, &mut outer).unwrap();
        finalize_envelope_frame(&mut outer);

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

        let view = decode_envelope(&mut outer).unwrap();
        let ver = view.as_challenge();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        let DecodedEnvelope {
            envelope: env,
            payload_position: ciphertext,
            ..
        } = view.into_opened().unwrap();
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));

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

        let mut outer = encode_envelope_vec(Envelope {
            crypto_type: CryptoType::Plaintext,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
        })
        .unwrap();
        // a non-confidential message carries its cleartext -Z## payload in the payload position
        encode_payload(
            &Payload::<_, &[u8]>::GenericMessage(b"treasure"),
            None,
            None,
            &mut outer,
        )
        .unwrap();
        finalize_envelope_frame(&mut outer);

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

        let view = decode_envelope(&mut outer).unwrap();
        let ver = view.as_challenge();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        let DecodedEnvelope {
            envelope: env,
            payload_position,
            ..
        } = view.into_opened::<&[u8]>().unwrap();
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));
        assert_eq!(env.crypto_type, CryptoType::Plaintext);

        // the payload position holds the cleartext payload
        let DecodedPayload {
            payload: Payload::GenericMessage(data),
            ..
        } = decode_payload(payload_position.unwrap()).unwrap()
        else {
            unreachable!();
        };
        assert_eq!(data, b"treasure");
    }

    #[test]
    #[wasm_bindgen_test]
    fn frame_count_must_cover_ciphertext() {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload =
            { encode_payload_vec(&Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_envelope_vec(Envelope {
            crypto_type: CryptoType::Plaintext,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
        })
        .unwrap();
        // finalizing before the ciphertext is appended produces a frame count
        // that does not cover the ciphertext, which the receiver must reject
        finalize_envelope_frame(&mut outer);
        let ciphertext = dummy_crypt(&cesr_payload);
        encode_ciphertext(ciphertext, CryptoType::HpkeBase, &mut outer).unwrap();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

        assert!(matches!(
            decode_envelope(&mut outer),
            Err(DecodeError::InvalidFrameCount)
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn envelope_failure() {
        let fixed_sig = [1; 64];

        let mut outer = vec![];
        encode_envelope(
            Envelope {
                crypto_type: CryptoType::HpkeBase,
                signature_type: SignatureType::Ed25519,
                sender: &b"Alister"[..],
                receiver: Some(&b"Bobbi"[..]),
            },
            &mut outer,
        )
        .unwrap();
        // no envelope frame, and signature and ciphertext in the wrong order
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);
        encode_ciphertext(&[], CryptoType::HpkeBase, &mut outer).unwrap();

        assert!(decode_envelope(&mut outer).is_err());
    }

    #[test]
    #[wasm_bindgen_test]
    fn trailing_data_is_ignored() {
        let fixed_sig = [1; 64];

        let mut outer = encode_envelope_vec(Envelope {
            crypto_type: CryptoType::HpkeBase,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
        })
        .unwrap();
        encode_ciphertext(&[], CryptoType::HpkeBase, &mut outer).unwrap();
        finalize_envelope_frame(&mut outer);
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

        // a transport may deliver several messages back-to-back: data after the
        // signature attachment is not part of this message and must not be an error
        outer.push(b'-');

        assert!(decode_envelope(&mut outer).is_ok());
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
                message: Payload::GenericMessage(payload),
            },
            |_, vec| vec,
            |_, _| [5; 64],
        )
        .unwrap();

        let tsp = decode_tsp_message(
            &mut data,
            |_: &&[u8], x| x.to_vec(),
            |_, _, sig| sig == [5u8; 64],
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
    fn mut_envelope_roundtrip() {
        test_turn_around(Payload::GenericMessage(&mut b"Hello TSP!".to_owned()));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_nested_msg() {
        // a nested message is itself CESR data, so always a multiple of 3 bytes
        test_turn_around(Payload::NestedMessage(&mut b"Hello TSP!!!".to_owned()));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_nested_msg_must_be_aligned() {
        assert!(matches!(
            encode_payload_vec(&Payload::<_, &[u8]>::NestedMessage(b"Hello TSP!")),
            Err(EncodeError::MisalignedNestedMessage)
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_routed_msg() {
        test_turn_around(Payload::RoutedMessage(
            vec![b"foo", b"bar"],
            &mut b"Hello TSP!!!".to_owned(),
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_large_payloads_use_long_form_counts() {
        // large payloads push the -Z##, -A## and -H## counts and the Bytes
        // primitive into their long forms; the counts must be computed over
        // the actual encodings, not assume short-form code sizes
        for len in [0usize, 3, 4095 * 3, 16 * 1024, 64 * 1024] {
            let data = vec![0x42u8; len];
            test_turn_around(Payload::GenericMessage(&mut data.clone()));
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_caller_supplied_padding() {
        // the pad's content is caller-chosen and discarded by the receiver
        let payload = Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!");
        let mut encoded = vec![];
        encode_payload(
            &payload,
            Some(b"did:test:alice"),
            Some(&[0xEE; 21]),
            &mut encoded,
        )
        .unwrap();

        let decoded = decode_payload(&mut encoded).unwrap();
        assert_eq!(decoded.sender_identity, Some(&b"did:test:alice"[..]));
        let Payload::GenericMessage(data) = decoded.payload else {
            panic!("expected GenericMessage");
        };
        assert_eq!(&data[..], b"Hello TSP!");
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_control_msg() {
        test_turn_around(Payload::ControlMessage(
            &mut b"upper layer control".to_owned(),
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_padding_msg() {
        test_turn_around(Payload::Padding {
            nonce: Nonce([11; 16]),
        });
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_par_refer_rel() {
        test_turn_around(Payload::ParallelRelationProposal {
            nonce: Nonce([7; 16]),
            request_digest: Digest::Sha2_256(&Default::default()),
            sig_new_vid: &[5; 64],
            new_vid: b"Charlie",
        });
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_parallel_relation_accept_round_trip() {
        test_turn_around(Payload::ParallelRelationAffirm {
            request_digest: Digest::Sha2_256(&[3; 32]),
            reply_digest: Digest::Blake2b256(&[4; 32]),
            sig_new_vid: &[9; 64],
            new_vid: b"Delta",
        });
    }

    fn test_turn_around(payload: Payload<&mut [u8], &[u8]>) {
        fn dummy_crypt(data: &mut [u8]) -> &mut [u8] {
            data
        }
        let fixed_sig = [1; 64];

        let mut cesr_payload = encode_payload_vec(&payload).unwrap();

        let mut outer = encode_envelope_vec(Envelope {
            crypto_type: CryptoType::HpkeBase,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&mut cesr_payload);
        encode_ciphertext(ciphertext, CryptoType::HpkeBase, &mut outer).unwrap();
        finalize_envelope_frame(&mut outer);

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

        let view = decode_envelope(&mut outer).unwrap();
        assert_eq!(view.as_challenge().signed_data, signed_data);
        assert_eq!(view.as_challenge().signature, &fixed_sig);
        let DecodedEnvelope {
            envelope: env,
            payload_position: ciphertext,
            ..
        } = view.into_opened::<&[u8]>().unwrap();

        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));

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
        let digest: &[u8; 32] = temp.as_slice().try_into().unwrap();
        let nonce = [7u8; 16];
        test_turn_around(Payload::DirectRelationProposal {
            nonce: Nonce(nonce),
            request_digest: Digest::Sha2_256(digest),
        });
        test_turn_around(Payload::DirectRelationAffirm {
            request_digest: Digest::Sha2_256(digest),
            reply_digest: Digest::Sha2_256(digest),
        });
        test_turn_around(Payload::DirectRelationAffirm {
            request_digest: Digest::Blake2b256(digest),
            reply_digest: Digest::Blake2b256(digest),
        });
        test_turn_around(Payload::RelationshipCancel {
            reply: Digest::Sha2_256(digest),
        });
        test_turn_around(Payload::RelationshipCancel {
            reply: Digest::Blake2b256(digest),
        });
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_message_to_parts() {
        let fixed_sig = [1; 64];

        // 3-byte-aligned field contents, so the part lengths are exact
        // (unaligned contents include their lead bytes in the reported parts)
        let mut message = encode_envelope_vec(Envelope {
            crypto_type: CryptoType::HpkeBase,
            signature_type: SignatureType::Ed25519,
            sender: &b"did:test:bob"[..],
            receiver: Some(&b"did:test:alice3"[..]),
        })
        .unwrap();
        encode_ciphertext(&[0xAA; 69], CryptoType::HpkeBase, &mut message).unwrap();
        finalize_envelope_frame(&mut message);
        encode_signature(&fixed_sig, &mut message, SignatureType::Ed25519);

        let parts = open_message_into_parts(&message).unwrap();

        // the message prefix is the `-E##` frame code (3) plus the version (6)
        assert_eq!(parts.prefix.prefix.len(), 9);
        assert_eq!(parts.sender.data.len(), b"did:test:bob".len());
        assert_eq!(parts.receiver.unwrap().data.len(), b"did:test:alice3".len());
        assert_eq!(parts.ciphertext.unwrap().data.len(), 69);
        assert_eq!(parts.signature.data.len(), 64);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_absent_receiver_is_null_vid() {
        let fixed_sig = [1; 64];

        let mut outer = encode_envelope_vec(Envelope {
            crypto_type: CryptoType::Plaintext,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: None::<&[u8]>,
        })
        .unwrap();
        encode_payload(
            &Payload::<_, &[u8]>::GenericMessage(b"treasure"),
            None,
            None,
            &mut outer,
        )
        .unwrap();
        finalize_envelope_frame(&mut outer);
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

        let view = decode_envelope(&mut outer).unwrap();
        let DecodedEnvelope { envelope: env, .. } = view.into_opened::<&[u8]>().unwrap();
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, None);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_hop_list_counts_bytes() {
        let mut hops = Vec::new();
        encode_hops(&[b"alpha".as_slice(), b"bravo-charlie"], &mut hops).unwrap();

        // each VID is encoded as a B-primitive; the count is the byte length
        // of the concatenated encodings in quadlets/triplets, not the VID count
        let mut expected = Vec::new();
        checked_encode_variable_data(TSP_VID, b"alpha", &mut expected).unwrap();
        checked_encode_variable_data(TSP_VID, b"bravo-charlie", &mut expected).unwrap();

        let mut stream = &hops[..];
        let count = decode_count(TSP_HOP_LIST, &mut stream).unwrap();
        assert_eq!(count as usize, expected.len() / 3);
        assert_eq!(stream, expected);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_not_tsp_vs_version_mismatch() {
        // arbitrary non-TSP data is NotTsp
        let mut garbage = *b"this is not a TSP message....";
        assert!(matches!(
            decode_envelope(&mut garbage),
            Err(DecodeError::NotTsp)
        ));

        // a valid message with a different MAJOR version is VersionMismatch
        let fixed_sig = [1; 64];
        let mut outer = encode_envelope_vec(Envelope {
            crypto_type: CryptoType::Plaintext,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
        })
        .unwrap();
        finalize_envelope_frame(&mut outer);
        encode_signature(&fixed_sig, &mut outer, SignatureType::Ed25519);

        // the version triplet follows the frame code (3 bytes) and the `YTSP`
        // marker (3 bytes): [dash:6][major:6][minor+patch:12]; overwriting the
        // second byte changes the MAJOR version without touching the dash selector
        outer[7] = 0xFF; // a MAJOR version far in the future
        assert!(matches!(
            decode_envelope(&mut outer),
            Err(DecodeError::VersionMismatch)
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_signature_attachment_structure() {
        let mut out = Vec::new();
        encode_signature(&[1; 64], &mut out, SignatureType::Ed25519);

        let mut stream = &out[..];
        // -C## attachment group: the indexed signature group code plus its contents
        assert_eq!(decode_count(TSP_ATTACH_GRP, &mut stream), Some(23));
        // -K## indexed signature group: one indexed Ed25519 signature (22 quadlets)
        assert_eq!(decode_count(TSP_INDEX_SIG_GRP, &mut stream), Some(22));
        // the signature primitive uses the indexed code `B#` with index 0 ("BA")
        let (index, sig) = decode_indexed_data::<64>(ED25519_SIGNATURE, &mut stream).unwrap();
        assert_eq!(index, 0);
        assert_eq!(sig, &[1; 64]);
        assert!(stream.is_empty());
    }

    #[test]
    fn test_decode_send_recv() {
        fn dummy_crypt(data: &mut [u8]) -> &mut [u8] {
            data
        }
        let fixed_sig = [1; 64];

        let mut cesr_payload =
            { encode_payload_vec(&Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_envelope_vec(Envelope {
            crypto_type: CryptoType::HpkeBase,
            signature_type: SignatureType::Ed25519,
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&mut cesr_payload);
        encode_ciphertext(ciphertext, CryptoType::HpkeBase, &mut outer).unwrap();
        finalize_envelope_frame(&mut outer);

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

        let (sender, receiver, _, _) = decode_sender_receiver(&outer2).unwrap();
        assert_eq!(env.sender, sender);
        assert_eq!(env.receiver, receiver);
    }
}
