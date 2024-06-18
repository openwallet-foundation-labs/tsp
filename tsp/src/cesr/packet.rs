/// Constants that determine the specific CESR types for "variable length data"
const TSP_PLAINTEXT: u32 = (b'B' - b'A') as u32;
const TSP_CIPHERTEXT: u32 = (b'C' - b'A') as u32;
const TSP_DEVELOPMENT_VID: u32 = (21 << 6 | 8) << 6 | 3; // "VID"

/// Constants that determine the specific CESR types for "fixed length data"
const TSP_TYPECODE: u32 = (b'X' - b'A') as u32;
const ED25519_SIGNATURE: u32 = (b'B' - b'A') as u32;
#[allow(clippy::eq_op)]
const TSP_NONCE: u32 = (b'A' - b'A') as u32;
const TSP_SHA256: u32 = (b'I' - b'A') as u32;

/// Constants that determine the specific CESR types for the framing codes
const TSP_ETS_WRAPPER: u16 = (b'E' - b'A') as u16;
const TSP_S_WRAPPER: u16 = (b'S' - b'A') as u16;
const TSP_HOP_LIST: u16 = (b'I' - b'A') as u16;
const TSP_PAYLOAD: u16 = (b'Z' - b'A') as u16;

/// Constants to encode message types
mod msgtype {
    pub(super) const GEN_MSG: [u8; 2] = [0, 0];
    pub(super) const NEST_MSG: [u8; 2] = [0, 1];
    pub(super) const ROUTE_MSG: [u8; 2] = [0, 2];
    pub(super) const NEW_REL: [u8; 2] = [1, 0];
    pub(super) const NEW_REL_REPLY: [u8; 2] = [1, 1];
    pub(super) const NEW_NEST_REL: [u8; 2] = [1, 2];
    pub(super) const NEW_NEST_REL_REPLY: [u8; 2] = [1, 3];
    pub(super) const REL_CANCEL: [u8; 2] = [1, 255];
}

use super::{
    decode::{decode_count, decode_fixed_data, decode_variable_data, decode_variable_data_index},
    encode::{encode_count, encode_fixed_data},
    error::{DecodeError, EncodeError},
};

/// A type to enforce that a random nonce contains enough bits of security
/// (128bits via a birthday attack -> 256bits needed)
/// This explicitly does not implement Clone or Copy to make sure nonces are not reused
#[derive(Debug)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(PartialEq, Eq, Clone))]
pub struct Nonce([u8; 32]);

impl Nonce {
    pub fn generate(gen: impl FnOnce(&mut [u8; 32])) -> Nonce {
        let mut bytes = Default::default();
        gen(&mut bytes);

        Nonce(bytes)
    }
}

/// A SHA256 Digest
//TODO: this should probably be in tsp-definitions
pub type Sha256Digest = [u8; 32];

/// A type to distinguish "normal" TSP messages from "control" messages
#[repr(u32)]
#[derive(Debug)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(PartialEq, Eq, Clone))]
//TODO: Boxed slices?
pub enum Payload<'a, Bytes: AsRef<[u8]>, Vid> {
    /// A TSP message which consists only of a message which will be protected using HPKE
    GenericMessage(Bytes),
    /// A payload that consists of a TSP Envelope+Message (TODO: maybe add some extra decoding)
    NestedMessage(Bytes),
    /// A routed payload; same as above but with routing information attached
    RoutedMessage(Vec<Vid>, Bytes),
    /// A TSP message requesting a relationship
    DirectRelationProposal { nonce: Nonce, hops: Vec<Vid> },
    /// A TSP message confiming a relationship
    DirectRelationAffirm { reply: &'a Sha256Digest },
    /// A TSP message requesting a nested relationship
    NestedRelationProposal { new_vid: Vid },
    /// A TSP message confiming a relationship
    NestedRelationAffirm {
        new_vid: Vid,
        connect_to_vid: Vid,
        reply: &'a Sha256Digest,
    },
    /// A TSP cancellation message
    RelationshipCancel {
        nonce: Nonce,
        reply: &'a Sha256Digest,
    },
}

impl<'a, Bytes: AsRef<[u8]>, Vid> Payload<'a, Bytes, Vid> {
    pub fn estimate_size(&self) -> usize {
        0 // TODO
    }
}

// helpers for generating and comparing arbitrary `Payload`s
#[cfg(feature = "fuzzing")]
pub mod fuzzing;

/// Type representing a TSP Envelope
#[derive(Debug, Clone)]
pub struct Envelope<'a, Vid> {
    pub sender: Vid,
    pub receiver: Option<Vid>,
    pub nonconfidential_data: Option<&'a [u8]>,
}

pub struct DecodedEnvelope<'a, Vid, Bytes> {
    pub envelope: Envelope<'a, Vid>,
    pub raw_header: &'a [u8], // for associated data purposes
    pub ciphertext: Option<Bytes>,
}

/// TODO: something more type safe
pub type Signature = [u8; 64];

/// Safely encode variable data, returning a soft error in case the size limit is exceeded
fn checked_encode_variable_data(
    identifier: u32,
    payload: &[u8],
    stream: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    const DATA_LIMIT: usize = 50000000;

    if payload.len() >= DATA_LIMIT {
        return Err(EncodeError::PayloadTooLarge);
    }

    super::encode::encode_variable_data(identifier, payload, stream);

    Ok(())
}

/// Encode a TSP Payload into CESR for encryption
pub fn encode_payload(
    payload: &Payload<impl AsRef<[u8]>, impl AsRef<[u8]>>,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    encode_count(TSP_PAYLOAD, 1, output);
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
            encode_fixed_data(TSP_TYPECODE, &msgtype::ROUTE_MSG, output);
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
            encode_fixed_data(TSP_SHA256, reply.as_slice(), output);
        }
        Payload::NestedRelationProposal { new_vid } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_NEST_REL, output);
            checked_encode_variable_data(TSP_DEVELOPMENT_VID, new_vid.as_ref(), output)?;
        }
        Payload::NestedRelationAffirm {
            new_vid,
            connect_to_vid,
            reply,
        } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_NEST_REL_REPLY, output);
            checked_encode_variable_data(TSP_DEVELOPMENT_VID, new_vid.as_ref(), output)?;
            checked_encode_variable_data(TSP_DEVELOPMENT_VID, connect_to_vid.as_ref(), output)?;
            encode_fixed_data(TSP_SHA256, reply.as_slice(), output);
        }
        Payload::RelationshipCancel { nonce, reply } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::REL_CANCEL, output);
            encode_fixed_data(TSP_NONCE, &nonce.0, output);
            encode_fixed_data(TSP_SHA256, reply.as_slice(), output);
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
fn decode_hops<'a, Vid: TryFrom<&'a [u8]>>(stream: &mut &'a [u8]) -> Result<Vec<Vid>, DecodeError> {
    let Some(hop_length) = decode_count(TSP_HOP_LIST, stream) else {
        return Ok(Vec::new());
    };

    let mut hop_list = Vec::with_capacity(hop_length as usize);
    for _ in 0..hop_length {
        hop_list.push(
            decode_variable_data(TSP_DEVELOPMENT_VID, stream)
                .ok_or(DecodeError::UnexpectedData)?
                .try_into()
                .map_err(|_| DecodeError::VidError)?,
        );
    }

    Ok(hop_list)
}

/// Decode a TSP Payload
pub fn decode_payload<'a, Vid: TryFrom<&'a [u8]>>(
    mut stream: &'a [u8],
) -> Result<Payload<&'a [u8], Vid>, DecodeError> {
    let Some(1) = decode_count(TSP_PAYLOAD, &mut stream) else {
        return Err(DecodeError::VersionMismatch);
    };

    let payload = match *decode_fixed_data(TSP_TYPECODE, &mut stream)
        .ok_or(DecodeError::UnexpectedData)?
    {
        msgtype::GEN_MSG => {
            decode_variable_data(TSP_PLAINTEXT, &mut stream).map(Payload::GenericMessage)
        }
        msgtype::NEW_REL => {
            let hop_list = decode_hops(&mut stream)?;

            decode_fixed_data(TSP_NONCE, &mut stream).map(|nonce| Payload::DirectRelationProposal {
                nonce: Nonce(*nonce),
                hops: hop_list,
            })
        }
        msgtype::NEST_MSG => {
            decode_variable_data(TSP_PLAINTEXT, &mut stream).map(Payload::NestedMessage)
        }
        msgtype::ROUTE_MSG => {
            let hop_list = decode_hops(&mut stream)?;
            if hop_list.is_empty() {
                return Err(DecodeError::MissingHops);
            }

            decode_variable_data(TSP_PLAINTEXT, &mut stream)
                .map(|msg| Payload::RoutedMessage(hop_list, msg))
        }
        msgtype::NEW_REL_REPLY => decode_fixed_data(TSP_SHA256, &mut stream)
            .map(|reply| Payload::DirectRelationAffirm { reply }),
        msgtype::NEW_NEST_REL => {
            let new_vid = decode_variable_data(TSP_DEVELOPMENT_VID, &mut stream)
                .ok_or(DecodeError::UnexpectedData)?
                .try_into()
                .map_err(|_| DecodeError::VidError)?;

            Some(Payload::NestedRelationProposal { new_vid })
        }
        msgtype::NEW_NEST_REL_REPLY => {
            let new_vid = decode_variable_data(TSP_DEVELOPMENT_VID, &mut stream)
                .ok_or(DecodeError::UnexpectedData)?
                .try_into()
                .map_err(|_| DecodeError::VidError)?;
            let connect_to_vid = decode_variable_data(TSP_DEVELOPMENT_VID, &mut stream)
                .ok_or(DecodeError::UnexpectedData)?
                .try_into()
                .map_err(|_| DecodeError::VidError)?;

            decode_fixed_data(TSP_SHA256, &mut stream).map(|reply| Payload::NestedRelationAffirm {
                new_vid,
                connect_to_vid,
                reply,
            })
        }
        msgtype::REL_CANCEL => decode_fixed_data(TSP_NONCE, &mut stream).and_then(|nonce| {
            decode_fixed_data(TSP_SHA256, &mut stream).map(|reply| Payload::RelationshipCancel {
                nonce: Nonce(*nonce),
                reply,
            })
        }),
        _ => return Err(DecodeError::UnexpectedMsgType),
    };

    if !stream.is_empty() {
        Err(DecodeError::TrailingGarbage)
    } else {
        payload.ok_or(DecodeError::UnexpectedData)
    }
}

/// Encode a encrypted TSP message plus Envelope into CESR
/// TODO: replace types of sender/receiver with VIDs (once we have that type)
pub fn encode_ets_envelope<'a, Vid: AsRef<[u8]>>(
    envelope: Envelope<'a, Vid>,
    output: &mut impl for<'b> Extend<&'b u8>,
) -> Result<(), EncodeError> {
    encode_count(TSP_ETS_WRAPPER, 1, output);

    encode_envelope_fields(envelope, output)
}

/// Encode a encrypted TSP message plus Envelope into CESR
/// TODO: replace types of sender/receiver with VIDs (once we have that type)
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
/// TODO: replace type with a more precise "signature" type
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
) -> Result<(usize, bool), DecodeError> {
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

    debug_assert_eq!(origin.len() - stream.len(), 6);
    Ok((6, encrypted))
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
) -> Result<(Vid, Option<Vid>, bool), DecodeError> {
    let (_, has_confidential_part) = detected_tsp_header_size_and_confidentiality(stream)?;

    let sender = decode_variable_data(TSP_DEVELOPMENT_VID, stream)
        .ok_or(DecodeError::UnexpectedData)?
        .try_into()
        .map_err(|_| DecodeError::VidError)?;

    let receiver = decode_variable_data(TSP_DEVELOPMENT_VID, stream)
        .map(|r| r.try_into().map_err(|_| DecodeError::VidError))
        .transpose()?;

    Ok((sender, receiver, has_confidential_part))
}

/// Decode an encrypted TSP message plus Envelope & Signature
pub fn decode_envelope<'a, Vid: TryFrom<&'a [u8]>>(
    mut stream: &'a [u8],
) -> Result<
    (
        DecodedEnvelope<'a, Vid, &'a [u8]>,
        VerificationChallenge<'a>,
    ),
    DecodeError,
> {
    let origin = stream;
    let (sender, receiver, has_confidential_part) = decode_sender_receiver(&mut stream)?;

    let nonconfidential_data = decode_variable_data(TSP_PLAINTEXT, &mut stream);
    let raw_header = &origin[..origin.len() - stream.len()];

    let ciphertext = has_confidential_part
        .then(|| {
            decode_variable_data(TSP_CIPHERTEXT, &mut stream).ok_or(DecodeError::UnexpectedData)
        })
        .transpose()?;
    let signed_data = &origin[..origin.len() - stream.len()];
    let signature =
        decode_fixed_data(ED25519_SIGNATURE, &mut stream).ok_or(DecodeError::UnexpectedData)?;

    if !stream.is_empty() {
        return Err(DecodeError::TrailingGarbage);
    }

    Ok((
        DecodedEnvelope {
            envelope: Envelope {
                sender,
                receiver,
                nonconfidential_data,
            },
            raw_header,
            ciphertext,
        },
        VerificationChallenge {
            signed_data,
            signature,
        },
    ))
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
pub fn decode_envelope_mut<'a>(stream: &'a mut [u8]) -> Result<CipherView<'a>, DecodeError> {
    let (mut pos, has_confidential_part) =
        detected_tsp_header_size_and_confidentiality(&mut (stream as &[u8]))?;
    let mut sender = decode_variable_data_index(TSP_DEVELOPMENT_VID, &stream[pos..])
        .ok_or(DecodeError::UnexpectedData)?;
    sender.start += pos;
    sender.end += pos;
    pos = sender.end;

    let mut receiver = decode_variable_data_index(TSP_DEVELOPMENT_VID, &stream[pos..]);
    if let Some(range) = &mut receiver {
        range.start += pos;
        range.end += pos;
        pos = range.end;
    }

    let mut nonconfidential_data = decode_variable_data_index(TSP_PLAINTEXT, &stream[pos..]);
    if let Some(range) = &mut nonconfidential_data {
        range.start += pos;
        range.end += pos;
        pos = range.end;
    }

    let associated_data = 0..pos;

    let ciphertext = if has_confidential_part {
        let mut ciphertext = decode_variable_data_index(TSP_CIPHERTEXT, &stream[pos..])
            .ok_or(DecodeError::UnexpectedData)?;
        ciphertext.start += pos;
        ciphertext.end += pos;
        pos = ciphertext.end;

        Some(ciphertext)
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
    encode_payload(payload, &mut data)?;

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
        match decode_variable_data_index(identifier, &data[*pos..]) {
            Some(range) => {
                let part = Part {
                    prefix: &data[*pos..(*pos + range.start)],
                    data: &data[(*pos + range.start)..(*pos + range.end)],
                };
                *pos += range.end;

                Some(part)
            }
            None => None,
        }
    }
}

/// Describes the CESR-encoded parts of a TSP message
#[derive(Default, Debug)]
pub struct MessageParts<'a> {
    pub prefix: Part<'a>,
    pub sender: Part<'a>,
    pub receiver: Option<Part<'a>>,
    pub nonconfidential_data: Option<Part<'a>>,
    pub ciphertext: Option<Part<'a>>,
    pub signature: Part<'a>,
}

/// Decode a CESR-encoded message into its CESR-encoded parts
pub fn open_message_into_parts(data: &[u8]) -> Result<MessageParts, DecodeError> {
    let (mut pos, _) = detected_tsp_header_size_and_confidentiality(&mut (data as &[u8]))?;

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
    })
}

/// Convenience interface: this struct is isomorphic to [Envelope] but represents
/// a "opened" envelope, i.e. message.
#[cfg(all(feature = "demo", feature = "test"))]
#[derive(Debug, Clone)]
pub struct Message<'a, Vid, Bytes: AsRef<[u8]>> {
    pub sender: Vid,
    pub receiver: Vid,
    pub nonconfidential_data: Option<&'a [u8]>,
    pub message: Payload<'a, Bytes, Vid>,
}

/// Convenience interface which illustrates encoding as a single operation
#[cfg(all(feature = "demo", feature = "test"))]
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
    let mut cesr = encode_envelope_vec(Envelope {
        sender,
        receiver,
        nonconfidential_data,
    })?;

    let ciphertext = &encrypt(receiver, encode_payload_vec(&message)?);

    encode_ciphertext(ciphertext, &mut cesr)?;
    encode_signature(&sign(sender, &cesr), &mut cesr);

    Ok(cesr)
}

/// A convenience interface which illustrates decoding as a single operation
#[cfg(all(feature = "demo", feature = "test"))]
pub fn decode_tsp_message<'a, Vid: TryFrom<&'a [u8]>>(
    data: &'a [u8],
    decrypt: impl FnOnce(&Vid, &[u8]) -> Vec<u8>,
    verify: impl FnOnce(&[u8], &Vid, &Signature) -> bool,
) -> Result<Message<Vid, Vec<u8>>, DecodeError> {
    let (
        DecodedEnvelope {
            envelope:
                Envelope {
                    sender,
                    receiver,
                    nonconfidential_data,
                },
            ciphertext,
            ..
        },
        VerificationChallenge {
            signed_data,
            signature,
        },
    ) = decode_envelope(data)?;

    if !verify(signed_data, &sender, signature) {
        return Err(DecodeError::SignatureError);
    }

    let decrypted = decrypt(&receiver, ciphertext);

    // This illustrates a challenge: unless decryption happens in place, either a needless
    // allocation or at the very least moving the contents of the payload around must occur.
    let Payload::GenericMessage(message) = decode_payload(&decrypted)?;
    let message = Payload::GenericMessage(message.to_owned());

    Ok(Message {
        sender,
        receiver,
        nonconfidential_data,
        message,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn envelope_without_nonconfidential_data() {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload =
            { encode_payload_vec(&Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_ets_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: None,
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let (
            DecodedEnvelope {
                envelope: env,
                ciphertext,
                ..
            },
            ver,
        ) = decode_envelope::<&[u8]>(&outer).unwrap();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));
        assert_eq!(env.nonconfidential_data, None);

        let Payload::<_, &[u8]>::GenericMessage(data) =
            decode_payload(dummy_crypt(ciphertext.unwrap())).unwrap()
        else {
            unreachable!();
        };
        assert_eq!(data, b"Hello TSP!");
    }

    #[test]
    fn envelope_with_nonconfidential_data() {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload =
            { encode_payload_vec(&Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_ets_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let (
            DecodedEnvelope {
                envelope: env,
                ciphertext,
                ..
            },
            ver,
        ) = decode_envelope::<&[u8]>(&outer).unwrap();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));
        assert_eq!(env.nonconfidential_data, Some(&b"treasure"[..]));

        let Payload::<_, &[u8]>::GenericMessage(data) =
            decode_payload(dummy_crypt(ciphertext.unwrap())).unwrap()
        else {
            unreachable!();
        };
        assert_eq!(data, b"Hello TSP!");
    }

    #[test]
    fn envelope_without_confidential_data() {
        let fixed_sig = [1; 64];

        let mut outer = encode_s_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let (
            DecodedEnvelope {
                envelope: env,
                ciphertext,
                ..
            },
            ver,
        ) = decode_envelope::<&[u8]>(&outer).unwrap();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, Some(&b"Bobbi"[..]));
        assert_eq!(env.nonconfidential_data, Some(&b"treasure"[..]));

        assert!(ciphertext.is_none());
    }

    #[test]
    fn s_envelope_with_confidential_data_failure() {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload =
            { encode_payload_vec(&Payload::<_, &[u8]>::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_s_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload); // this is wrong
        encode_ciphertext(ciphertext, &mut outer).unwrap();
        encode_signature(&fixed_sig, &mut outer);

        assert!(decode_envelope::<&[u8]>(&outer).is_err());
    }

    #[test]
    fn envelope_failure() {
        let fixed_sig = [1; 64];

        let mut outer = vec![];
        encode_ets_envelope(
            Envelope {
                sender: &b"Alister"[..],
                receiver: Some(&b"Bobbi"[..]),
                nonconfidential_data: Some(b"treasure"),
            },
            &mut outer,
        )
        .unwrap();
        encode_signature(&fixed_sig, &mut outer);
        encode_ciphertext(&[], &mut outer).unwrap();

        assert!(decode_envelope::<&[u8]>(&outer).is_err());
    }

    #[test]
    fn trailing_data() {
        let fixed_sig = [1; 64];

        let mut outer = encode_ets_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        encode_ciphertext(&[], &mut outer).unwrap();
        encode_signature(&fixed_sig, &mut outer);
        outer.push(b'-');

        assert!(decode_envelope::<&[u8]>(&outer).is_err());
    }

    #[cfg(all(feature = "demo", feature = "test"))]
    #[test]
    fn convenience() {
        let sender = b"Alister".as_slice();
        let receiver = b"Bobbi".as_slice();
        let payload = b"Hello TSP!";
        let data = encode_tsp_message(
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
            &data,
            |_: &&[u8], x| x.to_vec(),
            |_, _, sig| sig == &[5u8; 64],
        )
        .unwrap();

        assert_eq!(tsp.sender, b"Alister".as_slice());
        assert_eq!(tsp.receiver, b"Bobbi");

        let Payload::GenericMessage(content) = tsp.message;
        assert_eq!(&content[..], b"Hello TSP!");
    }

    #[test]
    fn mut_envelope_with_nonconfidential_data() {
        test_turn_around(Payload::GenericMessage(&b"Hello TSP!"[..]));
    }

    #[test]
    fn test_nested_msg() {
        test_turn_around(Payload::NestedMessage(&b"Hello TSP!"[..]));
    }

    #[test]
    fn test_routed_msg() {
        test_turn_around(Payload::RoutedMessage(
            vec![b"foo", b"bar"],
            &b"Hello TSP!"[..],
        ));
    }

    fn test_turn_around(payload: Payload<&[u8], &[u8]>) {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload = encode_payload_vec(&payload).unwrap();

        let mut outer = encode_ets_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: Some(&b"Bobbi"[..]),
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let view = decode_envelope_mut(&mut outer).unwrap();
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
            decode_payload(dummy_crypt(ciphertext.unwrap())).unwrap(),
            payload
        );
    }

    #[test]
    fn test_relation_forming() {
        let temp = (1u8..33).collect::<Vec<u8>>();
        let nonce: &[u8; 32] = temp.as_slice().try_into().unwrap();
        test_turn_around(Payload::DirectRelationProposal {
            nonce: Nonce(*nonce),
            hops: vec![],
        });
        test_turn_around(Payload::DirectRelationAffirm { reply: nonce });
        let new_vid = &[];
        test_turn_around(Payload::NestedRelationProposal { new_vid });
        test_turn_around(Payload::NestedRelationAffirm {
            new_vid,
            connect_to_vid: new_vid,
            reply: nonce,
        });

        test_turn_around(Payload::RelationshipCancel {
            reply: nonce,
            nonce: Nonce(*nonce),
        });
    }

    #[test]
    fn test_message_to_parts() {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let message = Base64UrlUnpadded::decode_vec("-EABXAAA7VIDAAAEZGlkOnRlc3Q6Ym9i8VIDAAAFAGRpZDp0ZXN0OmFsaWNl6BAEAABleHRyYSBkYXRh4CAXScvzIiBCgfOu9jHtGwd1qN-KlMB7uhFbE9YOSyTmnp9yziA1LVPdQmST27yjuDRTlxeRo7H7gfuaGFY4iyf2EsfiqvEg0BBNDbKoW0DDczGxj7rNWKH_suyj18HCUxMZ6-mDymZdNhHZIS8zIstC9Kxv5Q-GxmI-1v4SNbeCemuCMBzMPogK").unwrap();
        let parts = open_message_into_parts(&message).unwrap();

        assert_eq!(parts.prefix.prefix.len(), 6);
        assert_eq!(parts.sender.data.len(), 12);
        assert_eq!(parts.receiver.unwrap().data.len(), 14);
        assert_eq!(parts.ciphertext.unwrap().data.len(), 69);
    }
}
