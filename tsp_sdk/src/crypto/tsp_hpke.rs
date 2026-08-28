use crate::{
    cesr::{CryptoType, DecodedPayload, Envelope},
    definitions::{Payload, PrivateVid, TSPMessage, VerifiedVid, VidEncryptionKeyType},
};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::AeadTag,
    inout::InOutBuf, single_shot_open_inout_detached, single_shot_seal_inout_detached,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};

use super::{
    CryptoError, MessageContents, ParallelSignatureInfo, RelationshipDigestAlgorithm,
    append_signature, build_relationship_accept_payload, build_relationship_request_payload,
    open_relationship_accept, open_relationship_request, signature_type,
};

type Aead = hpke::aead::ChaCha20Poly1305;
type Kdf = hpke::kdf::HkdfSha256;
type X25519Kem = hpke::kem::X25519HkdfSha256;
/// The PQ/T hybrid KEM X25519MLKEM768 (HPKE KEM id 0x647a); there is no separate
/// post-quantum ciphertext code or mode -- only the KEM differs (spec 8.2.3)
type PqKem = hpke::kem::XWing;

/// The HPKE `info` input: the TSP protocol CESR code (spec 8.2.2, 9.1)
const HPKE_INFO: &[u8] = b"YTSP-";

type SealPayload<'a> = crate::cesr::Payload<'a, &'a [u8], &'a [u8]>;
type PreparedPayload<'a> = (SealPayload<'a>, Option<super::Digest>);

#[allow(clippy::too_many_arguments)]
fn payload_for_seal<'a>(
    secret_payload: &'a Payload<'a, &'a [u8]>,
    sender_in_payload: Option<&'a [u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    envelope_prefix: &[u8],
    request_nonce_override: Option<[u8; 16]>,
    csprng: &mut StdRng,
    request_digest_storage: &'a mut super::Digest,
    reply_digest_storage: &'a mut super::Digest,
) -> Result<PreparedPayload<'a>, CryptoError> {
    let mut payload_digest_override = None;

    let payload = match secret_payload {
        Payload::Content(data) => crate::cesr::Payload::GenericMessage(*data),
        Payload::RequestRelationship {
            thread_id: _ignored,
            form,
        } => {
            let nonce_bytes = request_nonce_override.unwrap_or_else(|| {
                let mut nonce_bytes = [0_u8; 16];
                csprng.fill_bytes(&mut nonce_bytes);
                nonce_bytes
            });

            let (payload, payload_digest) = build_relationship_request_payload(
                form,
                sender_in_payload,
                digest_algorithm,
                nonce_bytes,
                envelope_prefix,
                request_digest_storage,
            )?;
            payload_digest_override = Some(payload_digest);
            payload
        }
        Payload::AcceptRelationship {
            thread_id,
            reply_thread_id: _ignored,
            form,
        } => {
            let (payload, payload_digest) = build_relationship_accept_payload(
                thread_id,
                form,
                sender_in_payload,
                digest_algorithm,
                envelope_prefix,
                reply_digest_storage,
            )?;
            payload_digest_override = Some(payload_digest);
            payload
        }
        Payload::CancelRelationship { thread_id } => crate::cesr::Payload::RelationshipCancel {
            nonce: crate::cesr::Nonce::generate(|dst| csprng.fill_bytes(dst)),
            reply: digest_algorithm.field(thread_id),
        },
        Payload::NestedMessage(data) => crate::cesr::Payload::NestedMessage(*data),
        Payload::RoutedMessage(hops, data) => {
            crate::cesr::Payload::RoutedMessage(hops.clone(), *data)
        }
    };

    Ok((payload, payload_digest_override))
}

/// Seal a message with HPKE-Base (spec 8.2.2). The KEM is selected by the
/// recipient VID's encryption key type; everything else is identical.
pub(crate) fn seal(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    secret_payload: Payload<&[u8]>,
    digest: Option<&mut super::Digest>,
    request_nonce_override: Option<[u8; 16]>,
) -> Result<TSPMessage, CryptoError> {
    match receiver.encryption_key_type() {
        VidEncryptionKeyType::X25519 => seal_with_kem::<X25519Kem>(
            sender,
            receiver,
            secret_payload,
            digest,
            request_nonce_override,
        ),
        VidEncryptionKeyType::X25519MlKem768 => seal_with_kem::<PqKem>(
            sender,
            receiver,
            secret_payload,
            digest,
            request_nonce_override,
        ),
    }
}

fn seal_with_kem<Kem: KemTrait>(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    secret_payload: Payload<&[u8]>,
    digest: Option<&mut super::Digest>,
    request_nonce_override: Option<[u8; 16]>,
) -> Result<TSPMessage, CryptoError> {
    let crypto_type = CryptoType::HpkeBase;
    let mut csprng = StdRng::from_entropy();
    let mut data = Vec::with_capacity(64);

    // the envelope fields (version, sender VID, receiver VID); these are
    // exactly the aad of the spec: aad = CONCAT(TSP_Version, VID_sndr, VID_rcvr)
    crate::cesr::encode_envelope(
        crate::cesr::Envelope {
            crypto_type,
            signature_type: signature_type(sender),
            sender: sender.identifier(),
            receiver: Some(receiver.identifier()),
        },
        &mut data,
    )?;

    let sender_in_payload = Some(sender.identifier().as_bytes());
    let mut request_digest_storage = [0_u8; 32];
    let mut reply_digest_storage = [0_u8; 32];
    let digest_algorithm = RelationshipDigestAlgorithm::for_crypto_type(crypto_type)?;
    let (secret_payload, payload_digest_override) = payload_for_seal(
        &secret_payload,
        sender_in_payload,
        digest_algorithm,
        &data,
        request_nonce_override,
        &mut csprng,
        &mut request_digest_storage,
        &mut reply_digest_storage,
    )?;

    let mut cesr_message = Vec::with_capacity(secret_payload.calculate_size(sender_in_payload));
    crate::cesr::encode_payload(&secret_payload, sender_in_payload, None, &mut cesr_message)?;

    if let Some(digest) = digest {
        *digest = payload_digest_override.unwrap_or_else(|| digest_algorithm.hash(&cesr_message));
    }

    let message_receiver = Kem::PublicKey::from_bytes(receiver.encryption_key().as_ref())?;

    let (encapped_key, tag) = single_shot_seal_inout_detached::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &message_receiver,
        HPKE_INFO,
        InOutBuf::from(cesr_message.as_mut_slice()),
        &data,
    )?;

    // the wire ciphertext is CONCAT(enc, ct), with the AEAD tag inside ct (spec 9.2.8)
    let encapped_key = encapped_key.to_bytes();
    let mut ciphertext =
        Vec::with_capacity(encapped_key.len() + cesr_message.len() + AeadTag::<Aead>::size());
    ciphertext.extend(encapped_key.as_slice());
    ciphertext.extend(&cesr_message);
    ciphertext.extend(tag.to_bytes());

    crate::cesr::encode_ciphertext(&ciphertext, crypto_type, &mut data)?;
    crate::cesr::finalize_envelope_frame(&mut data);
    append_signature(sender, &mut data)?;

    Ok(data)
}

/// Open an HPKE-Base message; the KEM is selected by the receiving VID's key type
pub(crate) fn open<'a>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    raw_header: &'a [u8],
    envelope: Envelope<&[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
    match receiver.encryption_key_type() {
        VidEncryptionKeyType::X25519 => {
            open_with_kem::<X25519Kem>(receiver, sender, raw_header, envelope, ciphertext)
        }
        VidEncryptionKeyType::X25519MlKem768 => {
            open_with_kem::<PqKem>(receiver, sender, raw_header, envelope, ciphertext)
        }
    }
}

fn open_with_kem<'a, Kem: KemTrait>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    raw_header: &'a [u8],
    envelope: Envelope<&[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
    // the wire ciphertext is CONCAT(enc, ct); the encapsulated key size is
    // known from the KEM, and the AEAD tag sits at the end of ct
    let enc_size = Kem::EncappedKey::size();
    let tag_size = AeadTag::<Aead>::size();
    if ciphertext.len() < enc_size + tag_size {
        return Err(CryptoError::MissingCiphertext);
    }
    let (encapped_key, rest) = ciphertext.split_at_mut(enc_size);
    let (ciphertext, tag) = rest.split_at_mut(rest.len() - tag_size);

    let receiver_decryption_key = Kem::PrivateKey::from_bytes(receiver.decryption_key().as_ref())?;
    let encapped_key = Kem::EncappedKey::from_bytes(encapped_key)?;
    let tag = AeadTag::<Aead>::from_bytes(tag)?;

    single_shot_open_inout_detached::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &receiver_decryption_key,
        &encapped_key,
        HPKE_INFO,
        InOutBuf::from(&mut *ciphertext),
        raw_header,
        &tag,
    )?;

    open_payload(sender, raw_header, envelope, ciphertext)
}

fn open_payload<'a>(
    sender: &dyn VerifiedVid,
    raw_header: &[u8],
    envelope: Envelope<&[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
    #[allow(unused_variables)]
    let DecodedPayload {
        payload,
        sender_identity,
    } = crate::cesr::decode_payload(ciphertext)?;

    // verify the embedded self-referencing digest of relationship payloads
    super::verify_relationship_digest(&payload, sender_identity, raw_header)?;

    // In HPKE-Base the sender-VID confidential field is optional (the aad binds
    // the sender identity); when present it MUST match the envelope (spec 8.2.2)
    if let Some(id) = sender_identity
        && id != sender.identifier().as_bytes()
    {
        return Err(CryptoError::UnexpectedSender);
    }

    let (secret_payload, parallel_signature_info) = match payload {
        crate::cesr::Payload::GenericMessage(data) => (Payload::Content(data as _), None),
        crate::cesr::Payload::DirectRelationProposal { request_digest, .. } => (
            open_relationship_request(
                *request_digest.as_bytes(),
                crate::definitions::RelationshipForm::Direct,
            ),
            None,
        ),
        crate::cesr::Payload::DirectRelationAffirm {
            request_digest,
            reply_digest,
        } => (
            open_relationship_accept(
                *request_digest.as_bytes(),
                *reply_digest.as_bytes(),
                crate::definitions::RelationshipForm::Direct,
            ),
            None,
        ),
        crate::cesr::Payload::ParallelRelationProposal {
            nonce,
            request_digest,
            sig_new_vid,
            new_vid,
            ..
        } => (
            open_relationship_request(
                *request_digest.as_bytes(),
                crate::definitions::RelationshipForm::Parallel {
                    new_vid,
                    sig_new_vid,
                },
            ),
            Some(ParallelSignatureInfo {
                new_vid,
                sig_new_vid,
                signed_data: crate::cesr::encode_parallel_relation_proposal_challenge(
                    sender_identity,
                    &nonce,
                    request_digest,
                    new_vid,
                )?,
            }),
        ),
        crate::cesr::Payload::ParallelRelationAffirm {
            request_digest,
            reply_digest,
            sig_new_vid,
            new_vid,
        } => (
            open_relationship_accept(
                *request_digest.as_bytes(),
                *reply_digest.as_bytes(),
                crate::definitions::RelationshipForm::Parallel {
                    new_vid,
                    sig_new_vid,
                },
            ),
            Some(ParallelSignatureInfo {
                new_vid,
                sig_new_vid,
                signed_data: crate::cesr::encode_parallel_relation_affirm_challenge(
                    sender_identity,
                    request_digest,
                    reply_digest,
                    new_vid,
                )?,
            }),
        ),
        crate::cesr::Payload::ControlMessage(_) | crate::cesr::Payload::Padding { .. } => {
            // recognized on the wire, but not yet surfaced through the API
            return Err(CryptoError::UnsupportedPayload);
        }
        crate::cesr::Payload::RelationshipCancel { reply, .. } => (
            Payload::CancelRelationship {
                thread_id: *reply.as_bytes(),
            },
            None,
        ),
        crate::cesr::Payload::NestedMessage(data) => (Payload::NestedMessage(data), None),
        crate::cesr::Payload::RoutedMessage(hops, data) => {
            (Payload::RoutedMessage(hops, data as _), None)
        }
    };

    Ok((
        (
            secret_payload,
            envelope.crypto_type,
            envelope.signature_type,
        ),
        parallel_signature_info,
    ))
}
