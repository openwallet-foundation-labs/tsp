use crate::{
    cesr::{CryptoType, DecodedPayload, Envelope},
    definitions::{Payload, PrivateVid, VerifiedVid},
};
use crypto_box::{PublicKey, SecretKey};

use super::{
    CryptoError, MessageContents, ParallelSignatureInfo, open_relationship_accept,
    open_relationship_request,
};
use super::{
    RelationshipDigestAlgorithm, append_signature, build_relationship_accept_payload,
    build_relationship_request_payload, signature_type,
};
use crate::definitions::TSPMessage;
use crypto_box::aead::OsRng;
use rand::{RngCore, SeedableRng, rngs::StdRng};

pub(crate) fn seal(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    secret_payload: Payload<&[u8]>,
    digest: Option<&mut super::Digest>,
    request_nonce_override: Option<[u8; 16]>,
) -> Result<TSPMessage, CryptoError> {
    let crypto_type = CryptoType::SealedBox;
    let mut csprng = StdRng::from_entropy();

    let mut data = Vec::with_capacity(64);
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
    let mut payload_digest_override = None;
    let digest_algorithm = RelationshipDigestAlgorithm::for_crypto_type(crypto_type)?;

    let secret_payload = match secret_payload {
        Payload::Content(data) => crate::cesr::Payload::GenericMessage(data),
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
                &form,
                sender_in_payload,
                digest_algorithm,
                nonce_bytes,
                &mut request_digest_storage,
            )?;
            payload_digest_override = Some(payload_digest);
            payload
        }
        Payload::AcceptRelationship {
            ref thread_id,
            reply_thread_id: _ignored,
            form,
        } => {
            let (payload, payload_digest) = build_relationship_accept_payload(
                thread_id,
                &form,
                sender_in_payload,
                digest_algorithm,
                &mut reply_digest_storage,
            )?;
            payload_digest_override = Some(payload_digest);
            payload
        }
        Payload::CancelRelationship { ref thread_id } => crate::cesr::Payload::RelationshipCancel {
            nonce: crate::cesr::Nonce::generate(|dst| csprng.fill_bytes(dst)),
            reply: digest_algorithm.field(thread_id),
        },
        Payload::NestedMessage(data) => crate::cesr::Payload::NestedMessage(data),
        Payload::RoutedMessage(hops, data) => crate::cesr::Payload::RoutedMessage(hops, data),
    };

    // prepare CESR-encoded ciphertext
    let mut cesr_message = Vec::new();

    crate::cesr::encode_payload(&secret_payload, sender_in_payload, None, &mut cesr_message)?;

    // hash the raw bytes of the plaintext before encryption
    if let Some(digest) = digest {
        *digest = payload_digest_override.unwrap_or_else(|| digest_algorithm.hash(&cesr_message));
    }

    // the libsodium anonymous sealed box: an ephemeral key pair, the nonce
    // derived from the ephemeral and recipient public keys, X25519 +
    // XSalsa20-Poly1305 (spec 8.3). The sender's static keys are not used;
    // sender authenticity comes from the ESSR sender-VID field and the signature.
    let receiver_public_key = PublicKey::from_slice(receiver.encryption_key())?;
    let ciphertext = receiver_public_key.seal(&mut OsRng, &cesr_message)?;

    // encode and append the ciphertext to the envelope data
    crate::cesr::encode_ciphertext(&ciphertext, crypto_type, &mut data)?;
    crate::cesr::finalize_envelope_frame(&mut data);

    append_signature(sender, &mut data)?;

    Ok(data)
}

pub(crate) fn open<'a>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    _raw_header: &'a [u8],
    envelope: Envelope<&[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
    let receiver_secret_key = SecretKey::from_slice(receiver.decryption_key().as_slice())?;
    let plaintext = receiver_secret_key.unseal(ciphertext)?;

    // the sealed box decrypts into a fresh buffer; copy back into the message
    // buffer so the payload can borrow from it
    let ciphertext = &mut ciphertext[..plaintext.len()];
    ciphertext.copy_from_slice(&plaintext);

    let DecodedPayload {
        payload,
        sender_identity,
    } = crate::cesr::decode_payload(ciphertext)?;

    // the sealed box is anonymous: the ESSR sender-VID confidential field is
    // required and MUST match the envelope (spec 8.3.2)
    match sender_identity {
        Some(id) => {
            if id != sender.identifier().as_bytes() {
                return Err(CryptoError::UnexpectedSender);
            }
        }
        None => return Err(CryptoError::MissingSender),
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
