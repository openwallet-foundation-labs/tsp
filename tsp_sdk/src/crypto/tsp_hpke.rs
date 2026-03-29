use crate::{
    cesr::{CryptoType, DecodedPayload, Envelope},
    definitions::{Payload, PrivateVid, VerifiedVid},
};

#[cfg(not(feature = "nacl"))]
use crate::{
    cesr::SignatureType,
    definitions::{NonConfidentialData, TSPMessage, VidSignatureKeyType},
};

#[cfg(not(feature = "nacl"))]
use ed25519_dalek::Signer;
#[cfg(not(feature = "nacl"))]
use rand::{RngCore, SeedableRng, rngs::StdRng};

#[cfg(not(feature = "pq"))]
use hpke::{
    Deserializable, OpModeR, Serializable, aead, kdf, kem, single_shot_open_in_place_detached,
};

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
use hpke::{OpModeS, single_shot_seal_in_place_detached};

use super::{
    CryptoError, MessageContents, ParallelSignatureInfo, open_relationship_accept,
    open_relationship_request,
};
#[cfg(not(feature = "nacl"))]
use super::{
    RelationshipDigestAlgorithm, build_relationship_accept_payload,
    build_relationship_request_payload,
};
#[cfg(feature = "pq")]
use hpke_pq::{
    Deserializable, OpModeR, OpModeS, Serializable, aead, kdf, kem,
    single_shot_open_in_place_detached, single_shot_seal_in_place_detached,
};
#[cfg(feature = "pq")]
use ml_dsa::{EncodedSigningKey, MlDsa65};

#[cfg(not(feature = "nacl"))]
pub(crate) fn seal<A, Kdf, Kem>(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    secret_payload: Payload<&[u8]>,
    digest: Option<&mut super::Digest>,
    request_nonce_override: Option<[u8; 32]>,
) -> Result<TSPMessage, CryptoError>
where
    A: aead::Aead,
    Kdf: kdf::Kdf,
    Kem: kem::Kem + crate::cesr::AsCryptoType,
{
    let mut csprng = StdRng::from_entropy();

    let mut data = Vec::with_capacity(64);

    let signature_type = match sender.signature_key_type() {
        VidSignatureKeyType::Ed25519 => SignatureType::Ed25519,
        #[cfg(feature = "pq")]
        VidSignatureKeyType::MlDsa65 => SignatureType::MlDsa65,
    };

    let crypto_type = Kem::crypto_type();

    crate::cesr::encode_ets_envelope(
        crate::cesr::Envelope {
            crypto_type,
            signature_type,
            sender: sender.identifier(),
            receiver: Some(receiver.identifier()),
            nonconfidential_data,
        },
        &mut data,
    )?;

    let sender_in_payload = Some(sender.identifier().as_bytes());

    let mut request_digest_storage = [0_u8; 32];
    let mut reply_digest_storage = [0_u8; 32];
    let mut payload_digest_override = None;

    let secret_payload = match secret_payload {
        Payload::Content(data) => crate::cesr::Payload::GenericMessage(data),
        Payload::RequestRelationship {
            thread_id: _ignored,
            form,
        } => {
            let nonce_bytes = request_nonce_override.unwrap_or_else(|| {
                let mut nonce_bytes = [0_u8; 32];
                csprng.fill_bytes(&mut nonce_bytes);
                nonce_bytes
            });

            let (payload, payload_digest) = build_relationship_request_payload(
                &form,
                sender_in_payload,
                RelationshipDigestAlgorithm::Sha2_256,
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
                RelationshipDigestAlgorithm::Sha2_256,
                &mut reply_digest_storage,
            )?;
            payload_digest_override = Some(payload_digest);
            payload
        }
        Payload::CancelRelationship { ref thread_id } => crate::cesr::Payload::RelationshipCancel {
            reply: crate::cesr::Digest::Sha2_256(thread_id),
        },
        Payload::NestedMessage(data) => crate::cesr::Payload::NestedMessage(data),
        Payload::RoutedMessage(hops, data) => crate::cesr::Payload::RoutedMessage(hops, data),
    };

    // prepare CESR-encoded ciphertext
    let mut cesr_message = Vec::with_capacity(
        // plaintext size
        secret_payload.calculate_size(sender_in_payload)
        // authenticated encryption tag length
        + aead::AeadTag::<A>::size()
        // encapsulated key length
        + Kem::EncappedKey::size(),
    );

    crate::cesr::encode_payload(&secret_payload, sender_in_payload, &mut cesr_message)?;

    // HPKE sender mode: "Auth" for ESSR and PQ features
    #[cfg(all(not(feature = "essr"), not(feature = "pq")))]
    let mode = {
        let sender_decryption_key = Kem::PrivateKey::from_bytes(sender.decryption_key().as_ref())?;
        let sender_encryption_key = Kem::PublicKey::from_bytes(sender.encryption_key().as_ref())?;

        OpModeS::Auth((sender_decryption_key, sender_encryption_key))
    };

    #[cfg(any(feature = "essr", feature = "pq"))]
    let mode = OpModeS::Base;

    // recipient public key
    let message_receiver = Kem::PublicKey::from_bytes(receiver.encryption_key().as_ref())?;

    // hash the raw bytes of the plaintext before encryption
    if let Some(digest) = digest {
        *digest = payload_digest_override.unwrap_or_else(|| crate::crypto::sha256(&cesr_message));
    }

    // perform encryption
    let (encapped_key, tag) = single_shot_seal_in_place_detached::<A, Kdf, Kem, StdRng>(
        &mode,
        &message_receiver,
        &data,
        &mut cesr_message,
        &[],
        &mut csprng,
    )?;

    // append the authentication tag and encapsulated key to the end of the ciphertext
    cesr_message.extend(tag.to_bytes());
    cesr_message.extend(encapped_key.to_bytes());

    // encode and append the ciphertext to the envelope data
    crate::cesr::encode_ciphertext(&cesr_message, crypto_type, &mut data)?;

    // create and append signature
    match sender.signature_key_type() {
        VidSignatureKeyType::Ed25519 => {
            let sign_key = ed25519_dalek::SigningKey::from_bytes(&TryInto::<[u8; 32]>::try_into(
                sender.signing_key().as_slice(),
            )?);
            let signature = sign_key.sign(&data).to_bytes();
            crate::cesr::encode_signature(&signature, &mut data, SignatureType::Ed25519);
        }
        #[cfg(feature = "pq")]
        VidSignatureKeyType::MlDsa65 => {
            let sign_key = ml_dsa::SigningKey::<MlDsa65>::decode(
                &EncodedSigningKey::<MlDsa65>::try_from(sender.signing_key().as_slice())?,
            );
            let signature = sign_key.sign(&data).encode();
            crate::cesr::encode_signature(signature.as_slice(), &mut data, SignatureType::MlDsa65);
        }
    }

    Ok(data)
}

pub(crate) fn open<'a, A, Kdf, Kem>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    raw_header: &'a [u8],
    envelope: Envelope<'a, &[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError>
where
    A: aead::Aead,
    Kdf: kdf::Kdf,
    Kem: kem::Kem,
{
    // split encapsulated key and authenticated encryption tag length
    let (ciphertext, footer) = ciphertext
        .split_at_mut(ciphertext.len() - aead::AeadTag::<A>::size() - Kem::EncappedKey::size());
    let (tag, encapped_key) = footer.split_at(footer.len() - Kem::EncappedKey::size());

    // construct correct key types
    let receiver_decryption_key = Kem::PrivateKey::from_bytes(receiver.decryption_key().as_ref())?;
    let encapped_key = Kem::EncappedKey::from_bytes(encapped_key)?;
    let tag = aead::AeadTag::from_bytes(tag)?;

    #[cfg(feature = "pq")]
    let mode = OpModeR::Base;

    #[cfg(not(feature = "pq"))]
    let mode = if envelope.crypto_type == CryptoType::HpkeEssr {
        OpModeR::Base
    } else {
        let sender_encryption_key = Kem::PublicKey::from_bytes(sender.encryption_key().as_ref())?;
        OpModeR::Auth(sender_encryption_key)
    };

    // decrypt the ciphertext
    single_shot_open_in_place_detached::<A, Kdf, Kem>(
        &mode,
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )?;

    #[allow(unused_variables)]
    let DecodedPayload {
        payload,
        sender_identity,
    } = crate::cesr::decode_payload(ciphertext)?;

    if envelope.crypto_type == CryptoType::HpkeEssr {
        match sender_identity {
            Some(id) => {
                if id != sender.identifier().as_bytes() {
                    return Err(CryptoError::UnexpectedSender);
                }
            }
            None => return Err(CryptoError::MissingSender),
        }
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
    };

    Ok((
        (
            envelope.nonconfidential_data,
            secret_payload,
            envelope.crypto_type,
            envelope.signature_type,
        ),
        parallel_signature_info,
    ))
}
