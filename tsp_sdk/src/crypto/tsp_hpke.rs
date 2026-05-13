use crate::{
    cesr::{CryptoType, DecodedPayload, Envelope},
    definitions::{NonConfidentialData, Payload, PrivateVid, TSPMessage, VerifiedVid},
};
use hpke::{
    Deserializable, OpModeR, OpModeS, Serializable, single_shot_open_in_place_detached,
    single_shot_seal_in_place_detached,
};
use hpke_pq::{
    Deserializable as PqDeserializable, OpModeR as PqOpModeR, OpModeS as PqOpModeS,
    Serializable as PqSerializable,
    single_shot_open_in_place_detached as pq_single_shot_open_in_place_detached,
    single_shot_seal_in_place_detached as pq_single_shot_seal_in_place_detached,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};

use super::{
    CryptoError, MessageContents, ParallelSignatureInfo, RelationshipDigestAlgorithm,
    append_signature, build_relationship_accept_payload, build_relationship_request_payload,
    open_relationship_accept, open_relationship_request, signature_type,
};

type X25519Aead = hpke::aead::ChaCha20Poly1305;
type X25519Kdf = hpke::kdf::HkdfSha256;
type X25519Kem = hpke::kem::X25519HkdfSha256;

type PqAead = hpke_pq::aead::ChaCha20Poly1305;
type PqKdf = hpke_pq::kdf::HkdfSha256;
type PqKem = hpke_pq::kem::X25519Kyber768Draft00;
type SealPayload<'a> = crate::cesr::Payload<'a, &'a [u8], &'a [u8]>;
type PreparedPayload<'a> = (SealPayload<'a>, Option<super::Digest>);

fn payload_for_seal<'a>(
    secret_payload: &'a Payload<'a, &'a [u8]>,
    sender_in_payload: Option<&'a [u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    request_nonce_override: Option<[u8; 32]>,
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
                let mut nonce_bytes = [0_u8; 32];
                csprng.fill_bytes(&mut nonce_bytes);
                nonce_bytes
            });

            let (payload, payload_digest) = build_relationship_request_payload(
                form,
                sender_in_payload,
                digest_algorithm,
                nonce_bytes,
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
                reply_digest_storage,
            )?;
            payload_digest_override = Some(payload_digest);
            payload
        }
        Payload::CancelRelationship { thread_id } => crate::cesr::Payload::RelationshipCancel {
            reply: digest_algorithm.field(thread_id),
        },
        Payload::NestedMessage(data) => crate::cesr::Payload::NestedMessage(*data),
        Payload::RoutedMessage(hops, data) => {
            crate::cesr::Payload::RoutedMessage(hops.clone(), *data)
        }
    };

    Ok((payload, payload_digest_override))
}

pub(crate) fn seal_x25519(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    secret_payload: Payload<&[u8]>,
    digest: Option<&mut super::Digest>,
    request_nonce_override: Option<[u8; 32]>,
    crypto_type: CryptoType,
) -> Result<TSPMessage, CryptoError> {
    if !matches!(crypto_type, CryptoType::HpkeAuth | CryptoType::HpkeEssr) {
        return Err(CryptoError::InvalidCryptoSelection(crypto_type));
    }

    let mut csprng = StdRng::from_entropy();
    let mut data = Vec::with_capacity(64);

    crate::cesr::encode_ets_envelope(
        crate::cesr::Envelope {
            crypto_type,
            signature_type: signature_type(sender),
            sender: sender.identifier(),
            receiver: Some(receiver.identifier()),
            nonconfidential_data,
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
        request_nonce_override,
        &mut csprng,
        &mut request_digest_storage,
        &mut reply_digest_storage,
    )?;

    let mut cesr_message = Vec::with_capacity(
        secret_payload.calculate_size(sender_in_payload)
            + hpke::aead::AeadTag::<X25519Aead>::size()
            + <X25519Kem as hpke::Kem>::EncappedKey::size(),
    );
    crate::cesr::encode_payload(&secret_payload, sender_in_payload, &mut cesr_message)?;

    let mode = if crypto_type == CryptoType::HpkeEssr {
        OpModeS::Base
    } else {
        let sender_decryption_key =
            <X25519Kem as hpke::Kem>::PrivateKey::from_bytes(sender.decryption_key().as_ref())?;
        let sender_encryption_key =
            <X25519Kem as hpke::Kem>::PublicKey::from_bytes(sender.encryption_key().as_ref())?;

        OpModeS::Auth((sender_decryption_key, sender_encryption_key))
    };

    let message_receiver =
        <X25519Kem as hpke::Kem>::PublicKey::from_bytes(receiver.encryption_key().as_ref())?;

    if let Some(digest) = digest {
        *digest = payload_digest_override.unwrap_or_else(|| digest_algorithm.hash(&cesr_message));
    }

    let (encapped_key, tag) =
        single_shot_seal_in_place_detached::<X25519Aead, X25519Kdf, X25519Kem, StdRng>(
            &mode,
            &message_receiver,
            &data,
            &mut cesr_message,
            &[],
            &mut csprng,
        )?;

    cesr_message.extend(tag.to_bytes());
    cesr_message.extend(encapped_key.to_bytes());
    crate::cesr::encode_ciphertext(&cesr_message, crypto_type, &mut data)?;
    append_signature(sender, &mut data)?;

    Ok(data)
}

pub(crate) fn seal_pq(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    secret_payload: Payload<&[u8]>,
    digest: Option<&mut super::Digest>,
    request_nonce_override: Option<[u8; 32]>,
) -> Result<TSPMessage, CryptoError> {
    let crypto_type = CryptoType::X25519Kyber768Draft00;
    let mut csprng = StdRng::from_entropy();
    let mut data = Vec::with_capacity(64);

    crate::cesr::encode_ets_envelope(
        crate::cesr::Envelope {
            crypto_type,
            signature_type: signature_type(sender),
            sender: sender.identifier(),
            receiver: Some(receiver.identifier()),
            nonconfidential_data,
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
        request_nonce_override,
        &mut csprng,
        &mut request_digest_storage,
        &mut reply_digest_storage,
    )?;

    let mut cesr_message = Vec::with_capacity(
        secret_payload.calculate_size(sender_in_payload)
            + hpke_pq::aead::AeadTag::<PqAead>::size()
            + <PqKem as hpke_pq::Kem>::EncappedKey::size(),
    );
    crate::cesr::encode_payload(&secret_payload, sender_in_payload, &mut cesr_message)?;

    let message_receiver =
        <PqKem as hpke_pq::Kem>::PublicKey::from_bytes(receiver.encryption_key().as_ref())?;

    if let Some(digest) = digest {
        *digest = payload_digest_override.unwrap_or_else(|| digest_algorithm.hash(&cesr_message));
    }

    let (encapped_key, tag) = pq_single_shot_seal_in_place_detached::<PqAead, PqKdf, PqKem, StdRng>(
        &PqOpModeS::Base,
        &message_receiver,
        &data,
        &mut cesr_message,
        &[],
        &mut csprng,
    )?;

    cesr_message.extend(tag.to_bytes());
    cesr_message.extend(encapped_key.to_bytes());
    crate::cesr::encode_ciphertext(&cesr_message, crypto_type, &mut data)?;
    append_signature(sender, &mut data)?;

    Ok(data)
}

pub(crate) fn open_x25519<'a>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    raw_header: &'a [u8],
    envelope: Envelope<'a, &[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - hpke::aead::AeadTag::<X25519Aead>::size()
            - <X25519Kem as hpke::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <X25519Kem as hpke::Kem>::EncappedKey::size());

    let receiver_decryption_key =
        <X25519Kem as hpke::Kem>::PrivateKey::from_bytes(receiver.decryption_key().as_ref())?;
    let encapped_key = <X25519Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key)?;
    let tag = hpke::aead::AeadTag::<X25519Aead>::from_bytes(tag)?;

    let mode = if envelope.crypto_type == CryptoType::HpkeEssr {
        OpModeR::Base
    } else {
        let sender_encryption_key =
            <X25519Kem as hpke::Kem>::PublicKey::from_bytes(sender.encryption_key().as_ref())?;
        OpModeR::Auth(sender_encryption_key)
    };

    single_shot_open_in_place_detached::<X25519Aead, X25519Kdf, X25519Kem>(
        &mode,
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )?;

    open_payload(sender, envelope, ciphertext)
}

pub(crate) fn open_pq<'a>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    raw_header: &'a [u8],
    envelope: Envelope<'a, &[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
    let (ciphertext, footer) = ciphertext.split_at_mut(
        ciphertext.len()
            - hpke_pq::aead::AeadTag::<PqAead>::size()
            - <PqKem as hpke_pq::Kem>::EncappedKey::size(),
    );
    let (tag, encapped_key) =
        footer.split_at(footer.len() - <PqKem as hpke_pq::Kem>::EncappedKey::size());

    let receiver_decryption_key =
        <PqKem as hpke_pq::Kem>::PrivateKey::from_bytes(receiver.decryption_key().as_ref())?;
    let encapped_key = <PqKem as hpke_pq::Kem>::EncappedKey::from_bytes(encapped_key)?;
    let tag = hpke_pq::aead::AeadTag::<PqAead>::from_bytes(tag)?;

    pq_single_shot_open_in_place_detached::<PqAead, PqKdf, PqKem>(
        &PqOpModeR::Base,
        &receiver_decryption_key,
        &encapped_key,
        raw_header,
        ciphertext,
        &[],
        &tag,
    )?;

    open_payload(sender, envelope, ciphertext)
}

fn open_payload<'a>(
    sender: &dyn VerifiedVid,
    envelope: Envelope<'a, &[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
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
            envelope.nonconfidential_data,
            secret_payload,
            envelope.crypto_type,
            envelope.signature_type,
        ),
        parallel_signature_info,
    ))
}
