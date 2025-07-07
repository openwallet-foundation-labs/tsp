use crate::{
    cesr::{CryptoType, DecodedPayload, Envelope},
    definitions::{Payload, PrivateVid, VerifiedVid},
};

#[cfg(not(feature = "nacl"))]
use crate::{
    cesr::SignatureType,
    definitions::{NonConfidentialData, TSPMessage},
};

#[cfg(not(feature = "nacl"))]
use ed25519_dalek::Signer;
#[cfg(not(feature = "nacl"))]
use rand::{SeedableRng, rngs::StdRng};

#[cfg(not(feature = "pq"))]
use hpke::{
    Deserializable, OpModeR, Serializable, aead, kdf, kem, single_shot_open_in_place_detached,
};

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
use hpke::{OpModeS, single_shot_seal_in_place_detached};

#[cfg(feature = "pq")]
use hpke_pq::{
    Deserializable, OpModeR, OpModeS, Serializable, aead, kdf, kem,
    single_shot_open_in_place_detached, single_shot_seal_in_place_detached,
};

use super::{CryptoError, MessageContents};

#[cfg(not(feature = "nacl"))]
pub(crate) fn seal<A, Kdf, Kem>(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    secret_payload: Payload<&[u8]>,
    digest: Option<&mut super::Digest>,
) -> Result<TSPMessage, CryptoError>
where
    A: aead::Aead,
    Kdf: kdf::Kdf,
    Kem: kem::Kem + crate::cesr::AsCryptoType,
{
    let mut csprng = StdRng::from_entropy();

    let mut data = Vec::with_capacity(64);
    crate::cesr::encode_ets_envelope(
        crate::cesr::Envelope {
            crypto_type: Kem::crypto_type(),
            signature_type: SignatureType::Ed25519,
            sender: sender.identifier(),
            receiver: Some(receiver.identifier()),
            nonconfidential_data,
        },
        &mut data,
    )?;

    let secret_payload = match secret_payload {
        Payload::Content(data) => crate::cesr::Payload::GenericMessage(data),
        Payload::RequestRelationship {
            route,
            thread_id: _ignored,
        } => crate::cesr::Payload::DirectRelationProposal {
            nonce: fresh_nonce(&mut csprng),
            hops: route.unwrap_or_else(Vec::new),
        },
        Payload::AcceptRelationship { ref thread_id } => {
            crate::cesr::Payload::DirectRelationAffirm {
                reply: crate::cesr::Digest::Sha2_256(thread_id),
            }
        }
        Payload::RequestNestedRelationship {
            inner,
            thread_id: _ignored,
        } => crate::cesr::Payload::NestedRelationProposal {
            nonce: fresh_nonce(&mut csprng),
            message: inner,
        },
        Payload::AcceptNestedRelationship {
            ref thread_id,
            inner,
        } => crate::cesr::Payload::NestedRelationAffirm {
            reply: crate::cesr::Digest::Sha2_256(thread_id),
            message: inner,
        },
        Payload::CancelRelationship { ref thread_id } => crate::cesr::Payload::RelationshipCancel {
            reply: crate::cesr::Digest::Sha2_256(thread_id),
        },
        Payload::NestedMessage(data) => crate::cesr::Payload::NestedMessage(data),
        Payload::RoutedMessage(hops, data) => crate::cesr::Payload::RoutedMessage(hops, data),
        Payload::NewIdentifier {
            ref thread_id,
            new_vid,
        } => crate::cesr::Payload::NewIdentifierProposal {
            thread_id: crate::cesr::Digest::Sha2_256(thread_id),
            new_vid,
        },
        Payload::Referral { referred_vid } => {
            crate::cesr::Payload::RelationshipReferral { referred_vid }
        }
    };

    #[cfg(feature = "essr")]
    let sender_in_payload = Some(sender.identifier().as_bytes());
    #[cfg(not(feature = "essr"))]
    let sender_in_payload = None;

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
        *digest = crate::crypto::sha256(&cesr_message)
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
    crate::cesr::encode_ciphertext(&cesr_message, &mut data)?;

    // create and append outer signature
    let sign_key = ed25519_dalek::SigningKey::from_bytes(sender.signing_key());
    let signature = sign_key.sign(&data).to_bytes();
    crate::cesr::encode_signature(&signature, &mut data);

    Ok(data)
}

pub(crate) fn open<'a, A, Kdf, Kem>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    raw_header: &'a [u8],
    envelope: Envelope<'a, &[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<MessageContents<'a>, CryptoError>
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

    // micro-optimization: only compute the thread_id digest if we really need it; we cannot do this
    // later since after constructing the resulting Payload, we are giving out mutable borrows
    let thread_id = match crate::cesr::decode_payload(ciphertext)?.payload {
        crate::cesr::Payload::DirectRelationProposal { .. }
        | crate::cesr::Payload::NestedRelationProposal { .. } => crate::crypto::sha256(ciphertext),
        _ => Default::default(),
    };

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

    let secret_payload = match payload {
        crate::cesr::Payload::GenericMessage(data) => Payload::Content(data as _),
        crate::cesr::Payload::DirectRelationProposal { hops, .. } => Payload::RequestRelationship {
            route: if hops.is_empty() { None } else { Some(hops) },
            thread_id,
        },
        crate::cesr::Payload::DirectRelationAffirm { reply } => Payload::AcceptRelationship {
            thread_id: *reply.as_bytes(),
        },
        crate::cesr::Payload::NestedRelationProposal { message: inner, .. } => {
            Payload::RequestNestedRelationship { inner, thread_id }
        }
        crate::cesr::Payload::NestedRelationAffirm { message, reply } => {
            Payload::AcceptNestedRelationship {
                inner: message,
                thread_id: *reply.as_bytes(),
            }
        }
        crate::cesr::Payload::RelationshipCancel { reply, .. } => Payload::CancelRelationship {
            thread_id: *reply.as_bytes(),
        },
        crate::cesr::Payload::NestedMessage(data) => Payload::NestedMessage(data),
        crate::cesr::Payload::RoutedMessage(hops, data) => Payload::RoutedMessage(hops, data as _),
        crate::cesr::Payload::NewIdentifierProposal { thread_id, new_vid } => {
            Payload::NewIdentifier {
                thread_id: *thread_id.as_bytes(),
                new_vid,
            }
        }
        crate::cesr::Payload::RelationshipReferral { referred_vid } => {
            Payload::Referral { referred_vid }
        }
    };

    Ok((
        envelope.nonconfidential_data,
        secret_payload,
        envelope.crypto_type,
        envelope.signature_type,
    ))
}

/// Generate N random bytes using the provided RNG
#[cfg(not(feature = "nacl"))]
fn fresh_nonce(csprng: &mut (impl rand::RngCore + rand::CryptoRng)) -> crate::cesr::Nonce {
    crate::cesr::Nonce::generate(|dst| csprng.fill_bytes(dst))
}
