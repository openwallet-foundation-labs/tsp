use crate::{
    cesr::{CryptoType, DecodedEnvelope, DecodedPayload, SignatureType},
    definitions::{NonConfidentialData, Payload, PrivateVid, TSPMessage, VerifiedVid},
};
use crypto_box::{
    aead::{AeadCore, AeadInPlace, OsRng},
    ChaChaBox, PublicKey, SecretKey,
};
use ed25519_dalek::Signer;
use rand::{rngs::StdRng, SeedableRng};

use super::{CryptoError, MessageContents};

pub(crate) fn seal(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    secret_payload: Payload<&[u8]>,
    plaintext_observer: Option<super::ObservingClosure>,
) -> Result<TSPMessage, CryptoError> {
    let mut csprng = StdRng::from_entropy();

    let mut data = Vec::with_capacity(64);
    crate::cesr::encode_ets_envelope(
        crate::cesr::Envelope {
            crypto_type: CryptoType::NaclAuth,
            signature_type: SignatureType::Ed25519,
            sender: sender.identifier(),
            receiver: Some(receiver.identifier()),
            nonconfidential_data,
        },
        &mut data,
    )?;

    let secret_payload = match secret_payload {
        Payload::Content(data) => crate::cesr::Payload::GenericMessage(data),
        Payload::RequestRelationship { route } => crate::cesr::Payload::DirectRelationProposal {
            nonce: fresh_nonce(&mut csprng),
            hops: route.unwrap_or_else(Vec::new),
        },
        Payload::AcceptRelationship { ref thread_id } => {
            crate::cesr::Payload::DirectRelationAffirm { reply: thread_id }
        }
        Payload::RequestNestedRelationship { vid } => {
            crate::cesr::Payload::NestedRelationProposal {
                nonce: fresh_nonce(&mut csprng),
                new_vid: vid,
            }
        }
        Payload::AcceptNestedRelationship {
            ref thread_id,
            vid,
            connect_to_vid,
        } => crate::cesr::Payload::NestedRelationAffirm {
            reply: thread_id,
            new_vid: vid,
            connect_to_vid,
        },
        Payload::Referral {
            route,
            referred_vid,
        } => crate::cesr::Payload::RelationshipReferral {
            hops: route.unwrap_or_else(Vec::new),
            referred_vid,
        },
        Payload::CancelRelationship { ref thread_id } => {
            crate::cesr::Payload::RelationshipCancel { reply: thread_id }
        }
        Payload::NestedMessage(data) => crate::cesr::Payload::NestedMessage(data),
        Payload::RoutedMessage(hops, data) => crate::cesr::Payload::RoutedMessage(hops, data),
    };

    // prepare CESR-encoded ciphertext
    let mut cesr_message = Vec::new();

    #[cfg(feature = "essr")]
    crate::cesr::encode_payload(
        &secret_payload,
        Some(sender.identifier().as_bytes()),
        &mut cesr_message,
    )?;

    #[cfg(not(feature = "essr"))]
    crate::cesr::encode_payload(&secret_payload, None, &mut cesr_message)?;

    // this callback allows "observing" the raw bytes of the plaintext before encryption, for hash computations
    if let Some(func) = plaintext_observer {
        func(&cesr_message);
    }

    let sender_secret_key = SecretKey::from_bytes(**sender.decryption_key());
    let receiver_public_key = PublicKey::from(**receiver.encryption_key());

    let sender_box = ChaChaBox::new(&receiver_public_key, &sender_secret_key);

    // Get a random nonce to encrypt the message under
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);

    // aad not yet supported: https://github.com/RustCrypto/nacl-compat/blob/78b59261458923740724c84937459f0a6017a592/crypto_box/src/lib.rs#L227
    let tag = sender_box.encrypt_in_place_detached(&nonce, &[], &mut cesr_message);

    cesr_message.extend(tag.unwrap());
    cesr_message.extend(nonce);

    // encode and append the ciphertext to the envelope data
    crate::cesr::encode_ciphertext(&cesr_message, &mut data)?;

    // create and append outer signature
    let sign_key = ed25519_dalek::SigningKey::from_bytes(sender.signing_key());
    let signature = sign_key.sign(&data).to_bytes();
    crate::cesr::encode_signature(&signature, &mut data);

    Ok(data)
}

pub(crate) fn open<'a>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<MessageContents<'a>, CryptoError> {
    let view = crate::cesr::decode_envelope_mut(tsp_message)?;

    // verify outer signature
    let verification_challenge = view.as_challenge();
    let signature = ed25519_dalek::Signature::from(verification_challenge.signature);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(sender.verifying_key())?;
    verifying_key.verify_strict(verification_challenge.signed_data, &signature)?;

    // decode envelope
    let DecodedEnvelope {
        raw_header: _data,
        envelope,
        ciphertext: Some(ciphertext),
    } = view
        .into_opened::<&[u8]>()
        .map_err(|_| crate::cesr::error::DecodeError::VidError)?
    else {
        return Err(CryptoError::MissingCiphertext);
    };

    // verify the message was intended for the specified receiver
    if envelope.receiver != Some(receiver.identifier().as_bytes()) {
        return Err(CryptoError::UnexpectedRecipient);
    }

    let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 16 - 24);
    let (tag, nonce) = footer.split_at(16);

    let receiver_secret_key = SecretKey::from_bytes(**receiver.decryption_key());
    let sender_public_key = PublicKey::from(**sender.encryption_key());
    let receiver_box = ChaChaBox::new(&sender_public_key, &receiver_secret_key);

    receiver_box.decrypt_in_place_detached(nonce.into(), &[], ciphertext, tag.into())?;

    #[allow(unused_variables)]
    let DecodedPayload {
        payload,
        sender_identity,
    } = crate::cesr::decode_payload(ciphertext)?;

    #[cfg(feature = "essr")]
    match sender_identity {
        Some(id) => {
            if id != sender.identifier().as_bytes() {
                return Err(CryptoError::UnexpectedSender);
            }
        }
        None => return Err(CryptoError::MissingSender),
    }

    let secret_payload = match payload {
        crate::cesr::Payload::GenericMessage(data) => Payload::Content(data),
        crate::cesr::Payload::DirectRelationProposal { hops, .. } => Payload::RequestRelationship {
            route: if hops.is_empty() { None } else { Some(hops) },
        },
        crate::cesr::Payload::DirectRelationAffirm { reply: &thread_id } => {
            Payload::AcceptRelationship { thread_id }
        }
        crate::cesr::Payload::NestedRelationProposal { new_vid, .. } => {
            Payload::RequestNestedRelationship { vid: new_vid }
        }
        crate::cesr::Payload::NestedRelationAffirm {
            new_vid,
            connect_to_vid,
            reply: &thread_id,
        } => Payload::AcceptNestedRelationship {
            vid: new_vid,
            connect_to_vid,
            thread_id,
        },
        crate::cesr::Payload::RelationshipReferral { hops, referred_vid } => Payload::Referral {
            route: if hops.is_empty() { None } else { Some(hops) },
            referred_vid,
        },
        crate::cesr::Payload::RelationshipCancel {
            reply: &thread_id, ..
        } => Payload::CancelRelationship { thread_id },
        crate::cesr::Payload::NestedMessage(data) => Payload::NestedMessage(data),
        crate::cesr::Payload::RoutedMessage(hops, data) => Payload::RoutedMessage(hops, data),
    };

    Ok((envelope.nonconfidential_data, secret_payload, ciphertext))
}

/// Generate N random bytes using the provided RNG
fn fresh_nonce(csprng: &mut (impl rand::RngCore + rand::CryptoRng)) -> crate::cesr::Nonce {
    crate::cesr::Nonce::generate(|dst| csprng.fill_bytes(dst))
}
