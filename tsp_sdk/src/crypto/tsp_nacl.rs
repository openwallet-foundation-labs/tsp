use crate::{
    cesr::{CryptoType, DecodedPayload, Envelope},
    definitions::{Payload, PrivateVid, VerifiedVid},
};
use crypto_box::{ChaChaBox, PublicKey, SecretKey, aead::AeadInPlace};

use super::{CryptoError, MessageContents};
#[cfg(feature = "nacl")]
use crate::{
    cesr::SignatureType,
    definitions::{NonConfidentialData, TSPMessage, VidSignatureKeyType},
};
#[cfg(feature = "nacl")]
use crypto_box::aead::{AeadCore, OsRng};
#[cfg(feature = "nacl")]
use ed25519_dalek::Signer;
#[cfg(all(feature = "pq", feature = "nacl"))]
use ml_dsa::{EncodedSigningKey, MlDsa65};
#[cfg(feature = "nacl")]
use rand::{SeedableRng, rngs::StdRng};

#[cfg(feature = "nacl")]
pub(crate) fn seal(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    secret_payload: Payload<&[u8]>,
    digest: Option<&mut super::Digest>,
) -> Result<TSPMessage, CryptoError> {
    let mut csprng = StdRng::from_entropy();

    let mut data = Vec::with_capacity(64);
    crate::cesr::encode_ets_envelope(
        crate::cesr::Envelope {
            #[cfg(feature = "essr")]
            crypto_type: CryptoType::NaclEssr,
            #[cfg(not(feature = "essr"))]
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
        Payload::RequestRelationship {
            route,
            thread_id: _ignored,
        } => crate::cesr::Payload::DirectRelationProposal {
            nonce: fresh_nonce(&mut csprng),
            hops: route.unwrap_or_else(Vec::new),
        },
        Payload::AcceptRelationship { ref thread_id } => {
            crate::cesr::Payload::DirectRelationAffirm {
                reply: crate::cesr::Digest::Blake2b256(thread_id),
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
            reply: crate::cesr::Digest::Blake2b256(thread_id),
            message: inner,
        },
        Payload::NewIdentifier {
            ref thread_id,
            new_vid,
        } => crate::cesr::Payload::NewIdentifierProposal {
            thread_id: crate::cesr::Digest::Blake2b256(thread_id),
            new_vid,
        },
        Payload::Referral { referred_vid } => {
            crate::cesr::Payload::RelationshipReferral { referred_vid }
        }
        Payload::CancelRelationship { ref thread_id } => crate::cesr::Payload::RelationshipCancel {
            reply: crate::cesr::Digest::Blake2b256(thread_id),
        },
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

    // hash the raw bytes of the plaintext before encryption
    if let Some(digest) = digest {
        *digest = crate::crypto::blake2b256(&cesr_message)
    }

    let sender_secret_key = SecretKey::from_slice(&sender.decryption_key())?;
    let receiver_public_key = PublicKey::from_slice(&receiver.encryption_key())?;

    let sender_box = ChaChaBox::new(&receiver_public_key, &sender_secret_key);

    // Get a random nonce to encrypt the message under
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);

    // aad not yet supported: https://github.com/RustCrypto/nacl-compat/blob/78b59261458923740724c84937459f0a6017a592/crypto_box/src/lib.rs#L227
    let tag = sender_box.encrypt_in_place_detached(&nonce, &[], &mut cesr_message);

    cesr_message.extend(tag.unwrap());
    cesr_message.extend(nonce);

    // encode and append the ciphertext to the envelope data
    crate::cesr::encode_ciphertext(
        &cesr_message,
        if cfg!(feature = "essr") {
            CryptoType::NaclEssr
        } else {
            CryptoType::NaclAuth
        },
        &mut data,
    )?;

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

pub(crate) fn open<'a>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    _raw_header: &'a [u8],
    envelope: Envelope<'a, &[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<MessageContents<'a>, CryptoError> {
    let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 16 - 24);
    let (tag, nonce) = footer.split_at(16);

    let receiver_secret_key = SecretKey::from_slice(receiver.decryption_key().as_slice())?;
    let sender_public_key = PublicKey::from_slice(sender.encryption_key().as_slice())?;
    let receiver_box = ChaChaBox::new(&sender_public_key, &receiver_secret_key);

    receiver_box.decrypt_in_place_detached(nonce.into(), &[], ciphertext, tag.into())?;

    let thread_id = crate::crypto::blake2b256(ciphertext);

    #[allow(unused_variables)]
    let DecodedPayload {
        payload,
        sender_identity,
    } = crate::cesr::decode_payload(ciphertext)?;

    if envelope.crypto_type == CryptoType::NaclEssr {
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
        crate::cesr::Payload::NestedRelationProposal { message, .. } => {
            Payload::RequestNestedRelationship {
                inner: message,
                thread_id,
            }
        }
        crate::cesr::Payload::NestedRelationAffirm {
            message: inner,
            reply,
        } => Payload::AcceptNestedRelationship {
            inner,
            thread_id: *reply.as_bytes(),
        },
        crate::cesr::Payload::NewIdentifierProposal { thread_id, new_vid } => {
            Payload::NewIdentifier {
                thread_id: *thread_id.as_bytes(),
                new_vid,
            }
        }
        crate::cesr::Payload::RelationshipReferral { referred_vid } => {
            Payload::Referral { referred_vid }
        }
        crate::cesr::Payload::RelationshipCancel { reply, .. } => Payload::CancelRelationship {
            thread_id: *reply.as_bytes(),
        },
        crate::cesr::Payload::NestedMessage(data) => Payload::NestedMessage(data),
        crate::cesr::Payload::RoutedMessage(hops, data) => Payload::RoutedMessage(hops, data as _),
    };

    Ok((
        envelope.nonconfidential_data,
        secret_payload,
        envelope.crypto_type,
        envelope.signature_type,
    ))
}

/// Generate N random bytes using the provided RNG
#[cfg(feature = "nacl")]
fn fresh_nonce(csprng: &mut (impl rand::RngCore + rand::CryptoRng)) -> crate::cesr::Nonce {
    crate::cesr::Nonce::generate(|dst| csprng.fill_bytes(dst))
}
