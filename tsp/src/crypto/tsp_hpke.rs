use crate::{
    cesr::DecodedEnvelope,
    definitions::{NonConfidentialData, Payload, PrivateVid, TSPMessage, VerifiedVid},
};
use ed25519_dalek::Signer;
use hpke::{aead::AeadTag, Deserializable, OpModeR, OpModeS, Serializable};
use rand::{rngs::StdRng, SeedableRng};

use super::{CryptoError, MessageContents};

pub(crate) fn seal<A, Kdf, Kem>(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    secret_payload: Payload<&[u8]>,
    plaintext_observer: Option<super::ObservingClosure>,
) -> Result<TSPMessage, CryptoError>
where
    A: hpke::aead::Aead,
    Kdf: hpke::kdf::Kdf,
    Kem: hpke::kem::Kem,
{
    let mut csprng = StdRng::from_entropy();

    let mut data = Vec::with_capacity(64);
    crate::cesr::encode_ets_envelope(
        crate::cesr::Envelope {
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
        Payload::CancelRelationship { ref thread_id } => crate::cesr::Payload::RelationshipCancel {
            nonce: fresh_nonce(&mut csprng),
            reply: thread_id,
        },
        Payload::NestedMessage(data) => crate::cesr::Payload::NestedMessage(data),
        Payload::RoutedMessage(hops, data) => crate::cesr::Payload::RoutedMessage(hops, data),
    };

    // prepare CESR-encoded ciphertext
    let mut cesr_message = Vec::with_capacity(
        // plaintext size
        secret_payload.estimate_size()
        // authenticated encryption tag length
        + AeadTag::<A>::size()
        // encapsulated key length
        + Kem::EncappedKey::size(),
    );
    crate::cesr::encode_payload(&secret_payload, &mut cesr_message)?;

    // HPKE sender mode: "Auth"
    let sender_decryption_key = Kem::PrivateKey::from_bytes(sender.decryption_key())?;
    let sender_encryption_key = Kem::PublicKey::from_bytes(sender.encryption_key())?;
    let mode = OpModeS::Auth((&sender_decryption_key, &sender_encryption_key));

    // recipient public key
    let message_receiver = Kem::PublicKey::from_bytes(receiver.encryption_key())?;

    // this callback allows "observing" the raw bytes of the plaintext before encryption, for hash computations
    if let Some(func) = plaintext_observer {
        func(&cesr_message);
    }

    // perform encryption
    let (encapped_key, tag) = hpke::single_shot_seal_in_place_detached::<A, Kdf, Kem, StdRng>(
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
    tsp_message: &'a mut [u8],
) -> Result<MessageContents<'a>, CryptoError>
where
    A: hpke::aead::Aead,
    Kdf: hpke::kdf::Kdf,
    Kem: hpke::kem::Kem,
{
    let view = crate::cesr::decode_envelope_mut(tsp_message)?;

    // verify outer signature
    let verification_challange = view.as_challenge();
    let signature = ed25519_dalek::Signature::from(verification_challange.signature);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(sender.verifying_key())?;
    verifying_key.verify_strict(verification_challange.signed_data, &signature)?;

    // decode envelope
    let DecodedEnvelope {
        raw_header: info,
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

    // split encapsulated key and authenticated encryption tag length
    let (ciphertext, footer) =
        ciphertext.split_at_mut(ciphertext.len() - AeadTag::<A>::size() - Kem::EncappedKey::size());
    let (tag, encapped_key) = footer.split_at(footer.len() - Kem::EncappedKey::size());

    // construct correct key types
    let sender_encryption_key = Kem::PublicKey::from_bytes(sender.encryption_key())?;
    let receiver_decryption_key = Kem::PrivateKey::from_bytes(receiver.decryption_key())?;
    let encapped_key = Kem::EncappedKey::from_bytes(encapped_key)?;
    let tag = AeadTag::from_bytes(tag)?;

    // decrypt the ciphertext
    hpke::single_shot_open_in_place_detached::<A, Kdf, Kem>(
        &OpModeR::Auth(&sender_encryption_key),
        &receiver_decryption_key,
        &encapped_key,
        info,
        ciphertext,
        &[],
        &tag,
    )?;

    let secret_payload = match crate::cesr::decode_payload(ciphertext)? {
        crate::cesr::Payload::GenericMessage(data) => Payload::Content(data),
        crate::cesr::Payload::DirectRelationProposal { hops, .. } => Payload::RequestRelationship {
            route: if hops.is_empty() {
                None
            } else {
                Some(hops.to_vec())
            },
        },
        crate::cesr::Payload::DirectRelationAffirm { reply: &thread_id } => {
            Payload::AcceptRelationship { thread_id }
        }
        crate::cesr::Payload::NestedRelationProposal { .. } => todo!(),
        crate::cesr::Payload::NestedRelationAffirm { .. } => todo!(),
        crate::cesr::Payload::RelationshipCancel {
            reply: &thread_id, ..
        } => Payload::CancelRelationship { thread_id },
        crate::cesr::Payload::NestedMessage(data) => Payload::NestedMessage(data),
        crate::cesr::Payload::RoutedMessage(hops, data) => {
            Payload::RoutedMessage(hops.to_vec(), data)
        }
    };

    Ok((envelope.nonconfidential_data, secret_payload, ciphertext))
}

/// Generate N random bytes using the provided RNG
fn fresh_nonce(csprng: &mut (impl rand::RngCore + rand::CryptoRng)) -> crate::cesr::Nonce {
    crate::cesr::Nonce::generate(|dst| csprng.fill_bytes(dst))
}
