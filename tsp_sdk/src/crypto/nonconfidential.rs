use super::CryptoError;
use crate::crypto::CryptoError::Verify;
use crate::definitions::VidSignatureKeyType;
use crate::{
    cesr::{CryptoType, DecodedEnvelope, Envelope, SignatureType},
    definitions::{MessageType, PrivateVid, TSPMessage, VerifiedVid},
};
#[cfg(feature = "pq")]
use ed25519_dalek::Verifier;
use ed25519_dalek::ed25519::signature::Signer;
#[cfg(feature = "pq")]
use ml_dsa::{EncodedSigningKey, EncodedVerifyingKey, MlDsa65};

/// Construct and sign a non-confidential TSP message
pub fn sign(
    sender: &dyn PrivateVid,
    receiver: Option<&dyn VerifiedVid>,
    payload: &[u8],
) -> Result<TSPMessage, CryptoError> {
    let mut data = Vec::with_capacity(64);

    let signature_type = match sender.signature_key_type() {
        VidSignatureKeyType::Ed25519 => SignatureType::Ed25519,
        #[cfg(feature = "pq")]
        VidSignatureKeyType::MlDsa65 => SignatureType::MlDsa65,
    };

    crate::cesr::encode_s_envelope(
        crate::cesr::Envelope {
            crypto_type: CryptoType::Plaintext,
            signature_type,
            sender: sender.identifier(),
            receiver: receiver.map(|r| r.identifier()),
            nonconfidential_data: Some(payload),
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

/// Decode a CESR Authentic Non-Confidential Message, verify the signature and return its contents
pub fn verify<'a>(
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<(&'a [u8], MessageType), CryptoError> {
    let view = crate::cesr::decode_envelope(tsp_message)?;

    // verify outer signature
    let verification_challenge = view.as_challenge();
    match view.signature_type() {
        SignatureType::NoSignature => {}
        SignatureType::Ed25519 => {
            let signature = ed25519_dalek::Signature::from_slice(verification_challenge.signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err))?;
            let verifying_key =
                ed25519_dalek::VerifyingKey::try_from(sender.verifying_key().as_slice())
                    .map_err(|err| Verify(sender.identifier().to_string(), err))?;
            verifying_key
                .verify_strict(verification_challenge.signed_data, &signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err))?;
        }
        #[cfg(feature = "pq")]
        SignatureType::MlDsa65 => {
            let signature: ml_dsa::Signature<MlDsa65> =
                ml_dsa::Signature::try_from(verification_challenge.signature)
                    .map_err(|err| Verify(sender.identifier().to_string(), err))?;
            let verifying_key = ml_dsa::VerifyingKey::decode(
                &EncodedVerifyingKey::<MlDsa65>::try_from(sender.verifying_key().as_slice())?,
            );
            verifying_key
                .verify(verification_challenge.signed_data, &signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err))?;
        }
    }

    // decode envelope
    let DecodedEnvelope {
        raw_header: _,
        envelope:
            Envelope {
                crypto_type,
                signature_type,
                sender: _,
                receiver: _,
                nonconfidential_data: Some(nonconfidential_data),
            },
        ciphertext: None,
    } = view
        .into_opened::<&[u8]>()
        .map_err(|_| crate::cesr::error::DecodeError::VidError)?
    else {
        return Err(CryptoError::MissingCiphertext);
    };

    Ok((
        nonconfidential_data,
        MessageType {
            crypto_type,
            signature_type,
        },
    ))
}
