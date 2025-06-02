use super::CryptoError;
use crate::crypto::CryptoError::Verify;
use crate::{
    cesr::{CryptoType, DecodedEnvelope, Envelope, SignatureType},
    definitions::{MessageType, PrivateVid, TSPMessage, VerifiedVid},
};
use ed25519_dalek::ed25519::signature::Signer;

/// Construct and sign a non-confidential TSP message
pub fn sign(
    sender: &dyn PrivateVid,
    receiver: Option<&dyn VerifiedVid>,
    payload: &[u8],
) -> Result<TSPMessage, CryptoError> {
    let mut data = Vec::with_capacity(64);

    crate::cesr::encode_s_envelope(
        crate::cesr::Envelope {
            crypto_type: CryptoType::Plaintext,
            signature_type: SignatureType::Ed25519,
            sender: sender.identifier(),
            receiver: receiver.map(|r| r.identifier()),
            nonconfidential_data: Some(payload),
        },
        &mut data,
    )?;

    // create and append signature
    let sign_key = ed25519_dalek::SigningKey::from_bytes(sender.signing_key());
    let signature = sign_key.sign(&data).to_bytes();
    crate::cesr::encode_signature(&signature, &mut data);

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
    let signature = ed25519_dalek::Signature::from(verification_challenge.signature);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(sender.verifying_key())
        .map_err(|err| Verify(sender.identifier().to_string(), err))?;
    verifying_key
        .verify_strict(verification_challenge.signed_data, &signature)
        .map_err(|err| Verify(sender.identifier().to_string(), err))?;

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
