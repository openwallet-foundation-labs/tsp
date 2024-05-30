use crate::{
    cesr::{DecodedEnvelope, Envelope},
    definitions::{PrivateVid, TSPMessage, VerifiedVid},
};
use ed25519_dalek::ed25519::signature::Signer;

use super::CryptoError;

/// Construct and sign a non-confidential TSP message
pub fn sign(
    sender: &dyn PrivateVid,
    receiver: Option<&dyn VerifiedVid>,
    payload: &[u8],
) -> Result<TSPMessage, CryptoError> {
    let mut data = Vec::with_capacity(64);

    crate::cesr::encode_s_envelope(
        crate::cesr::Envelope {
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
) -> Result<&'a [u8], CryptoError> {
    let view = crate::cesr::decode_envelope_mut(tsp_message)?;

    // verify outer signature
    let verification_challange = view.as_challenge();
    let signature = ed25519_dalek::Signature::from(verification_challange.signature);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(sender.verifying_key())?;
    verifying_key.verify_strict(verification_challange.signed_data, &signature)?;

    // decode envelope
    let DecodedEnvelope {
        raw_header: _,
        envelope:
            Envelope {
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

    Ok(nonconfidential_data)
}
