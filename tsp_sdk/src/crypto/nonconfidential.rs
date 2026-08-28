use super::{CryptoError, append_signature, signature_type};
use crate::{
    cesr::{CryptoType, DecodedEnvelope, DecodedPayload, Envelope},
    definitions::{MessageType, PrivateVid, TSPMessage, VerifiedVid},
};

/// Construct and sign a non-confidential TSP message; the payload is carried
/// as a cleartext -Z## payload in the payload position
pub fn sign(
    sender: &dyn PrivateVid,
    receiver: Option<&dyn VerifiedVid>,
    payload: &[u8],
) -> Result<TSPMessage, CryptoError> {
    let mut data = Vec::with_capacity(64);

    crate::cesr::encode_envelope(
        Envelope {
            crypto_type: CryptoType::Plaintext,
            signature_type: signature_type(sender),
            sender: sender.identifier(),
            receiver: receiver.map(|r| r.identifier()),
        },
        &mut data,
    )?;

    crate::cesr::encode_payload(
        &crate::cesr::Payload::<_, &[u8]>::GenericMessage(payload),
        None,
        None,
        &mut data,
    )?;
    crate::cesr::finalize_envelope_frame(&mut data);

    append_signature(sender, &mut data)?;

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
    super::verify_detached(
        sender,
        verification_challenge.signed_data,
        verification_challenge.signature,
    )?;

    // decode envelope; a non-confidential message has a cleartext payload
    let DecodedEnvelope {
        raw_header: _,
        envelope:
            Envelope {
                crypto_type,
                signature_type,
                sender: _,
                receiver: _,
            },
        payload_position: Some(payload),
    } = view
        .into_opened::<&[u8]>()
        .map_err(|_| crate::cesr::error::DecodeError::VidError)?
    else {
        return Err(CryptoError::MissingCiphertext);
    };

    if crypto_type != CryptoType::Plaintext {
        return Err(CryptoError::MissingCiphertext);
    }

    let DecodedPayload {
        payload: decoded, ..
    } = crate::cesr::decode_payload(payload)?;
    let crate::cesr::Payload::GenericMessage(message) = decoded else {
        // other payload types in signed-only messages are not yet surfaced
        return Err(CryptoError::UnsupportedPayload);
    };

    Ok((
        message,
        MessageType {
            crypto_type,
            signature_type,
        },
    ))
}
