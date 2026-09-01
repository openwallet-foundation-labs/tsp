use super::{CryptoError, append_signature, signature_type};
use crate::{
    cesr::{CryptoType, DecodedEnvelope, DecodedPayload, Envelope},
    definitions::{MessageType, PrivateVid, TSPMessage, VerifiedVid},
};

/// Construct and sign a non-confidential TSP message carrying an application
/// payload; it is carried as a cleartext `XSCS` payload in the payload position.
///
/// A message whose payload is a control message is built with
/// [`sign_payload`] instead — wrapping one in `XSCS` would put a payload
/// inside a payload.
pub fn sign(
    sender: &dyn PrivateVid,
    receiver: Option<&dyn VerifiedVid>,
    payload: &[u8],
) -> Result<TSPMessage, CryptoError> {
    sign_payload(
        sender,
        receiver,
        &crate::cesr::Payload::<_, &[u8]>::GenericMessage(payload),
        None,
    )
}

/// Construct and sign a non-confidential TSP message whose payload is
/// `payload`, encoded in the payload position as it stands.
///
/// This is what a signed-only control message needs: spec 9.4.13 and 9.4.14
/// require the inner message of a nested `TSP_RFI`/`TSP_RFA` to carry that
/// control payload itself, not an `XSCS` payload wrapping one.
pub fn sign_payload(
    sender: &dyn PrivateVid,
    receiver: Option<&dyn VerifiedVid>,
    payload: &crate::cesr::Payload<impl AsRef<[u8]>, impl AsRef<[u8]>>,
    sender_identity: Option<&[u8]>,
) -> Result<TSPMessage, CryptoError> {
    sign_payload_as(
        sender,
        sender.identifier(),
        receiver,
        payload,
        sender_identity,
    )
}

/// As [`sign_payload`], but writing `sender_id` into the envelope rather than
/// the sender's own identifier.
///
/// This exists for a VID that is being introduced: a `did:peer:4` is used by
/// its short form, which a peer cannot resolve until it has seen the document,
/// so the message that introduces it carries the long form instead. The keys
/// are the same either way, and the peer resolves the long form back to the
/// short form it will use thereafter.
pub fn sign_payload_as(
    sender: &dyn PrivateVid,
    sender_id: &str,
    receiver: Option<&dyn VerifiedVid>,
    payload: &crate::cesr::Payload<impl AsRef<[u8]>, impl AsRef<[u8]>>,
    sender_identity: Option<&[u8]>,
) -> Result<TSPMessage, CryptoError> {
    let mut data = Vec::with_capacity(64);

    crate::cesr::encode_envelope(
        Envelope {
            crypto_type: CryptoType::Plaintext,
            signature_type: signature_type(sender),
            sender: sender_id,
            receiver: receiver.map(|r| r.identifier()),
        },
        &mut data,
    )?;

    crate::cesr::encode_payload(payload, sender_identity, None, &mut data)?;
    crate::cesr::finalize_envelope_frame(&mut data);

    append_signature(sender, &mut data)?;

    Ok(data)
}

/// Decode a CESR Authentic Non-Confidential Message, verify the signature and
/// return its application payload. A message carrying anything other than an
/// application payload is read with [`verify_payload`].
pub fn verify<'a>(
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<(&'a [u8], MessageType), CryptoError> {
    let (DecodedPayload { payload, .. }, message_type) = verify_payload(sender, tsp_message)?;

    let crate::cesr::Payload::GenericMessage(message) = payload else {
        return Err(CryptoError::UnsupportedPayload);
    };

    Ok((message, message_type))
}

/// Decode a CESR Authentic Non-Confidential Message, verify the signature and
/// return its payload decoded, whatever its type.
pub fn verify_payload<'a>(
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<(DecodedPayload<'a>, MessageType), CryptoError> {
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

    Ok((
        crate::cesr::decode_payload(payload)?,
        MessageType {
            crypto_type,
            signature_type,
        },
    ))
}
