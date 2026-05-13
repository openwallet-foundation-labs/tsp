use super::{CryptoError, append_signature, signature_type};
use crate::crypto::CryptoError::Verify;
use crate::{
    cesr::{CryptoType, DecodedEnvelope, Envelope, SignatureType},
    definitions::{MessageType, PrivateVid, TSPMessage, VerifiedVid},
};
use ml_dsa::{EncodedVerifyingKey, MlDsa65};

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
            signature_type: signature_type(sender),
            sender: sender.identifier(),
            receiver: receiver.map(|r| r.identifier()),
            nonconfidential_data: Some(payload),
        },
        &mut data,
    )?;

    append_signature(sender, &mut data)?;

    Ok(data)
}

/// Decode a CESR Authentic Non-Confidential Message, verify the signature and return its contents
pub fn verify<'a>(
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<(&'a [u8], MessageType), CryptoError> {
    #[cfg(feature = "bench-network-timings")]
    let open_core_started = std::time::Instant::now();
    let view = crate::cesr::decode_envelope(tsp_message)?;
    #[cfg(feature = "bench-network-timings")]
    crate::bench::record_open_core(open_core_started);

    // verify outer signature
    let verification_challenge = view.as_challenge();
    #[cfg(feature = "bench-network-timings")]
    let verify_started = std::time::Instant::now();
    match view.signature_type() {
        SignatureType::NoSignature => {}
        SignatureType::Ed25519 => {
            let signature = ed25519_dalek::Signature::from_slice(verification_challenge.signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err.to_string()))?;
            let verifying_key =
                ed25519_dalek::VerifyingKey::try_from(sender.verifying_key().as_slice())
                    .map_err(|err| Verify(sender.identifier().to_string(), err.to_string()))?;
            verifying_key
                .verify_strict(verification_challenge.signed_data, &signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err.to_string()))?;
        }
        SignatureType::MlDsa65 => {
            let signature: ml_dsa::Signature<MlDsa65> =
                ml_dsa::Signature::try_from(verification_challenge.signature)
                    .map_err(|err| Verify(sender.identifier().to_string(), err.to_string()))?;
            let verifying_key = ml_dsa::VerifyingKey::decode(
                &EncodedVerifyingKey::<MlDsa65>::try_from(sender.verifying_key().as_slice())?,
            );
            ml_dsa::Verifier::verify(
                &verifying_key,
                verification_challenge.signed_data,
                &signature,
            )
            .map_err(|err| Verify(sender.identifier().to_string(), err.to_string()))?;
        }
    }
    #[cfg(feature = "bench-network-timings")]
    crate::bench::record_verify(verify_started);

    // decode envelope
    #[cfg(feature = "bench-network-timings")]
    let open_core_started = std::time::Instant::now();
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

    #[cfg(feature = "bench-network-timings")]
    crate::bench::record_open_core(open_core_started);

    Ok((
        nonconfidential_data,
        MessageType {
            crypto_type,
            signature_type,
        },
    ))
}
