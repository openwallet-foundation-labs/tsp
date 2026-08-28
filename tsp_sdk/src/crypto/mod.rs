use crate::definitions::{
    Digest, MessageType, Payload, PrivateKeyData, PrivateSigningKeyData, PrivateVid, PublicKeyData,
    PublicVerificationKeyData, RelationshipForm, TSPMessage, VerifiedVid, VidEncryptionKeyType,
    VidSignatureKeyType,
};
use ed25519_dalek::Signer;
use ml_dsa::{EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa65};
use rand_core::OsRng;
#[cfg(feature = "bench-network-timings")]
use std::time::Instant;

pub use digest::{blake2b256, sha256};

mod digest;
pub mod error;
mod nonconfidential;

mod tsp_hpke;
mod tsp_nacl;

use crate::cesr::{CryptoType, SignatureType};
use crate::crypto::CryptoError::Verify;
pub use error::CryptoError;

type CesrRelationshipPayload<'a> = crate::cesr::Payload<'a, &'a [u8], &'a [u8]>;

pub(crate) struct ParallelSignatureInfo<'a> {
    pub new_vid: &'a [u8],
    pub sig_new_vid: &'a [u8],
    pub signed_data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutboundCryptoSelection {
    pub crypto_type: CryptoType,
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum RelationshipDigestAlgorithm {
    Sha2_256,
    Blake2b256,
}

impl RelationshipDigestAlgorithm {
    pub(crate) fn for_crypto_type(crypto_type: CryptoType) -> Result<Self, CryptoError> {
        Ok(match crypto_type {
            CryptoType::SealedBox => RelationshipDigestAlgorithm::Blake2b256,
            CryptoType::HpkeBase => RelationshipDigestAlgorithm::Sha2_256,
            CryptoType::Plaintext => return Err(CryptoError::InvalidCryptoSelection(crypto_type)),
        })
    }

    pub(crate) fn for_field(field: &crate::cesr::Digest) -> Self {
        match field {
            crate::cesr::Digest::Sha2_256(_) => RelationshipDigestAlgorithm::Sha2_256,
            crate::cesr::Digest::Blake2b256(_) => RelationshipDigestAlgorithm::Blake2b256,
        }
    }

    pub(crate) fn field<'a>(self, digest: &'a Digest) -> crate::cesr::Digest<'a> {
        match self {
            RelationshipDigestAlgorithm::Sha2_256 => crate::cesr::Digest::Sha2_256(digest),
            RelationshipDigestAlgorithm::Blake2b256 => crate::cesr::Digest::Blake2b256(digest),
        }
    }

    pub(crate) fn hash(self, bytes: &[u8]) -> Digest {
        match self {
            RelationshipDigestAlgorithm::Sha2_256 => sha256(bytes),
            RelationshipDigestAlgorithm::Blake2b256 => blake2b256(bytes),
        }
    }
}

pub(crate) fn default_outbound_crypto_selection(
    sender: &dyn VerifiedVid,
    receiver: &dyn VerifiedVid,
) -> OutboundCryptoSelection {
    let receiver_key_type = receiver.encryption_key_type();
    let _ = sender;
    let crypto_type = if matches!(receiver_key_type, VidEncryptionKeyType::X25519MlKem768) {
        CryptoType::HpkeBase
    } else if cfg!(feature = "nacl") {
        CryptoType::SealedBox
    } else {
        CryptoType::HpkeBase
    };

    OutboundCryptoSelection { crypto_type }
}

pub(crate) fn signature_type(sender: &dyn VerifiedVid) -> SignatureType {
    match sender.signature_key_type() {
        VidSignatureKeyType::Ed25519 => SignatureType::Ed25519,
        VidSignatureKeyType::MlDsa65 => SignatureType::MlDsa65,
    }
}

pub(crate) fn append_signature(
    sender: &dyn PrivateVid,
    data: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    match sender.signature_key_type() {
        VidSignatureKeyType::Ed25519 => {
            #[cfg(feature = "bench-network-timings")]
            let signature_started = std::time::Instant::now();
            let sign_key = ed25519_dalek::SigningKey::from_bytes(&TryInto::<[u8; 32]>::try_into(
                sender.signing_key().as_slice(),
            )?);
            let signature = sign_key.sign(data).to_bytes();
            crate::cesr::encode_signature(&signature, data, SignatureType::Ed25519);
            #[cfg(feature = "bench-network-timings")]
            crate::bench::record_signature(signature_started);
        }
        VidSignatureKeyType::MlDsa65 => {
            #[cfg(feature = "bench-network-timings")]
            let signature_started = std::time::Instant::now();
            let sign_key = mldsa65_signing_key_from_bytes(sender.signing_key().as_slice())?;
            let signature = ml_dsa::Signer::sign(&sign_key, data).encode();
            crate::cesr::encode_signature(signature.as_slice(), data, SignatureType::MlDsa65);
            #[cfg(feature = "bench-network-timings")]
            crate::bench::record_signature(signature_started);
        }
    }

    Ok(())
}

fn mldsa65_signing_key_from_bytes(
    signing_key: &[u8],
) -> Result<ExpandedSigningKey<MlDsa65>, CryptoError> {
    let signing_key = ExpandedSigningKeyBytes::<MlDsa65>::try_from(signing_key)?;
    #[allow(deprecated)]
    Ok(ExpandedSigningKey::<MlDsa65>::from_expanded(&signing_key))
}

/// Compute the self-referencing TSP digest (spec 7.2.1) of a relationship
/// payload: the hash over the envelope prefix and the payload fields, with the
/// digest's own slot filled with the 0x23 dummy and the padding field excluded
fn compute_relationship_digest(
    payload: &CesrRelationshipPayload<'_>,
    sender_in_payload: Option<&[u8]>,
    envelope_prefix: &[u8],
    algorithm: RelationshipDigestAlgorithm,
) -> Result<Digest, CryptoError> {
    let mut input = Vec::with_capacity(envelope_prefix.len() + 256);
    crate::cesr::encode_digest_input(payload, sender_in_payload, envelope_prefix, &mut input)?;
    Ok(algorithm.hash(&input))
}

pub(crate) fn build_parallel_request_signed_data(
    sender_in_payload: Option<&[u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    nonce_bytes: [u8; 16],
    envelope_prefix: &[u8],
    request_digest: &mut Digest,
    new_vid: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // the digest is derived first (its own slot dummied, the new-VID signature
    // not yet present); the signature is then made over the final digest
    let payload = crate::cesr::Payload::<&[u8], &[u8]>::ParallelRelationProposal {
        nonce: crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes),
        request_digest: digest_algorithm.field(&*request_digest),
        sig_new_vid: &[0; 64],
        new_vid,
    };
    *request_digest = compute_relationship_digest(
        &payload,
        sender_in_payload,
        envelope_prefix,
        digest_algorithm,
    )?;

    let nonce = crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes);
    Ok(crate::cesr::encode_parallel_relation_proposal_challenge(
        sender_in_payload,
        &nonce,
        digest_algorithm.field(request_digest),
        new_vid,
    )?)
}

pub(crate) fn build_parallel_accept_signed_data(
    thread_id: &Digest,
    sender_in_payload: Option<&[u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    envelope_prefix: &[u8],
    reply_digest: &mut Digest,
    new_vid: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let payload = crate::cesr::Payload::<&[u8], &[u8]>::ParallelRelationAffirm {
        request_digest: digest_algorithm.field(thread_id),
        reply_digest: digest_algorithm.field(&*reply_digest),
        sig_new_vid: &[0; 64],
        new_vid,
    };
    *reply_digest = compute_relationship_digest(
        &payload,
        sender_in_payload,
        envelope_prefix,
        digest_algorithm,
    )?;

    Ok(crate::cesr::encode_parallel_relation_affirm_challenge(
        sender_in_payload,
        digest_algorithm.field(thread_id),
        digest_algorithm.field(reply_digest),
        new_vid,
    )?)
}

fn relationship_request_payload<'a>(
    form: &RelationshipForm<'a, &'a [u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    nonce_bytes: [u8; 16],
    request_digest: &'a Digest,
) -> CesrRelationshipPayload<'a> {
    match form {
        RelationshipForm::Direct => crate::cesr::Payload::DirectRelationProposal {
            nonce: crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes),
            request_digest: digest_algorithm.field(request_digest),
        },
        RelationshipForm::Parallel {
            new_vid,
            sig_new_vid,
        } => crate::cesr::Payload::ParallelRelationProposal {
            nonce: crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes),
            request_digest: digest_algorithm.field(request_digest),
            sig_new_vid,
            new_vid,
        },
    }
}

fn relationship_accept_payload<'a>(
    thread_id: &'a Digest,
    form: &RelationshipForm<'a, &'a [u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    reply_digest: &'a Digest,
) -> CesrRelationshipPayload<'a> {
    match form {
        RelationshipForm::Direct => crate::cesr::Payload::DirectRelationAffirm {
            request_digest: digest_algorithm.field(thread_id),
            reply_digest: digest_algorithm.field(reply_digest),
        },
        RelationshipForm::Parallel {
            new_vid,
            sig_new_vid,
        } => crate::cesr::Payload::ParallelRelationAffirm {
            request_digest: digest_algorithm.field(thread_id),
            reply_digest: digest_algorithm.field(reply_digest),
            sig_new_vid,
            new_vid,
        },
    }
}

pub(crate) fn build_relationship_request_payload<'a>(
    form: &RelationshipForm<'a, &'a [u8]>,
    sender_in_payload: Option<&[u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    nonce_bytes: [u8; 16],
    envelope_prefix: &[u8],
    request_digest: &'a mut Digest,
) -> Result<(CesrRelationshipPayload<'a>, Digest), CryptoError> {
    let placeholder =
        relationship_request_payload(form, digest_algorithm, nonce_bytes, &*request_digest);
    *request_digest = compute_relationship_digest(
        &placeholder,
        sender_in_payload,
        envelope_prefix,
        digest_algorithm,
    )?;

    let digest = *request_digest;

    Ok((
        relationship_request_payload(form, digest_algorithm, nonce_bytes, &*request_digest),
        digest,
    ))
}

pub(crate) fn build_relationship_accept_payload<'a>(
    thread_id: &'a Digest,
    form: &RelationshipForm<'a, &'a [u8]>,
    sender_in_payload: Option<&[u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    envelope_prefix: &[u8],
    reply_digest: &'a mut Digest,
) -> Result<(CesrRelationshipPayload<'a>, Digest), CryptoError> {
    let placeholder =
        relationship_accept_payload(thread_id, form, digest_algorithm, &*reply_digest);
    *reply_digest = compute_relationship_digest(
        &placeholder,
        sender_in_payload,
        envelope_prefix,
        digest_algorithm,
    )?;

    let digest = *reply_digest;

    Ok((
        relationship_accept_payload(thread_id, form, digest_algorithm, &*reply_digest),
        digest,
    ))
}

/// Verify the embedded self-referencing digest (spec 7.2.1) of a received
/// relationship-forming payload: recompute it from the envelope prefix and the
/// decoded payload fields (with the digest's own slot dummied) using the hash
/// identified by the embedded digest's code, and compare
pub(crate) fn verify_relationship_digest(
    payload: &crate::cesr::Payload<'_, impl AsRef<[u8]>, impl AsRef<[u8]>>,
    sender_identity: Option<&[u8]>,
    envelope_prefix: &[u8],
) -> Result<(), CryptoError> {
    let embedded = match payload {
        crate::cesr::Payload::DirectRelationProposal { request_digest, .. }
        | crate::cesr::Payload::ParallelRelationProposal { request_digest, .. } => request_digest,
        crate::cesr::Payload::DirectRelationAffirm { reply_digest, .. }
        | crate::cesr::Payload::ParallelRelationAffirm { reply_digest, .. } => reply_digest,
        _ => return Ok(()),
    };

    let algorithm = RelationshipDigestAlgorithm::for_field(embedded);
    let mut input = Vec::with_capacity(envelope_prefix.len() + 256);
    crate::cesr::encode_digest_input(payload, sender_identity, envelope_prefix, &mut input)?;

    if algorithm.hash(&input) != *embedded.as_bytes() {
        return Err(CryptoError::DigestMismatch);
    }

    Ok(())
}

pub(crate) fn open_relationship_request<'a>(
    thread_id: Digest,
    form: RelationshipForm<'a, &'a [u8]>,
) -> Payload<'a, &'a [u8], &'a mut [u8]> {
    Payload::RequestRelationship { thread_id, form }
}

pub(crate) fn open_relationship_accept<'a>(
    thread_id: Digest,
    reply_thread_id: Digest,
    form: RelationshipForm<'a, &'a [u8]>,
) -> Payload<'a, &'a [u8], &'a mut [u8]> {
    Payload::AcceptRelationship {
        thread_id,
        reply_thread_id,
        form,
    }
}

pub(crate) fn sign_detached(sender: &dyn PrivateVid, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(match sender.signature_key_type() {
        crate::definitions::VidSignatureKeyType::Ed25519 => {
            let sign_key = ed25519_dalek::SigningKey::from_bytes(&TryInto::<[u8; 32]>::try_into(
                sender.signing_key().as_slice(),
            )?);
            sign_key.sign(data).to_bytes().to_vec()
        }
        crate::definitions::VidSignatureKeyType::MlDsa65 => {
            let sign_key = mldsa65_signing_key_from_bytes(sender.signing_key().as_slice())?;
            ml_dsa::Signer::sign(&sign_key, data).encode().to_vec()
        }
    })
}

pub(crate) fn verify_detached(
    sender: &dyn VerifiedVid,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    match sender.signature_key_type() {
        crate::definitions::VidSignatureKeyType::Ed25519 => {
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err.to_string()))?;
            let verifying_key =
                ed25519_dalek::VerifyingKey::try_from(sender.verifying_key().as_slice())
                    .map_err(|err| Verify(sender.identifier().to_string(), err.to_string()))?;
            verifying_key
                .verify_strict(signed_data, &signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err.to_string()))?;
        }
        crate::definitions::VidSignatureKeyType::MlDsa65 => {
            let signature: ml_dsa::Signature<MlDsa65> = ml_dsa::Signature::try_from(signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err.to_string()))?;
            let verifying_key = ml_dsa::VerifyingKey::decode(
                &EncodedVerifyingKey::<MlDsa65>::try_from(sender.verifying_key().as_slice())?,
            );
            ml_dsa::Verifier::verify(&verifying_key, signed_data, &signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err.to_string()))?;
        }
    }

    Ok(())
}

/// Encrypt, authenticate and sign and CESR encode a TSP message
pub fn seal(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    payload: Payload<&[u8]>,
) -> Result<TSPMessage, CryptoError> {
    #[cfg(feature = "bench-network-timings")]
    let signature_before = crate::bench::signature_before();
    #[cfg(feature = "bench-network-timings")]
    let started = Instant::now();

    let result = seal_and_hash(sender, receiver, payload, None);

    #[cfg(feature = "bench-network-timings")]
    crate::bench::record_seal_core(started, signature_before);

    result
}

/// Encrypt, authenticate and sign and CESR encode a TSP message; also returns the hash value of the plaintext parts before encryption
pub fn seal_and_hash(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    payload: Payload<&[u8]>,
    digest: Option<&mut Digest>,
) -> Result<TSPMessage, CryptoError> {
    seal_and_hash_with_relationship_nonce(sender, receiver, payload, digest, None)
}

pub fn seal_with_crypto_type(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    payload: Payload<&[u8]>,
    crypto_type: CryptoType,
) -> Result<TSPMessage, CryptoError> {
    seal_and_hash_with_crypto_type(sender, receiver, payload, None, crypto_type)
}

pub fn seal_and_hash_with_crypto_type(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    payload: Payload<&[u8]>,
    digest: Option<&mut Digest>,
    crypto_type: CryptoType,
) -> Result<TSPMessage, CryptoError> {
    seal_with_selection(
        sender,
        receiver,
        payload,
        digest,
        None,
        OutboundCryptoSelection { crypto_type },
    )
}

pub(crate) fn seal_and_hash_with_relationship_nonce(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    payload: Payload<&[u8]>,
    digest: Option<&mut Digest>,
    request_nonce_override: Option<[u8; 16]>,
) -> Result<TSPMessage, CryptoError> {
    seal_with_selection(
        sender,
        receiver,
        payload,
        digest,
        request_nonce_override,
        default_outbound_crypto_selection(sender, receiver),
    )
}

pub(crate) fn seal_with_selection(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    payload: Payload<&[u8]>,
    digest: Option<&mut Digest>,
    request_nonce_override: Option<[u8; 16]>,
    selection: OutboundCryptoSelection,
) -> Result<TSPMessage, CryptoError> {
    ensure_selection_matches_key_types(sender, receiver, selection.crypto_type)?;

    match selection.crypto_type {
        CryptoType::SealedBox => {
            tsp_nacl::seal(sender, receiver, payload, digest, request_nonce_override)
        }
        CryptoType::HpkeBase => {
            tsp_hpke::seal(sender, receiver, payload, digest, request_nonce_override)
        }
        CryptoType::Plaintext => Err(CryptoError::InvalidCryptoSelection(selection.crypto_type)),
    }
}

fn ensure_selection_matches_key_types(
    sender: &dyn VerifiedVid,
    receiver: &dyn VerifiedVid,
    crypto_type: CryptoType,
) -> Result<(), CryptoError> {
    let _ = sender;
    let receiver_key_type = receiver.encryption_key_type();
    match crypto_type {
        // the sealed box requires an X25519 recipient key; HPKE-Base accepts
        // any supported KEM key type. Neither uses the sender's encryption
        // keys: HPKE-Base and the anonymous sealed box need no sender KEM key.
        CryptoType::SealedBox => {
            if receiver_key_type != VidEncryptionKeyType::X25519 {
                return Err(CryptoError::IncompatibleCryptoSelection {
                    crypto_type,
                    key_type: receiver_key_type,
                });
            }
        }
        CryptoType::HpkeBase => {}
        CryptoType::Plaintext => return Err(CryptoError::InvalidCryptoSelection(crypto_type)),
    }

    Ok(())
}

pub type MessageContents<'a> = (
    Payload<'a, &'a [u8], &'a mut [u8]>,
    crate::cesr::CryptoType,
    crate::cesr::SignatureType,
);

/// Decode a CESR Authentic Confidential Message, verify the signature and decrypt its contents
pub fn open<'a>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<MessageContents<'a>, CryptoError> {
    open_with_signature_info(receiver, sender, tsp_message)
        .map(|(message_contents, _parallel_signature_info)| message_contents)
}

pub(crate) fn open_with_signature_info<'a>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
    #[cfg(feature = "bench-network-timings")]
    let open_core_started = std::time::Instant::now();
    let view = crate::cesr::decode_envelope(tsp_message)?;
    #[cfg(feature = "bench-network-timings")]
    crate::bench::record_open_core(open_core_started);

    // verify outer signature
    let verification_challenge = view.as_challenge();
    #[cfg(feature = "bench-network-timings")]
    let verify_started = std::time::Instant::now();
    if !matches!(view.signature_type(), SignatureType::NoSignature) {
        verify_detached(
            sender,
            verification_challenge.signed_data,
            verification_challenge.signature,
        )?;
    }
    #[cfg(feature = "bench-network-timings")]
    crate::bench::record_verify(verify_started);

    // decode envelope
    #[cfg(feature = "bench-network-timings")]
    let open_core_started = std::time::Instant::now();
    let crate::cesr::DecodedEnvelope {
        raw_header,
        envelope,
        payload_position: Some(ciphertext),
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

    let result = match envelope.crypto_type {
        CryptoType::HpkeBase => tsp_hpke::open(receiver, sender, raw_header, envelope, ciphertext),
        CryptoType::SealedBox => tsp_nacl::open(receiver, sender, raw_header, envelope, ciphertext),
        CryptoType::Plaintext => Err(CryptoError::MissingCiphertext),
    };
    #[cfg(feature = "bench-network-timings")]
    crate::bench::record_open_core(open_core_started);

    result
}

/// Construct and sign a non-confidential TSP message
pub fn sign(
    sender: &dyn PrivateVid,
    receiver: Option<&dyn VerifiedVid>,
    payload: &[u8],
) -> Result<TSPMessage, CryptoError> {
    nonconfidential::sign(sender, receiver, payload)
}

/// Decode a CESR Authentic Non-Confidential Message, verify the signature and return its contents
pub fn verify<'a>(
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<(&'a [u8], MessageType), CryptoError> {
    nonconfidential::verify(sender, tsp_message)
}

pub fn default_encryption_key_type() -> VidEncryptionKeyType {
    if cfg!(feature = "pq") {
        VidEncryptionKeyType::X25519MlKem768
    } else {
        VidEncryptionKeyType::X25519
    }
}

pub fn default_signature_key_type() -> VidSignatureKeyType {
    if cfg!(feature = "pq") {
        VidSignatureKeyType::MlDsa65
    } else {
        VidSignatureKeyType::Ed25519
    }
}

/// Generate a new encryption / decryption key pair with the default key type.
pub fn gen_encrypt_keypair() -> (PrivateKeyData, PublicKeyData) {
    gen_encrypt_keypair_for(default_encryption_key_type())
}

/// Generate a new encryption / decryption key pair for an explicit key type.
pub fn gen_encrypt_keypair_for(key_type: VidEncryptionKeyType) -> (PrivateKeyData, PublicKeyData) {
    match key_type {
        VidEncryptionKeyType::X25519 => {
            let private_key = crypto_box::SecretKey::generate(&mut OsRng);

            (
                private_key.to_bytes().to_vec().into(),
                crypto_box::PublicKey::from(&private_key)
                    .to_bytes()
                    .to_vec()
                    .into(),
            )
        }
        VidEncryptionKeyType::X25519MlKem768 => {
            use hpke::Serializable;

            let (private, public) = <hpke::kem::XWing as hpke::Kem>::gen_keypair();

            let private = private.to_bytes();
            let public = public.to_bytes();

            (
                private.as_slice().to_vec().into(),
                public.as_slice().to_vec().into(),
            )
        }
    }
}

/// Generate a new signing / verification key pair with the default key type.
pub fn gen_sign_keypair() -> (PrivateSigningKeyData, PublicVerificationKeyData) {
    gen_sign_keypair_for(default_signature_key_type())
}

/// Generate a new signing / verification key pair for an explicit key type.
pub fn gen_sign_keypair_for(
    key_type: VidSignatureKeyType,
) -> (PrivateSigningKeyData, PublicVerificationKeyData) {
    match key_type {
        VidSignatureKeyType::Ed25519 => {
            let sigkey = ed25519_dalek::SigningKey::generate(&mut OsRng);

            (
                sigkey.to_bytes().to_vec().into(),
                sigkey.verifying_key().to_bytes().to_vec().into(),
            )
        }
        VidSignatureKeyType::MlDsa65 => {
            let sigkey = <ml_dsa::SigningKey<MlDsa65> as ml_dsa::Generate>::generate();
            let verifying_key =
                <ml_dsa::SigningKey<MlDsa65> as ml_dsa::Keypair>::verifying_key(&sigkey);
            #[allow(deprecated)]
            let signing_key = sigkey.expanded_key().to_expanded();

            (
                signing_key.to_vec().into(),
                verifying_key.encode().to_vec().into(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cesr::CryptoType,
        definitions::{Payload, VidEncryptionKeyType, VidSignatureKeyType},
        vid::OwnedVid,
    };
    use url::Url;

    use super::{CryptoError, open, seal, seal_with_crypto_type, sign};

    #[test]
    fn relationship_digest_tampering_is_detected() {
        // a request payload whose embedded digest is the correct SAID verifies;
        // any other value in the digest slot is rejected
        let sender = b"did:test:alice".as_slice();
        let receiver = b"did:test:bob".as_slice();
        let mut envelope_prefix = Vec::new();
        crate::cesr::encode_envelope_prefix(sender, Some(receiver), &mut envelope_prefix).unwrap();

        let algorithm = super::RelationshipDigestAlgorithm::Sha2_256;
        let nonce_bytes = [7_u8; 16];
        let mut digest = [0_u8; 32];
        let payload = crate::cesr::Payload::<&[u8], &[u8]>::DirectRelationProposal {
            nonce: crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes),
            request_digest: algorithm.field(&digest),
        };
        let mut input = Vec::new();
        crate::cesr::encode_digest_input(&payload, Some(sender), &envelope_prefix, &mut input)
            .unwrap();
        digest = algorithm.hash(&input);

        let good = crate::cesr::Payload::<&[u8], &[u8]>::DirectRelationProposal {
            nonce: crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes),
            request_digest: algorithm.field(&digest),
        };
        super::verify_relationship_digest(&good, Some(sender), &envelope_prefix).unwrap();

        let mut tampered_digest = digest;
        tampered_digest[0] ^= 0x01;
        let tampered = crate::cesr::Payload::<&[u8], &[u8]>::DirectRelationProposal {
            nonce: crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes),
            request_digest: algorithm.field(&tampered_digest),
        };
        assert!(matches!(
            super::verify_relationship_digest(&tampered, Some(sender), &envelope_prefix),
            Err(CryptoError::DigestMismatch)
        ));
    }

    #[test]
    fn seal_open_message() {
        let alice = OwnedVid::bind(
            "did:test:alice",
            Url::parse("tcp://127.0.0.1:13371").unwrap(),
        );
        let bob = OwnedVid::bind("did:test:bob", Url::parse("tcp://127.0.0.1:13372").unwrap());

        let secret_message: &[u8] = b"hello world";

        let mut message = seal(&bob, &alice, Payload::Content(secret_message)).unwrap();

        let (received_secret_message, _, _) = open(&alice, &bob, &mut message).unwrap();

        assert_eq!(received_secret_message, Payload::Content(secret_message));
    }

    #[test]
    fn explicit_crypto_selection_supports_multiple_backends() {
        let alice = OwnedVid::bind_with_key_types(
            "did:test:alice-explicit",
            Url::parse("tcp://127.0.0.1:13381").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519,
        );
        let bob_x25519 = OwnedVid::bind_with_key_types(
            "did:test:bob-x25519-explicit",
            Url::parse("tcp://127.0.0.1:13382").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519,
        );
        let bob_pq = OwnedVid::bind_with_key_types(
            "did:test:bob-pq-explicit",
            Url::parse("tcp://127.0.0.1:13383").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519MlKem768,
        );

        for (receiver, crypto_type) in [
            (&bob_x25519, CryptoType::HpkeBase),
            (&bob_x25519, CryptoType::SealedBox),
            (&bob_pq, CryptoType::HpkeBase),
        ] {
            let mut message = seal_with_crypto_type(
                &alice,
                receiver,
                Payload::Content(b"selected backend"),
                crypto_type,
            )
            .unwrap();

            let (payload, opened_crypto_type, _) = open(receiver, &alice, &mut message).unwrap();

            assert_eq!(payload, Payload::Content(b"selected backend" as &[u8]));
            assert_eq!(opened_crypto_type, crypto_type);
        }
    }

    #[test]
    fn default_selection_uses_pq_for_pq_receiver() {
        let alice = OwnedVid::bind_with_key_types(
            "did:test:alice-default-pq",
            Url::parse("tcp://127.0.0.1:13386").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519,
        );
        let bob = OwnedVid::bind_with_key_types(
            "did:test:bob-default-pq",
            Url::parse("tcp://127.0.0.1:13387").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519MlKem768,
        );

        let mut message = seal(&alice, &bob, Payload::Content(b"default pq")).unwrap();
        let (payload, opened_crypto_type, _) = open(&bob, &alice, &mut message).unwrap();

        assert_eq!(payload, Payload::Content(b"default pq" as &[u8]));
        assert_eq!(opened_crypto_type, CryptoType::HpkeBase);
    }

    #[test]
    fn default_selection_for_pq_sender_to_x25519_receiver() {
        let alice = OwnedVid::bind_with_key_types(
            "did:test:alice-pq-to-x25519-default",
            Url::parse("tcp://127.0.0.1:13388").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519MlKem768,
        );
        let bob = OwnedVid::bind_with_key_types(
            "did:test:bob-x25519-from-pq-default",
            Url::parse("tcp://127.0.0.1:13389").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519,
        );

        // the anonymous sealed box does not use the sender's encryption keys,
        // so a PQ-keyed sender can seal to an X25519 receiver with either suite;
        // the default follows the feature configuration
        let mut message = seal(&alice, &bob, Payload::Content(b"default suite")).unwrap();
        let (payload, opened_crypto_type, _) = open(&bob, &alice, &mut message).unwrap();

        assert_eq!(payload, Payload::Content(b"default suite" as &[u8]));
        let expected = if cfg!(feature = "nacl") {
            CryptoType::SealedBox
        } else {
            CryptoType::HpkeBase
        };
        assert_eq!(opened_crypto_type, expected);
    }

    #[test]
    fn explicit_crypto_selection_rejects_incompatible_receiver_key() {
        let alice = OwnedVid::bind_with_key_types(
            "did:test:alice-incompatible",
            Url::parse("tcp://127.0.0.1:13384").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519,
        );
        let bob = OwnedVid::bind_with_key_types(
            "did:test:bob-incompatible",
            Url::parse("tcp://127.0.0.1:13385").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519,
        );

        let err = seal_with_crypto_type(
            &alice,
            &bob,
            Payload::Content(b"selected backend"),
            CryptoType::Plaintext,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CryptoError::InvalidCryptoSelection(CryptoType::Plaintext)
        ));
    }

    #[test]
    fn sealed_box_rejects_pq_receiver_key() {
        let alice = OwnedVid::bind_with_key_types(
            "did:test:alice-sealedbox",
            Url::parse("tcp://127.0.0.1:13390").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519,
        );
        let bob = OwnedVid::bind_with_key_types(
            "did:test:bob-pq-sealedbox",
            Url::parse("tcp://127.0.0.1:13391").unwrap(),
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519MlKem768,
        );

        let err = seal_with_crypto_type(
            &alice,
            &bob,
            Payload::Content(b"selected backend"),
            CryptoType::SealedBox,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CryptoError::IncompatibleCryptoSelection {
                crypto_type: CryptoType::SealedBox,
                key_type: VidEncryptionKeyType::X25519MlKem768,
            }
        ));
    }

    #[test]
    fn open_wrong_recipient() {
        let alice = OwnedVid::bind(
            "did:test:alice",
            Url::parse("tcp://127.0.0.1:13371").unwrap(),
        );
        let bob = OwnedVid::bind("did:test:bob", Url::parse("tcp://127.0.0.1:13372").unwrap());
        let carol = OwnedVid::bind(
            "did:test:carol",
            Url::parse("tcp://127.0.0.1:13373").unwrap(),
        );

        let mut message = seal(&bob, &alice, Payload::Content(b"secret")).unwrap();

        let result = open(&carol, &bob, &mut message);

        assert!(matches!(result, Err(CryptoError::UnexpectedRecipient)))
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn open_wrong_key() {
        let alice = OwnedVid::bind(
            "did:test:alice",
            Url::parse("tcp://127.0.0.1:13371").unwrap(),
        );
        let bob = OwnedVid::bind("did:test:bob", Url::parse("tcp://127.0.0.1:13372").unwrap());

        let mut message = seal(&bob, &alice, Payload::Content(b"secret")).unwrap();

        let wrong_alice = OwnedVid::from_bytes(
            "did:test:alice",
            Url::parse("tcp://127.0.0.1:13371").unwrap(),
            [1u8; 32],
            [2u8; 32],
        );

        let result = open(&wrong_alice, &bob, &mut message);

        assert!(matches!(result, Err(CryptoError::CryptographicNacl(_))))
    }

    #[test]
    fn open_missing_ciphertext() {
        let alice = OwnedVid::bind(
            "did:test:alice",
            Url::parse("tcp://127.0.0.1:13371").unwrap(),
        );
        let bob = OwnedVid::bind("did:test:bob", Url::parse("tcp://127.0.0.1:13372").unwrap());

        let mut message = sign(&alice, Some(&bob), b"hello").unwrap();

        let result = open(&bob, &alice, &mut message);

        assert!(matches!(result, Err(CryptoError::MissingCiphertext)))
    }

    #[test]
    fn open_tampered_signature() {
        let alice = OwnedVid::bind(
            "did:test:alice",
            Url::parse("tcp://127.0.0.1:13371").unwrap(),
        );
        let bob = OwnedVid::bind("did:test:bob", Url::parse("tcp://127.0.0.1:13372").unwrap());

        let mut message = seal(&bob, &alice, Payload::Content(b"secret")).unwrap();

        let last = message.len() - 1;
        message[last] ^= 0xFF;

        let result = open(&alice, &bob, &mut message);

        assert!(matches!(result, Err(CryptoError::Verify(_, _))))
    }
}
