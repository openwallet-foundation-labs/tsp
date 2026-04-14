#[cfg(not(feature = "nacl"))]
use crate::definitions::VidEncryptionKeyType;
use crate::definitions::{
    Digest, MessageType, NonConfidentialData, Payload, PrivateKeyData, PrivateSigningKeyData,
    PrivateVid, PublicKeyData, PublicVerificationKeyData, RelationshipForm, TSPMessage,
    VerifiedVid,
};
use ed25519_dalek::Signer;
#[cfg(not(feature = "pq"))]
use hpke::kem;
#[cfg(feature = "pq")]
use hpke_pq::kem;
#[cfg(feature = "pq")]
use ml_dsa::{EncodedVerifyingKey, KeyGen, MlDsa65, signature::Verifier};
use rand_core::OsRng;

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

// Which digest algorithm is active depends on the crypto backend feature set.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum RelationshipDigestAlgorithm {
    Sha2_256,
    Blake2b256,
}

impl RelationshipDigestAlgorithm {
    fn field<'a>(self, digest: &'a Digest) -> crate::cesr::Digest<'a> {
        match self {
            RelationshipDigestAlgorithm::Sha2_256 => crate::cesr::Digest::Sha2_256(digest),
            RelationshipDigestAlgorithm::Blake2b256 => crate::cesr::Digest::Blake2b256(digest),
        }
    }

    fn hash(self, bytes: &[u8]) -> Digest {
        match self {
            RelationshipDigestAlgorithm::Sha2_256 => sha256(bytes),
            RelationshipDigestAlgorithm::Blake2b256 => blake2b256(bytes),
        }
    }
}

fn encode_hashed_payload(
    payload: &CesrRelationshipPayload<'_>,
    sender_in_payload: Option<&[u8]>,
    algorithm: RelationshipDigestAlgorithm,
) -> Result<Digest, CryptoError> {
    let mut encoded = Vec::with_capacity(payload.calculate_size(sender_in_payload));
    crate::cesr::encode_payload(payload, sender_in_payload, &mut encoded)?;
    Ok(algorithm.hash(&encoded))
}

pub(crate) fn build_parallel_request_signed_data(
    sender_in_payload: Option<&[u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    nonce_bytes: [u8; 32],
    request_digest: &mut Digest,
    new_vid: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes);
    let mut signed_data = crate::cesr::encode_parallel_relation_proposal_challenge(
        sender_in_payload,
        &nonce,
        digest_algorithm.field(request_digest),
        new_vid,
    )?;
    *request_digest = digest_algorithm.hash(&signed_data);
    signed_data = crate::cesr::encode_parallel_relation_proposal_challenge(
        sender_in_payload,
        &nonce,
        digest_algorithm.field(request_digest),
        new_vid,
    )?;
    Ok(signed_data)
}

pub(crate) fn build_parallel_accept_signed_data(
    thread_id: &Digest,
    sender_in_payload: Option<&[u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    reply_digest: &mut Digest,
    new_vid: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut signed_data = crate::cesr::encode_parallel_relation_affirm_challenge(
        sender_in_payload,
        digest_algorithm.field(thread_id),
        digest_algorithm.field(reply_digest),
        new_vid,
    )?;
    *reply_digest = digest_algorithm.hash(&signed_data);
    signed_data = crate::cesr::encode_parallel_relation_affirm_challenge(
        sender_in_payload,
        digest_algorithm.field(thread_id),
        digest_algorithm.field(reply_digest),
        new_vid,
    )?;
    Ok(signed_data)
}

fn relationship_request_payload<'a>(
    form: &RelationshipForm<'a, &'a [u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    nonce_bytes: [u8; 32],
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
    nonce_bytes: [u8; 32],
    request_digest: &'a mut Digest,
) -> Result<(CesrRelationshipPayload<'a>, Digest), CryptoError> {
    match form {
        RelationshipForm::Direct => {
            let placeholder_payload =
                relationship_request_payload(form, digest_algorithm, nonce_bytes, &*request_digest);
            *request_digest =
                encode_hashed_payload(&placeholder_payload, sender_in_payload, digest_algorithm)?;

            let digest = *request_digest;

            Ok((
                relationship_request_payload(form, digest_algorithm, nonce_bytes, &*request_digest),
                digest,
            ))
        }
        RelationshipForm::Parallel {
            new_vid,
            sig_new_vid: _,
        } => {
            build_parallel_request_signed_data(
                sender_in_payload,
                digest_algorithm,
                nonce_bytes,
                request_digest,
                new_vid,
            )?;

            let digest = *request_digest;

            Ok((
                relationship_request_payload(form, digest_algorithm, nonce_bytes, &*request_digest),
                digest,
            ))
        }
    }
}

pub(crate) fn build_relationship_accept_payload<'a>(
    thread_id: &'a Digest,
    form: &RelationshipForm<'a, &'a [u8]>,
    sender_in_payload: Option<&[u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    reply_digest: &'a mut Digest,
) -> Result<(CesrRelationshipPayload<'a>, Digest), CryptoError> {
    match form {
        RelationshipForm::Direct => {
            let placeholder_payload =
                relationship_accept_payload(thread_id, form, digest_algorithm, &*reply_digest);
            *reply_digest =
                encode_hashed_payload(&placeholder_payload, sender_in_payload, digest_algorithm)?;

            let digest = *reply_digest;

            Ok((
                relationship_accept_payload(thread_id, form, digest_algorithm, &*reply_digest),
                digest,
            ))
        }
        RelationshipForm::Parallel {
            new_vid,
            sig_new_vid: _,
        } => {
            build_parallel_accept_signed_data(
                thread_id,
                sender_in_payload,
                digest_algorithm,
                reply_digest,
                new_vid,
            )?;

            let digest = *reply_digest;

            Ok((
                relationship_accept_payload(thread_id, form, digest_algorithm, &*reply_digest),
                digest,
            ))
        }
    }
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
        #[cfg(feature = "pq")]
        crate::definitions::VidSignatureKeyType::MlDsa65 => {
            use ml_dsa::EncodedSigningKey;
            let sign_key = ml_dsa::SigningKey::<MlDsa65>::decode(
                &EncodedSigningKey::<MlDsa65>::try_from(sender.signing_key().as_slice())?,
            );
            sign_key.sign(data).encode().to_vec()
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
                .map_err(|err| Verify(sender.identifier().to_string(), err))?;
            let verifying_key =
                ed25519_dalek::VerifyingKey::try_from(sender.verifying_key().as_slice())
                    .map_err(|err| Verify(sender.identifier().to_string(), err))?;
            verifying_key
                .verify_strict(signed_data, &signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err))?;
        }
        #[cfg(feature = "pq")]
        crate::definitions::VidSignatureKeyType::MlDsa65 => {
            let signature: ml_dsa::Signature<MlDsa65> = ml_dsa::Signature::try_from(signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err))?;
            let verifying_key = ml_dsa::VerifyingKey::decode(
                &EncodedVerifyingKey::<MlDsa65>::try_from(sender.verifying_key().as_slice())?,
            );
            verifying_key
                .verify(signed_data, &signature)
                .map_err(|err| Verify(sender.identifier().to_string(), err))?;
        }
    }

    Ok(())
}

#[cfg(not(feature = "pq"))]
pub type Aead = hpke::aead::ChaCha20Poly1305;

#[cfg(not(feature = "pq"))]
pub type Kdf = hpke::kdf::HkdfSha256;

#[cfg(not(feature = "pq"))]
pub type Kem = kem::X25519HkdfSha256;

#[cfg(feature = "pq")]
pub type Aead = hpke_pq::aead::ChaCha20Poly1305;

#[cfg(feature = "pq")]
pub type Kdf = hpke_pq::kdf::HkdfSha256;

#[cfg(feature = "pq")]
pub type Kem = kem::X25519Kyber768Draft00;

/// Encrypt, authenticate and sign and CESR encode a TSP message
pub fn seal(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    payload: Payload<&[u8]>,
) -> Result<TSPMessage, CryptoError> {
    seal_and_hash(sender, receiver, nonconfidential_data, payload, None)
}

/// Encrypt, authenticate and sign and CESR encode a TSP message; also returns the hash value of the plaintext parts before encryption
pub fn seal_and_hash(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    payload: Payload<&[u8]>,
    digest: Option<&mut Digest>,
) -> Result<TSPMessage, CryptoError> {
    seal_and_hash_with_relationship_nonce(
        sender,
        receiver,
        nonconfidential_data,
        payload,
        digest,
        None,
    )
}

pub(crate) fn seal_and_hash_with_relationship_nonce(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    payload: Payload<&[u8]>,
    digest: Option<&mut Digest>,
    request_nonce_override: Option<[u8; 32]>,
) -> Result<TSPMessage, CryptoError> {
    #[cfg(not(feature = "nacl"))]
    let msg = match receiver.encryption_key_type() {
        VidEncryptionKeyType::X25519 => tsp_hpke::seal::<Aead, Kdf, kem::X25519HkdfSha256>(
            sender,
            receiver,
            nonconfidential_data,
            payload,
            digest,
            request_nonce_override,
        ),
        #[cfg(feature = "pq")]
        VidEncryptionKeyType::X25519Kyber768Draft00 => {
            tsp_hpke::seal::<Aead, Kdf, kem::X25519Kyber768Draft00>(
                sender,
                receiver,
                nonconfidential_data,
                payload,
                digest,
                request_nonce_override,
            )
        }
    }?;

    #[cfg(feature = "nacl")]
    let msg = tsp_nacl::seal(
        sender,
        receiver,
        nonconfidential_data,
        payload,
        digest,
        request_nonce_override,
    )?;

    Ok(msg)
}

pub type MessageContents<'a> = (
    Option<NonConfidentialData<'a>>,
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
    let view = crate::cesr::decode_envelope(tsp_message)?;

    // verify outer signature
    let verification_challenge = view.as_challenge();
    if !matches!(view.signature_type(), SignatureType::NoSignature) {
        verify_detached(
            sender,
            verification_challenge.signed_data,
            verification_challenge.signature,
        )?;
    }

    // decode envelope
    let crate::cesr::DecodedEnvelope {
        raw_header,
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

    match envelope.crypto_type {
        #[cfg(feature = "pq")]
        CryptoType::X25519Kyber768Draft00 => {
            tsp_hpke::open::<Aead, Kdf, kem::X25519Kyber768Draft00>(
                receiver, sender, raw_header, envelope, ciphertext,
            )
        }
        CryptoType::HpkeAuth | CryptoType::HpkeEssr => {
            tsp_hpke::open::<Aead, Kdf, kem::X25519HkdfSha256>(
                receiver, sender, raw_header, envelope, ciphertext,
            )
        }
        CryptoType::NaclAuth | CryptoType::NaclEssr => {
            tsp_nacl::open(receiver, sender, raw_header, envelope, ciphertext)
        }
        CryptoType::Plaintext => Err(CryptoError::MissingCiphertext),
    }
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

#[cfg(all(not(feature = "nacl"), not(feature = "pq")))]
/// Generate a new encryption / decryption key pair
pub fn gen_encrypt_keypair() -> (PrivateKeyData, PublicKeyData) {
    use hpke::Serializable;

    let (private, public) = <Kem as hpke::Kem>::gen_keypair(&mut OsRng);

    (
        private.to_bytes().to_vec().into(),
        public.to_bytes().to_vec().into(),
    )
}

#[cfg(feature = "pq")]
/// Generate a new encryption / decryption key pair
pub fn gen_encrypt_keypair() -> (PrivateKeyData, PublicKeyData) {
    use hpke_pq::Serializable;

    let (private, public) = <Kem as hpke_pq::Kem>::gen_keypair(&mut OsRng);

    let private = private.to_bytes();
    let public = public.to_bytes();

    (
        private.as_slice().to_vec().into(),
        public.as_slice().to_vec().into(),
    )
}

#[cfg(all(feature = "nacl", not(feature = "pq")))]
/// Generate a new encryption / decryption key pair
pub fn gen_encrypt_keypair() -> (PrivateKeyData, PublicKeyData) {
    let private_key = crypto_box::SecretKey::generate(&mut OsRng);

    (
        private_key.to_bytes().to_vec().into(),
        crypto_box::PublicKey::from(&private_key)
            .to_bytes()
            .to_vec()
            .into(),
    )
}

/// Generate a new signing / verification key pair
#[cfg(not(feature = "pq"))]
pub fn gen_sign_keypair() -> (PrivateSigningKeyData, PublicVerificationKeyData) {
    let sigkey = ed25519_dalek::SigningKey::generate(&mut OsRng);

    (
        sigkey.to_bytes().to_vec().into(),
        sigkey.verifying_key().to_bytes().to_vec().into(),
    )
}

/// Generate a new signing / verification key pair
#[cfg(feature = "pq")]
pub fn gen_sign_keypair() -> (PrivateSigningKeyData, PublicVerificationKeyData) {
    let sigkey = MlDsa65::key_gen(&mut OsRng);

    (
        sigkey.signing_key().encode().to_vec().into(),
        sigkey.verifying_key().encode().to_vec().into(),
    )
}

#[cfg(test)]
mod tests {
    use crate::{definitions::Payload, vid::OwnedVid};
    use url::Url;

    use super::{open, seal};

    #[test]
    fn seal_open_message() {
        let alice = OwnedVid::bind(
            "did:test:alice",
            Url::parse("tcp://127.0.0.1:13371").unwrap(),
        );
        let bob = OwnedVid::bind("did:test:bob", Url::parse("tcp://127.0.0.1:13372").unwrap());

        let secret_message: &[u8] = b"hello world";
        let nonconfidential_data = b"extra header data";

        let mut message = seal(
            &bob,
            &alice,
            Some(nonconfidential_data),
            Payload::Content(secret_message),
        )
        .unwrap();

        let (received_nonconfidential_data, received_secret_message, _, _) =
            open(&alice, &bob, &mut message).unwrap();

        assert_eq!(received_nonconfidential_data.unwrap(), nonconfidential_data);
        assert_eq!(received_secret_message, Payload::Content(secret_message));
    }
}
