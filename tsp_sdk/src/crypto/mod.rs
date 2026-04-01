#[cfg(not(feature = "nacl"))]
use crate::definitions::VidEncryptionKeyType;
use crate::definitions::{
    Digest, MessageType, NonConfidentialData, Payload, PrivateKeyData, PrivateSigningKeyData,
    PrivateVid, PublicKeyData, PublicVerificationKeyData, TSPMessage, VerifiedVid,
};
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
    #[cfg(feature = "bench-network-timings")] timings: &mut crate::BenchNetworkTimings,
) -> Result<TSPMessage, CryptoError> {
    seal_and_hash(
        sender,
        receiver,
        nonconfidential_data,
        payload,
        None,
        #[cfg(feature = "bench-network-timings")]
        timings,
    )
}

/// Encrypt, authenticate and sign and CESR encode a TSP message; also returns the hash value of the plaintext parts before encryption
pub fn seal_and_hash(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    payload: Payload<&[u8]>,
    digest: Option<&mut Digest>,
    #[cfg(feature = "bench-network-timings")] timings: &mut crate::BenchNetworkTimings,
) -> Result<TSPMessage, CryptoError> {
    #[cfg(not(feature = "nacl"))]
    let msg = match receiver.encryption_key_type() {
        VidEncryptionKeyType::X25519 => tsp_hpke::seal::<Aead, Kdf, kem::X25519HkdfSha256>(
            sender,
            receiver,
            nonconfidential_data,
            payload,
            digest,
            #[cfg(feature = "bench-network-timings")]
            timings,
        ),
        #[cfg(feature = "pq")]
        VidEncryptionKeyType::X25519Kyber768Draft00 => {
            tsp_hpke::seal::<Aead, Kdf, kem::X25519Kyber768Draft00>(
                sender,
                receiver,
                nonconfidential_data,
                payload,
                digest,
                #[cfg(feature = "bench-network-timings")]
                timings,
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
        #[cfg(feature = "bench-network-timings")]
        timings,
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
    #[cfg(feature = "bench-network-timings")] timings: &mut crate::BenchNetworkTimings,
) -> Result<MessageContents<'a>, CryptoError> {
    #[cfg(feature = "bench-network-timings")]
    let open_core_started = std::time::Instant::now();
    let view = crate::cesr::decode_envelope(tsp_message)?;
    #[cfg(feature = "bench-network-timings")]
    {
        timings.open_core_ns = timings.open_core_ns.saturating_add(
            u64::try_from(open_core_started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
    }

    // verify outer signature
    let verification_challenge = view.as_challenge();
    #[cfg(feature = "bench-network-timings")]
    let verify_started = std::time::Instant::now();
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
    #[cfg(feature = "bench-network-timings")]
    {
        timings.verify_ns = timings
            .verify_ns
            .saturating_add(u64::try_from(verify_started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }

    // decode envelope
    #[cfg(feature = "bench-network-timings")]
    let open_core_started = std::time::Instant::now();
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

    let result = match envelope.crypto_type {
        #[cfg(feature = "pq")]
        CryptoType::X25519Kyber768Draft00 => {
            tsp_hpke::open::<Aead, Kdf, kem::X25519Kyber768Draft00>(
                receiver,
                sender,
                raw_header,
                envelope,
                ciphertext,
                #[cfg(feature = "bench-network-timings")]
                timings,
            )
        }
        CryptoType::HpkeAuth | CryptoType::HpkeEssr => {
            tsp_hpke::open::<Aead, Kdf, kem::X25519HkdfSha256>(
                receiver,
                sender,
                raw_header,
                envelope,
                ciphertext,
                #[cfg(feature = "bench-network-timings")]
                timings,
            )
        }
        CryptoType::NaclAuth | CryptoType::NaclEssr => tsp_nacl::open(
            receiver,
            sender,
            raw_header,
            envelope,
            ciphertext,
            #[cfg(feature = "bench-network-timings")]
            timings,
        ),
        CryptoType::Plaintext => Err(CryptoError::MissingCiphertext),
    };
    #[cfg(feature = "bench-network-timings")]
    if result.is_ok() {
        timings.open_core_ns = timings.open_core_ns.saturating_add(
            u64::try_from(open_core_started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
    }
    result
}

/// Construct and sign a non-confidential TSP message
pub fn sign(
    sender: &dyn PrivateVid,
    receiver: Option<&dyn VerifiedVid>,
    payload: &[u8],
    #[cfg(feature = "bench-network-timings")] timings: &mut crate::BenchNetworkTimings,
) -> Result<TSPMessage, CryptoError> {
    nonconfidential::sign(
        sender,
        receiver,
        payload,
        #[cfg(feature = "bench-network-timings")]
        timings,
    )
}

/// Decode a CESR Authentic Non-Confidential Message, verify the signature and return its contents
pub fn verify<'a>(
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
    #[cfg(feature = "bench-network-timings")] timings: &mut crate::BenchNetworkTimings,
) -> Result<(&'a [u8], MessageType), CryptoError> {
    nonconfidential::verify(
        sender,
        tsp_message,
        #[cfg(feature = "bench-network-timings")]
        timings,
    )
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
        #[cfg(feature = "bench-network-timings")]
        let mut timings = crate::BenchNetworkTimings::default();

        let mut message = seal(
            &bob,
            &alice,
            Some(nonconfidential_data),
            Payload::Content(secret_message),
            #[cfg(feature = "bench-network-timings")]
            &mut timings,
        )
        .unwrap();

        #[cfg(feature = "bench-network-timings")]
        let mut timings = crate::BenchNetworkTimings::default();
        let (received_nonconfidential_data, received_secret_message, _, _) = open(
            &alice,
            &bob,
            &mut message,
            #[cfg(feature = "bench-network-timings")]
            &mut timings,
        )
        .unwrap();

        assert_eq!(received_nonconfidential_data.unwrap(), nonconfidential_data);
        assert_eq!(received_secret_message, Payload::Content(secret_message));
    }
}
