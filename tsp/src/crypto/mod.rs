use crate::definitions::MessageType;
use crate::definitions::{
    Digest, NonConfidentialData, Payload, PrivateKeyData, PrivateSigningKeyData, PrivateVid,
    PublicKeyData, PublicVerificationKeyData, TSPMessage, VerifiedVid,
};
use rand_core::OsRng;

pub use digest::blake2b256;
pub use digest::sha256;

mod digest;
pub mod error;
mod nonconfidential;

mod tsp_hpke;
#[cfg(not(feature = "pq"))]
mod tsp_nacl;

pub use error::CryptoError;

#[cfg(not(feature = "pq"))]
use crate::cesr::CryptoType;

#[cfg(not(feature = "pq"))]
pub type Aead = hpke::aead::ChaCha20Poly1305;

#[cfg(not(feature = "pq"))]
pub type Kdf = hpke::kdf::HkdfSha256;

#[cfg(not(feature = "pq"))]
pub type Kem = hpke::kem::X25519HkdfSha256;

#[cfg(feature = "pq")]
pub type Aead = hpke_pq::aead::ChaCha20Poly1305;

#[cfg(feature = "pq")]
pub type Kdf = hpke_pq::kdf::HkdfSha256;

#[cfg(feature = "pq")]
pub type Kem = hpke_pq::kem::X25519Kyber768Draft00;

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
    #[cfg(not(feature = "nacl"))]
    let msg =
        tsp_hpke::seal::<Aead, Kdf, Kem>(sender, receiver, nonconfidential_data, payload, digest)?;

    #[cfg(feature = "nacl")]
    let msg = tsp_nacl::seal(sender, receiver, nonconfidential_data, payload, digest)?;

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
    let view = crate::cesr::decode_envelope(tsp_message)?;

    // verify outer signature
    let verification_challenge = view.as_challenge();
    let signature = ed25519_dalek::Signature::from(verification_challenge.signature);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(sender.verifying_key())?;
    verifying_key.verify_strict(verification_challenge.signed_data, &signature)?;

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

    #[cfg(feature = "pq")]
    return tsp_hpke::open::<Aead, Kdf, Kem>(receiver, sender, raw_header, envelope, ciphertext);

    #[cfg(not(feature = "pq"))]
    match envelope.crypto_type {
        CryptoType::HpkeAuth | CryptoType::HpkeEssr => {
            tsp_hpke::open::<Aead, Kdf, Kem>(receiver, sender, raw_header, envelope, ciphertext)
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

#[cfg(all(not(feature = "essr"), not(feature = "pq")))]
/// Generate a new encryption / decryption key pair
pub fn gen_encrypt_keypair() -> (PrivateKeyData, PublicKeyData) {
    use hpke::Serializable;

    let (private, public) = <Kem as hpke::Kem>::gen_keypair(&mut OsRng);

    (
        Into::<[u8; 32]>::into(private.to_bytes()).into(),
        Into::<[u8; 32]>::into(public.to_bytes()).into(),
    )
}

#[cfg(feature = "pq")]
/// Generate a new encryption / decryption key pair
pub fn gen_encrypt_keypair() -> (PrivateKeyData, PublicKeyData) {
    use crate::definitions::{PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE};
    use hpke_pq::Serializable;

    let (private, public) = <Kem as hpke_pq::Kem>::gen_keypair(&mut OsRng);

    let private = private.to_bytes();
    let public = public.to_bytes();

    (
        TryInto::<[u8; PRIVATE_KEY_SIZE]>::try_into(private.as_slice())
            .unwrap()
            .into(),
        TryInto::<[u8; PUBLIC_KEY_SIZE]>::try_into(public.as_slice())
            .unwrap()
            .into(),
    )
}

#[cfg(feature = "nacl")]
/// Generate a new encryption / decryption key pair
pub fn gen_encrypt_keypair() -> (PrivateKeyData, PublicKeyData) {
    let private_key = crypto_box::SecretKey::generate(&mut OsRng);

    (
        private_key.to_bytes().into(),
        crypto_box::PublicKey::from(&private_key).to_bytes().into(),
    )
}

/// Generate a new signing / verificationkey pair
pub fn gen_sign_keypair() -> (PrivateSigningKeyData, PublicVerificationKeyData) {
    let sigkey = ed25519_dalek::SigningKey::generate(&mut OsRng);

    (
        sigkey.to_bytes().into(),
        sigkey.verifying_key().to_bytes().into(),
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
            Url::parse("tcp:://127.0.0.1:13371").unwrap(),
        );
        let bob = OwnedVid::bind(
            "did:test:bob",
            Url::parse("tcp:://127.0.0.1:13372").unwrap(),
        );

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
