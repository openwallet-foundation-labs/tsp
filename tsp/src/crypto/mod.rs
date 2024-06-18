use crate::definitions::{
    Digest, NonConfidentialData, Payload, PrivateKeyData, PrivateVid, PublicKeyData, TSPMessage,
    VerifiedVid,
};
pub use digest::sha256;
use rand::rngs::OsRng;

mod digest;
pub mod error;
mod nonconfidential;

#[cfg(feature = "nacl")]
mod tsp_nacl;

#[cfg(feature = "hpke")]
mod tsp_hpke;

pub use error::CryptoError;

#[cfg(feature = "hpke")]
pub type Aead = hpke::aead::ChaCha20Poly1305;

#[cfg(feature = "hpke")]
pub type Kdf = hpke::kdf::HkdfSha256;

#[cfg(feature = "hpke")]
pub type Kem = hpke::kem::X25519HkdfSha256;

type ObservingClosure<'a> = &'a mut dyn FnMut(&[u8]);

/// Encrypt, authenticate and sign and CESR encode a TSP message
pub fn seal(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    payload: Payload<&[u8]>,
) -> Result<TSPMessage, CryptoError> {
    #[cfg(feature = "hpke")]
    return tsp_hpke::seal::<Aead, Kdf, Kem>(sender, receiver, nonconfidential_data, payload, None);

    #[cfg(feature = "nacl")]
    return tsp_nacl::seal(sender, receiver, nonconfidential_data, payload, None);
}

/// Encrypt, authenticate and sign and CESR encode a TSP message; also returns the hash value of the plaintext parts before encryption
pub fn seal_and_hash(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    payload: Payload<&[u8]>,
) -> Result<(TSPMessage, Digest), CryptoError> {
    let digest = &mut Default::default();

    #[cfg(feature = "hpke")]
    let msg = tsp_hpke::seal::<Aead, Kdf, Kem>(
        sender,
        receiver,
        nonconfidential_data,
        payload,
        Some(&mut |bytes| *digest = sha256(bytes)),
    )?;

    #[cfg(feature = "nacl")]
    let msg = tsp_nacl::seal(
        sender,
        receiver,
        nonconfidential_data,
        payload,
        Some(&mut |bytes| *digest = sha256(bytes)),
    )?;

    Ok((msg, *digest))
}

pub type MessageContents<'a> = (
    Option<NonConfidentialData<'a>>,
    Payload<'a, &'a [u8]>,
    &'a [u8],
);

/// Decode a CESR Authentic Confidential Message, verify the signature and decrypt its contents
pub fn open<'a>(
    receiver: &dyn PrivateVid,
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<MessageContents<'a>, CryptoError> {
    #[cfg(feature = "hpke")]
    return tsp_hpke::open::<Aead, Kdf, Kem>(receiver, sender, tsp_message);

    #[cfg(feature = "nacl")]
    return tsp_nacl::open(receiver, sender, tsp_message);
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
) -> Result<&'a [u8], CryptoError> {
    nonconfidential::verify(sender, tsp_message)
}

#[cfg(feature = "hpke")]
/// Generate a new encryption / decryption key pair
pub fn gen_encrypt_keypair() -> (PrivateKeyData, PublicKeyData) {
    use hpke::Serializable;

    let (private, public) = <Kem as hpke::Kem>::gen_keypair(&mut OsRng);

    (
        Into::<[u8; 32]>::into(private.to_bytes()).into(),
        Into::<[u8; 32]>::into(public.to_bytes()).into(),
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
pub fn gen_sign_keypair() -> (PrivateKeyData, PublicKeyData) {
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

        let (received_nonconfidential_data, received_secret_message, _) =
            open(&alice, &bob, &mut message).unwrap();

        assert_eq!(received_nonconfidential_data.unwrap(), nonconfidential_data);
        assert_eq!(received_secret_message, Payload::Content(secret_message));
    }
}
