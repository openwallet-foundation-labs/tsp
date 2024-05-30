use crate::definitions::{
    Digest, NonConfidentialData, Payload, PrivateVid, TSPMessage, VerifiedVid,
};

mod digest;
pub mod error;
mod nonconfidential;
mod tsp_hpke;

pub use error::CryptoError;

pub type Aead = hpke::aead::ChaCha20Poly1305;
pub type Kdf = hpke::kdf::HkdfSha256;
pub type Kem = hpke::kem::X25519HkdfSha256;

type ObservingClosure<'a> = &'a mut dyn FnMut(&[u8]);

/// Encrypt, authenticate and sign and CESR encode a TSP message
pub fn seal(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    payload: Payload<&[u8]>,
) -> Result<TSPMessage, CryptoError> {
    tsp_hpke::seal::<Aead, Kdf, Kem>(sender, receiver, nonconfidential_data, payload, None)
}

/// Encrypt, authenticate and sign and CESR encode a TSP message; also returns the hash value of the plaintext parts before encryption
pub fn seal_and_hash(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    payload: Payload<&[u8]>,
) -> Result<(TSPMessage, Digest), CryptoError> {
    let digest = &mut Default::default();
    let msg = tsp_hpke::seal::<Aead, Kdf, Kem>(
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
    tsp_hpke::open::<Aead, Kdf, Kem>(receiver, sender, tsp_message)
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

pub use digest::sha256;

#[cfg(test)]
mod tests {
    use crate::{definitions::Payload, vid::OwnedVid};
    use url::Url;

    use super::{open, seal};

    #[test]
    fn seal_open_message() {
        let bob = OwnedVid::bind("did:test:bob", Url::parse("tcp:://127.0.0.1:1337").unwrap());
        let alice = OwnedVid::bind(
            "did:test:alice",
            Url::parse("tcp:://127.0.0.1:1337").unwrap(),
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
