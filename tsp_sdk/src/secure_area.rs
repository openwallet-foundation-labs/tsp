//! The boundary around private keys.
//!
//! A [`SecureArea`] holds keys by alias and performs the private operations on them; nothing
//! it offers returns a key. The shape is Multipaz's `SecureArea` and Apple's Secure Enclave
//! API: `sign`, `key_agreement` (X25519, the shared secret comes out and HPKE or the sealed
//! box run outside), and `kem_decapsulate` (the post-quantum KEM, which neither of those
//! has). A placement that protects keys in hardware, a phone's keystore or a cloud KMS,
//! implements the same trait; the endpoint does not notice which one it is talking to.
//!
//! [`SoftwareSecureArea`] is the in-process implementation: keys in memory, zeroised on
//! drop, and the only code in the SDK that touches key material. Its persistence is the
//! wallet's (see `secure_storage`), which is why it alone can hand its material out, and
//! only inside the crate.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use zeroize::Zeroizing;

use crate::definitions::{VidEncryptionKeyType, VidSignatureKeyType};

/// What a key is for, and therefore which of the three operations it answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    MlDsa65,
    X25519,
    MlKem768X25519,
}

impl From<VidSignatureKeyType> for KeyType {
    fn from(t: VidSignatureKeyType) -> Self {
        match t {
            VidSignatureKeyType::Ed25519 => KeyType::Ed25519,
            VidSignatureKeyType::MlDsa65 => KeyType::MlDsa65,
        }
    }
}

impl From<VidEncryptionKeyType> for KeyType {
    fn from(t: VidEncryptionKeyType) -> Self {
        match t {
            VidEncryptionKeyType::X25519 => KeyType::X25519,
            VidEncryptionKeyType::MlKem768X25519 => KeyType::MlKem768X25519,
        }
    }
}

/// Why a private operation did not happen. `Locked` is the one the application acts on:
/// the key needs the user, or a credential, before it answers; the SDK never unlocks.
#[derive(Debug, thiserror::Error)]
pub enum SecureAreaError {
    #[error("key {alias} is locked: {reason}")]
    Locked { alias: String, reason: String },
    #[error("no key named {0}")]
    UnknownKey(String),
    #[error("key {0} does not perform this operation")]
    WrongKeyType(String),
    #[error("key material for {0} is malformed")]
    Malformed(String),
    #[error("cryptographic failure: {0}")]
    Crypto(String),
}

/// Bytes that are secret while they live: a shared secret, or key material on its way into
/// a secure area. Zeroised when dropped.
pub type Secret = Zeroizing<Vec<u8>>;

/// Keys by alias, and the private operations on them. Nothing returns a key.
pub trait SecureArea: Send + Sync {
    /// The public half of the key, in the encoding its type uses on the wire.
    fn public_key(&self, alias: &str) -> Result<Vec<u8>, SecureAreaError>;

    fn key_type(&self, alias: &str) -> Result<KeyType, SecureAreaError>;

    /// A signature over `data` by the key: 64 bytes for Ed25519, an ML-DSA-65 signature
    /// otherwise.
    fn sign(&self, alias: &str, data: &[u8]) -> Result<Vec<u8>, SecureAreaError>;

    /// The raw X25519 shared secret between the key and `other_public`.
    fn key_agreement(&self, alias: &str, other_public: &[u8]) -> Result<Secret, SecureAreaError>;

    /// The KEM shared secret for `encapsulated`, decapsulated with the key.
    fn kem_decapsulate(&self, alias: &str, encapsulated: &[u8]) -> Result<Secret, SecureAreaError>;
}

struct StoredKey {
    key_type: KeyType,
    material: Secret,
    public: Vec<u8>,
}

/// Keys in this process's memory. The import vehicle for keys that arrive as bytes (a VID
/// file, a seed for a test vector) and the wallet on a laptop.
#[derive(Default)]
pub struct SoftwareSecureArea {
    keys: RwLock<HashMap<String, StoredKey>>,
}

impl std::fmt::Debug for SoftwareSecureArea {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let aliases = self.aliases();
        f.debug_struct("SoftwareSecureArea")
            .field("aliases", &aliases)
            .finish()
    }
}

impl SoftwareSecureArea {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn aliases(&self) -> Vec<String> {
        self.keys
            .read()
            .map(|k| k.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn has_key(&self, alias: &str) -> bool {
        self.keys.read().is_ok_and(|k| k.contains_key(alias))
    }

    /// Generate a key of `key_type` under `alias`; returns its public half.
    pub fn generate(&self, alias: &str, key_type: KeyType) -> Result<Vec<u8>, SecureAreaError> {
        let (material, public) = generate(key_type);
        self.insert(alias, key_type, material, public)
    }

    /// Bring key material in from outside: a 32-byte seed for Ed25519, X25519 and the
    /// post-quantum KEM, the expanded key for ML-DSA-65. Returns the public half.
    pub fn import(
        &self,
        alias: &str,
        key_type: KeyType,
        material: Secret,
    ) -> Result<Vec<u8>, SecureAreaError> {
        let public = public_of(key_type, &material)
            .ok_or_else(|| SecureAreaError::Malformed(alias.into()))?;
        self.insert(alias, key_type, material, public)
    }

    pub fn delete(&self, alias: &str) {
        if let Ok(mut keys) = self.keys.write() {
            keys.remove(alias);
        }
    }

    fn insert(
        &self,
        alias: &str,
        key_type: KeyType,
        material: Secret,
        public: Vec<u8>,
    ) -> Result<Vec<u8>, SecureAreaError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?;
        keys.insert(
            alias.to_string(),
            StoredKey {
                key_type,
                material,
                public: public.clone(),
            },
        );
        Ok(public)
    }

    /// The material of a key, for the wallet that persists this software area and for
    /// nothing else. A hardware placement has no equivalent.
    pub(crate) fn material(&self, alias: &str) -> Option<(KeyType, Secret)> {
        self.keys
            .read()
            .ok()?
            .get(alias)
            .map(|k| (k.key_type, k.material.clone()))
    }

    fn with_key<T>(
        &self,
        alias: &str,
        f: impl FnOnce(&StoredKey) -> Result<T, SecureAreaError>,
    ) -> Result<T, SecureAreaError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?;
        let key = keys
            .get(alias)
            .ok_or_else(|| SecureAreaError::UnknownKey(alias.into()))?;
        f(key)
    }
}

impl SecureArea for SoftwareSecureArea {
    fn public_key(&self, alias: &str) -> Result<Vec<u8>, SecureAreaError> {
        self.with_key(alias, |k| Ok(k.public.clone()))
    }

    fn key_type(&self, alias: &str) -> Result<KeyType, SecureAreaError> {
        self.with_key(alias, |k| Ok(k.key_type))
    }

    fn sign(&self, alias: &str, data: &[u8]) -> Result<Vec<u8>, SecureAreaError> {
        self.with_key(alias, |k| match k.key_type {
            KeyType::Ed25519 => {
                use ed25519_dalek::Signer;
                let seed: [u8; 32] = k.material[..]
                    .try_into()
                    .map_err(|_| SecureAreaError::Malformed(alias.into()))?;
                let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                Ok(key.sign(data).to_bytes().to_vec())
            }
            KeyType::MlDsa65 => {
                let key = mldsa65_signing_key(&k.material)
                    .ok_or_else(|| SecureAreaError::Malformed(alias.into()))?;
                Ok(ml_dsa::Signer::sign(&key, data).encode().to_vec())
            }
            _ => Err(SecureAreaError::WrongKeyType(alias.into())),
        })
    }

    fn key_agreement(&self, alias: &str, other_public: &[u8]) -> Result<Secret, SecureAreaError> {
        self.with_key(alias, |k| match k.key_type {
            KeyType::X25519 => {
                let scalar: [u8; 32] = k.material[..]
                    .try_into()
                    .map_err(|_| SecureAreaError::Malformed(alias.into()))?;
                let other: [u8; 32] = other_public
                    .try_into()
                    .map_err(|_| SecureAreaError::Crypto("public key is not 32 bytes".into()))?;
                let secret = x25519_dalek::StaticSecret::from(scalar);
                let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(other));
                Ok(Zeroizing::new(shared.as_bytes().to_vec()))
            }
            _ => Err(SecureAreaError::WrongKeyType(alias.into())),
        })
    }

    fn kem_decapsulate(&self, alias: &str, encapsulated: &[u8]) -> Result<Secret, SecureAreaError> {
        self.with_key(alias, |k| match k.key_type {
            KeyType::MlKem768X25519 => {
                use hpke::{Deserializable, Kem, kem::XWing};
                let sk = <XWing as Kem>::PrivateKey::from_bytes(&k.material)
                    .map_err(|_| SecureAreaError::Malformed(alias.into()))?;
                let enc = <XWing as Kem>::EncappedKey::from_bytes(encapsulated)
                    .map_err(|e| SecureAreaError::Crypto(e.to_string()))?;
                let shared = XWing::decap(&sk, None, &enc)
                    .map_err(|e| SecureAreaError::Crypto(e.to_string()))?;
                Ok(Zeroizing::new(shared.0.to_vec()))
            }
            _ => Err(SecureAreaError::WrongKeyType(alias.into())),
        })
    }
}

impl<T: SecureArea + ?Sized> SecureArea for Arc<T> {
    fn public_key(&self, alias: &str) -> Result<Vec<u8>, SecureAreaError> {
        (**self).public_key(alias)
    }
    fn key_type(&self, alias: &str) -> Result<KeyType, SecureAreaError> {
        (**self).key_type(alias)
    }
    fn sign(&self, alias: &str, data: &[u8]) -> Result<Vec<u8>, SecureAreaError> {
        (**self).sign(alias, data)
    }
    fn key_agreement(&self, alias: &str, other_public: &[u8]) -> Result<Secret, SecureAreaError> {
        (**self).key_agreement(alias, other_public)
    }
    fn kem_decapsulate(&self, alias: &str, encapsulated: &[u8]) -> Result<Secret, SecureAreaError> {
        (**self).kem_decapsulate(alias, encapsulated)
    }
}

fn mldsa65_signing_key(material: &[u8]) -> Option<ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>> {
    let bytes = ml_dsa::ExpandedSigningKeyBytes::<ml_dsa::MlDsa65>::try_from(material).ok()?;
    #[allow(deprecated)]
    Some(ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_expanded(&bytes))
}

/// The public half of `material`, or `None` if the material is not a key of that type.
fn public_of(key_type: KeyType, material: &[u8]) -> Option<Vec<u8>> {
    match key_type {
        KeyType::Ed25519 => {
            let seed: [u8; 32] = material.try_into().ok()?;
            Some(
                ed25519_dalek::SigningKey::from_bytes(&seed)
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            )
        }
        KeyType::MlDsa65 => {
            let key = mldsa65_signing_key(material)?;
            Some(ml_dsa::Keypair::verifying_key(&key).encode().to_vec())
        }
        KeyType::X25519 => {
            let scalar: [u8; 32] = material.try_into().ok()?;
            let secret = x25519_dalek::StaticSecret::from(scalar);
            Some(x25519_dalek::PublicKey::from(&secret).as_bytes().to_vec())
        }
        KeyType::MlKem768X25519 => {
            use hpke::{Deserializable, Kem, Serializable, kem::XWing};
            let sk = <XWing as Kem>::PrivateKey::from_bytes(material).ok()?;
            Some(XWing::sk_to_pk(&sk).to_bytes().to_vec())
        }
    }
}

/// Fresh material and its public half, drawn by the crypto module's generators.
fn generate(key_type: KeyType) -> (Secret, Vec<u8>) {
    match key_type {
        KeyType::Ed25519 | KeyType::MlDsa65 => {
            let t = match key_type {
                KeyType::Ed25519 => VidSignatureKeyType::Ed25519,
                _ => VidSignatureKeyType::MlDsa65,
            };
            let (private, public) = crate::crypto::gen_sign_keypair_for(t);
            (
                Zeroizing::new(private.as_slice().to_vec()),
                public.as_ref().to_vec(),
            )
        }
        KeyType::X25519 | KeyType::MlKem768X25519 => {
            let t = match key_type {
                KeyType::X25519 => VidEncryptionKeyType::X25519,
                _ => VidEncryptionKeyType::MlKem768X25519,
            };
            let (private, public) = crate::crypto::gen_encrypt_keypair_for(t);
            (
                Zeroizing::new(private.as_slice().to_vec()),
                public.as_ref().to_vec(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_signs_and_agrees_but_never_comes_out() {
        let area = SoftwareSecureArea::new();
        let vk = area.generate("sig", KeyType::Ed25519).unwrap();
        let sig = area.sign("sig", b"hello").unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk.try_into().unwrap()).unwrap();
        vk.verify_strict(
            b"hello",
            &ed25519_dalek::Signature::from_slice(&sig).unwrap(),
        )
        .unwrap();

        let pk = area.generate("enc", KeyType::X25519).unwrap();
        let other = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let theirs = other.diffie_hellman(&x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(pk.as_slice()).unwrap(),
        ));
        let ours = area
            .key_agreement("enc", x25519_dalek::PublicKey::from(&other).as_bytes())
            .unwrap();
        assert_eq!(theirs.as_bytes().as_slice(), ours.as_slice());

        assert!(matches!(
            area.sign("enc", b"x"),
            Err(SecureAreaError::WrongKeyType(_))
        ));
        assert!(matches!(
            area.sign("nope", b"x"),
            Err(SecureAreaError::UnknownKey(_))
        ));
        assert!(!format!("{area:?}").contains("material"));
    }
}
