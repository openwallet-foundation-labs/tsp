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
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    MlDsa65,
    X25519,
    MlKem768X25519,
}

impl KeyType {
    /// The name a key type is stored under.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "Ed25519",
            KeyType::MlDsa65 => "MlDsa65",
            KeyType::X25519 => "X25519",
            KeyType::MlKem768X25519 => "MlKem768X25519",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "Ed25519" => KeyType::Ed25519,
            "MlDsa65" => KeyType::MlDsa65,
            "X25519" => KeyType::X25519,
            "MlKem768X25519" => KeyType::MlKem768X25519,
            _ => return None,
        })
    }
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

/// A key as the secure area names it: its alias and its public half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub alias: String,
    pub public: Vec<u8>,
}

/// The multikey of an Ed25519 public key: `z` + base58btc(`ed 01` ‖ key). The name a
/// did:webvh update key goes by, and the alias the software area gives such a key when the
/// caller names none.
pub fn ed25519_multikey(public: &[u8]) -> String {
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(public);
    format!("z{}", bs58::encode(bytes).into_string())
}

/// A secure area whose keys live elsewhere, a KMS or a hardware token, reached by a handle
/// the area keeps per alias: what the software area attaches to keep the wallet in one
/// piece. The handle, not the key, is what the wallet persists.
pub trait RemoteKeys: SecureArea {
    /// The handle the remote keeps for `alias`, a KMS resource name, say.
    fn handle(&self, alias: &str) -> Option<String>;

    /// Know `alias` as the remote key `handle` again, after the wallet was reopened.
    fn bind(&self, alias: &str, key_type: KeyType, handle: &str) -> Result<(), SecureAreaError>;
}

/// Keys by alias, and the private operations on them. Nothing returns a key.
pub trait SecureArea: Send + Sync {
    /// Make a key of `key_type`. With no alias the area names it: an Ed25519 key by its
    /// multikey, any other by a random name.
    fn create_key(
        &self,
        alias: Option<&str>,
        key_type: KeyType,
    ) -> Result<KeyInfo, SecureAreaError>;

    /// Destroy a key. A key that is not there is not an error.
    fn delete_key(&self, alias: &str) -> Result<(), SecureAreaError>;

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
    /// `None` when the material is not a key of its type: kept as it came, refused at use.
    public: Option<Vec<u8>>,
}

/// Keys in this process's memory. The import vehicle for keys that arrive as bytes (a VID
/// file, a seed for a test vector) and the wallet on a laptop.
///
/// A [`RemoteKeys`] area may be attached: every Ed25519 key created from then on is made
/// there and only its handle is kept here, so a wallet on a VM signs in a KMS while its
/// encryption keys, which no KMS does, stay in memory. Handles are persisted with the
/// wallet; a reopened wallet knows its remote keys by name and refuses to use them,
/// `Locked`, until the remote is attached again.
#[derive(Default)]
pub struct SoftwareSecureArea {
    keys: RwLock<HashMap<String, StoredKey>>,
    remote: RwLock<Option<Arc<dyn RemoteKeys>>>,
    /// alias → (type, handle) of the keys that live in the remote
    remote_keys: RwLock<HashMap<String, (KeyType, String)>>,
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
        let mut all: Vec<String> = self
            .keys
            .read()
            .map(|k| k.keys().cloned().collect())
            .unwrap_or_default();
        if let Ok(r) = self.remote_keys.read() {
            all.extend(r.keys().cloned());
        }
        all
    }

    pub fn has_key(&self, alias: &str) -> bool {
        self.keys.read().is_ok_and(|k| k.contains_key(alias))
            || self.remote_keys.read().is_ok_and(|r| r.contains_key(alias))
    }

    /// Whether `alias` lives in the attached remote, by handle, rather than in memory here.
    pub fn is_remote(&self, alias: &str) -> bool {
        self.remote_keys.read().is_ok_and(|r| r.contains_key(alias))
    }

    /// Attach the area where signing keys are made from now on. Keys this area already
    /// knows by handle are bound into it.
    pub fn attach_remote(&self, remote: Arc<dyn RemoteKeys>) -> Result<(), SecureAreaError> {
        let known: Vec<(String, KeyType, String)> = self
            .remote_keys
            .read()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?
            .iter()
            .map(|(a, (t, h))| (a.clone(), *t, h.clone()))
            .collect();
        for (alias, key_type, handle) in known {
            remote.bind(&alias, key_type, &handle)?;
        }
        *self
            .remote
            .write()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))? = Some(remote);
        Ok(())
    }

    /// Know `alias` as a key held remotely under `handle`: what the wallet's storage
    /// restores. Bound into the remote now if one is attached, else when it is.
    pub fn bind_remote(
        &self,
        alias: &str,
        key_type: KeyType,
        handle: &str,
    ) -> Result<(), SecureAreaError> {
        if let Some(remote) = self.remote()? {
            remote.bind(alias, key_type, handle)?;
        }
        self.remote_keys
            .write()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?
            .insert(alias.to_string(), (key_type, handle.to_string()));
        Ok(())
    }

    /// Every remote key's alias, type and handle, for the wallet that persists them.
    pub(crate) fn remote_handles(&self) -> Vec<(String, KeyType, String)> {
        self.remote_keys
            .read()
            .map(|r| {
                r.iter()
                    .map(|(a, (t, h))| (a.clone(), *t, h.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn remote(&self) -> Result<Option<Arc<dyn RemoteKeys>>, SecureAreaError> {
        Ok(self
            .remote
            .read()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?
            .clone())
    }

    /// The attached remote, for an operation on a key that lives there; `Locked` when the
    /// key is known but the remote is not attached.
    fn remote_for(&self, alias: &str) -> Result<Option<Arc<dyn RemoteKeys>>, SecureAreaError> {
        let is_remote = self
            .remote_keys
            .read()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?
            .contains_key(alias);
        if !is_remote {
            return Ok(None);
        }
        match self.remote()? {
            Some(r) => Ok(Some(r)),
            None => Err(SecureAreaError::Locked {
                alias: alias.to_string(),
                reason: "the key lives in a remote secure area that is not attached".into(),
            }),
        }
    }

    /// Generate a key of `key_type` under `alias`; returns its public half.
    pub fn generate(&self, alias: &str, key_type: KeyType) -> Result<Vec<u8>, SecureAreaError> {
        let (material, public) = generate(key_type);
        self.insert(alias, key_type, material, Some(public.clone()))?;
        Ok(public)
    }

    /// Every key's type and material, for the wallet that persists this software area and
    /// for nothing else.
    pub(crate) fn all_material(&self) -> Vec<(String, KeyType, Secret)> {
        self.keys
            .read()
            .map(|k| {
                k.iter()
                    .map(|(a, key)| (a.clone(), key.key_type, key.material.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Bring key material in from outside: a 32-byte seed for Ed25519, X25519 and the
    /// post-quantum KEM, the expanded key for ML-DSA-65. Returns the public half.
    pub fn import(
        &self,
        alias: &str,
        key_type: KeyType,
        material: Secret,
    ) -> Result<Option<Vec<u8>>, SecureAreaError> {
        // material that is not a key of its type is kept as it came and refused when used,
        // so a wallet with one bad key still opens
        let public = public_of(key_type, &material);
        self.insert(alias, key_type, material, public)
    }

    pub fn delete(&self, alias: &str) {
        if let Ok(mut keys) = self.keys.write() {
            keys.remove(alias);
        }
        let was_remote = self
            .remote_keys
            .write()
            .ok()
            .and_then(|mut r| r.remove(alias))
            .is_some();
        if was_remote && let Ok(Some(remote)) = self.remote() {
            let _ = remote.delete_key(alias);
        }
    }

    /// Copy one key of `other` into this area under `alias`: how a store takes on the keys
    /// of an [`crate::OwnedVid`] it is given, under the aliases its identifier gives them.
    pub(crate) fn adopt_key(
        &self,
        other: &SoftwareSecureArea,
        from_alias: &str,
        alias: &str,
    ) -> Result<(), SecureAreaError> {
        // a key that lives remotely is adopted by its handle, under the new alias
        let remote_entry = other
            .remote_keys
            .read()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?
            .get(from_alias)
            .cloned();
        if let Some((key_type, handle)) = remote_entry {
            if std::ptr::eq(self, other) && from_alias == alias {
                return Ok(());
            }
            if self.remote()?.is_none()
                && let Some(remote) = other.remote()?
            {
                *self
                    .remote
                    .write()
                    .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))? =
                    Some(remote);
            }
            return self.bind_remote(alias, key_type, &handle);
        }
        let (key_type, material, public) = other.with_key(from_alias, |k| {
            Ok((k.key_type, k.material.clone(), k.public.clone()))
        })?;
        self.insert(alias, key_type, material, public)?;
        Ok(())
    }

    /// Copy every key of `other` into this area, under the same aliases: how a store takes
    /// on the keys of a wallet state read from storage.
    pub(crate) fn adopt(&self, other: &SoftwareSecureArea) -> Result<(), SecureAreaError> {
        let taken: Vec<(String, KeyType, Secret, Option<Vec<u8>>)> = other
            .keys
            .read()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?
            .iter()
            .map(|(a, k)| (a.clone(), k.key_type, k.material.clone(), k.public.clone()))
            .collect();
        for (alias, key_type, material, public) in taken {
            self.insert(&alias, key_type, material, public)?;
        }
        for (alias, key_type, handle) in other.remote_handles() {
            self.bind_remote(&alias, key_type, &handle)?;
        }
        Ok(())
    }

    /// The alias the area gives a key nobody named.
    fn default_alias(key_type: KeyType, public: &[u8]) -> String {
        match key_type {
            KeyType::Ed25519 => ed25519_multikey(public),
            _ => {
                let mut r = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut r);
                format!("key-{}", bs58::encode(r).into_string())
            }
        }
    }

    fn insert(
        &self,
        alias: &str,
        key_type: KeyType,
        material: Secret,
        public: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, SecureAreaError> {
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
    fn create_key(
        &self,
        alias: Option<&str>,
        key_type: KeyType,
    ) -> Result<KeyInfo, SecureAreaError> {
        // a signing key is made where it will live: in the remote, when one is attached
        if key_type == KeyType::Ed25519
            && let Some(remote) = self.remote()?
        {
            let info = remote.create_key(alias, key_type)?;
            let handle = remote
                .handle(&info.alias)
                .ok_or_else(|| SecureAreaError::Crypto("remote key without a handle".into()))?;
            self.remote_keys
                .write()
                .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?
                .insert(info.alias.clone(), (key_type, handle));
            return Ok(info);
        }
        let (material, public) = generate(key_type);
        let alias = alias
            .map(str::to_string)
            .unwrap_or_else(|| Self::default_alias(key_type, &public));
        self.insert(&alias, key_type, material, Some(public.clone()))?;
        Ok(KeyInfo { alias, public })
    }

    fn delete_key(&self, alias: &str) -> Result<(), SecureAreaError> {
        self.delete(alias);
        Ok(())
    }

    fn public_key(&self, alias: &str) -> Result<Vec<u8>, SecureAreaError> {
        if let Some(remote) = self.remote_for(alias)? {
            return remote.public_key(alias);
        }
        self.with_key(alias, |k| {
            k.public
                .clone()
                .ok_or_else(|| SecureAreaError::Malformed(alias.into()))
        })
    }

    fn key_type(&self, alias: &str) -> Result<KeyType, SecureAreaError> {
        if let Some((key_type, _)) = self
            .remote_keys
            .read()
            .map_err(|_| SecureAreaError::Crypto("secure area lock".into()))?
            .get(alias)
        {
            return Ok(*key_type);
        }
        self.with_key(alias, |k| Ok(k.key_type))
    }

    fn sign(&self, alias: &str, data: &[u8]) -> Result<Vec<u8>, SecureAreaError> {
        if let Some(remote) = self.remote_for(alias)? {
            return remote.sign(alias, data);
        }
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
        if let Some(remote) = self.remote_for(alias)? {
            return remote.key_agreement(alias, other_public);
        }
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
        if let Some(remote) = self.remote_for(alias)? {
            return remote.kem_decapsulate(alias, encapsulated);
        }
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
    fn create_key(
        &self,
        alias: Option<&str>,
        key_type: KeyType,
    ) -> Result<KeyInfo, SecureAreaError> {
        (**self).create_key(alias, key_type)
    }
    fn delete_key(&self, alias: &str) -> Result<(), SecureAreaError> {
        (**self).delete_key(alias)
    }
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
