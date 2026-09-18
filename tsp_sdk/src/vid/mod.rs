use crate::{
    RelationshipStatus,
    definitions::{
        PendingIncomingParallelRelationship, PendingParallelRelationship, PrivateKeyData,
        PrivateSigningKeyData, PrivateVid, PublicKeyData, PublicVerificationKeyData, VerifiedVid,
    },
};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serialize")]
pub mod deserialize;

pub mod did;

pub mod error;

pub mod key_state;

pub mod resolve;

#[cfg(feature = "resolve")]
pub use did::web::{create_did_web, vid_to_did_document};

#[cfg(feature = "resolve")]
pub use did::peer::{
    encode_did_peer, encode_did_peer_long_form, introduction_identifier, short_form,
    verify_did_peer,
};

pub use error::VidError;

pub use key_state::{KeyStateProvenance, extends_held_key_state, key_state_provenance};
use url::Url;

use crate::secure_area::SoftwareSecureArea;
use std::sync::Arc;

use crate::definitions::{VidEncryptionKeyType, VidSignatureKeyType};
#[cfg(feature = "resolve")]
pub use resolve::{
    verify_vid, verify_vid_offline, verify_vid_offline_with_options, verify_vid_with_options,
};

#[cfg_attr(
    feature = "serialize",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
#[derive(Clone, Debug, Default)]
pub struct VerifyVidOptions {
    pub resolution_context: Option<ResolutionContext>,
}

#[cfg_attr(
    feature = "serialize",
    derive(Serialize, Deserialize),
    serde(tag = "kind", content = "value", rename_all = "camelCase")
)]
#[derive(Clone, Debug)]
pub enum ResolutionContext {
    #[cfg(feature = "resolve")]
    Scid(did::scid::ScidResolutionContext),
}

/// A Vid represents a *verified* Identifier
/// (so it doesn't carry any information that allows to verify it)
#[cfg_attr(
    feature = "serialize",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
#[derive(Clone, Debug)]
pub struct Vid {
    id: String,
    transport: Url,
    #[cfg_attr(feature = "serialize", serde(default))]
    sig_key_type: VidSignatureKeyType,
    public_sigkey: PublicVerificationKeyData,
    #[cfg_attr(feature = "serialize", serde(default))]
    enc_key_type: VidEncryptionKeyType,
    public_enckey: PublicKeyData,
}

/// A OwnedVid represents the 'owner' of a particular Vid
#[cfg_attr(
    feature = "serialize",
    derive(Serialize),
    serde(rename_all = "camelCase")
)]
#[derive(Clone)]
pub struct OwnedVid {
    #[cfg_attr(feature = "serialize", serde(flatten))]
    vid: Vid,
    /// The keys, behind the boundary. Serialised only by the software wallet's own import
    /// and export (a VID file, the JavaScript wallet); see `PrivateKeys`.
    #[cfg_attr(feature = "serialize", serde(flatten))]
    keys: PrivateKeys,
}

/// The two keys of an [`OwnedVid`] in a [`SoftwareSecureArea`], under the aliases
/// `<id>#signing-key` and `<id>#decryption-key`. This is the import vehicle: bytes come in
/// here from a file or a seed and are never read back by anything but the wallet that
/// persists them.
#[derive(Clone)]
struct PrivateKeys {
    area: Arc<SoftwareSecureArea>,
    sig_alias: String,
    enc_alias: String,
}

impl PrivateKeys {
    fn from_material(
        id: &str,
        sig_key_type: VidSignatureKeyType,
        sigkey: PrivateSigningKeyData,
        enc_key_type: VidEncryptionKeyType,
        enckey: PrivateKeyData,
    ) -> Result<Self, crate::SecureAreaError> {
        let area = SoftwareSecureArea::new();
        let sig_alias = format!("{id}#signing-key");
        let enc_alias = format!("{id}#decryption-key");
        area.import(
            &sig_alias,
            sig_key_type.into(),
            zeroize::Zeroizing::new(sigkey.as_slice().to_vec()),
        )?
        .ok_or_else(|| crate::SecureAreaError::Malformed(sig_alias.clone()))?;
        area.import(
            &enc_alias,
            enc_key_type.into(),
            zeroize::Zeroizing::new(enckey.as_slice().to_vec()),
        )?
        .ok_or_else(|| crate::SecureAreaError::Malformed(enc_alias.clone()))?;
        Ok(Self {
            area: Arc::new(area),
            sig_alias,
            enc_alias,
        })
    }

    fn material(&self) -> Option<(PrivateSigningKeyData, PrivateKeyData)> {
        let (_, sig) = self.area.material(&self.sig_alias)?;
        let (_, enc) = self.area.material(&self.enc_alias)?;
        Some((sig.to_vec().into(), enc.to_vec().into()))
    }
}

#[cfg(feature = "serialize")]
impl Serialize for PrivateKeys {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let (sigkey, enckey) = self
            .material()
            .ok_or_else(|| serde::ser::Error::custom("keys are not in the software area"))?;
        let mut st = serializer.serialize_struct("PrivateKeys", 2)?;
        st.serialize_field("sigkey", &sigkey)?;
        st.serialize_field("enckey", &enckey)?;
        st.end()
    }
}

#[cfg(feature = "serialize")]
#[derive(Deserialize)]
struct PrivateKeysWire {
    sigkey: PrivateSigningKeyData,
    enckey: PrivateKeyData,
}

#[cfg(feature = "serialize")]
impl<'de> Deserialize<'de> for OwnedVid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(flatten)]
            vid: Vid,
            #[serde(flatten)]
            keys: PrivateKeysWire,
        }
        let w = Wire::deserialize(deserializer)?;
        OwnedVid::from_parts(w.vid, w.keys.sigkey, w.keys.enckey).map_err(serde::de::Error::custom)
    }
}

/// A custom implementation of Debug for PrivateVid to avoid key material from leaking during panics.
impl std::fmt::Debug for OwnedVid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("PrivateVid")
            .field("vid", &self.vid)
            .field("keys", &"<in the secure area>")
            .finish()
    }
}

impl VerifiedVid for Vid {
    fn identifier(&self) -> &str {
        self.id.as_ref()
    }

    fn endpoint(&self) -> &url::Url {
        &self.transport
    }

    fn verifying_key(&self) -> &PublicVerificationKeyData {
        &self.public_sigkey
    }

    fn encryption_key(&self) -> &PublicKeyData {
        &self.public_enckey
    }

    fn encryption_key_type(&self) -> VidEncryptionKeyType {
        self.enc_key_type
    }

    fn signature_key_type(&self) -> VidSignatureKeyType {
        self.sig_key_type
    }
}

impl VerifiedVid for OwnedVid {
    fn identifier(&self) -> &str {
        self.vid.identifier()
    }

    fn endpoint(&self) -> &url::Url {
        self.vid.endpoint()
    }

    fn verifying_key(&self) -> &PublicVerificationKeyData {
        self.vid.verifying_key()
    }

    fn encryption_key(&self) -> &PublicKeyData {
        self.vid.encryption_key()
    }

    fn encryption_key_type(&self) -> VidEncryptionKeyType {
        self.vid.encryption_key_type()
    }

    fn signature_key_type(&self) -> VidSignatureKeyType {
        self.vid.signature_key_type()
    }
}

impl PrivateVid for OwnedVid {
    fn secure_area(&self) -> &dyn crate::SecureArea {
        self.keys.area.as_ref()
    }

    fn signing_key_alias(&self) -> &str {
        &self.keys.sig_alias
    }

    fn decryption_key_alias(&self) -> &str {
        &self.keys.enc_alias
    }
}

impl AsRef<[u8]> for Vid {
    fn as_ref(&self) -> &[u8] {
        self.identifier().as_bytes()
    }
}

impl OwnedVid {
    pub fn bind(id: impl Into<String>, transport: url::Url) -> Self {
        let sig_key_type = crate::crypto::default_signature_key_type();
        let enc_key_type = crate::crypto::default_encryption_key_type();

        Self::bind_with_key_types(id, transport, sig_key_type, enc_key_type)
    }

    pub fn bind_with_key_types(
        id: impl Into<String>,
        transport: url::Url,
        sig_key_type: VidSignatureKeyType,
        enc_key_type: VidEncryptionKeyType,
    ) -> Self {
        let (sigkey, public_sigkey) = crate::crypto::gen_sign_keypair_for(sig_key_type);
        let (enckey, public_enckey) = crate::crypto::gen_encrypt_keypair_for(enc_key_type);

        Self::from_parts(
            Vid {
                id: id.into(),
                transport,
                sig_key_type,
                public_sigkey,
                enc_key_type,
                public_enckey,
            },
            sigkey,
            enckey,
        )
        .expect("freshly generated keys")
    }
    #[cfg(feature = "fuzzing")]
    pub fn from_bytes(
        id: impl Into<String>,
        transport: url::Url,
        sign_key: [u8; 32],
        enc_key: [u8; 32],
    ) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&sign_key);
        let public_sigkey: PublicVerificationKeyData =
            signing_key.verifying_key().to_bytes().to_vec().into();

        let secret_key = crypto_box::SecretKey::from(enc_key);
        let public_enckey: PublicKeyData = crypto_box::PublicKey::from(&secret_key)
            .to_bytes()
            .to_vec()
            .into();

        Self::from_parts(
            Vid {
                id: id.into(),
                transport,
                sig_key_type: VidSignatureKeyType::Ed25519,
                public_sigkey,
                enc_key_type: VidEncryptionKeyType::X25519,
                public_enckey,
            },
            sign_key.to_vec().into(),
            enc_key.to_vec().into(),
        )
        .expect("32-byte keys")
    }

    pub fn new_did_peer(transport: Url) -> OwnedVid {
        let sig_key_type = crate::crypto::default_signature_key_type();
        let enc_key_type = crate::crypto::default_encryption_key_type();

        Self::new_did_peer_with_key_types(transport, sig_key_type, enc_key_type)
    }

    /// A `did:peer` whose keys are derived from `seed` rather than drawn at
    /// random, so the identifier it produces is the same every time.
    ///
    /// This exists for the published test vectors: a vector is only a test of
    /// an encoder if a verifier can regenerate its bytes, and that requires
    /// every value the message depends on — the keys included — to be recorded
    /// or derivable. Classical keys only; a deterministic VID is not something
    /// to use for a real identity.
    pub fn new_did_peer_from_seed(transport: Url, seed: [u8; 32]) -> OwnedVid {
        Self::new_did_peer_from_seed_with_key_types(
            transport,
            seed,
            VidSignatureKeyType::Ed25519,
            VidEncryptionKeyType::X25519,
        )
    }

    /// As [`Self::new_did_peer_from_seed`], for an explicit pair of key types.
    ///
    /// Both the classical and the post-quantum schemes generate deterministically
    /// from a seed — ML-DSA by FIPS 204's `KeyGen_internal`, and the KEM by HPKE's
    /// `DeriveKeyPair` — so a post-quantum vector is as reproducible as any other.
    pub fn new_did_peer_from_seed_with_key_types(
        transport: Url,
        seed: [u8; 32],
        sig_key_type: VidSignatureKeyType,
        enc_key_type: VidEncryptionKeyType,
    ) -> OwnedVid {
        use rand::{RngCore, SeedableRng};

        let mut rng = rand::rngs::StdRng::from_seed(seed);

        let mut sign_seed = [0_u8; 32];
        rng.fill_bytes(&mut sign_seed);
        let (sigkey, public_sigkey): (PrivateSigningKeyData, PublicVerificationKeyData) =
            match sig_key_type {
                VidSignatureKeyType::Ed25519 => {
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sign_seed);

                    (
                        sign_seed.to_vec().into(),
                        signing_key.verifying_key().to_bytes().to_vec().into(),
                    )
                }
                VidSignatureKeyType::MlDsa65 => {
                    use ml_dsa::{B32, MlDsa65, SigningKey};

                    let signing_key = SigningKey::<MlDsa65>::from_seed(&B32::from(sign_seed));
                    let verifying_key = ml_dsa::Keypair::verifying_key(&signing_key);
                    #[allow(deprecated)]
                    let expanded = signing_key.expanded_key().to_expanded();

                    (
                        expanded.to_vec().into(),
                        verifying_key.encode().to_vec().into(),
                    )
                }
            };

        let mut enc_seed = [0_u8; 32];
        rng.fill_bytes(&mut enc_seed);
        let (enckey, public_enckey): (PrivateKeyData, PublicKeyData) = match enc_key_type {
            VidEncryptionKeyType::X25519 => {
                let secret_key = crypto_box::SecretKey::from(enc_seed);

                (
                    secret_key.to_bytes().to_vec().into(),
                    crypto_box::PublicKey::from(&secret_key)
                        .to_bytes()
                        .to_vec()
                        .into(),
                )
            }
            VidEncryptionKeyType::MlKem768X25519 => {
                use hpke::{Kem, Serializable, kem::XWing};

                let (private, public) = XWing::derive_keypair(&enc_seed);

                (
                    private.to_bytes().as_slice().to_vec().into(),
                    public.to_bytes().as_slice().to_vec().into(),
                )
            }
        };

        let mut vid = Vid {
            id: Default::default(),
            transport,
            sig_key_type,
            enc_key_type,
            public_sigkey,
            public_enckey,
        };
        vid.id = crate::vid::did::peer::encode_did_peer(&vid);

        OwnedVid::from_parts(vid, sigkey, enckey).expect("keys derived from the seed")
    }

    pub fn new_did_peer_with_key_types(
        transport: Url,
        sig_key_type: VidSignatureKeyType,
        enc_key_type: VidEncryptionKeyType,
    ) -> OwnedVid {
        let (sigkey, public_sigkey) = crate::crypto::gen_sign_keypair_for(sig_key_type);
        let (enckey, public_enckey) = crate::crypto::gen_encrypt_keypair_for(enc_key_type);

        let mut vid = Vid {
            id: Default::default(),
            transport,
            sig_key_type,
            enc_key_type,
            public_sigkey,
            public_enckey,
        };

        vid.id = crate::vid::did::peer::encode_did_peer(&vid);

        Self::from_parts(vid, sigkey, enckey).expect("freshly generated keys")
    }

    pub fn vid(&self) -> &Vid {
        &self.vid
    }

    pub fn into_vid(self) -> Vid {
        self.vid
    }

    /// A VID from its public half and its two keys as bytes: the one way key material
    /// enters, from a file, a seed or the wallet's storage. The bytes go straight into a
    /// software secure area; the error is material that is not a key of the VID's types.
    pub(crate) fn from_parts(
        vid: Vid,
        sigkey: PrivateSigningKeyData,
        enckey: PrivateKeyData,
    ) -> Result<Self, crate::SecureAreaError> {
        let keys = PrivateKeys::from_material(
            &vid.id,
            vid.sig_key_type,
            sigkey,
            vid.enc_key_type,
            enckey,
        )?;
        Ok(Self { vid, keys })
    }

    /// The aliases a VID's keys go by in any secure area.
    pub fn key_aliases(id: &str) -> (String, String) {
        (format!("{id}#signing-key"), format!("{id}#decryption-key"))
    }

    /// A handle on a VID whose keys are already in `area` under the VID's aliases; `None`
    /// if they are not.
    pub(crate) fn from_area(vid: Vid, area: Arc<SoftwareSecureArea>) -> Option<Self> {
        let (sig_alias, enc_alias) = Self::key_aliases(&vid.id);
        if !area.has_key(&sig_alias) || !area.has_key(&enc_alias) {
            return None;
        }
        Some(Self {
            vid,
            keys: PrivateKeys {
                area,
                sig_alias,
                enc_alias,
            },
        })
    }

    /// The same VID with its keys copied into `area` under the aliases its identifier gives
    /// them, and this handle pointing there. The aliases may differ from this handle's: a
    /// did:webvh is created under a placeholder identifier, a did:scid is presented under
    /// another identifier than its source.
    pub(crate) fn adopted_by(
        &self,
        area: Arc<SoftwareSecureArea>,
    ) -> Result<Self, crate::SecureAreaError> {
        let (sig_alias, enc_alias) = Self::key_aliases(&self.vid.id);
        area.adopt_key(&self.keys.area, &self.keys.sig_alias, &sig_alias)?;
        area.adopt_key(&self.keys.area, &self.keys.enc_alias, &enc_alias)?;
        Ok(Self {
            vid: self.vid.clone(),
            keys: PrivateKeys {
                area,
                sig_alias,
                enc_alias,
            },
        })
    }

    /// Give the VID its final identifier, re-aliasing its keys to it: a did:webvh is built
    /// under a placeholder until its SCID is known.
    pub(crate) fn set_identifier(&mut self, id: String) -> Result<(), crate::SecureAreaError> {
        let (sig_alias, enc_alias) = Self::key_aliases(&id);
        let area = &self.keys.area;
        area.adopt_key(area, &self.keys.sig_alias, &sig_alias)?;
        area.adopt_key(area, &self.keys.enc_alias, &enc_alias)?;
        area.delete(&self.keys.sig_alias);
        area.delete(&self.keys.enc_alias);
        self.keys.sig_alias = sig_alias;
        self.keys.enc_alias = enc_alias;
        self.vid.id = id;
        Ok(())
    }

    /// The same identifier and keys with another transport.
    pub fn with_transport(&self, transport: Url) -> Self {
        let mut vid = self.vid.clone();
        vid.transport = transport;
        Self {
            vid,
            keys: self.keys.clone(),
        }
    }

    /// The same keys under another identifier: the aliases stay, the area is shared.
    pub(crate) fn with_identifier(&self, id: impl Into<String>) -> Self {
        Self {
            vid: self.vid.with_identifier(id),
            keys: self.keys.clone(),
        }
    }
}

impl Vid {
    #[cfg(test)]
    pub(crate) fn test_vid(
        id: &str,
        sig_key_type: VidSignatureKeyType,
        public_sigkey: PublicVerificationKeyData,
        enc_key_type: VidEncryptionKeyType,
        public_enckey: PublicKeyData,
    ) -> Self {
        Self {
            id: id.to_string(),
            transport: "https://example.com".parse().unwrap(),
            sig_key_type,
            public_sigkey,
            enc_key_type,
            public_enckey,
        }
    }

    pub(crate) fn with_identifier(&self, id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            transport: self.transport.clone(),
            sig_key_type: self.sig_key_type,
            public_sigkey: self.public_sigkey.clone(),
            enc_key_type: self.enc_key_type,
            public_enckey: self.public_enckey.clone(),
        }
    }
}

#[cfg_attr(
    feature = "serialize",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
#[derive(Clone)]
pub struct ExportVid {
    pub id: String,
    pub transport: Url,
    pub public_sigkey: PublicVerificationKeyData,
    pub sig_key_type: VidSignatureKeyType,
    pub public_enckey: PublicKeyData,
    pub enc_key_type: VidEncryptionKeyType,
    /// Whether this endpoint controls the VID: its keys are then in the wallet's secure area
    /// under `<id>#signing-key` and `<id>#decryption-key`, and travel with it, never here.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub private: bool,
    pub relation_status: RelationshipStatus,
    pub relation_vid: Option<String>,
    pub parent_vid: Option<String>,
    pub tunnel: Option<Box<[String]>>,
    #[cfg_attr(feature = "serialize", serde(default))]
    pub pending_parallel_requests: Vec<PendingParallelRelationship>,
    #[cfg_attr(feature = "serialize", serde(default))]
    pub pending_incoming_parallel_requests: Vec<PendingIncomingParallelRelationship>,
    pub metadata: Option<serde_json::Value>,
}

impl ExportVid {
    pub(crate) fn verified_vid(&self) -> Vid {
        Vid {
            id: self.id.clone(),
            transport: self.transport.clone(),
            sig_key_type: self.sig_key_type,
            public_sigkey: self.public_sigkey.clone(),
            enc_key_type: self.enc_key_type,
            public_enckey: self.public_enckey.clone(),
        }
    }

    pub fn is_private(&self) -> bool {
        self.private
    }
}
