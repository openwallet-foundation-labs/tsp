use crate::{
    definitions::{
        PrivateKeyData, PrivateSigningKeyData, PrivateVid, PublicKeyData,
        PublicVerificationKeyData, VerifiedVid,
    },
    RelationshipStatus,
};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serialize")]
pub mod deserialize;

#[cfg(feature = "resolve")]
pub mod did;

pub mod error;

#[cfg(feature = "resolve")]
pub mod resolve;

#[cfg(feature = "resolve")]
pub use did::web::{create_did_web, vid_to_did_document};

pub use error::VidError;
use url::Url;

#[cfg(feature = "resolve")]
pub use resolve::verify_vid;

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
    public_sigkey: PublicVerificationKeyData,
    public_enckey: PublicKeyData,
}

/// A OwnedVid represents the 'owner' of a particular Vid
#[cfg_attr(
    feature = "serialize",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
#[derive(Clone)]
pub struct OwnedVid {
    #[cfg_attr(feature = "serialize", serde(flatten))]
    vid: Vid,
    sigkey: PrivateSigningKeyData,
    enckey: PrivateKeyData,
}

/// A custom implementation of Debug for PrivateVid to avoid key material from leaking during panics.
impl std::fmt::Debug for OwnedVid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("PrivateVid")
            .field("vid", &self.vid)
            .field("sigkey", &"<secret>")
            .field("enckey", &"<secret>")
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
}

impl PrivateVid for OwnedVid {
    fn signing_key(&self) -> &PrivateSigningKeyData {
        &self.sigkey
    }

    fn decryption_key(&self) -> &PrivateKeyData {
        &self.enckey
    }
}

impl AsRef<[u8]> for Vid {
    fn as_ref(&self) -> &[u8] {
        self.identifier().as_bytes()
    }
}

impl OwnedVid {
    pub fn bind(id: impl Into<String>, transport: url::Url) -> Self {
        let (sigkey, public_sigkey) = crate::crypto::gen_sign_keypair();
        let (enckey, public_enckey) = crate::crypto::gen_encrypt_keypair();

        Self {
            vid: Vid {
                id: id.into(),
                transport,
                public_sigkey,
                public_enckey,
            },
            sigkey,
            enckey,
        }
    }

    #[cfg(feature = "resolve")]
    pub fn new_did_peer(transport: Url) -> OwnedVid {
        let (sigkey, public_sigkey) = crate::crypto::gen_sign_keypair();
        let (enckey, public_enckey) = crate::crypto::gen_encrypt_keypair();

        let mut vid = Vid {
            id: Default::default(),
            transport,
            public_sigkey,
            public_enckey,
        };

        vid.id = crate::vid::did::peer::encode_did_peer(&vid);

        Self {
            vid,
            sigkey,
            enckey,
        }
    }

    pub fn vid(&self) -> &Vid {
        &self.vid
    }

    pub fn into_vid(self) -> Vid {
        self.vid
    }
}

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Clone)]
pub struct ExportVid {
    pub(crate) id: String,
    pub(crate) transport: Url,
    pub(crate) public_sigkey: PublicVerificationKeyData,
    pub(crate) public_enckey: PublicKeyData,
    pub(crate) sigkey: Option<PrivateSigningKeyData>,
    pub(crate) enckey: Option<PrivateKeyData>,
    pub(crate) relation_status: RelationshipStatus,
    pub(crate) relation_vid: Option<String>,
    pub(crate) parent_vid: Option<String>,
    pub(crate) tunnel: Option<Box<[String]>>,
}

impl ExportVid {
    pub(crate) fn verified_vid(&self) -> Vid {
        Vid {
            id: self.id.clone(),
            transport: self.transport.clone(),
            public_sigkey: self.public_sigkey.clone(),
            public_enckey: self.public_enckey.clone(),
        }
    }

    pub(crate) fn private_vid(&self) -> Option<OwnedVid> {
        match (&self.sigkey, &self.enckey) {
            (Some(sigkey), Some(enckey)) => Some(OwnedVid {
                vid: self.verified_vid(),
                sigkey: sigkey.clone(),
                enckey: enckey.clone(),
            }),
            _ => None,
        }
    }
}
