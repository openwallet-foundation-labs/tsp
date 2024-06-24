use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

use crate::definitions::{
    PrivateKeyData, PrivateSigningKeyData, PublicKeyData, PublicVerificationKeyData,
    PRIVATE_KEY_SIZE, PRIVATE_SIGNING_KEY_SIZE, PUBLIC_KEY_SIZE, PUBLIC_VERIFICATION_KEY_SIZE,
};

#[cfg(feature = "async")]
use super::{error::VidError, OwnedVid};

#[cfg(feature = "async")]
use std::path::Path;

#[cfg(feature = "async")]
use tokio::fs;

#[cfg(feature = "async")]
impl OwnedVid {
    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self, VidError> {
        let vid_data = fs::read_to_string(path)
            .await
            .map_err(|_| VidError::ResolveVid("private VID file not found"))?;

        serde_json::from_str(&vid_data)
            .map_err(|_| VidError::ResolveVid("private VID contains invalid JSON"))
    }
}

impl Serialize for PublicKeyData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(self.as_ref());
        serializer.serialize_str(&key)
    }
}

impl Serialize for PublicVerificationKeyData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(self.as_ref());
        serializer.serialize_str(&key)
    }
}

impl Serialize for PrivateKeyData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(self.as_ref());
        serializer.serialize_str(&key)
    }
}

impl Serialize for PrivateSigningKeyData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(self.as_ref());
        serializer.serialize_str(&key)
    }
}

impl<'de> Deserialize<'de> for PublicKeyData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: [u8; PUBLIC_KEY_SIZE] = key
            .try_into()
            .map_err(|_| serde::de::Error::custom("key data has incorrect length"))?;

        Ok(key.into())
    }
}

impl<'de> Deserialize<'de> for PublicVerificationKeyData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: [u8; PUBLIC_VERIFICATION_KEY_SIZE] = key
            .try_into()
            .map_err(|_| serde::de::Error::custom("key data has incorrect length"))?;

        Ok(key.into())
    }
}

impl<'de> Deserialize<'de> for PrivateKeyData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: [u8; PRIVATE_KEY_SIZE] = key
            .try_into()
            .map_err(|_| serde::de::Error::custom("key data has incorrect length"))?;

        Ok(key.into())
    }
}

impl<'de> Deserialize<'de> for PrivateSigningKeyData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: [u8; PRIVATE_SIGNING_KEY_SIZE] = key
            .try_into()
            .map_err(|_| serde::de::Error::custom("key data has incorrect length"))?;

        Ok(key.into())
    }
}

#[cfg(feature = "async")]
#[cfg(test)]
mod test {
    use super::OwnedVid;

    #[tokio::test]
    async fn deserialize() {
        let alice = OwnedVid::from_file("../examples/test/alice.json")
            .await
            .unwrap();

        assert_eq!(alice.vid().id, "did:web:did.tsp-test.org:user:alice");
        assert_eq!(alice.vid().transport.as_str(), "tcp://127.0.0.1:13371");
    }
}
