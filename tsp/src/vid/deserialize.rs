use ed25519_dalek::{self as Ed};

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

pub(crate) mod serde_key_data {
    use crate::definitions::KeyData;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &KeyData, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(key);
        serializer.serialize_str(&key)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<KeyData, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| serde::de::Error::custom("key data is not exactly 32 bytes"))?;

        Ok(key)
    }
}

pub(crate) mod serde_sigkey {
    use super::Ed;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &Ed::SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(key.as_bytes());
        serializer.serialize_str(&key)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ed::SigningKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: &[u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(serde::de::Error::custom)?;

        Ok(Ed::SigningKey::from_bytes(key))
    }
}

pub(crate) mod serde_public_sigkey {
    use super::Ed;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &Ed::VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(key.as_bytes());
        serializer.serialize_str(&key)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ed::VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: &[u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(serde::de::Error::custom)?;

        Ed::VerifyingKey::from_bytes(key).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use super::OwnedVid;

    #[tokio::test]
    async fn deserialize() {
        let alice = OwnedVid::from_file("../examples/test/alice.json")
            .await
            .unwrap();

        assert_eq!(alice.vid().id, "did:web:did.tsp-test.org:user:alice");
        assert_eq!(alice.vid().transport.as_str(), "tcp://127.0.0.1:1337");
    }
}
