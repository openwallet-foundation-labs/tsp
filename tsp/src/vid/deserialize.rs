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

pub(crate) mod serde_public_key_data {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::definitions::PublicKeyData;

    pub fn serialize<S>(key: &PublicKeyData, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(key.as_ref());
        serializer.serialize_str(&key)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKeyData, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| serde::de::Error::custom("key data is not exactly 32 bytes"))?;

        Ok(key.into())
    }
}

pub(crate) mod serde_key_data {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::definitions::PrivateKeyData;

    pub fn serialize<S>(key: &PrivateKeyData, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(key.as_ref());
        serializer.serialize_str(&key)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PrivateKeyData, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| serde::de::Error::custom("key data is not exactly 32 bytes"))?;

        Ok(key.into())
    }
}

pub(crate) mod serde_key_data_option {
    use crate::definitions::PrivateKeyData;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &Option<PrivateKeyData>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match key {
            Some(key) => {
                let key = Base64UrlUnpadded::encode_string(key.as_ref());
                serializer.serialize_str(&key)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<PrivateKeyData>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: Option<&str> = Deserialize::deserialize(deserializer)?;

        if let Some(encoded) = encoded {
            let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
            let key: [u8; 32] = key
                .try_into()
                .map_err(|_| serde::de::Error::custom("key data is not exactly 32 bytes"))?;

            Ok(Some(key.into()))
        } else {
            Ok(None)
        }
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
