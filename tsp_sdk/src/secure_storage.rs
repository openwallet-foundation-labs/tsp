use std::collections::HashMap;

use crate::store::WebvhUpdateKeys;
use crate::{
    Error, ExportVid, RelationshipStatus,
    definitions::{
        PRIVATE_KEY_SIZE, PRIVATE_SIGNING_KEY_SIZE, PUBLIC_KEY_SIZE, PUBLIC_VERIFICATION_KEY_SIZE,
    },
    store::Aliases,
};
use aries_askar::{
    ErrorKind, StoreKeyMethod,
    entry::EntryOperation,
    kms::{KeyAlg, LocalKey},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ANCHOR: custom-secure-storage-mbBook
#[async_trait]
pub trait SecureStorage: Sized {
    /// Create a new secure storage
    async fn new(url: &str, password: &[u8]) -> Result<Self, Error>;

    /// Open an existing secure storage
    async fn open(url: &str, password: &[u8]) -> Result<Self, Error>;

    /// Write data from memory to secure storage
    async fn persist(
        &self,
        (vids, aliases, update_keys): (Vec<ExportVid>, Aliases, WebvhUpdateKeys),
    ) -> Result<(), Error>;

    /// Read data from secure storage to memory
    async fn read(&self) -> Result<(Vec<ExportVid>, Aliases, WebvhUpdateKeys), Error>;

    /// Close the secure storage
    async fn close(self) -> Result<(), Error>;

    /// Destroy the secure storage
    async fn destroy(self) -> Result<(), Error>;
}
// ANCHOR_END: custom-secure-storage-mbBook

/// An implementation of secure storage using Aries Askar
pub struct AskarSecureStorage {
    inner: aries_askar::Store,
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Metadata {
    id: String,
    transport: String,
    relation_status: RelationshipStatus,
    relation_vid: Option<String>,
    parent_vid: Option<String>,
    tunnel: Option<Box<[String]>>,
    metadata: Option<serde_json::Value>,
}

#[async_trait]
impl SecureStorage for AskarSecureStorage {
    async fn new(url: &str, password: &[u8]) -> Result<Self, Error> {
        let pass_key = aries_askar::Store::new_raw_key(Some(password))?;

        let inner =
            aries_askar::Store::provision(url, StoreKeyMethod::RawKey, pass_key, None, true)
                .await?;

        Ok(Self {
            inner,
            url: url.to_string(),
        })
    }

    async fn open(url: &str, password: &[u8]) -> Result<Self, Error> {
        let pass_key = aries_askar::Store::new_raw_key(Some(password))?;

        let inner =
            aries_askar::Store::open(url, Some(StoreKeyMethod::RawKey), pass_key, None).await?;

        Ok(Self {
            inner,
            url: url.to_string(),
        })
    }

    async fn persist(
        &self,
        (vids, aliases, keys): (Vec<ExportVid>, Aliases, WebvhUpdateKeys),
    ) -> Result<(), Error> {
        let mut conn = self.inner.session(None).await?;

        for export in vids {
            let id = export.id;

            if let Some(private) = export.sigkey {
                let signing_key = LocalKey::from_secret_bytes(KeyAlg::Ed25519, private.as_ref())?;
                let signing_key_name = format!("{id}#signing-key");

                if let Err(e) = conn
                    .insert_key(&signing_key_name, &signing_key, None, None, None, None)
                    .await
                {
                    if e.kind() == ErrorKind::Duplicate {
                        conn.remove_key(&signing_key_name).await?;
                        conn.insert_key(&signing_key_name, &signing_key, None, None, None, None)
                            .await?;
                    } else {
                        Err(Error::from(e))?;
                    }
                }
            }

            if let Some(private) = export.enckey {
                let decryption_key = LocalKey::from_secret_bytes(KeyAlg::X25519, private.as_ref())?;
                let decryption_key_name = format!("{id}#decryption-key");
                if let Err(e) = conn
                    .insert_key(
                        &decryption_key_name,
                        &decryption_key,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await
                {
                    if e.kind() == ErrorKind::Duplicate {
                        conn.remove_key(&decryption_key_name).await?;
                        conn.insert_key(
                            &decryption_key_name,
                            &decryption_key,
                            None,
                            None,
                            None,
                            None,
                        )
                        .await?;
                    } else {
                        Err(Error::from(e))?;
                    }
                }
            }

            let verification_key =
                LocalKey::from_public_bytes(KeyAlg::Ed25519, export.public_sigkey.as_ref())?;
            let verification_key_name = format!("{id}#verification-key");
            if let Err(e) = conn
                .insert_key(
                    &verification_key_name,
                    &verification_key,
                    None,
                    None,
                    None,
                    None,
                )
                .await
            {
                if e.kind() == ErrorKind::Duplicate {
                    conn.remove_key(&verification_key_name).await?;
                    conn.insert_key(
                        &verification_key_name,
                        &verification_key,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await?;
                } else {
                    Err(Error::from(e))?;
                }
            }

            let encryption_key =
                LocalKey::from_public_bytes(KeyAlg::X25519, export.public_enckey.as_ref())?;
            let encryption_key_name = format!("{id}#encryption-key");
            if let Err(e) = conn
                .insert_key(
                    &encryption_key_name,
                    &encryption_key,
                    None,
                    None,
                    None,
                    None,
                )
                .await
            {
                if e.kind() == ErrorKind::Duplicate {
                    conn.remove_key(&encryption_key_name).await?;
                    conn.insert_key(
                        &encryption_key_name,
                        &encryption_key,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await?;
                } else {
                    Err(Error::from(e))?;
                }
            }

            if let Ok(data) = serde_json::to_string(&Metadata {
                id: id.to_string(),
                transport: export.transport.to_string(),
                relation_status: export.relation_status,
                relation_vid: export.relation_vid,
                parent_vid: export.parent_vid,
                tunnel: export.tunnel,
                metadata: export.metadata,
            }) {
                if let Err(e) = conn.insert("vid", &id, data.as_bytes(), None, None).await {
                    if e.kind() == ErrorKind::Duplicate {
                        conn.update(
                            EntryOperation::Replace,
                            "vid",
                            &id,
                            Some(data.as_bytes()),
                            None,
                            None,
                        )
                        .await?;
                    } else {
                        Err(Error::from(e))?;
                    }
                }
            }
        }

        if let Ok(aliases) = serde_json::to_value(&aliases) {
            if let Err(e) = conn
                .insert(
                    "extra_data",
                    "aliases",
                    aliases.to_string().as_bytes(),
                    None,
                    None,
                )
                .await
            {
                if e.kind() == ErrorKind::Duplicate {
                    conn.update(
                        EntryOperation::Replace,
                        "extra_data",
                        "aliases",
                        Some(aliases.to_string().as_bytes()),
                        None,
                        None,
                    )
                    .await?;
                } else {
                    Err(Error::from(e))?;
                }
            }
        }

        if let Ok(update_keys) = serde_json::to_value(&keys) {
            if let Err(e) = conn
                .insert(
                    "webvh_update_keys",
                    "all",
                    update_keys.to_string().as_bytes(),
                    None,
                    None,
                )
                .await
            {
                if e.kind() == ErrorKind::Duplicate {
                    conn.update(
                        EntryOperation::Replace,
                        "webvh_update_keys",
                        "all",
                        Some(update_keys.to_string().as_bytes()),
                        None,
                        None,
                    )
                    .await?;
                } else {
                    Err(Error::from(e))?;
                }
            }
        }

        conn.commit().await?;

        Ok(())
    }

    async fn read(&self) -> Result<(Vec<ExportVid>, Aliases, WebvhUpdateKeys), Error> {
        let mut vids = Vec::new();

        let mut conn = self.inner.session(None).await?;
        let results = conn
            .fetch_all(Some("vid"), None, None, None, false, false)
            .await?;

        for item in results.iter() {
            let data: Metadata = serde_json::from_slice(&item.value)
                .map_err(|_| Error::DecodeState("could not decode vid metadata"))?;

            let id = data.id.clone();

            let verification_key_name = format!("{id}#verification-key");
            let Some(verification_key) = conn.fetch_key(&verification_key_name, false).await?
            else {
                continue;
            };

            let encryption_key_name = format!("{id}#encryption-key");
            let Some(encryption_key) = conn.fetch_key(&encryption_key_name, false).await? else {
                continue;
            };

            let verification_bytes: [u8; PUBLIC_VERIFICATION_KEY_SIZE] = verification_key
                .load_local_key()?
                .to_public_bytes()?
                .as_ref()
                .try_into()
                .map_err(|_| {
                    Error::DecodeState("could not parse verification key bytes from storage")
                })?;

            let encryption_bytes: [u8; PUBLIC_KEY_SIZE] = encryption_key
                .load_local_key()?
                .to_public_bytes()?
                .as_ref()
                .try_into()
                .map_err(|_| {
                    Error::DecodeState("could not parse encryption key bytes from storage")
                })?;

            let mut vid = ExportVid {
                id: data.id,
                transport: data.transport.parse().map_err(|_| {
                    Error::DecodeState("could not parse transport URL from storage")
                })?,
                public_sigkey: verification_bytes.into(),
                public_enckey: encryption_bytes.into(),
                sigkey: None,
                enckey: None,
                relation_status: data.relation_status,
                relation_vid: data.relation_vid,
                parent_vid: data.parent_vid,
                tunnel: data.tunnel,
                metadata: data.metadata,
            };

            let signing_key_name = format!("{id}#signing-key");
            let signing_key = conn.fetch_key(&signing_key_name, false).await?;

            let decryption_key_name = format!("{id}#decryption-key");
            let decryption_key = conn.fetch_key(&decryption_key_name, false).await?;

            if let (Some(signing_key), Some(decryption_key)) = (signing_key, decryption_key) {
                let signing_key: [u8; PRIVATE_SIGNING_KEY_SIZE] = signing_key
                    .load_local_key()?
                    .to_secret_bytes()?
                    .as_ref()
                    .try_into()
                    .map_err(|_| {
                        Error::DecodeState("could not parse signing key bytes from storage")
                    })?;

                let decryption_key: [u8; PRIVATE_KEY_SIZE] = decryption_key
                    .load_local_key()?
                    .to_secret_bytes()?
                    .as_ref()
                    .try_into()
                    .map_err(|_| {
                        Error::DecodeState("could not parse decryption key bytes from storage")
                    })?;

                vid.sigkey = Some(signing_key.into());
                vid.enckey = Some(decryption_key.into());
            }

            vids.push(vid);
        }

        let aliases = match conn.fetch("extra_data", "aliases", false).await? {
            Some(data) => serde_json::from_slice(&data.value)
                .map_err(|_| Error::DecodeState("could not decode extra data from storage"))?,
            None => HashMap::new(),
        };

        let keys = match conn.fetch("webvh_update_keys", "all", false).await? {
            Some(data) => serde_json::from_slice(&data.value)
                .map_err(|_| Error::DecodeState("could not webvh keys from storage"))?,
            None => HashMap::new(),
        };

        conn.commit().await?;

        Ok((vids, aliases, keys))
    }

    async fn close(self) -> Result<(), Error> {
        self.inner.close().await?;

        Ok(())
    }

    async fn destroy(self) -> Result<(), Error> {
        self.inner.close().await?;
        aries_askar::Store::remove(&self.url).await?;

        Ok(())
    }
}

#[cfg(not(feature = "pq"))]
#[cfg(test)]
mod test {
    use crate::{OwnedVid, SecureStore, VerifiedVid};

    use super::*;

    #[tokio::test]
    async fn test_vault() {
        let id = {
            let vault = AskarSecureStorage::new("sqlite://test.sqlite", b"password")
                .await
                .unwrap();

            let store = SecureStore::new();
            let vid = OwnedVid::new_did_peer("tcp://127.0.0.1:1337".parse().unwrap());
            store.add_private_vid(vid.clone(), None).unwrap();

            store.aliases.write().unwrap().insert(
                "pigeon".to_string(),
                "did:web:did.teaspoon.world:endpoint:pigeon".to_string(),
            );

            vault.persist(store.export().unwrap()).await.unwrap();

            vid.identifier().to_string()
        };

        {
            let vault = AskarSecureStorage::open("sqlite://test.sqlite", b"password")
                .await
                .unwrap();
            let (vids, aliases, keys) = vault.read().await.unwrap();

            assert_eq!(
                aliases.get("pigeon"),
                Some(&"did:web:did.teaspoon.world:endpoint:pigeon".to_string())
            );

            let store = SecureStore::new();
            store.import(vids, aliases, keys).unwrap();
            assert!(store.has_private_vid(&id).unwrap());

            vault.destroy().await.unwrap();
        }
    }
}
