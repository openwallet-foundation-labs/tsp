use std::collections::HashMap;

use crate::definitions::{
    Digest, PendingNestedRelationship, VidEncryptionKeyType, VidSignatureKeyType,
};
use crate::{
    Error, ExportVid, PendingIncomingParallelRelationship, PendingParallelRelationship,
    RelationshipStatus,
    store::{Aliases, WalletMethodState},
};
use aries_askar::{ErrorKind, StoreKeyMethod, entry::EntryOperation};
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
        state: (Vec<ExportVid>, Aliases, WalletMethodState),
    ) -> Result<(), Error>;

    /// Read data from secure storage to memory
    async fn read(&self) -> Result<(Vec<ExportVid>, Aliases, WalletMethodState), Error>;

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
    enc_key_type: VidEncryptionKeyType,
    sig_key_type: VidSignatureKeyType,
    transport: String,
    relation_status: RelationshipStatus,
    relation_vid: Option<String>,
    parent_vid: Option<String>,
    tunnel: Option<Box<[String]>>,
    #[serde(default)]
    pending_parallel_requests: Vec<PendingParallelRelationship>,
    #[serde(default)]
    pending_incoming_parallel_requests: Vec<PendingIncomingParallelRelationship>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct LegacyMetadata {
    id: String,
    enc_key_type: VidEncryptionKeyType,
    sig_key_type: VidSignatureKeyType,
    transport: String,
    relation_status: LegacyRelationshipStatus,
    relation_vid: Option<String>,
    parent_vid: Option<String>,
    tunnel: Option<Box<[String]>>,
    #[serde(default)]
    pending_parallel_requests: Vec<PendingParallelRelationship>,
    #[serde(default)]
    pending_incoming_parallel_requests: Vec<PendingIncomingParallelRelationship>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
enum LegacyRelationshipStatus {
    _Controlled,
    Bidirectional {
        thread_id: Digest,
        #[serde(default)]
        remote_thread_id: Option<Digest>,
        #[serde(default)]
        outstanding_nested_requests: Vec<PendingNestedRelationship>,
        #[serde(default)]
        outstanding_nested_thread_ids: Vec<Digest>,
    },
    Unidirectional {
        thread_id: Digest,
    },
    ReverseUnidirectional {
        thread_id: Digest,
    },
    Unrelated,
}

impl From<LegacyMetadata> for Metadata {
    fn from(value: LegacyMetadata) -> Self {
        Self {
            id: value.id,
            enc_key_type: value.enc_key_type,
            sig_key_type: value.sig_key_type,
            transport: value.transport,
            relation_status: value.relation_status.into(),
            relation_vid: value.relation_vid,
            parent_vid: value.parent_vid,
            tunnel: value.tunnel,
            pending_parallel_requests: value.pending_parallel_requests,
            pending_incoming_parallel_requests: value.pending_incoming_parallel_requests,
            metadata: value.metadata,
        }
    }
}

impl From<LegacyRelationshipStatus> for RelationshipStatus {
    fn from(value: LegacyRelationshipStatus) -> Self {
        match value {
            LegacyRelationshipStatus::_Controlled => RelationshipStatus::_Controlled,
            LegacyRelationshipStatus::Bidirectional {
                thread_id,
                remote_thread_id,
                outstanding_nested_requests,
                outstanding_nested_thread_ids,
            } => RelationshipStatus::Bidirectional {
                thread_id,
                remote_thread_id: remote_thread_id.unwrap_or(thread_id),
                outstanding_nested_requests: if outstanding_nested_requests.is_empty() {
                    outstanding_nested_thread_ids
                        .into_iter()
                        .map(|thread_id| PendingNestedRelationship {
                            thread_id,
                            local_nested_vid: String::new(),
                        })
                        .collect()
                } else {
                    outstanding_nested_requests
                },
            },
            LegacyRelationshipStatus::Unidirectional { thread_id } => {
                RelationshipStatus::Unidirectional { thread_id }
            }
            LegacyRelationshipStatus::ReverseUnidirectional { thread_id } => {
                RelationshipStatus::ReverseUnidirectional { thread_id }
            }
            LegacyRelationshipStatus::Unrelated => RelationshipStatus::Unrelated,
        }
    }
}

fn decode_metadata(bytes: &[u8]) -> Result<Metadata, Error> {
    serde_json::from_slice(bytes)
        .or_else(|_| serde_json::from_slice::<LegacyMetadata>(bytes).map(Into::into))
        .map_err(|_| Error::DecodeState("could not decode vid metadata"))
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
        (vids, aliases, method_state): (Vec<ExportVid>, Aliases, WalletMethodState),
    ) -> Result<(), Error> {
        let mut conn = self.inner.session(None).await?;

        for export in vids {
            let id = export.id.clone();

            if let Some(ref private) = export.sigkey {
                let signing_key_name = format!("{id}#signing-key");

                if let Err(e) = conn
                    .insert("key", &signing_key_name, private.as_slice(), None, None)
                    .await
                {
                    if e.kind() == ErrorKind::Duplicate {
                        conn.remove("key", &signing_key_name).await?;
                        conn.insert("key", &signing_key_name, private.as_slice(), None, None)
                            .await?;
                    } else {
                        Err(Error::from(e))?;
                    }
                }
            }

            if let Some(private) = export.enckey {
                let decryption_key_name = format!("{id}#decryption-key");

                if let Err(e) = conn
                    .insert("key", &decryption_key_name, private.as_slice(), None, None)
                    .await
                {
                    if e.kind() == ErrorKind::Duplicate {
                        conn.remove("key", &decryption_key_name).await?;
                        conn.insert("key", &decryption_key_name, private.as_slice(), None, None)
                            .await?
                    } else {
                        Err(Error::from(e))?;
                    }
                }
            }

            let verification_key_name = format!("{id}#verification-key");
            if let Err(e) = conn
                .insert(
                    "key",
                    &verification_key_name,
                    export.public_sigkey.as_slice(),
                    None,
                    None,
                )
                .await
            {
                if e.kind() == ErrorKind::Duplicate {
                    conn.remove("key", &verification_key_name).await?;
                    conn.insert(
                        "key",
                        &verification_key_name,
                        export.public_sigkey.as_slice(),
                        None,
                        None,
                    )
                    .await?;
                } else {
                    Err(Error::from(e))?;
                }
            }

            let encryption_key_name = format!("{id}#encryption-key");
            if let Err(e) = conn
                .insert(
                    "key",
                    &encryption_key_name,
                    export.public_enckey.as_slice(),
                    None,
                    None,
                )
                .await
            {
                if e.kind() == ErrorKind::Duplicate {
                    conn.remove("key", &encryption_key_name).await?;
                    conn.insert(
                        "key",
                        &encryption_key_name,
                        export.public_enckey.as_slice(),
                        None,
                        None,
                    )
                    .await?;
                } else {
                    Err(Error::from(e))?;
                }
            }

            #[allow(clippy::collapsible_if)]
            if let Ok(data) = serde_json::to_string(&Metadata {
                id: id.to_string(),
                enc_key_type: export.enc_key_type,
                sig_key_type: export.sig_key_type,
                transport: export.transport.to_string(),
                relation_status: export.relation_status,
                relation_vid: export.relation_vid,
                parent_vid: export.parent_vid,
                tunnel: export.tunnel,
                pending_parallel_requests: export.pending_parallel_requests,
                pending_incoming_parallel_requests: export.pending_incoming_parallel_requests,
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

        if let Ok(aliases) = serde_json::to_value(&aliases)
            && let Err(e) = conn
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

        let secret_keys = serde_json::to_value(&method_state.secret_keys)
            .map_err(|_| Error::DecodeState("could not encode secret keys for storage"))?;
        if let Err(e) = conn
            .insert(
                "method_state",
                "secret_keys",
                secret_keys.to_string().as_bytes(),
                None,
                None,
            )
            .await
        {
            if e.kind() == ErrorKind::Duplicate {
                conn.update(
                    EntryOperation::Replace,
                    "method_state",
                    "secret_keys",
                    Some(secret_keys.to_string().as_bytes()),
                    None,
                    None,
                )
                .await?;
            } else {
                Err(Error::from(e))?;
            }
        }

        let resolution_contexts = serde_json::to_value(&method_state.resolution_contexts)
            .map_err(|_| Error::DecodeState("could not encode resolution contexts for storage"))?;
        if let Err(e) = conn
            .insert(
                "method_state",
                "resolution_contexts",
                resolution_contexts.to_string().as_bytes(),
                None,
                None,
            )
            .await
        {
            if e.kind() == ErrorKind::Duplicate {
                conn.update(
                    EntryOperation::Replace,
                    "method_state",
                    "resolution_contexts",
                    Some(resolution_contexts.to_string().as_bytes()),
                    None,
                    None,
                )
                .await?;
            } else {
                Err(Error::from(e))?;
            }
        }

        conn.commit().await?;

        Ok(())
    }

    async fn read(&self) -> Result<(Vec<ExportVid>, Aliases, WalletMethodState), Error> {
        let mut vids = Vec::new();

        let mut conn = self.inner.session(None).await?;
        let results = conn
            .fetch_all(Some("vid"), None, None, None, false, false)
            .await?;

        for item in results.iter() {
            let data: Metadata = decode_metadata(&item.value)?;

            let id = data.id.clone();

            let verification_key_name = format!("{id}#verification-key");
            let Some(verification_bytes) = conn
                .fetch("key", &verification_key_name, false)
                .await?
                .map(|e| e.value.to_vec())
            else {
                continue;
            };

            let encryption_key_name = format!("{id}#encryption-key");
            let Some(encryption_bytes) = conn
                .fetch("key", &encryption_key_name, false)
                .await?
                .map(|e| e.value.to_vec())
            else {
                continue;
            };

            let mut vid = ExportVid {
                id: data.id,
                transport: data.transport.parse().map_err(|_| {
                    Error::DecodeState("could not parse transport URL from storage")
                })?,
                public_sigkey: verification_bytes.into(),
                sig_key_type: data.sig_key_type,
                public_enckey: encryption_bytes.into(),
                enc_key_type: data.enc_key_type,
                sigkey: None,
                enckey: None,
                relation_status: data.relation_status,
                relation_vid: data.relation_vid,
                parent_vid: data.parent_vid,
                tunnel: data.tunnel,
                pending_parallel_requests: data.pending_parallel_requests,
                pending_incoming_parallel_requests: data.pending_incoming_parallel_requests,
                metadata: data.metadata,
            };

            let signing_key_name = format!("{id}#signing-key");
            let signing_key = conn
                .fetch("key", &signing_key_name, false)
                .await?
                .map(|e| e.value.to_vec());

            let decryption_key_name = format!("{id}#decryption-key");
            let decryption_key = conn
                .fetch("key", &decryption_key_name, false)
                .await?
                .map(|e| e.value.to_vec());

            if let (Some(signing_key), Some(decryption_key)) = (signing_key, decryption_key) {
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

        let secret_keys = match conn.fetch("method_state", "secret_keys", false).await? {
            Some(data) => serde_json::from_slice(&data.value)
                .map_err(|_| Error::DecodeState("could not decode secret keys from storage"))?,
            None => match conn.fetch("webvh_update_keys", "all", false).await? {
                Some(data) => serde_json::from_slice(&data.value)
                    .map_err(|_| Error::DecodeState("could not webvh keys from storage"))?,
                None => HashMap::new(),
            },
        };

        let resolution_contexts = match conn
            .fetch("method_state", "resolution_contexts", false)
            .await?
        {
            Some(data) => serde_json::from_slice(&data.value).map_err(|_| {
                Error::DecodeState("could not decode resolution contexts from storage")
            })?,
            None => HashMap::new(),
        };

        conn.commit().await?;

        Ok((
            vids,
            aliases,
            WalletMethodState {
                secret_keys,
                resolution_contexts,
            },
        ))
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

impl AskarSecureStorage {
    pub async fn store_kv(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        let mut conn = self.inner.session(None).await?;

        conn.insert("custom_kv", key, value, None, None).await?;

        conn.commit().await?;

        Ok(())
    }

    pub async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        let mut conn = self.inner.session(None).await?;

        let result = conn.fetch("custom_kv", key, false).await?;

        Ok(result.map(|e| e.value.to_vec()))
    }

    pub async fn remove_kv(&self, key: &str) -> Result<(), Error> {
        let mut conn = self.inner.session(None).await?;

        conn.remove("custom_kv", key).await?;

        conn.commit().await?;

        Ok(())
    }
}

#[cfg(not(feature = "pq"))]
#[cfg(test)]
mod test {
    use crate::{OwnedVid, RelationshipStatus, SecureStore, VerifiedVid};

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

    #[test]
    fn decode_legacy_bidirectional_metadata() {
        let raw = serde_json::json!({
            "id": "did:test:alice",
            "enc_key_type": "X25519",
            "sig_key_type": "Ed25519",
            "transport": "tcp://127.0.0.1:13371",
            "relation_status": {
                "Bidirectional": {
                    "thread_id": vec![1; 32],
                    "outstanding_nested_thread_ids": [vec![2; 32]]
                }
            },
            "relation_vid": "did:test:bob",
            "parent_vid": null,
            "tunnel": null,
            "metadata": null
        });

        let decoded = decode_metadata(raw.to_string().as_bytes()).unwrap();

        let RelationshipStatus::Bidirectional {
            thread_id,
            remote_thread_id,
            outstanding_nested_requests,
        } = decoded.relation_status
        else {
            panic!()
        };

        assert_eq!(thread_id, [1; 32]);
        assert_eq!(remote_thread_id, [1; 32]);
        assert_eq!(outstanding_nested_requests.len(), 1);
        assert_eq!(outstanding_nested_requests[0].thread_id, [2; 32]);
        assert!(outstanding_nested_requests[0].local_nested_vid.is_empty());
    }
}
