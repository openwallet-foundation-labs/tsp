use std::collections::HashMap;

use crate::definitions::{
    Digest, PendingNestedRelationship, VidEncryptionKeyType, VidSignatureKeyType,
};
use crate::{
    Error, ExportVid, KeyType, OwnedVid, PendingIncomingParallelRelationship,
    PendingParallelRelationship, RelationshipStatus, SoftwareSecureArea,
    store::{WalletMethodState, WalletState},
};
use aries_askar::{
    ErrorKind, StoreKeyMethod,
    entry::{EntryOperation, EntryTag},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[async_trait]
pub trait SecureStorage: Sized {
    /// Create a new secure storage
    async fn new(url: &str, password: &[u8]) -> Result<Self, Error>;

    /// Open an existing secure storage
    async fn open(url: &str, password: &[u8]) -> Result<Self, Error>;

    /// Write the wallet's state to secure storage, keys included: they come as the software
    /// secure area in `state.keys` and are written under their aliases.
    async fn persist(&self, state: WalletState) -> Result<(), Error>;

    /// Read the wallet's state from secure storage; the keys come back in a fresh software
    /// secure area.
    async fn read(&self) -> Result<WalletState, Error>;

    /// Close the secure storage
    async fn close(self) -> Result<(), Error>;

    /// Destroy the secure storage
    async fn destroy(self) -> Result<(), Error>;
}

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
            // a state that was never entered and carried no relationship
            LegacyRelationshipStatus::_Controlled => RelationshipStatus::Unrelated,
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

/// Insert a record, or replace the one already there.
async fn upsert(
    conn: &mut aries_askar::Session,
    category: &str,
    name: &str,
    value: &[u8],
    tags: Option<&[EntryTag]>,
) -> Result<(), Error> {
    match conn.insert(category, name, value, tags, None).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::Duplicate => {
            conn.update(
                EntryOperation::Replace,
                category,
                name,
                Some(value),
                tags,
                None,
            )
            .await?;
            Ok(())
        }
        Err(e) => Err(e.into()),
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

    async fn persist(&self, state: WalletState) -> Result<(), Error> {
        let WalletState {
            vids,
            aliases,
            method_state,
            keys,
        } = state;
        let mut conn = self.inner.session(None).await?;

        // the keys of every private VID, under the VID's aliases, in the records this
        // storage has always used for them
        let mut vid_key_aliases = std::collections::HashSet::new();
        for export in vids {
            let id = export.id.clone();

            if export.private {
                let (sig_alias, enc_alias) = OwnedVid::key_aliases(&id);
                for alias in [&sig_alias, &enc_alias] {
                    if let Some((_, material)) = keys.material(alias) {
                        upsert(&mut conn, "key", alias, &material, None).await?;
                    }
                }
                vid_key_aliases.insert(sig_alias);
                vid_key_aliases.insert(enc_alias);
            }

            upsert(
                &mut conn,
                "key",
                &format!("{id}#verification-key"),
                export.public_sigkey.as_slice(),
                None,
            )
            .await?;
            upsert(
                &mut conn,
                "key",
                &format!("{id}#encryption-key"),
                export.public_enckey.as_slice(),
                None,
            )
            .await?;

            let data = serde_json::to_string(&Metadata {
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
            })
            .map_err(|_| Error::DecodeState("could not encode vid metadata for storage"))?;
            upsert(&mut conn, "vid", &id, data.as_bytes(), None).await?;
        }

        // every other key of the secure area: a did:webvh update key, an application's key;
        // and a key the area no longer holds, a retired update key, leaves the storage too
        let mut kept = std::collections::HashSet::new();
        for (alias, key_type, material) in keys.all_material() {
            if vid_key_aliases.contains(&alias) {
                continue;
            }
            let tags = [EntryTag::Encrypted(
                "type".to_string(),
                key_type.as_str().to_string(),
            )];
            upsert(&mut conn, "secure_area_key", &alias, &material, Some(&tags)).await?;
            kept.insert(alias);
        }
        let stored: Vec<String> = conn
            .fetch_all(Some("secure_area_key"), None, None, None, false, false)
            .await?
            .iter()
            .map(|e| e.name.clone())
            .collect();
        for alias in stored {
            if !kept.contains(&alias) {
                conn.remove("secure_area_key", &alias).await?;
            }
        }
        // the records that carried method keys as a blob before the secure area
        for (category, name) in [
            ("method_state", "secret_keys"),
            ("method_state", "secret_key_types"),
            ("webvh_update_keys", "all"),
        ] {
            match conn.remove(category, name).await {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => Err(Error::from(e))?,
            }
        }

        let aliases = serde_json::to_value(&aliases)
            .map_err(|_| Error::DecodeState("could not encode aliases for storage"))?;
        upsert(
            &mut conn,
            "extra_data",
            "aliases",
            aliases.to_string().as_bytes(),
            None,
        )
        .await?;

        let resolution_contexts = serde_json::to_value(&method_state.resolution_contexts)
            .map_err(|_| Error::DecodeState("could not encode resolution contexts for storage"))?;
        upsert(
            &mut conn,
            "method_state",
            "resolution_contexts",
            resolution_contexts.to_string().as_bytes(),
            None,
        )
        .await?;

        conn.commit().await?;

        Ok(())
    }

    async fn read(&self) -> Result<WalletState, Error> {
        let mut vids = Vec::new();
        let keys = SoftwareSecureArea::new();

        let mut conn = self.inner.session(None).await?;
        let results = conn
            .fetch_all(Some("vid"), None, None, None, false, false)
            .await?;

        for item in results.iter() {
            let data: Metadata = decode_metadata(&item.value)?;

            let id = data.id.clone();

            let Some(verification_bytes) = conn
                .fetch("key", &format!("{id}#verification-key"), false)
                .await?
                .map(|e| e.value.to_vec())
            else {
                continue;
            };

            let Some(encryption_bytes) = conn
                .fetch("key", &format!("{id}#encryption-key"), false)
                .await?
                .map(|e| e.value.to_vec())
            else {
                continue;
            };

            // the VID's keys, straight into the secure area
            let (sig_alias, enc_alias) = OwnedVid::key_aliases(&id);
            let signing_key = conn.fetch("key", &sig_alias, false).await?;
            let decryption_key = conn.fetch("key", &enc_alias, false).await?;
            let private = match (signing_key, decryption_key) {
                (Some(sig), Some(enc)) => {
                    keys.import(
                        &sig_alias,
                        data.sig_key_type.into(),
                        zeroize::Zeroizing::new(sig.value.to_vec()),
                    )?;
                    keys.import(
                        &enc_alias,
                        data.enc_key_type.into(),
                        zeroize::Zeroizing::new(enc.value.to_vec()),
                    )?;
                    true
                }
                _ => false,
            };

            vids.push(ExportVid {
                id: data.id,
                transport: data.transport.parse().map_err(|_| {
                    Error::DecodeState("could not parse transport URL from storage")
                })?,
                public_sigkey: verification_bytes.into(),
                sig_key_type: data.sig_key_type,
                public_enckey: encryption_bytes.into(),
                enc_key_type: data.enc_key_type,
                private,
                relation_status: data.relation_status,
                relation_vid: data.relation_vid,
                parent_vid: data.parent_vid,
                tunnel: data.tunnel,
                pending_parallel_requests: data.pending_parallel_requests,
                pending_incoming_parallel_requests: data.pending_incoming_parallel_requests,
                metadata: data.metadata,
            });
        }

        // the other keys of the secure area, by alias, typed by their tag
        for item in conn
            .fetch_all(Some("secure_area_key"), None, None, None, false, false)
            .await?
            .iter()
        {
            let key_type = item
                .tags
                .iter()
                .find_map(|t| match t {
                    EntryTag::Encrypted(name, value) | EntryTag::Plaintext(name, value)
                        if name == "type" =>
                    {
                        KeyType::parse(value)
                    }
                    _ => None,
                })
                .unwrap_or(KeyType::Ed25519);
            keys.import(
                &item.name,
                key_type,
                zeroize::Zeroizing::new(item.value.to_vec()),
            )?;
        }

        // and what a wallet written before the secure area holds: a blob of method keys,
        // with their types beside it if they were ever recorded; all Ed25519 otherwise
        let legacy: Option<HashMap<String, Vec<u8>>> =
            match conn.fetch("method_state", "secret_keys", false).await? {
                Some(data) => Some(serde_json::from_slice(&data.value).map_err(|_| {
                    Error::DecodeState("could not decode secret keys from storage")
                })?),
                None => match conn.fetch("webvh_update_keys", "all", false).await? {
                    Some(data) => Some(serde_json::from_slice(&data.value).map_err(|_| {
                        Error::DecodeState("could not decode webvh keys from storage")
                    })?),
                    None => None,
                },
            };
        if let Some(legacy) = legacy {
            let types: HashMap<String, KeyType> = match conn
                .fetch("method_state", "secret_key_types", false)
                .await?
            {
                Some(data) => serde_json::from_slice(&data.value).unwrap_or_default(),
                None => HashMap::new(),
            };
            for (alias, material) in legacy {
                if keys.has_key(&alias) {
                    continue;
                }
                let key_type = types.get(&alias).copied().unwrap_or(KeyType::Ed25519);
                keys.import(&alias, key_type, zeroize::Zeroizing::new(material))?;
            }
        }

        let aliases = match conn.fetch("extra_data", "aliases", false).await? {
            Some(data) => serde_json::from_slice(&data.value)
                .map_err(|_| Error::DecodeState("could not decode extra data from storage"))?,
            None => HashMap::new(),
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

        Ok(WalletState {
            vids,
            aliases,
            method_state: WalletMethodState {
                resolution_contexts,
            },
            keys: Arc::new(keys),
        })
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
            let state = vault.read().await.unwrap();

            assert_eq!(
                state.aliases.get("pigeon"),
                Some(&"did:web:did.teaspoon.world:endpoint:pigeon".to_string())
            );

            let store = SecureStore::new();
            store.import(state).unwrap();
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
