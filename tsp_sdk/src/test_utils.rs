//! Test utilities and helpers for writing tests.

use crate::{
    OwnedVid, RelationshipStatus, SecureStore,
    definitions::{Digest, VerifiedVid},
};
use once_cell::sync::Lazy;

#[cfg(feature = "async")]
use crate::{AskarSecureStorage, AsyncSecureStore, SecureStorage};

#[cfg(any(test, feature = "test-utils"))]
use tempfile::TempDir;

const MIN_TEST_PORT: u16 = 50_000;
const MAX_TEST_PORT: u16 = 59_999;
const TEST_PORT_SPAN: u32 = (MAX_TEST_PORT - MIN_TEST_PORT + 1) as u32;
static CAN_PROBE_TEST_PORTS: Lazy<bool> =
    Lazy::new(|| std::net::TcpListener::bind(("127.0.0.1", 0)).is_ok());

/// Port allocator to avoid conflicts in concurrent tests.
///
/// The allocator cycles over a dedicated test port range instead of
/// monotonically increasing without bounds.
pub struct TestPortAllocator;

static GLOBAL_PORT_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

impl TestPortAllocator {
    /// Create a new port allocator.
    pub fn new() -> Self {
        Self
    }

    /// Allocate a test port from the configured test port range.
    pub fn allocate(&self) -> u16 {
        let start =
            GLOBAL_PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % TEST_PORT_SPAN;

        // Probe for an available port when the runtime environment allows socket binding.
        // In restricted environments (e.g. sandboxed CI), fall back to deterministic cycling.
        if *CAN_PROBE_TEST_PORTS {
            for i in 0..TEST_PORT_SPAN {
                let offset = (start + i) % TEST_PORT_SPAN;
                let port = MIN_TEST_PORT + offset as u16;
                if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
                    return port;
                }
            }

            panic!("No available test ports in range {MIN_TEST_PORT}-{MAX_TEST_PORT}");
        }

        MIN_TEST_PORT + start as u16
    }

    /// Create a TCP endpoint URL with an allocated port.
    pub fn tcp_endpoint(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.allocate())
    }
}

impl Default for TestPortAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a test VID with a unique localhost TCP endpoint.
pub fn create_test_vid() -> OwnedVid {
    let allocator = TestPortAllocator::new();
    OwnedVid::new_did_peer(url::Url::parse(&allocator.tcp_endpoint()).unwrap())
}

/// Create a pair of test VIDs (alice, bob).
pub fn create_test_vid_pair() -> (OwnedVid, OwnedVid) {
    (create_test_vid(), create_test_vid())
}

/// Load a test VID from a file.
#[cfg(feature = "async")]
pub async fn create_vid_from_file(path: &str) -> OwnedVid {
    OwnedVid::from_file(path)
        .await
        .unwrap_or_else(|e| panic!("Failed to load VID from {path}: {e}"))
}

/// Create a test SecureStore.
pub fn create_test_store() -> SecureStore {
    SecureStore::new()
}

/// Create a test AsyncSecureStore.
#[cfg(feature = "async")]
pub fn create_async_test_store() -> AsyncSecureStore {
    AsyncSecureStore::new()
}

fn relationship_digest(seed: usize) -> Digest {
    let mut digest = [0_u8; 32];
    digest[..8].copy_from_slice(&(seed as u64).to_le_bytes());
    digest[8..16].copy_from_slice((!(seed as u64)).to_le_bytes().as_ref());
    digest[16..24].copy_from_slice(((seed as u64).wrapping_mul(31)).to_le_bytes().as_ref());
    digest[24..32].copy_from_slice(((seed as u64).wrapping_mul(131)).to_le_bytes().as_ref());
    digest
}

fn relationship_status_for(index: usize) -> RelationshipStatus {
    match index % 4 {
        0 => RelationshipStatus::Unrelated,
        1 => RelationshipStatus::Unidirectional {
            thread_id: relationship_digest(index),
        },
        2 => RelationshipStatus::ReverseUnidirectional {
            thread_id: relationship_digest(index),
        },
        _ => RelationshipStatus::Bidirectional {
            thread_id: relationship_digest(index),
            outstanding_nested_thread_ids: vec![relationship_digest(index + 10_000)],
        },
    }
}

/// Create a store with `n` relationships in mixed states.
pub fn create_store_with_relationships(n: usize) -> SecureStore {
    let store = create_test_store();
    let local_vid = create_test_vid();

    store.add_private_vid(local_vid.clone(), None).unwrap();
    store
        .set_alias(
            "local-owner".to_string(),
            local_vid.identifier().to_string(),
        )
        .unwrap();

    for i in 0..n {
        let remote_vid = create_test_vid();
        store.add_verified_vid(remote_vid.clone(), None).unwrap();
        store
            .set_relation_and_status_for_vid(
                remote_vid.identifier(),
                relationship_status_for(i),
                local_vid.identifier(),
            )
            .unwrap();
    }

    store
}

/// Create a store that mimics a dirty wallet with existing identities,
/// nested relationships, aliases, and key history.
pub fn create_prepopulated_store() -> SecureStore {
    let store = create_store_with_relationships(8);

    let root_local = store.resolve_alias("local-owner").unwrap().unwrap();

    let nested_local = create_test_vid();
    store.add_private_vid(nested_local.clone(), None).unwrap();
    store
        .set_parent_for_vid(nested_local.identifier(), Some(&root_local))
        .unwrap();

    let remote_parent = create_test_vid();
    store.add_verified_vid(remote_parent.clone(), None).unwrap();
    store
        .set_relation_and_status_for_vid(
            remote_parent.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: relationship_digest(20_001),
                outstanding_nested_thread_ids: vec![relationship_digest(20_002)],
            },
            &root_local,
        )
        .unwrap();

    let remote_nested = create_test_vid();
    store.add_verified_vid(remote_nested.clone(), None).unwrap();
    store
        .set_parent_for_vid(remote_nested.identifier(), Some(remote_parent.identifier()))
        .unwrap();
    store
        .set_relation_and_status_for_vid(
            remote_nested.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: relationship_digest(20_101),
                outstanding_nested_thread_ids: vec![relationship_digest(20_102)],
            },
            nested_local.identifier(),
        )
        .unwrap();

    // Keep some persisted key history around as part of the fixture state.
    store
        .add_secret_key("test-history-key-1".to_string(), vec![1, 2, 3, 4])
        .unwrap();
    store
        .add_secret_key("test-history-key-2".to_string(), vec![5, 6, 7, 8])
        .unwrap();

    store
}

/// Fixture for persisted wallets backed by a real SQLite file.
#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
pub struct PersistedStoreFixture {
    _dir: TempDir,
    sqlite_url: String,
    password: Vec<u8>,
}

#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
impl PersistedStoreFixture {
    /// Create a new persisted wallet fixture.
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().expect("Failed to create temporary persisted wallet dir");
        let wallet_path = dir.path().join("wallet.sqlite");
        let sqlite_url = format!("sqlite://{}", wallet_path.to_string_lossy());
        let password = b"test-password".to_vec();

        let storage = AskarSecureStorage::new(&sqlite_url, &password)
            .await
            .expect("Failed to create persisted wallet storage");
        storage
            .close()
            .await
            .expect("Failed to close persisted wallet storage");

        Self {
            _dir: dir,
            sqlite_url,
            password,
        }
    }

    /// Persist an in-memory async store to the SQLite wallet.
    pub async fn persist_from(&self, store: &AsyncSecureStore) {
        let storage = AskarSecureStorage::open(&self.sqlite_url, &self.password)
            .await
            .expect("Failed to open persisted wallet storage");
        storage
            .persist(store.export().expect("Failed to export async store"))
            .await
            .expect("Failed to persist async store");
        storage
            .close()
            .await
            .expect("Failed to close persisted wallet storage");
    }

    /// Reopen the SQLite wallet and import it into a fresh async store.
    pub async fn reopen_into_store(&self) -> AsyncSecureStore {
        let storage = AskarSecureStorage::open(&self.sqlite_url, &self.password)
            .await
            .expect("Failed to reopen persisted wallet storage");
        let (vids, aliases, keys) = storage
            .read()
            .await
            .expect("Failed to read persisted wallet storage");
        storage
            .close()
            .await
            .expect("Failed to close reopened wallet storage");

        let store = AsyncSecureStore::new();
        store
            .import(vids, aliases, keys)
            .expect("Failed to import persisted store data");
        store
    }
}

/// Create a persisted store fixture backed by a real SQLite file.
#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
pub async fn create_persisted_store() -> PersistedStoreFixture {
    PersistedStoreFixture::new().await
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_create_test_vid() {
        let vid = create_test_vid();
        assert!(vid.identifier().starts_with("did:peer:"));
    }

    #[test]
    fn test_create_store_with_relationships() {
        let store = create_store_with_relationships(6);
        let vids = store.list_vids().unwrap();
        assert!(vids.len() >= 7);
    }

    #[test]
    fn test_create_prepopulated_store_has_history_keys() {
        let store = create_prepopulated_store();
        assert_eq!(
            store.get_secret_key("test-history-key-1").unwrap(),
            Some(vec![1, 2, 3, 4])
        );
        assert_eq!(
            store.get_secret_key("test-history-key-2").unwrap(),
            Some(vec![5, 6, 7, 8])
        );
    }

    #[test]
    fn test_port_allocator_range() {
        let allocator = TestPortAllocator::new();
        let port = allocator.allocate();
        assert!((MIN_TEST_PORT..=MAX_TEST_PORT).contains(&port));
    }

    #[test]
    fn test_port_allocator_cycles_after_range() {
        let allocator = TestPortAllocator::new();
        let mut seen = HashSet::new();
        let mut found_duplicate = false;

        for _ in 0..(TEST_PORT_SPAN as usize + 32) {
            let port = allocator.allocate();
            assert!((MIN_TEST_PORT..=MAX_TEST_PORT).contains(&port));
            if !seen.insert(port) {
                found_duplicate = true;
                break;
            }
        }

        assert!(found_duplicate);
    }

    #[cfg(all(feature = "async", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_persisted_store_fixture_roundtrip() {
        let fixture = create_persisted_store().await;

        let original = create_async_test_store();
        let vid = create_test_vid();
        original.add_private_vid(vid, None).unwrap();

        fixture.persist_from(&original).await;
        let reopened = fixture.reopen_into_store().await;

        assert_eq!(
            original.export().unwrap().0.len(),
            reopened.export().unwrap().0.len()
        );
    }
}
