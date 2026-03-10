//! Test utilities and helpers for writing tests.

use crate::{
    ExportVid, OwnedVid, RelationshipStatus, SecureStore,
    definitions::{Digest, VerifiedVid},
    store::{Aliases, WebvhUpdateKeys},
};
use once_cell::sync::Lazy;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

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

/// Snapshot shape used to compare wallet exports across reopen cycles.
pub type StoreExportSnapshot = (
    BTreeMap<String, String>,
    Vec<String>,
    BTreeMap<String, String>,
);

/// Return a stable string form for a relationship status.
pub fn relationship_status_signature(status: RelationshipStatus) -> String {
    match status {
        RelationshipStatus::_Controlled => "Controlled".to_string(),
        RelationshipStatus::Unrelated => "Unrelated".to_string(),
        RelationshipStatus::Unidirectional { thread_id } => format!("Uni:{thread_id:?}"),
        RelationshipStatus::ReverseUnidirectional { thread_id } => format!("RevUni:{thread_id:?}"),
        RelationshipStatus::Bidirectional {
            thread_id,
            outstanding_nested_thread_ids,
        } => format!("Bi:{thread_id:?}:{outstanding_nested_thread_ids:?}"),
    }
}

fn export_snapshot_parts(
    vids: Vec<ExportVid>,
    aliases: Aliases,
    keys: WebvhUpdateKeys,
) -> StoreExportSnapshot {
    let mut vid_rows = vids
        .into_iter()
        .map(|exported| {
            let tunnel = exported
                .tunnel
                .as_ref()
                .map(|route| route.join(">"))
                .unwrap_or_default();
            format!(
                "{}|{}|{}|{}|{}|{}",
                exported.id,
                exported.is_private(),
                exported.relation_vid.unwrap_or_default(),
                exported.parent_vid.unwrap_or_default(),
                tunnel,
                relationship_status_signature(exported.relation_status)
            )
        })
        .collect::<Vec<_>>();
    vid_rows.sort();

    let key_rows = keys
        .into_iter()
        .map(|(k, v)| (k, format!("{v:?}")))
        .collect::<BTreeMap<_, _>>();

    (
        aliases.into_iter().collect::<BTreeMap<_, _>>(),
        vid_rows,
        key_rows,
    )
}

/// Export a synchronous store into a normalized snapshot.
pub fn export_snapshot_sync(store: &SecureStore) -> StoreExportSnapshot {
    let (vids, aliases, keys) = store.export().unwrap();
    export_snapshot_parts(vids, aliases, keys)
}

/// Seed data for relationship transition tests on dirty wallets.
#[cfg(feature = "async")]
pub struct DirtyTransitionSeed {
    pub local_vid: String,
    pub remote_unrelated_vid: String,
    pub remote_bidirectional_vid: String,
}

/// Create an async store pre-seeded for relationship transition tests.
#[cfg(feature = "async")]
pub fn create_dirty_store_with_transition_seed() -> (AsyncSecureStore, DirtyTransitionSeed) {
    let store = create_async_test_store();

    let local = create_test_vid();
    let remote_unrelated = create_test_vid();
    let remote_bidirectional = create_test_vid();

    store.add_private_vid(local.clone(), None).unwrap();
    store
        .add_verified_vid(remote_unrelated.clone(), None)
        .unwrap();
    store
        .add_verified_vid(remote_bidirectional.clone(), None)
        .unwrap();

    store
        .set_alias("local-owner".to_string(), local.identifier().to_string())
        .unwrap();
    store
        .set_relation_and_status_for_vid(
            remote_unrelated.identifier(),
            RelationshipStatus::Unrelated,
            local.identifier(),
        )
        .unwrap();
    store
        .set_relation_and_status_for_vid(
            remote_bidirectional.identifier(),
            RelationshipStatus::Bidirectional {
                thread_id: relationship_digest(30_001),
                outstanding_nested_thread_ids: vec![relationship_digest(30_002)],
            },
            local.identifier(),
        )
        .unwrap();
    store
        .add_secret_key("transition-seed-key".to_string(), vec![9, 8, 7, 6])
        .unwrap();

    (
        store,
        DirtyTransitionSeed {
            local_vid: local.identifier().to_string(),
            remote_unrelated_vid: remote_unrelated.identifier().to_string(),
            remote_bidirectional_vid: remote_bidirectional.identifier().to_string(),
        },
    )
}

/// Seed data for high-entropy dirty wallet tests.
#[cfg(feature = "async")]
pub struct HighEntropyDirtySeed {
    pub local_vid: String,
    pub bidirectional_remote_vid: String,
    pub routed_remote_vid: String,
}

/// Create a large dirty wallet with mixed relations, nested VIDs, aliases,
/// custom keys, and routed entries.
#[cfg(feature = "async")]
pub fn create_high_entropy_dirty_store() -> (AsyncSecureStore, HighEntropyDirtySeed) {
    let store = create_async_test_store();
    let local_vid = create_test_vid();
    store.add_private_vid(local_vid.clone(), None).unwrap();
    store
        .set_alias(
            "local-owner".to_string(),
            local_vid.identifier().to_string(),
        )
        .unwrap();
    store
        .set_alias(
            "high-entropy-root".to_string(),
            local_vid.identifier().to_string(),
        )
        .unwrap();

    let route_hop_a = create_test_vid();
    let route_hop_b = create_test_vid();
    for hop in [&route_hop_a, &route_hop_b] {
        store.add_verified_vid(hop.clone(), None).unwrap();
        store
            .set_relation_and_status_for_vid(
                hop.identifier(),
                RelationshipStatus::bi_default(),
                local_vid.identifier(),
            )
            .unwrap();
    }

    for i in 0..16 {
        store
            .add_secret_key(
                format!("high-entropy-key-{i:02}"),
                vec![i as u8, i as u8 ^ 0x5A, i as u8 ^ 0xA5, 0xFF],
            )
            .unwrap();
    }

    let mut bidirectional_remote_vid = None;
    let mut routed_remote_vid = None;

    for i in 0..64 {
        let remote_vid = create_test_vid();
        store.add_verified_vid(remote_vid.clone(), None).unwrap();
        let relationship = relationship_status_for(i + 100);
        if bidirectional_remote_vid.is_none()
            && matches!(relationship, RelationshipStatus::Bidirectional { .. })
        {
            bidirectional_remote_vid = Some(remote_vid.identifier().to_string());
        }
        store
            .set_relation_and_status_for_vid(
                remote_vid.identifier(),
                relationship,
                local_vid.identifier(),
            )
            .unwrap();

        if i % 8 == 0 {
            store
                .set_route_for_vid(
                    remote_vid.identifier(),
                    &[route_hop_a.identifier(), route_hop_b.identifier()],
                )
                .unwrap();
            if routed_remote_vid.is_none() {
                routed_remote_vid = Some(remote_vid.identifier().to_string());
            }
        }
    }

    for i in 0..4 {
        let nested_local = create_test_vid();
        store.add_private_vid(nested_local.clone(), None).unwrap();
        store
            .set_parent_for_vid(nested_local.identifier(), Some(local_vid.identifier()))
            .unwrap();
        store
            .set_alias(
                format!("nested-local-{i}"),
                nested_local.identifier().to_string(),
            )
            .unwrap();

        let remote_parent = create_test_vid();
        let remote_nested = create_test_vid();
        store.add_verified_vid(remote_parent.clone(), None).unwrap();
        store.add_verified_vid(remote_nested.clone(), None).unwrap();

        store
            .set_relation_and_status_for_vid(
                remote_parent.identifier(),
                RelationshipStatus::Bidirectional {
                    thread_id: relationship_digest(40_000 + i),
                    outstanding_nested_thread_ids: vec![relationship_digest(41_000 + i)],
                },
                local_vid.identifier(),
            )
            .unwrap();
        store
            .set_parent_for_vid(remote_nested.identifier(), Some(remote_parent.identifier()))
            .unwrap();
        store
            .set_relation_and_status_for_vid(
                remote_nested.identifier(),
                RelationshipStatus::Bidirectional {
                    thread_id: relationship_digest(42_000 + i),
                    outstanding_nested_thread_ids: vec![relationship_digest(43_000 + i)],
                },
                nested_local.identifier(),
            )
            .unwrap();
    }

    (
        store,
        HighEntropyDirtySeed {
            local_vid: local_vid.identifier().to_string(),
            bidirectional_remote_vid: bidirectional_remote_vid
                .expect("high-entropy fixture is missing a bidirectional remote"),
            routed_remote_vid: routed_remote_vid
                .expect("high-entropy fixture is missing a routed remote"),
        },
    )
}

/// Pre-seeded routed topology for dirty wallet restart tests.
#[cfg(feature = "async")]
pub struct RoutedDirtyTopology {
    pub sender: AsyncSecureStore,
    pub intermediary: AsyncSecureStore,
    pub receiver: AsyncSecureStore,
    pub sender_vid: String,
    pub intermediary_vid: String,
    pub receiver_vid: String,
}

/// Create sender/intermediary/receiver stores with persisted route metadata.
#[cfg(feature = "async")]
pub fn create_routed_dirty_topology() -> RoutedDirtyTopology {
    let sender = create_async_test_store();
    let intermediary = create_async_test_store();
    let receiver = create_async_test_store();

    let sender_vid = create_test_vid();
    let intermediary_vid = create_test_vid();
    let receiver_vid = create_test_vid();

    sender.add_private_vid(sender_vid.clone(), None).unwrap();
    intermediary
        .add_private_vid(intermediary_vid.clone(), None)
        .unwrap();
    receiver
        .add_private_vid(receiver_vid.clone(), None)
        .unwrap();

    sender
        .add_verified_vid(intermediary_vid.clone(), None)
        .unwrap();
    sender.add_verified_vid(receiver_vid.clone(), None).unwrap();
    sender
        .set_relation_and_status_for_vid(
            intermediary_vid.identifier(),
            RelationshipStatus::bi_default(),
            sender_vid.identifier(),
        )
        .unwrap();
    sender
        .set_relation_and_status_for_vid(
            receiver_vid.identifier(),
            RelationshipStatus::bi_default(),
            sender_vid.identifier(),
        )
        .unwrap();
    sender
        .set_route_for_vid(
            receiver_vid.identifier(),
            &[intermediary_vid.identifier(), intermediary_vid.identifier()],
        )
        .unwrap();

    intermediary
        .add_verified_vid(sender_vid.clone(), None)
        .unwrap();
    intermediary
        .add_verified_vid(receiver_vid.clone(), None)
        .unwrap();
    intermediary
        .set_relation_and_status_for_vid(
            receiver_vid.identifier(),
            RelationshipStatus::bi_default(),
            intermediary_vid.identifier(),
        )
        .unwrap();
    intermediary
        .set_relation_and_status_for_vid(
            intermediary_vid.identifier(),
            RelationshipStatus::bi_default(),
            receiver_vid.identifier(),
        )
        .unwrap();
    intermediary
        .set_relation_and_status_for_vid(
            sender_vid.identifier(),
            RelationshipStatus::Unrelated,
            intermediary_vid.identifier(),
        )
        .unwrap();

    receiver.add_verified_vid(sender_vid.clone(), None).unwrap();
    receiver
        .add_verified_vid(intermediary_vid.clone(), None)
        .unwrap();
    receiver
        .set_relation_and_status_for_vid(
            sender_vid.identifier(),
            RelationshipStatus::bi_default(),
            receiver_vid.identifier(),
        )
        .unwrap();
    receiver
        .set_relation_and_status_for_vid(
            intermediary_vid.identifier(),
            RelationshipStatus::bi_default(),
            receiver_vid.identifier(),
        )
        .unwrap();

    RoutedDirtyTopology {
        sender,
        intermediary,
        receiver,
        sender_vid: sender_vid.identifier().to_string(),
        intermediary_vid: intermediary_vid.identifier().to_string(),
        receiver_vid: receiver_vid.identifier().to_string(),
    }
}

/// Export an async store into a normalized snapshot.
#[cfg(feature = "async")]
pub fn export_snapshot(store: &AsyncSecureStore) -> StoreExportSnapshot {
    let (vids, aliases, keys) = store.export().unwrap();
    export_snapshot_parts(vids, aliases, keys)
}

/// Repository-backed wallet fixtures used for smoke tests and future
/// compatibility coverage.
#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
#[derive(Clone, Copy, Debug)]
pub enum RepoWalletFixture {
    CurrentDirtySmall,
}

#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
impl RepoWalletFixture {
    fn file_name(self) -> &'static str {
        match self {
            Self::CurrentDirtySmall => "current-dirty-small.sqlite",
        }
    }

    pub fn password(self) -> &'static [u8] {
        b"test-password"
    }

    pub fn path(self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wallets")
            .join(self.file_name())
    }
}

/// Fixture for persisted wallets backed by a real SQLite file.
#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
pub struct PersistedStoreFixture {
    _dir: TempDir,
    wallet_path: PathBuf,
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
            wallet_path,
            sqlite_url,
            password,
        }
    }

    /// Copy an existing wallet file into a temporary persisted fixture.
    pub fn from_existing_wallet(source_path: &Path, password: &[u8]) -> Self {
        let dir = tempfile::tempdir().expect("Failed to create temporary persisted wallet dir");
        let wallet_path = dir.path().join("wallet.sqlite");
        std::fs::copy(source_path, &wallet_path)
            .unwrap_or_else(|e| panic!("Failed to copy wallet fixture from {source_path:?}: {e}"));
        let sqlite_url = format!("sqlite://{}", wallet_path.to_string_lossy());

        Self {
            _dir: dir,
            wallet_path,
            sqlite_url,
            password: password.to_vec(),
        }
    }

    /// Return the storage URL used by this fixture.
    pub fn storage_url(&self) -> &str {
        &self.sqlite_url
    }

    /// Return the raw password used by this fixture.
    pub fn password(&self) -> &[u8] {
        &self.password
    }

    /// Return the SQLite file path used by this fixture.
    pub fn sqlite_path(&self) -> &Path {
        &self.wallet_path
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

/// Create a persisted fixture from a repo-tracked sqlite wallet.
#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
pub fn create_repo_wallet_fixture(fixture: RepoWalletFixture) -> PersistedStoreFixture {
    PersistedStoreFixture::from_existing_wallet(&fixture.path(), fixture.password())
}

/// Persist and reopen an async store repeatedly using the same fixture.
#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
pub async fn persist_reopen_cycle(
    store: &AsyncSecureStore,
    fixture: &PersistedStoreFixture,
    times: usize,
) -> AsyncSecureStore {
    if times == 0 {
        return store.clone();
    }

    let mut current = store.clone();
    for _ in 0..times {
        fixture.persist_from(&current).await;
        current = fixture.reopen_into_store().await;
    }

    current
}

/// Corrupt a sqlite file intentionally for failure-path testing.
#[cfg(not(target_arch = "wasm32"))]
pub fn corrupt_sqlite_file(path: &Path) {
    std::fs::write(path, b"not-a-valid-sqlite-file")
        .expect("Failed to write corrupted sqlite fixture");
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
        let (_, vid_rows, _) = export_snapshot_sync(&store);
        assert!(vid_rows.iter().any(|row| row.contains("Bi:")));
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

    #[cfg(feature = "async")]
    #[test]
    fn test_create_dirty_store_with_transition_seed() {
        let (store, seed) = create_dirty_store_with_transition_seed();
        assert_eq!(
            store.resolve_alias("local-owner").unwrap().as_deref(),
            Some(seed.local_vid.as_str())
        );
        assert_eq!(
            store.get_secret_key("transition-seed-key").unwrap(),
            Some(vec![9, 8, 7, 6])
        );
    }

    #[cfg(feature = "async")]
    #[test]
    fn test_create_high_entropy_dirty_store_shapes_state() {
        let (store, seed) = create_high_entropy_dirty_store();
        assert_eq!(
            store.resolve_alias("high-entropy-root").unwrap().as_deref(),
            Some(seed.local_vid.as_str())
        );
        assert!(
            store
                .get_secret_key("high-entropy-key-00")
                .unwrap()
                .is_some()
        );
        let (_aliases, vid_rows, _keys) = export_snapshot(&store);
        assert!(vid_rows.iter().any(|row| row.contains(">")));
        assert!(vid_rows.iter().any(|row| row.contains("Bi:")));
    }

    #[cfg(feature = "async")]
    #[test]
    fn test_create_routed_dirty_topology_has_tunnel_metadata() {
        let topology = create_routed_dirty_topology();
        let (_aliases, vid_rows, _keys) = export_snapshot(&topology.sender);
        let routed_row = vid_rows
            .iter()
            .find(|row| row.starts_with(&topology.receiver_vid))
            .unwrap();
        assert!(routed_row.contains(&topology.intermediary_vid));
    }

    #[cfg(feature = "async")]
    #[test]
    fn test_create_routed_dirty_topology_supports_direct_open_message_flow() {
        let topology = create_routed_dirty_topology();
        let (_endpoint, mut sealed_message) = topology
            .sender
            .seal_message(
                &topology.sender_vid,
                &topology.receiver_vid,
                None,
                b"direct-open-flow",
            )
            .unwrap();

        let crate::ReceivedTspMessage::ForwardRequest {
            next_hop,
            route,
            opaque_payload,
            ..
        } = topology
            .intermediary
            .open_message(&mut sealed_message)
            .unwrap()
        else {
            panic!("intermediary did not decode routed payload");
        };

        let (_endpoint, mut forwarded_message) = topology
            .intermediary
            .make_next_routed_message(&next_hop, route, &opaque_payload)
            .unwrap();

        let crate::ReceivedTspMessage::GenericMessage {
            sender, message, ..
        } = topology
            .receiver
            .open_message(&mut forwarded_message)
            .unwrap()
        else {
            panic!("receiver did not decode forwarded payload");
        };

        assert_eq!(sender, topology.sender_vid);
        assert_eq!(message.iter().as_slice(), b"direct-open-flow");
    }

    #[cfg(all(feature = "async", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_persist_reopen_cycle_helper() {
        let fixture = create_persisted_store().await;
        let original = create_async_test_store();
        let vid = create_test_vid();
        original.add_private_vid(vid, None).unwrap();

        let reopened = persist_reopen_cycle(&original, &fixture, 2).await;
        assert_eq!(
            original.export().unwrap().0.len(),
            reopened.export().unwrap().0.len()
        );
    }

    #[cfg(all(feature = "async", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_repo_wallet_fixture_roundtrip() {
        let fixture = create_repo_wallet_fixture(RepoWalletFixture::CurrentDirtySmall);
        let reopened = fixture.reopen_into_store().await;
        let (vids, aliases, keys) = reopened.export().unwrap();
        assert!(!vids.is_empty());
        assert!(
            !aliases.is_empty() || !keys.is_empty(),
            "repo wallet fixture should carry dirty wallet state"
        );
    }
}
