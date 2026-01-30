//! Test utilities and helpers for writing tests
//!
//! This module provides test utilities to make writing tests easier and more consistent.
//! It includes helpers for creating VIDs, stores, assertions, and async test utilities.

use crate::{
    definitions::{Payload, PrivateVid, VerifiedVid},
    OwnedVid, SecureStore,
};

#[cfg(feature = "async")]
use crate::AsyncSecureStore;

// =============================================================================
// VID Creation Helpers
// =============================================================================

/// Create a test VID with a localhost TCP endpoint
///
/// This is useful for unit tests that don't need real network connectivity.
pub fn create_test_vid() -> OwnedVid {
    OwnedVid::new_did_peer(url::Url::parse("tcp://127.0.0.1:1337").unwrap())
}

/// Create a test VID with a custom endpoint
pub fn create_test_vid_with_endpoint(endpoint: &str) -> OwnedVid {
    OwnedVid::new_did_peer(url::Url::parse(endpoint).unwrap())
}

/// Create a pair of test VIDs (alice, bob) for testing bidirectional communication
pub fn create_test_vid_pair() -> (OwnedVid, OwnedVid) {
    let alice = create_test_vid();
    let bob = create_test_vid();
    (alice, bob)
}

/// Load a test VID from a file (for integration tests)
///
/// # Examples
///
/// ```no_run
/// # use tsp_sdk::test_utils::create_vid_from_file;
/// # tokio_test::block_on(async {
/// let alice = create_vid_from_file("../examples/test/alice/piv.json").await;
/// # });
/// ```
#[cfg(feature = "async")]
pub async fn create_vid_from_file(path: &str) -> OwnedVid {
    OwnedVid::from_file(path)
        .await
        .unwrap_or_else(|e| panic!("Failed to load VID from {}: {}", path, e))
}

// =============================================================================
// Store Creation Helpers
// =============================================================================

/// Create a test SecureStore with a temporary in-memory database
pub fn create_test_store() -> SecureStore {
    SecureStore::new()
}

/// Create a test AsyncSecureStore with a temporary in-memory database
#[cfg(feature = "async")]
pub fn create_async_test_store() -> AsyncSecureStore {
    AsyncSecureStore::new()
}

/// Create two connected stores with alice and bob VIDs already set up
///
/// Returns `(alice_store, alice_vid, bob_store, bob_vid)` with mutual verification
pub fn create_connected_stores() -> (SecureStore, OwnedVid, SecureStore, OwnedVid) {
    let alice_store = create_test_store();
    let bob_store = create_test_store();

    let alice = create_test_vid();
    let bob = create_test_vid();

    alice_store.add_private_vid(alice.clone(), None).unwrap();
    bob_store.add_private_vid(bob.clone(), None).unwrap();

    // Mutual verification
    alice_store.add_verified_vid(bob.clone(), None).unwrap();
    bob_store.add_verified_vid(alice.clone(), None).unwrap();

    (alice_store, alice, bob_store, bob)
}

/// Create two connected async stores with alice and bob VIDs already set up
///
/// Returns `(alice_store, alice_vid, bob_store, bob_vid)` with mutual verification
#[cfg(feature = "async")]
pub fn create_connected_async_stores() -> (AsyncSecureStore, OwnedVid, AsyncSecureStore, OwnedVid) {
    let alice_store = create_async_test_store();
    let bob_store = create_async_test_store();

    let alice = create_test_vid();
    let bob = create_test_vid();

    alice_store.add_private_vid(alice.clone(), None).unwrap();
    bob_store.add_private_vid(bob.clone(), None).unwrap();

    // Mutual verification
    alice_store.add_verified_vid(bob.clone(), None).unwrap();
    bob_store.add_verified_vid(alice.clone(), None).unwrap();

    (alice_store, alice, bob_store, bob)
}

// =============================================================================
// Message Helpers
// =============================================================================

/// Seal a test message between two VIDs
///
/// Helper to create an encrypted message for testing.
pub fn seal_test_message(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    content: &[u8],
) -> crate::definitions::TSPMessage {
    crate::crypto::seal(sender, receiver, None, Payload::Content(content))
        .expect("Failed to seal test message")
}

// =============================================================================
// Assertion Helpers
// =============================================================================

/// Assert that two byte slices are equal with a helpful error message
#[track_caller]
pub fn assert_bytes_eq(actual: &[u8], expected: &[u8], message: &str) {
    assert_eq!(
        actual, expected,
        "{}\nExpected: {:?}\nActual: {:?}",
        message,
        String::from_utf8_lossy(expected),
        String::from_utf8_lossy(actual)
    );
}

/// Assert that a message appears to be encrypted (not plaintext)
#[track_caller]
pub fn assert_message_encrypted(message: &[u8], plaintext: &[u8]) {
    assert!(
        !message.is_empty(),
        "Encrypted message should not be empty"
    );
    assert!(
        message.len() > plaintext.len(),
        "Encrypted message should be longer than plaintext"
    );
    // Check that plaintext doesn't appear verbatim in the message
    assert!(
        !message.windows(plaintext.len()).any(|w| w == plaintext),
        "Plaintext should not appear in encrypted message"
    );
}

/// Assert that a VID identifier has the expected format
#[track_caller]
pub fn assert_vid_format(identifier: &str, expected_prefix: &str) {
    assert!(
        identifier.starts_with(expected_prefix),
        "VID identifier '{}' should start with '{}'",
        identifier,
        expected_prefix
    );
}

// =============================================================================
// Async Test Helpers
// =============================================================================

/// Add a timeout to an async operation in tests
///
/// Prevents tests from hanging indefinitely if something goes wrong.
///
/// # Examples
///
/// ```no_run
/// # use tsp_sdk::test_utils::with_timeout;
/// # use std::time::Duration;
/// # tokio_test::block_on(async {
/// let result = with_timeout(Duration::from_secs(5), async {
///     // Some async operation
///     42
/// }).await;
/// assert_eq!(result.unwrap(), 42);
/// # });
/// ```
#[cfg(feature = "async")]
pub async fn with_timeout<F, T>(
    duration: std::time::Duration,
    future: F,
) -> Result<T, &'static str>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(duration, future)
        .await
        .map_err(|_| "Operation timed out")
}

/// Poll an async condition until it becomes true or timeout
///
/// Useful for testing eventual consistency or async state changes.
///
/// # Examples
///
/// ```no_run
/// # use tsp_sdk::test_utils::assert_eventually;
/// # use std::time::Duration;
/// # use std::sync::{Arc, Mutex};
/// # tokio_test::block_on(async {
/// let counter = Arc::new(Mutex::new(0));
/// let counter_clone = counter.clone();
///
/// // Start some async process that increments counter...
///
/// assert_eventually(
///     Duration::from_secs(5),
///     Duration::from_millis(100),
///     || {
///         let c = counter_clone.lock().unwrap();
///         *c > 5
///     }
/// ).await.expect("Counter never reached 5");
/// # });
/// ```
#[cfg(feature = "async")]
pub async fn assert_eventually<F>(
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
    mut condition: F,
) -> Result<(), &'static str>
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    loop {
        if condition() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err("Condition never became true within timeout");
        }
        tokio::time::sleep(poll_interval).await;
    }
}

// =============================================================================
// Cleanup Helpers
// =============================================================================

/// RAII wrapper for temporary wallet that cleans up on drop
///
/// Ensures test wallets are deleted even if the test panics.
///
/// # Examples
///
/// ```
/// # use tsp_sdk::test_utils::TempWallet;
/// {
///     let wallet = TempWallet::new("test_wallet.sqlite");
///     // Use wallet.path() in tests...
/// } // Automatically cleaned up here
/// ```
pub struct TempWallet {
    path: String,
}

impl TempWallet {
    /// Create a new temporary wallet
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    /// Get the wallet path
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl Drop for TempWallet {
    fn drop(&mut self) {
        // Clean up wallet files (including -shm and -wal files)
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(format!("{}-shm", self.path));
        let _ = std::fs::remove_file(format!("{}-wal", self.path));
    }
}

/// Port allocator to avoid conflicts in concurrent tests
///
/// Uses a global atomic counter to ensure unique ports across all tests.
pub struct TestPortAllocator;

// Global port counter starting at 50000
static GLOBAL_PORT_COUNTER: std::sync::atomic::AtomicU16 =
    std::sync::atomic::AtomicU16::new(50000);

impl TestPortAllocator {
    /// Create a new port allocator
    pub fn new() -> Self {
        Self
    }

    /// Allocate a new unique port using global atomic counter
    pub fn allocate(&self) -> u16 {
        GLOBAL_PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Create a TCP endpoint URL with an allocated port
    pub fn tcp_endpoint(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.allocate())
    }
}

impl Default for TestPortAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definitions::VerifiedVid;

    #[test]
    fn test_create_test_vid() {
        let vid = create_test_vid();
        assert!(vid.identifier().starts_with("did:peer:"));
    }

    #[test]
    fn test_create_test_vid_with_endpoint() {
        let vid = create_test_vid_with_endpoint("tcp://example.com:8080");
        assert!(vid.identifier().starts_with("did:peer:"));
    }

    #[test]
    fn test_create_test_vid_pair() {
        let (alice, bob) = create_test_vid_pair();
        assert_ne!(alice.identifier(), bob.identifier());
    }

    #[test]
    fn test_create_test_store() {
        let store = create_test_store();
        let vid = create_test_vid();
        assert!(store.add_private_vid(vid, None).is_ok());
    }

    #[test]
    fn test_create_connected_stores() {
        let (_alice_store, alice, bob_store, bob) = create_connected_stores();

        // Verify alice can seal to bob
        let message = seal_test_message(&alice, &bob, b"test");
        assert!(!message.is_empty());

        // Verify bob can open from alice
        let mut message_copy = message.clone();
        let result = bob_store.open_message(&mut message_copy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_seal_test_message() {
        let (alice, bob) = create_test_vid_pair();
        let message = seal_test_message(&alice, &bob, b"hello world");
        assert!(!message.is_empty());
        assert!(message.len() > 11);
    }

    #[test]
    fn test_assert_bytes_eq() {
        let a = b"hello";
        let b = b"hello";
        assert_bytes_eq(a, b, "should be equal");
    }

    #[test]
    #[should_panic]
    fn test_assert_bytes_eq_fails() {
        let a = b"hello";
        let b = b"world";
        assert_bytes_eq(a, b, "should not be equal");
    }

    #[test]
    fn test_assert_message_encrypted() {
        let (alice, bob) = create_test_vid_pair();
        let plaintext = b"secret message";
        let encrypted = seal_test_message(&alice, &bob, plaintext);
        assert_message_encrypted(&encrypted, plaintext);
    }

    #[test]
    fn test_assert_vid_format() {
        let vid = create_test_vid();
        assert_vid_format(vid.identifier(), "did:peer:");
    }

    #[test]
    #[should_panic]
    fn test_assert_vid_format_fails() {
        let vid = create_test_vid();
        assert_vid_format(vid.identifier(), "did:web:");
    }

    #[test]
    fn test_temp_wallet() {
        let path = "test_temp_wallet.sqlite";
        {
            let wallet = TempWallet::new(path);
            assert_eq!(wallet.path(), path);
            // Create files to simulate wallet
            std::fs::write(path, b"test").unwrap();
            std::fs::write(format!("{}-shm", path), b"test").unwrap();
            std::fs::write(format!("{}-wal", path), b"test").unwrap();
            assert!(std::path::Path::new(path).exists());
        }
        // All files should be cleaned up after drop
        assert!(!std::path::Path::new(path).exists());
        assert!(!std::path::Path::new(&format!("{}-shm", path)).exists());
        assert!(!std::path::Path::new(&format!("{}-wal", path)).exists());
    }

    #[test]
    fn test_port_allocator() {
        let allocator = TestPortAllocator::new();
        let port1 = allocator.allocate();
        let port2 = allocator.allocate();
        assert_ne!(port1, port2);
        assert_eq!(port2, port1 + 1);
    }

    #[test]
    fn test_port_allocator_tcp_endpoint() {
        let allocator = TestPortAllocator::new();
        let endpoint = allocator.tcp_endpoint();
        assert!(endpoint.starts_with("tcp://127.0.0.1:"));
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_create_async_test_store() {
        let store = create_async_test_store();
        let vid = create_test_vid();
        assert!(store.add_private_vid(vid, None).is_ok());
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_create_connected_async_stores() {
        let (_alice_store, alice, _bob_store, bob) = create_connected_async_stores();
        assert_ne!(alice.identifier(), bob.identifier());
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_with_timeout_success() {
        let result = with_timeout(std::time::Duration::from_secs(1), async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            42
        })
        .await;
        assert_eq!(result, Ok(42));
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_with_timeout_failure() {
        let result = with_timeout(std::time::Duration::from_millis(10), async {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            42
        })
        .await;
        assert!(result.is_err());
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_assert_eventually() {
        use std::sync::{Arc, Mutex};

        let counter = Arc::new(Mutex::new(0));
        let counter_clone = counter.clone();

        // Spawn a task that increments the counter
        tokio::spawn(async move {
            for _ in 0..10 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let mut c = counter_clone.lock().unwrap();
                *c += 1;
            }
        });

        let result = assert_eventually(
            std::time::Duration::from_secs(2),
            std::time::Duration::from_millis(100),
            || {
                let c = counter.lock().unwrap();
                *c > 3
            },
        )
        .await;

        assert!(result.is_ok());
    }
}
