//! # Trust Spanning Protocol
//!
//! The Trust Spanning Protocol (TSP) is a protocol for secure communication
//! between entities identified by their Verified Identities (VIDs).
//!
//! The primary API this crates exposes is the [AsyncStore] struct, which
//! is used to manage and resolve VIDs, as well as send and receive messages
//! between them.
//!
//! ## Core protocol
//!
//! By default this library comes with methods to send and receive messages
//! over various transport and code to resolve and verify various VIDs.
//!
//! If your use-case only requires the core protocol, you can disable the
//! `async` feature to remove the transport layer and resolve methods.
//!
//! The [AsyncStore] uses the tokio async runtime and offers a high level API.
//!
//! The [Store] struct implements managing VIDs and sealing / opening
//! TSP messages (low level API), it does not require an async runtime.
//! ## Example
//!
//! The following example demonstrates how to send a message from Alice to Bob
//!
//! ```no_run
//! use tsp::{AsyncStore, OwnedVid, Error, ReceivedTspMessage};
//! use futures::StreamExt;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     // bob database
//!     let mut bob_db = AsyncStore::new();
//!     let bob_vid = OwnedVid::from_file("../examples/test/bob.json").await?;
//!     bob_db.add_private_vid(bob_vid)?;
//!     bob_db.verify_vid("did:web:did.tsp-test.org:user:alice").await?;
//!
//!     let mut bobs_messages = bob_db.receive("did:web:did.tsp-test.org:user:bob").await?;
//!
//!     // alice database
//!     let mut alice_db = AsyncStore::new();
//!     let alice_vid = OwnedVid::from_file("../examples/test/bob.json").await?;
//!     alice_db.add_private_vid(alice_vid)?;
//!     alice_db.verify_vid("did:web:did.tsp-test.org:user:bob").await?;
//!
//!     // send a message
//!     alice_db.send(
//!         "did:web:did.tsp-test.org:user:alice",
//!         "did:web:did.tsp-test.org:user:bob",
//!         Some(b"extra non-confidential data"),
//!         b"hello world",
//!     ).await?;
//!
//!     // receive a message
//!     let Some(Ok(ReceivedTspMessage::GenericMessage { message, .. }))=
//!         bobs_messages.next().await else {
//!         panic!("bob did not receive a generic message")
//!     };
//!
//!     assert_eq!(message, b"hello world");
//!
//!     Ok(())
//! }
//! ```

/// Provides minimalist CESR encoding/decoding support that is sufficient for
/// generating and parsing TSP messages; to keep complexity to a minimum,
/// we explicitly do not provide a full CESR decoder/encoder.
pub mod cesr;

/// Contains the cryptographic core of the TSP protocol
///   - generating non-confidential messages signed using Ed25519
///   - generating confidential messages encrypted using
///     [HPKE-Auth](https://datatracker.ietf.org/doc/rfc9180/);
///     using DHKEM(X25519, HKDF-SHA256) as asymmetric primitives and
///     ChaCha20/Poly1305 as underlying AEAD encrypting scheme,
///     and signed using Ed25519 to achieve **non-repudiation**
///     (more precisely "strong receiver-unforgeability under chosen
pub mod crypto;

/// Defines several common data structures, traits and error types that are used throughout the project.
pub mod definitions;
mod error;
mod store;

/// Contains code for handling *verified identifiers* and identities.
/// Currently only an extended form of `did:web` and `did:peer` are supported.
pub mod vid;

/// Code (built using [tokio](https://tokio.rs/) foundations) for actually
/// sending and receiving data over a transport layer.
#[cfg(feature = "async")]
pub mod transport;

#[cfg(feature = "async")]
mod async_store;

#[cfg(feature = "async")]
#[cfg(test)]
mod test;

#[cfg(feature = "async")]
pub use async_store::AsyncStore;

pub use definitions::{Payload, PrivateVid, ReceivedTspMessage, VerifiedVid};
pub use error::Error;
pub use store::{ExportVid, Store};
pub use vid::{OwnedVid, Vid};
