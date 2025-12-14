#![deny(rustdoc::broken_intra_doc_links)]
// #![doc(test(attr(serial_test::serial(clean_wallet))))]

//! # Trust Spanning Protocol
//!
//! The Trust Spanning Protocol (TSP) is a protocol for secure communication
//! between entities identified by their Verified Identities (VIDs).
//!
//! The primary API this crates exposes is the [AsyncSecureStore] struct, which
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
//! The [AsyncSecureStore] uses the tokio async runtime and offers a high level API.
//!
//! The [SecureStore] struct implements managing VIDs and sealing / opening
//! TSP messages (low level API), it does not require an async runtime.
//! ## Example
//!
//! The following example demonstrates how to send a message from Alice to Bob
//!
//! ```rust
//! # #[cfg(feature="async")]
//! # mod example {
//! use futures::StreamExt;
//! use tsp_sdk::{AsyncSecureStore, Error, OwnedVid, ReceivedTspMessage};
//!
//! #[tokio::main]
//! # #[serial_test::serial(clean_wallet)]
//! async fn main() -> Result<(), Error> {
//!     // bob wallet
//!     let mut bob_db = AsyncSecureStore::new();
//!     let bob_vid = OwnedVid::from_file("../examples/test/bob/piv.json").await?;
//!     bob_db.add_private_vid(bob_vid, None)?;
//!     bob_db.verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", Some("alice".into())).await?;
//!
//!     let mut bobs_messages = bob_db.receive("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob").await?;
//!
//!     // alice wallet
//!     let mut alice_db = AsyncSecureStore::new();
//!     let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json").await?;
//!     alice_db.add_private_vid(alice_vid, None)?;
//!     alice_db.verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob", Some("bob".into())).await?;
//!
//!     // send a message
//!     alice_db.send(
//!         "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
//!         "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
//!         Some(b"extra non-confidential data"),
//!         b"hello world",
//!     ).await?;
//!
//!    // first, receive a Relationship request as this is the first contact
//!     let Some(Ok(ReceivedTspMessage::RequestRelationship { .. }))=
//!         bobs_messages.next().await else {
//!         panic!("bob did not receive a relationship request message")
//!     };
//!
//!     // receive a generic message
//!     let Some(Ok(ReceivedTspMessage::GenericMessage { message, .. }))=
//!         bobs_messages.next().await else {
//!         panic!("bob did not receive a generic message")
//!     };
//!
//!     assert_eq!(message.iter().as_slice(), b"hello world");
//!
//!     Ok(())
//! }
//! # }
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
#[cfg(feature = "resolve")]
mod http_client;
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
mod secure_storage;

#[cfg(not(feature = "pq"))]
#[cfg(feature = "async")]
#[cfg(test)]
mod test;

#[cfg(feature = "async")]
pub use async_store::AsyncSecureStore;

#[cfg(feature = "async")]
pub use secure_storage::AskarSecureStorage;
#[cfg(feature = "async")]
pub use secure_storage::SecureStorage;

pub use definitions::{Payload, PrivateVid, ReceivedTspMessage, RelationshipStatus, VerifiedVid};
pub use error::Error;
pub use store::{Aliases, SecureStore};
pub use vid::{ExportVid, OwnedVid, Vid};
