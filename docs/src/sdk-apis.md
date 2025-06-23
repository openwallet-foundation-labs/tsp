# API overview

The `tsp_sdk` library should allow endpoints to seal and open TSP messages. Note that the provided code is pseudo-Rust code; we abstract away from some implementation details.
For a detailed and complete API reference, please take a look at <https://docs.rs/tsp_sdk/>.

## Secure Store

A [`SecureStore`](https://docs.rs/tsp_sdk/latest/tsp_sdk/struct.SecureStore.html) allows the endpoint to store VID-public-key pairs and optionally metadata related to the VID, like a name or transport specification.

A `SecureStore` the data in memory. `SecureStorage` can be used to persist this data in a wallet.
We provide the `AskarSecureStorage` implementation, which uses [Aries Askar](https://github.com/openwallet-foundation/askar) to securely store the data.
See the [custom secure storage](./custom-secure-storage.md) page for documentation about how to implement custom secure storage solutions.

The SDK also has the [`AsyncSecureStore`](https://docs.rs/tsp_sdk/latest/tsp_sdk/struct.AsyncSecureStore.html) interface that provides an asynchronous version of the `SecureStore`.
The `AsyncSecureStore` is a higher level interface which also includes [`send`](https://docs.rs/tsp_sdk/latest/tsp_sdk/struct.AsyncSecureStore.html#method.send) and [`receive`](https://docs.rs/tsp_sdk/latest/tsp_sdk/struct.AsyncSecureStore.html#method.receive) functions to send or receive TSP messages using the built-in [transport layers](./transport.md).

## Seal and open a TSP message

Seal means encrypting, authenticating, signing, and encoding a message; open is the reverse operation. Note that the header may contain additional authenticated data. The sender and receiver VID are added to the header by this method.
All the methods below work on a `SecureStore` instance, which holds the cryptographic details and relations.

```rust
{{#include ../../tsp_sdk/src/store.rs:seal_message-mbBook}}

{{#include ../../tsp_sdk/src/store.rs:open_message-mbBook}}

{{#include ../../tsp_sdk/src/store.rs:probe_sender-mbBook}}
```

## Sign messages

The following methods allow encoding and signing a message without an encrypted payload.

```rust
/// Sign a unencrypted message, without a specified recipient
pub fn sign_anycast(&self, sender: &str, message: &[u8]) -> Result<Vec<u8>, Error>;
```

## Managing VID's

The `SecureStore` supports the following methods to manage the VIDs. This is just an extraction of the most relevant methods;
see the [API docs](https://docs.rs/tsp_sdk/) for the full list.

```rust
/// Add the already resolved `verified_vid` to the wallet as a relationship
pub fn add_verified_vid(&self, verified_vid: impl VerifiedVid + 'static) -> Result<(), Error>;

/// Adds `private_vid` to the wallet
pub fn add_private_vid(&self, private_vid: impl PrivateVid + 'static) -> Result<(), Error>;

/// Remove a VID from the Store
pub fn forget_vid(&self, vid: &str) -> Result<(), Error>;

/// Sets the parent for a VID, thus making it a nested VID
pub fn set_parent_for_vid(&self, vid: &str, parent_vid: Option<&str>) -> Result<(), Error>;

/// Set the relation VID for the VID.
///
/// The relation VID will be used as sender VID when sending messages to this VID.
pub fn set_relation_for_vid(&self, vid: &str, relation_vid: Option<&str>) -> Result<(), Error>;

/// Adds a route to an already existing VID, making it a nested VID
pub fn set_route_for_vid(
    &self,
    vid: &str,
    route: impl IntoIterator<Item: ToString, IntoIter: ExactSizeIterator>,
) -> Result<(), Error>;
```

## Library architecture

### Dependencies

A software library offering security operations is very prone to mistakes and bugs that compromise the security of the
cryptographic protocol as a whole in operation.
One of the ways to reduce the amount of code, and thereby reduce the number of possible security bugs, is reducing the
number of dependencies on other libraries.
The dependencies that are included should adhere to our quality standards, that is, we should have confidence in the
authors, and the library must not be abandoned and must have enough active users, i.e., must be popular.

We use the following Rust crates (library dependencies) in our implementation:

- [rand](https://crates.io/crates/rand): Random number generators and other randomness functionality.
- [hpke](https://crates.io/crates/hpke): An implementation of the HPKE hybrid encryption standard (RFC 9180) in pure
  Rust.
- [hpke_pq](https://crates.io/crates/hpke_pq): This fork of the `hpke` crate includes experimental support for the hybrid Kyber-X25519 KEM.
- [ed25519-dalek](https://crates.io/crates/ed25519-dalek): Fast and efficient Rust implementation of ed25519 key
  generation, signing, and verification.
- [sha2](https://crates.io/crates/sha2): Pure Rust implementation of the SHA-2 hash function family.
- [blake2](https://crates.io/crates/blake2): Pure Rust implementation of the BLAKE2 hash function family.
- [crypto_box](https://crates.io/crates/crypto_box): Pure Rust implementation of NaCl's crypto_box primitive.

### Bindings

The library is usable in other languages.
We designed the API in a way that allows the use with C, Python, and JavaScript.
The SDK contains bindings for JavaScript, Node.js, and Python.
