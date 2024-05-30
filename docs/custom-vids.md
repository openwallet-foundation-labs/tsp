# Implement custom VIDs

The `Store`, exposed as the primary API for the TSP Rust library
accepts adding private and verified VIDs.

A private VID is an identity that contains private key material
to sign and decrypt messages.

A verified VID is an identity that only contains public key material,
to encrypt data and verify signatures. In the context of TSP Rust a verified
VID should only be constructed if it is resolved and verified.
What verification means depends on the type of VID.

## Traits

The `Store` accepts any private or verified that implement
The `PrivateVid` and `VerifiedVid` traits. Each of these traits
defines methods to get the VID string itself and methods to get the key material:

```rust
pub trait VerifiedVid: Send + Sync {
    /// A identifier of the Vid as bytes (for inclusion in TSP packets)
    fn identifier(&self) -> &str;

    /// The transport layer endpoint in the transport layer associated with this Vid
    fn endpoint(&self) -> &url::Url;

    /// The verification key that can check signatures made by this Vid
    fn verifying_key(&self) -> PublicKeyData;

    /// The encryption key associated with this Vid
    fn encryption_key(&self) -> PublicKeyData;
}

pub trait PrivateVid: VerifiedVid + Send + Sync {
    /// The PRIVATE key used to decrypt data
    fn decryption_key(&self) -> PrivateKeyData;

    /// The PRIVATE key used to sign data
    fn signing_key(&self) -> PrivateKeyData;
}

```

Any Rust type that implements one of these traits can be added to the
store (either `AsyncStore` or the `Store`).

Caution: make sure a `VerifiedVid` is always verified.
