# Implement custom VIDs

The `SecureStore`, exposed as the primary API for the TSP Rust library,
accepts adding private and verified VIDs.

A private VID is an identity that contains private key material
to sign and decrypt messages.

A verified VID is an identity that only contains public key material
to encrypt data and verify signatures.
In the context of TSP Rust, a verified VID should only be constructed if it is resolved and verified.
What verification means depends on the type of VID.

## Traits

The `SecureStore` accepts any private or verified VID that implements the `PrivateVid` and `VerifiedVid` traits, respectively.
Each of these traits defines methods to get the VID string itself and methods to get the key material:

```rust
{{#include ../../tsp_sdk/src/definitions/mod.rs:custom-vid-mbBook}}
```

Any Rust type that implements one of these traits can be added to the
store (either `AsyncSecureStore` or the `SecureStore`).

<div class="warning">

**Caution:** make sure a `VerifiedVid` is always verified. How VIDs are verified depends on the type of VID used.

</div>
