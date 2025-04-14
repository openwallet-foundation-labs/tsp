# Implement custom secure storage

We use the `SecureStorage` interface to securely store a wallet containing the users private VIDs and relations. This data **must be securely encrypted** because it contains the private keys used to send TSP messages.

We provide a `AskarSqliteSecureStorage` implementation of the `SecureStorage` interface, which is used to securely store the wallets used by the [CLI](./cli/index.md). This implementation uses [Askar](https://github.com/openwallet-foundation/askar) to securely store the wallet encrypted in a local SQLite database.

## Secure storage trait

Developers using TSP are free to implement their own secure storage for wallets by implementing the `SecureStorage` trait:

```rust
{{#include ../../tsp_sdk/src/secure_storage.rs:custom-secure-storage-mbBook}}
```

<div class="warning">

**Caution:** make sure that the data stored using `persist()` is always securely encrypted to prevent exposing private keys.

</div>
