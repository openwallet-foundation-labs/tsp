# Implement custom secure storage

We use the `SecureStorage` interface to securely store a wallet containing the endpoint's private VIDs and relations. This data **must be securely encrypted** because it contains the private keys used to send TSP messages.

We provide a `AskarSecureStorage` implementation of the `SecureStorage` interface, which is used to securely store the wallets used by the [CLI](./cli/index.md). This implementation uses [Askar](https://github.com/openwallet-foundation/askar) to securely store the wallet in a database. Our CLI uses SQLite for this, as this is easy to use and does not require you to set up any external tools. However, other databases supported by Askar are also supported. For example, you can enable PostgreSQL using the `tsp_sdk/postgres` feature, and then you can open a PostgreSQL database with a `postgres://` URL.

## Secure storage trait

Developers using TSP are free to implement their own secure storage for wallets by implementing the `SecureStorage` trait:

```rust
{{#include ../../tsp_sdk/src/secure_storage.rs:custom-secure-storage-mbBook}}
```

<div class="warning">

**Caution:** make sure that the data stored using `persist()` is always securely encrypted to prevent exposing private keys.

</div>
