# DID webvh

The TSP SDK and CLI can resolve DID:webvh natively.
To create a new webvh identity, we use the official [Python implementation](https://github.com/decentralized-identity/didwebvh-py) 
by the Decentralized Identity Foundation.
As we rely on a Rust-to-Python interface, you have to compile the SDK or CLI with the `create-webvh` feature flag to
be able to create webvh identities.
Additionally, you have to prepare the Python environment to run the CLI in.

## Create a DID:webvh
### Initial setup

1. Make sure you compiled the CLI with the `create-webvh` feature flag enabled
```shell
cargo install --bin tsp --path ./examples --features create-webvh
```
2. Make sure you activated the Python environment and installed the required dependencies. 
   For that, make sure you have `uv` [installed on your machine](https://docs.astral.sh/uv/getting-started/installation/)
   and run `uv sync` in the `./tsp_sdk` directory.

### Create a DID:webvh
Creating a new webvh identity is as easy as running

```shell
tsp create --type webvh --alias foo-alias foo
```
The expected output would be something like
```
INFO tsp: published DID document at https://did.teaspoon.world/endpoint/foo/did.json
INFO tsp: published DID history
```

### FAQ

Q: I'm getting `error: invalid value 'webvh' for '--type <TYPE>': invalid did type: webvh`

A: Most likely, you did not compile with the `create-webvh` feature enabled. Please see [Initial setup](#initial-setup).

Q: I'm getting `error in the underlying Python code base: ModuleNotFoundError: No module named 'aries_askar'`

A: Most likely, you did not run the command in an activated python environment with all required dependencies.
Please see [Initial setup](#initial-setup).
