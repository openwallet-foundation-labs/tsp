# TSP Python bindings

We use PyO3 to generate Python bindings for the TSP SDK. We recommend using [uv](https://docs.astral.sh/uv/) to manage your Python dependencies, but it is also possible to use `pyenv` with `maturin` manually.

To add TSP as a dependency to your uv project, use the following command:

```sh
uv add git+https://github.com/openwallet-foundation-labs/tsp#subdirectory=tsp_python
```

## Example usage

Here's an example showing how you can use the Python bindings to create an identity, resolve someone else's identity, and send and receive TSP messages:

```py
{{#include ../../tsp_python/example.py}}
```

## Creating identities

The `OwnedVid` class is used to create and manage identities. It supports `did:web`, `did:webvh`, and `did:peer` identifiers:

```py
{{#include ../../tsp_python/tsp_python/tsp_python.pyi:OwnedVid-mdBook}}
```

To store a created identity, use the `add_private_vid` method of your `SecureStore`.

## Secure Store

The `SecureStore` class exposes the functionality from the Rust `AsyncSecureStore`, including methods to open and seal messages, and to send and receive messages. The Python `SecureStore` is connected to a secure storage wallet to store the state, the location of which can be configured during initialization of the `SecureStore`:

```py
{{#include ../../tsp_python/tsp_python/tsp.py:secure-store-init-mdBook}}
```

### Opening and sealing TSP messages

The `open_message` and `seal_message` functions of a `SecureStore` can be used to open and seal TSP messages:

```py
{{#include ../../tsp_python/tsp_python/tsp.py:open-seal-mdBook}}
```

### Sending and receiving TSP messages

The `send` and `receive` functions of a `SecureStore` can be used to send and receive TSP messages using the appropriate transport:

```py
{{#include ../../tsp_python/tsp_python/tsp.py:send-receive-mdBook}}
```

### Managing VIDs

The `SecureStore` provides a number of functions to manage VIDs. When adding a VID to the wallet (using `add_private_vid` for your own VIDs, or `verify_vid` for VIDs from others), it is also possible to set _aliases_ for them, which makes it easy to identify VIDs stored in the wallet.

```py
{{#include ../../tsp_python/tsp_python/tsp.py:manage-vids-mdBook}}
```
