[![Deploy](https://github.com/openwallet-foundation-labs/tsp/actions/workflows/deploy.yml/badge.svg)](https://github.com/openwallet-foundation-labs/tsp/actions/workflows/deploy.yml)
[![Crates.io Version](https://img.shields.io/crates/v/tsp_sdk)](https://crates.io/crates/tsp_sdk)
[![docs.rs](https://img.shields.io/docsrs/tsp_sdk?label=docs.rs)](https://docs.rs/tsp_sdk/latest/tsp_sdk/)
![Deps.rs Crate Dependencies (specific version)](https://img.shields.io/deps-rs/tsp_sdk/latest)
![Crates.io MSRV](https://img.shields.io/crates/msrv/tsp_sdk)

# TSP SDK

Prototype Rust SDK for the [Trust Spanning Protocol](https://trustoverip.github.io/tswg-tsp-specification/)

## Status

This implements revision 3 of the specification. Development is ongoing and interfaces or
structure of the repository are likely to change. Nothing in this repository at this moment
represents a "final design", overrides the Trust Spanning Protocol specification, or indicates a
future direction of the Trust Spanning Protocol.

In short, it is not the reference implementation _yet_.

Messages produced by this revision do not interoperate with earlier ones: the wire version
changed, the default encryption changed, and `did:peer` identifiers now use numalgo 4. Wallets
created by earlier versions still open, and `did:web` and `did:webvh` identifiers created by them
still resolve.

## How to build this project

You will need to install the most recent Rust compiler, by following the
[these instructions](https://www.rust-lang.org/tools/install).

Then, you can use these commands to check out and test the repository:

```sh
git clone https://github.com/openwallet-foundation-labs/tsp.git
cd tsp/tsp_sdk
cargo test
```

If you want to test the language bindings for Python and JavaScript as well, you can run `cargo test` in the top level
directory of this repository. Please be aware that this requires a working Python installation on your system.

To build the documentation, run:

```sh
cargo doc --workspace --no-deps
```

Apart from the library, there are a few example executables.
The CLI is most useful, see below how to install and use the CLI.

## Organization of the project folder

At this point in time, this repository is organized
using [Cargo workspaces](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html).
The workspace contains five crates, the TSP SDK crate, an examples crate, bindings for Python and JavaScript, and one
for fuzzing.

The code is organized in various directories:

- `examples/` contains example programs
- `tsp_python` contains the Python bindings
- `tsp_javascript` contains the JavaScript bindings
- `tsp_sdk/` contains the TSP library, the source code is divided in the following modules / folders:
  - `cesr/` provides minimalist CESR encoding/decoding support that is sufficient for generating and parsing TSP
    messages; to keep complexity to a minimum, we explicitly do not provide a full CESR decoder/encoder.
  - `crypto/` contains the cryptographic core:
    - signed-only messages, whose payload travels in the clear, signed with Ed25519 or ML-DSA-65
    - confidential messages encrypted with [HPKE](https://datatracker.ietf.org/doc/rfc9180/) in Base mode, using
      HKDF-SHA256 and ChaCha20/Poly1305, and signed. The key encapsulation follows the recipient's encryption key
      type — X25519, or X25519MLKEM768 for post-quantum — so there is no separate post-quantum mode to select.
    - the sender's own identifier travels *inside* the encrypted payload rather than beside it, which is what binds
      a message to its sender. The properties this provides, and the argument for them, are in the security
      considerations of the specification rather than restated here.
    - the libsodium anonymous sealed box remains available for existing implementations.
  - `definitions/` defines several common data structures, traits and error types that are used throughout the project.
  - `transport/` code (built using [tokio](https://tokio.rs/) foundations) for actually sending and receiving data over
    a transport layer.
  - `vid/` contains code for handling _verified identifiers_ and identities. Currently, `did:peer`, `did:web` and `did:webvh` are
    supported.

## Documentation

Documentation on TSP and how to use our example projects (CLI / web interface)
can be found on <https://docs.teaspoon.world>.

The development documentation is available at [docs.rs](https://docs.rs/tsp_sdk/).

## Test CLI

The `examples` crate contains a test CLI interface for this library.

Install it by running the following command in the project root:

```sh
cargo install --path examples/ --bin tsp
```

To create an identity:

```sh
tsp create --type webvh --alias bob bob
```

To verify a VID:

```sh
tsp verify --alias alice did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice
```

See <https://docs.teaspoon.world> for the full documentation.

## Implement custom VIDs

See [the documentation](https://docs.teaspoon.world/custom-vids.html) on how to implement custom
VIDs.

## Intermediary server

See [the documentation](https://docs.teaspoon.world/intermediary.html) on how to create / set up an
intermediary server.

## Technical specification

See [the documentation](https://docs.teaspoon.world/TSP-technical-specification.html) for the
technical specification.
