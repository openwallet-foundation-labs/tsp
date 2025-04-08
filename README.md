# rust-tsp

Prototype Rust SDK for the [Trust Spanning Protocol](https://trustoverip.github.io/tswg-tsp-specification/)

## Status

This project is in its initial state. Development is ongoing and interfaces or
structure of the repository are likely to change. Nothing in this repository at
this moment represents a "final design" or to be overriding the Trust Spanning Protocol specification, or indicating a future direction of the Trust Spanning Protocol.

In short, it is not the reference implementation _yet_.

## How to build this project

You will need to install the most recent Rust compiler, by following the
[these instructions](https://www.rust-lang.org/tools/install).

Then, you can use these commands to check out and test the repository:

```sh
git clone https://github.com/openwallet-foundation-labs/tsp.git
cd rust-tsp
cargo test
```

To build the documentation, run:

```sh
cargo doc --workspace --no-deps
```

Apart from the library, there are a few example executables.
The CLI is most useful, see below how to install and use the CLI.

## Organization of the project folder

At this point in time, this repository is organized using [Cargo workspaces](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html). The workspace contains only two crates, the TSP crate and an examples crate.

The code is organizes is various directories:

- `examples/` contains example programs
- `tsp/` contains the TSP library, the source code is divided in the following modules / folders:
  - `cesr/` provides minimalist CESR encoding/decoding support that is sufficient for generating and parsing TSP messages; to keep complexity to a minimum, we explicitly do not provide a full CESR decoder/encoder.
  - `crypto/` contains the cryptographic core:
    - generating non-confidential messages signed using Ed25519
    - generating confidential messages encrypted using [HPKE-Auth](https://datatracker.ietf.org/doc/rfc9180/); using DHKEM(X25519, HKDF-SHA256) as asymmetric primitives and ChaCha20/Poly1305 as underlying AEAD encrypting scheme, and signed using Ed25519 to achieve **non-repudiation** (more precisely "strong receiver-unforgeability under chosen ciphertext" or [RUF-CTXT](https://eprint.iacr.org/2001/079) or [Insider-Auth](https://eprint.iacr.org/2020/1499.pdf)).
  - `definitions/` defines several common data structures, traits and error types that are used throughout the project.
  - `transport/` code (built using [tokio](https://tokio.rs/) foundations) for actually sending and receiving data over a transport layer.
  - `vid/` contains code for handling _verified identifiers_ and identities. Currently, only an extended form of `did:web` is supported.

## Documentation

Documentation on TSP and how to use our example projects (CLI / web interface)
can be found on <https://openwallet-foundation-labs.github.io/tsp/>.

The development documentation is available at [docs.rs](https://docs.rs/tsp-sdk/).

## Test CLI

The examples crate contains a test CLI interface for this library.

Install it by running the following command in the project root:

```sh
cargo install --path examples/ --bin tsp
```

To create an identity:

```sh
tsp create --alias bob bob
```

To verify a VID:

```sh
tsp verify --alias alice did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice
```

To listen for - and receive messages:

```sh
tsp receive --one bob
```

To send a message:

```sh
echo "Hello World!" | tsp send -s alice -r bob
```

See <https://openwallet-foundation-labs.github.io/tsp/> for the full documentation.

## Implement custom VIDs

See [the documentation](/docs/src/custom-vids.md) on how to implement custom VIDs.

## Intermediary server

See [the documentation](/docs/src/intermediary.md) on how to create / set up an intermediary server.

## Technical specification

See [the documentation](/docs/src/TSP-technical-specification.md) for the technical specification.
