[![Deploy](https://github.com/openwallet-foundation-labs/tsp/actions/workflows/deploy.yml/badge.svg)](https://github.com/openwallet-foundation-labs/tsp/actions/workflows/deploy.yml)
[![Crates.io Version](https://img.shields.io/crates/v/tsp_sdk)](https://crates.io/crates/tsp_sdk)
[![docs.rs](https://img.shields.io/docsrs/tsp_sdk?label=docs.rs)](https://docs.rs/tsp_sdk/latest/tsp_sdk/)
![Deps.rs Crate Dependencies (specific version)](https://img.shields.io/deps-rs/tsp_sdk/latest)
![Crates.io MSRV](https://img.shields.io/crates/msrv/tsp_sdk)

# TSP SDK

A Rust implementation of the [Trust Spanning Protocol](https://trustoverip.github.io/tswg-tsp-specification/).

TSP lets two parties who each have a verifiable identifier — a `did:webvh`, a `did:peer`, or an
identifier from some other system entirely — exchange messages that are authentic, confidential,
and attributable to the identifier rather than to a key. It is a spanning layer: it does not
replace the network you send over, and it does not care which identifier system either side uses,
only that both can be resolved and verified.

This crate gives you a wallet holding your own identifiers and the ones you have verified, and a
small API for sending and receiving over that wallet. Where the message travels — HTTP, TCP, TLS,
QUIC, or through an intermediary that holds it until you collect it — is a property of the
identifier you are sending to, not something you choose at each call.

## What using it looks like

```rust
let mut alice = AsyncSecureStore::new();
alice.add_private_vid(OwnedVid::from_file("alice/piv.json").await?, None)?;
alice.verify_vid("did:webvh:...:bob", Some("bob".into())).await?;

alice.send(alice_vid, bob_vid, b"hello world").await?;
```

Bob receives a stream, because a message is not the only thing that can arrive — a first contact
also brings a request to form a relationship:

```rust
while let Some(message) = bobs_messages.next().await {
    match message? {
        ReceivedTspMessage::GenericMessage { sender, message, .. } => { /* ... */ }
        ReceivedTspMessage::RequestRelationship { sender, .. } => { /* ... */ }
        _ => {}
    }
}
```

The complete, compiling version of this is in the [crate documentation](https://docs.rs/tsp_sdk/),
where it runs as part of the test suite.

## Status

This implements revision 3 of the specification. Development is ongoing, and interfaces or the
structure of the repository are likely to change. Nothing here represents a "final design",
overrides the specification, or indicates a future direction for it. It is not the reference
implementation _yet_.

Messages produced by this revision do not interoperate with earlier ones: the wire version
changed, the default encryption changed, and `did:peer` identifiers moved to numalgo 4. Wallets
written by earlier versions still open, and `did:web` and `did:webvh` identifiers created by them
still resolve.

## Building and testing

Install a recent Rust compiler by [following these instructions](https://www.rust-lang.org/tools/install),
then:

```sh
git clone https://github.com/openwallet-foundation-labs/tsp.git
cd tsp
cargo test
```

Running `cargo test` from the top level also exercises the Python and JavaScript bindings, which
needs a working Python installation. To test only the library, run it in `tsp_sdk/` instead.

To build the documentation:

```sh
cargo doc --workspace --no-deps
```

## The command line tool

The `examples` crate contains a command line tool, which is the quickest way to see the protocol
work end to end. Install it from the project root:

```sh
cargo install --path examples/ --bin tsp
```

Create an identity, and verify someone else's:

```sh
tsp create --type webvh --alias bob bob
tsp verify --alias alice did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice
```

The [documentation](https://docs.teaspoon.world) walks through sending directly, sending through
an intermediary so that neither correspondent learns the other's address, and nesting one message
inside another.

## Cryptography

Confidential messages are encrypted with [HPKE](https://datatracker.ietf.org/doc/rfc9180/) in Base
mode, using HKDF-SHA256 and ChaCha20/Poly1305, and signed. The key encapsulation follows the
recipient's encryption key type — X25519, or X25519MLKEM768 for post-quantum — so there is no
separate post-quantum mode to select. Signatures are Ed25519 or ML-DSA-65. A message may also be
signed without being encrypted, in which case its payload travels in the clear.

What binds a message to its sender is that the sender's own identifier travels *inside* the
encrypted payload rather than beside it, where an attacker could change it. The properties this
provides are argued in the security considerations of the specification rather than restated here.

The libsodium anonymous sealed box remains available for existing implementations.

## Repository layout

The workspace holds five crates:

- `tsp_sdk/` — the library
- `examples/` — the command line tool, a demo server, an intermediary, and a DID server
- `tsp_python/`, `tsp_javascript/` — bindings
- `fuzz/` — fuzzing targets

Inside the library:

- `cesr/` — encoding and decoding of the wire format. Deliberately minimal: enough to produce and
  parse TSP messages, not a general CESR implementation.
- `crypto/` — the cryptographic core described above.
- `vid/` — verified identifiers. `did:peer`, `did:web` and `did:webvh` are supported; see
  [the documentation](https://docs.teaspoon.world/custom-vids.html) for adding your own.
- `transport/` — sending and receiving over HTTP, TCP, TLS and QUIC, built on
  [tokio](https://tokio.rs/).
- `definitions/` — the data structures, traits and errors shared across the above.

## Further reading

- [docs.teaspoon.world](https://docs.teaspoon.world) — guides, the command line tool, and how to
  [run an intermediary](https://docs.teaspoon.world/intermediary.html)
- [docs.rs/tsp_sdk](https://docs.rs/tsp_sdk/) — API documentation
- [the specification](https://trustoverip.github.io/tswg-tsp-specification/)
