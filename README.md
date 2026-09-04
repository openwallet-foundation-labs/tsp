[![Deploy](https://github.com/openwallet-foundation-labs/tsp/actions/workflows/deploy.yml/badge.svg)](https://github.com/openwallet-foundation-labs/tsp/actions/workflows/deploy.yml)
[![Crates.io Version](https://img.shields.io/crates/v/tsp_sdk)](https://crates.io/crates/tsp_sdk)
[![docs.rs](https://img.shields.io/docsrs/tsp_sdk?label=docs.rs)](https://docs.rs/tsp_sdk/latest/tsp_sdk/)
![Deps.rs Crate Dependencies (specific version)](https://img.shields.io/deps-rs/tsp_sdk/latest)
![Crates.io MSRV](https://img.shields.io/crates/msrv/tsp_sdk)

# TSP SDK

A Rust implementation of the [Trust Spanning Protocol](https://trustoverip.github.io/tswg-tsp-specification/).

TSP lets two endpoints communicate authentically, confidentially and more privately **even when they identify themselves in
different but verifiable ways**. One may be a `did:webvh`, another a `did:peer`, another a KERI AID — among potentially others. Any identifier built on public key cryptography with a
verifiable trust root may qualify. When public facing, these identifiers are often persistent, long term, supporting secure key rotations. TSP is the spanning layer between them: it makes messages
authentic, confidential where wanted, and resistant to the metadata correlation that otherwise
leaks who is talking to whom (meta-data privacy). The specification's own analogy is the one worth keeping — TSP
connects identifier systems much as IP connected heterogeneous networks.

Endpoints form **relationships**, each side verifying the other's identifier independently, and
those relationships are also persistent as the identifiers and can be the basis of trust or reputation. A virtual channel is established (transports) for a relationship only when the two parties need to communicate. A message can travel **directly** to its
recipient, or be **routed** through intermediaries that may provide better message delivery services and also better meta-data privacy.

This crate gives you a wallet holding your own identifiers and the ones you have verified, and an
API for sending and receiving over it. Which transport carries a message — HTTP, TCP, TLS, QUIC,
or an intermediary holding it until you collect it — follows from the verifiable identifier you are sending
to (its access point).

## Try it

You may get a sense of how TSP and its whole system work by using the command line tool included in this repo. This tool is for illustration and testing only, not intended for production use.

Install the command line tool:

```sh
cargo install --path examples/ --bin tsp
```

Create an identity. Identities are published to a shared public test server, so
`<your-endpoint-name>` has to be one nobody has taken — pick something unlikely. Creating an
identity under a name already in use fails rather than overwriting it.

```sh
tsp --wallet ann create --type webvh --alias me <your-endpoint-name>
```

In a second terminal, make someone to talk to, and print their identifier:

```sh
tsp --wallet ben create --type webvh --alias me <another-endpoint-name>
tsp --wallet ben print me
```

Leave Ben listening:

```sh
tsp --wallet ben receive me
```

Back in the first terminal, verify Ben's identifier and send to it:

```sh
tsp --wallet ann verify <ben's identifier> --alias ben
echo -n "hello" | tsp --wallet ann send -s me -r ben
```

Ben's terminal, verbatim — your identifiers will differ:

```
 INFO tsp: listening for messages...
 INFO tsp: received relationship request from did:webvh:Qmd6wgj9G7HaktNUPDS5JtsSLERCkzDA6Hqvo9QE8h4dSS:did.teaspoon.world:endpoint:ann12883, thread-id 'f/5OiwTEqk8suswgcCHks8KuYb0FT4K1d+KCNnF+u3Y'
did:webvh:Qmd6wgj9G7HaktNUPDS5JtsSLERCkzDA6Hqvo9QE8h4dSS:did.teaspoon.world:endpoint:ann12883	f/5OiwTEqk8suswgcCHks8KuYb0FT4K1d+KCNnF+u3Y
 INFO tsp: received confidential message (5 bytes) from did:webvh:Qmd6wgj9G7HaktNUPDS5JtsSLERCkzDA6Hqvo9QE8h4dSS:did.teaspoon.world:endpoint:ann12883 (HPKE-Base, Ed25519 signature)
hello
```

Ann had no prior relationship with Ben, so one is formed before the "hello" message. Once a relationship is formed, future messages will not have the relationship forming step.

## Using the SDK library

```rust
let mut alice = AsyncSecureStore::new();
alice.add_private_vid(OwnedVid::from_file("alice/piv.json").await?, None)?;
alice.verify_vid("did:webvh:...:bob", Some("bob".into())).await?;

alice.send(alice_vid, bob_vid, b"hello world").await?;
```

Receiving is a stream, because a message is not the only thing that can arrive:

```rust
while let Some(message) = bobs_messages.next().await {
    match message? {
        ReceivedTspMessage::GenericMessage { sender, message, .. } => { /* ... */ }
        ReceivedTspMessage::RequestRelationship { sender, .. } => { /* ... */ }
        _ => {}
    }
}
```

The complete, compiling version is in the [crate documentation](https://docs.rs/tsp_sdk/), where
it runs as part of the test suite.

### From Python and JavaScript

`tsp_python/` binds the library for Python through [PyO3](https://pyo3.rs/); its README shows
running the examples with [uv](https://docs.astral.sh/uv/), or with maturin directly.
`tsp_javascript/` builds to WebAssembly with `wasm-pack`, for Node and the browser. Both track the
Rust library and are built by the same checks.

## Status

This implements Revision 3 of the specification. Development is ongoing, and interfaces or the
structure of the repository are likely to change. Nothing here represents a "final design",
overrides the specification, or indicates a future direction for it. It is not the reference
implementation _yet_.

Messages produced by this revision do not interoperate with earlier ones: the wire version
changed, the default encryption changed, and `did:peer` identifiers moved to numalgo 4.

`did:webvh` and `did:peer` are implemented. KERI AIDs are in our roadmap; they are named above because the
protocol is meant to span them, not because this crate speaks them yet.

## Cryptography

An authentic and confidential message is sign-encrypted one of two ways, and which one is encoded in the message itself (not a static selection). This SDK supports both in per message level, further improving interoperability.

- **HPKE** in base mode ([HPKE](https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-04.txt)), with HKDF-SHA256
  and ChaCha20/Poly1305. The key encapsulation follows the recipient's encryption key type —
  X25519, or X25519MLKEM768 for post-quantum — so there is no separate post-quantum mode to pick.
- **The libsodium anonymous sealed box** ([libsodium](https://doc.libsodium.org/)), enhanced with a encrypted sender VID (aka ESSR).

A message may instead be signed without being encrypted, in which case its payload travels in the
clear. Signatures are Ed25519 or ML-DSA-65.

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
- `vid/` — verified identifiers, their resolution and verification.
- `transport/` — sending and receiving over HTTP, TCP, TLS and QUIC, built on
  [tokio](https://tokio.rs/).
- `definitions/` — the data structures, traits and errors shared across the above.

## Further reading

- [the manual](docs/manual.md) — using the protocol, embedding the library, operating the
  services, and working on the SDK
- [the specification](https://trustoverip.github.io/tswg-tsp-specification/) — the Trust Spanning Protocol specification
- [docs.rs/tsp_sdk](https://docs.rs/tsp_sdk/) — API documentation
