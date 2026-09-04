# TSP SDK Manual

Four parts: using the protocol from the command line, embedding the library, operating the
services, and working on the SDK itself.

The [specification](https://trustoverip.github.io/tswg-tsp-specification/) is the authority on the
protocol. This manual describes *this implementation*, and where the two disagree the
specification is right. API documentation lives at [docs.rs/tsp_sdk](https://docs.rs/tsp_sdk/) and
is generated from the source, so it cannot drift from the code.

---

## Part 1 — Using the protocol

The command line tool exists to demonstrate and test the protocol. It is not meant for production.

### Installing

```sh
cargo install --git https://github.com/openwallet-foundation-labs/tsp.git examples --bin tsp
```

Or from a clone, `cargo install --path examples/ --bin tsp`.

The wallet defaults to `wallet` and the password to `unsecure`, both overridable with `--wallet`
and `--password`. Every subcommand takes `--verbose`.

### Creating an identity

```sh
tsp --wallet ann create --type webvh --alias me <your-endpoint-name>
```

Identities are published to a shared public server, so the name has to be one nobody has taken.
Creating one under a name already in use fails rather than overwriting it.

Three identifier types are available:

- **`did:webvh`** — resolved from a server, and carries a verifiable history of its keys, so a
  rotation can be followed from the key state you already hold. Use this for anything public.
- **`did:peer`** — self-certifying: the identifier is a digest of the document holding its keys,
  so nothing has to be fetched to check it, and a change of keys is a change of identifier. Use
  this for private and nested relationships.
- **`did:web`** — resolved by fetching a document. It carries no provenance, so a document served
  under the same identifier with different keys is indistinguishable from a substitution. A
  rotation therefore ends a relationship rather than continuing it. Supported, not recommended.

### Sending a message directly

Create someone to talk to, and print their identifier:

```sh
tsp --wallet ben create --type webvh --alias me <another-endpoint-name>
tsp --wallet ben print me
```

Leave Ben listening:

```sh
tsp --wallet ben receive me
```

Then verify Ben's identifier and send to it:

```sh
tsp --wallet ann verify <ben's identifier> --alias ben
echo -n "hello" | tsp --wallet ann send -s me -r ben
```

Ben sees a relationship request arrive before the message, because none existed. Later messages
do not repeat that step.

### Sending through intermediaries

Routing hides who is talking to whom: neither correspondent learns the other's address, and no
intermediary sees the whole path.

Both endpoints first form a relationship with an intermediary, and the receiver forms a *nested*
relationship with theirs, which is where the message is finally dropped off. The route the sender
then sets names the first intermediary, the second, and the receiver's nested identifier — not the
receiver itself.

The intermediaries publish their identifiers on their own home pages; read them there rather than
copying them from documentation, since an identifier derived from a digest cannot be predicted and
changes if the intermediary is ever re-created.

`examples/cli-demo-routed-external.sh` performs the whole sequence against the public
intermediaries, and `examples/cli-demo-routed-local.sh` does the same against local ones.

### Nested and parallel relationships

A **nested** message is a complete TSP message carried inside another, so the outer envelope
reveals only the outer identifiers. This is what keeps a routed message's real correspondents
hidden from the intermediaries carrying it.

A **parallel** relationship proposes a second identity within an existing relationship — useful
when one party wants to be known by a different identifier for some purpose without establishing
trust again from nothing.

`examples/cli-demo-nested.sh` and `examples/cli-demo-doubly-nested.sh` demonstrate nesting.

---

## Part 2 — Embedding the library

`AsyncSecureStore` is the primary API: a wallet holding your own identifiers and the ones you have
verified, plus sending and receiving over them.

```rust
let mut alice = AsyncSecureStore::new();
alice.add_private_vid(OwnedVid::from_file("alice/piv.json").await?, None)?;
alice.verify_vid("did:webvh:...:bob", Some("bob".into())).await?;

alice.send(alice_vid, bob_vid, b"hello world").await?;
```

Receiving is a stream, because a message is not the only thing that can arrive — relationship
requests, acceptances and cancellations come through the same channel.

The complete, compiling version of this is in the
[crate documentation](https://docs.rs/tsp_sdk/), where it runs as part of the test suite.

`SecureStore` is the same wallet without the async runtime or transports: it seals and opens
messages and leaves delivery to you.

### Transports

`send` and `receive` choose a transport from the recipient's transport URL:

- **HTTP(S)** — server-sent events with a WebSocket fallback for receiving, POST for sending.
  Works for clients with no public address, which is what makes intermediaries useful.
- **TCP**, **TLS**, **QUIC** — direct connections between endpoints.

To use something else entirely — a queue, email, MQTT — seal with `SecureStore` and deliver the
bytes yourself. TMCP, which secures the traffic between AI agents and MCP servers, works this way.

### Custom identifier types

The store accepts anything implementing `VerifiedVid`, or `PrivateVid` for identities holding
private key material. See `tsp_sdk/src/definitions/mod.rs` for the traits, and
`tsp_sdk/src/vid/did/webvh.rs` for a worked implementation.

**A `VerifiedVid` must only be constructed after verification.** What verification means depends
on the identifier type, and the store trusts what you give it.

### Custom storage

Wallets are persisted through the `SecureStorage` trait, in `tsp_sdk/src/secure_storage.rs`.
`AskarSecureStorage` implements it over [Askar](https://github.com/openwallet-foundation/askar),
using SQLite by default; the `postgres` feature accepts a `postgres://` URL instead.

**Whatever you persist must be encrypted.** It contains the private keys that authenticate every
message you send.

### From Python and JavaScript

`tsp_python/` binds the library through PyO3; its README covers running the examples with `uv` or
maturin. `tsp_javascript/` builds to WebAssembly with `wasm-pack` for Node and the browser.
Neither is published to a package registry yet.

---

## Part 3 — Operating the services

Three services are deployed for the public testbed, all built from `examples/`.

### The DID server

Hosts identity documents and their histories. `did:webvh` identifiers resolve here, so it is the
authority a correspondent consults to learn anyone's current keys.

Identities are files in a bucket. There is no delete route: removing one is done at the storage
layer, which is the only remedy when an identity has been published whose keys are lost.

Publishing under a name that already exists **fails rather than overwriting**. This matters more
than it sounds — it is how an intermediary discovers that its wallet has gone missing rather than
silently claiming an identity its clients cannot reach.

### Intermediaries

An intermediary forwards messages, and buffers them for recipients that are not currently
listening, so a client behind a firewall can collect later. It is a TSP endpoint in its own right,
with its own identity, and it forms relationships with its clients like anyone else.

**Its identity must persist.** Each intermediary keeps a wallet, creates a `did:webvh` identity
once, publishes it, and reuses it thereafter. If it generated fresh keys on each start, every
relationship its clients hold would be invalidated on every deploy — clients would see the same
identifier with different keys, which is indistinguishable from a substitution and is correctly
refused.

Consequences worth understanding before deploying one:

- The wallet is kept in a bucket as **a single object**, written back whole on every change. Object
  storage replaces an object entirely or not at all, which is how the wallet is written anyway.
  It is deliberately not mounted as a filesystem: that would require pretending an object can be
  edited in place, which is what a database file does constantly.
- **The wallet is written before the identity is published**, and failing to write it is fatal.
  What is published cannot be withdrawn or updated without the keys, so publishing an identity
  that was never saved burns that name permanently.
- Startup refuses rather than guesses when the wallet, the arguments and the DID server disagree —
  a name already registered while the wallet is empty, an identifier published under a different
  name, an identity directing clients to a different domain. Each names the conflict.
- The wallet password is read at startup from a secret store using the service's own identity, so
  it appears nowhere in the deployment configuration.

### Running intermediaries locally

An SSL proxy provides HTTPS using the certificates in `examples/test/`:

```sh
npx local-ssl-proxy --config ./ssl-proxy.json
```

Then, in separate terminals, with the `use_local_certificate` feature so the test certificate is
trusted:

```sh
cargo run --features use_local_certificate --bin demo-intermediary -- --port 3011 localhost:3001
cargo run --features use_local_certificate --bin demo-intermediary -- --port 3012 localhost:3002
```

The proxy exposes these at `https://localhost:3001` and `https://localhost:3002`.

### Writing your own intermediary

Use `AsyncSecureStore` for the built-in transports, or `SecureStore` if you carry messages
yourself. `route_message` takes a sender, a receiver and the message bytes; the async store sends
the result immediately, the sync one returns it for you to deliver.

`cesr::get_sender_receiver` reads the envelope of an incoming message without opening it, and
`has_private_vid` answers whether a message is addressed to you.

---

## Part 4 — Working on the SDK

### Layout

Five crates: `tsp_sdk/` the library, `examples/` the command line tool and the three services,
`tsp_python/` and `tsp_javascript/` the bindings, `fuzz/` the fuzzing targets. `demo/` is excluded
from the workspace and frozen.

Inside the library: `cesr/` encodes and decodes the wire format, deliberately minimal rather than
a general CESR implementation; `crypto/` holds the cryptographic core; `vid/` resolves and
verifies identifiers; `transport/` carries messages; `definitions/` holds what the rest shares.

### Checks

```sh
cargo fmt --all --check
cargo clippy --workspace --tests -- --deny warnings
cargo test --workspace
cargo doc --workspace --no-deps
cargo deny check
```

`cargo doc` is easy to forget and catches things the others do not — an ambiguous documentation
link fails it while everything compiles and every test passes.

**The container builds differently from all of the above**, and the difference has broken
deployment twice. It builds the three deployed binaries with `--no-default-features`, on the
compiler version the workspace names as its minimum, which is older than the one the other checks
use. A check does the same, and it is the one to run before anything is deployed:

```sh
cargo build --bin demo-intermediary --bin demo-server --bin did-server --no-default-features
```

### Test vectors

`tsp_sdk/examples/generate_test_vectors.rs` produces the vectors published in the specification's
appendix. It calls the library's own sealing functions with fixed key material, so the output is
byte-stable and regenerating it after a wire change produces a reviewable diff.

Vectors are generated a handful of times in the protocol's life. That is why the generator is a
separate example binary rather than instrumentation inside the send and receive paths: the latter
would put code that can print private key material into the path that handles real messages, and
would establish only that the vectors match this implementation — not that they match the
specification, which is a human check either way.

### Benchmarks

`tsp_sdk/benches/` holds them, run with criterion:

```sh
cargo bench --features "resolve,bench-criterion" -p tsp_sdk --bench throughput
```

`guardrail` measures the cryptographic operations and runs in continuous integration to catch
performance regressions. The throughput benchmarks measure end-to-end message rates under various
configurations, and `throughput_store_backend` measures wallet persistence.

### Fuzzing

`fuzz/fuzz_targets/` covers encoding round-trips and robustness against malformed input:

```sh
cargo fuzz run payload_encode_decode
```

### Releasing

The library is published to crates.io by hand; the bindings are not published anywhere yet. There
is no release workflow, which is why the published version has lagged the manifest before.
