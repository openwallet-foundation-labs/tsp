# TSP SDK Technical specification

This document tries to focus on aspects that pertain to the SDK; i.e. how the TSP Specification impacts the design
choices for the Rust SDK. Since the TSP Specification is still in the process of being finalized, however, there may be
some duplication.

## Protocol overview

At its core, TSP consists of "simply sending a message" between parties; except that this message is (often) encrypted
and (always) signed. In this way the parties have confidence that any messages received are always by the same entity,
and trust can be built.

TSP uses Verified Identifiers to designate the sender and receiver of messages. A mechanism out of scope for
this project (but that we will have to write some simple examples of) will allow applications to retrieve addresses and
public keys for a VID.

A TSP message therefore contains at least the following information:

* Who is the originating sender?
* Who is the intended receiver?
* A message payload (encrypted or unencrypted), which can either be 'simple content' or a Control Message.
* A signature

So, a confidential message will conceptually look like this:

<svg width="771px" height="121px" font-size="16px" viewBox="-0.5 -0.5 771 121">
    <rect x="0" y="0" width="640" height="120" fill="white" stroke="black" />
    <rect x="10" y="30" width="490" height="80" fill="#eee" stroke="black" />
    <rect x="510" y="30" width="120" height="80" fill="#eee" stroke="black" />
    <text x="570" y="75" fill="black" text-anchor="middle">Ciphertext</text>
    <rect x="10" y="0" width="110" height="30" fill="none" stroke="none" />
    <text x="12" y="19" fill="black" font-size="12px">Authenticated data</text>
    <rect x="280" y="60" width="210" height="40" fill="white" stroke="black" />
    <text x="385" y="85" fill="black" text-anchor="middle">Non-confidential data</text>
    <rect x="20" y="60" width="120" height="40" fill="white" stroke="black" />
    <text x="80" y="85" fill="black" text-anchor="middle">Sender VID</text>
    <rect x="150" y="60" width="120" height="40" fill="white" stroke="black" />
    <text x="210" y="85" fill="black" text-anchor="middle">Receiver VID</text>
    <rect x="20" y="30" width="110" height="30" fill="none" stroke="none" />
    <text x="22" y="49" fill="black" font-size="12px">Envelope</text>
    <rect x="650" y="0" width="120" height="120" fill="white" stroke="black" />
    <text x="710" y="65" fill="black" text-anchor="middle">Signature</text>
</svg>

And a non-confidential message, when there is no receiver VID, will look like this:

<svg width="771px" height="121px" font-size="16px" viewBox="-0.5 -0.5 771 121">
    <rect x="0" y="0" width="640" height="120" fill="white" stroke="black" />
    <rect x="10" y="30" width="490" height="80" fill="#eee" stroke="black" />
    <rect x="10" y="0" width="110" height="30" fill="none" stroke="none" />
    <text x="12" y="19" fill="black" font-size="12px">Authenticated data</text>
    <rect x="280" y="60" width="210" height="40" fill="white" stroke="black" />
    <text x="385" y="85" fill="black" text-anchor="middle">Non-confidential data</text>
    <rect x="20" y="60" width="120" height="40" fill="white" stroke="black" />
    <text x="80" y="85" fill="black" text-anchor="middle">Sender VID</text>
    <rect x="20" y="30" width="110" height="30" fill="none" stroke="none" />
    <text x="22" y="49" fill="black" font-size="12px">Envelope</text>
    <rect x="650" y="0" width="120" height="120" fill="white" stroke="black" />
    <text x="710" y="65" fill="black" text-anchor="middle">Signature</text>
</svg>

### Modes of operation

1. Direct mode: TSP messages can be exchanged directly between two parties via publicly known VID's ("Well-Known
   VID's"); that gives confidentiality and authenticity but not much privacy.

2. Nested mode: TSP messages can be exchanged as the 'payload' of another TSP message using not-publicly known VID's.
   Such a nested connection is established via TSP Control Messages. This gives a little bit more privacy.

3. Routed mode: TSP messages can be routed through intermediaries to further hide the fact that two parties are
   communicating. This is done by parties first establishing "nested" communication lines between every involved party
   and then sending a message that spans over those nested communications lines.

### High-level architecture

The SDK will consist of functions that can be called by an application to completely perform all TSP-specific
operations, such as:

* Generating/retrieving/storing VID's
* Control operations on a private key associated with a VID
* Obtaining transport layer address information and other metadata from a verified VID.
* Creation and processing of TSP messages

This allows applications the flexibility to incorporate TSP in an existing setup: i.e., an application can create a TSP
message but chose by itself how and when to send it.

For other use cases, the SDK will also contain some convenience functions such as "generate-and-send" for some common
transport layers (such as HTTPS or QUIC) for applications that don't need this flexibility.

## SDK General Requirements

### Cryptography

| _  | Description                                             | Rationale                                                                                                                                       | Consequence                                                                                                                                                                                                                                  |
|----|---------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| C1 | Encryption primitives chosen have to be IND-CCA2 secure | This is the strongest notion of security: under an adaptive chosen ciphertext attack, the attacker cannot recognize correct ciphertext.         | We use `HPKE-Auth` for encryption, a modern asymmetric "weakly authenticated" encryption standard                                                                                                                                            |
| C2 | Signature schemes have to be SUF-CMA secure             | This is the strongest notion of unforgeability, meaning an attacker cannot create valid signatures themselves even if given a "signing oracle". | Ed25519 will be used for creating non-repudiation signatures in TSP messages.                                                                                                                                                                |
| C3 | Cryptographic code has to be reliable                   | TSP relies heavily on cryptography being reliable, and we should not write these ourselves.                                                     | For crypto "back-ends", code will come from the [`RustCrypto`](https://github.com/RustCrypto/) and `DALEK` projects. We avoid `ring` due to maintenance issues and `libsodium` since its Rust binding has been deprecated by its maintainer. |
| C4 | TSP must be resilient against key compromise events     | If a private key is leaked, the goal of TSP is compromised                                                                                      | The SDK will not have an API for providing the private key of a VID to an application. Furthermore, HPKE is used that offers more protection against KCI.                                                                                    |

### Interoperability

| _  | Description                                                                                                                      | Rationale                                                                                                                                                                     | Consequence                                                                                                                                              |
|----|----------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| I1 | The implementation must only use third-party dependencies that are "well adopted" by the Rust community and actively maintained. | This will "future-proof" the SDK by reduce the chance that the SDK will rely on code that will be abandoned, or that it will be unpopular by requiring uncommon dependencies. | Before taking a dependency, we check its activity status and number of downloads. In particular, we will have to write our own `CESR` support libraries. |
| I2 | TSP messages must support CESR encoding                                                                                          | CESR encoding is important for credibility in the wider Trust-over-IP community and interoperability with KERI                                                                | TSP messages will be formatted using CESR                                                                                                                |
| I3 | TSP messages must be capable of being easily generated and parsed in wide variety of contexts                                    | TSP must be a general protocol                                                                                                                                                | TSP will use CESR in the "B" domain as the canonical representation that will be signed, since that reduces the impact of the choice for CESR.           |
| I4 | The TSP SDK must be usable by programs not written in Rust                                                                       | Rust is a secure language, but not a "lingua franca"                                                                                                                          | Bindings will be written to make the SDK usable from C, Python and JavaScript.                                                                           |
| I5 | The SDK must not impose unduly restrictive limitations of use                                                                    | This allows for easier adoption by existing applications                                                                                                                      | TSP message creation/processing and sending/receiving will be split up in different functions.                                                           |

### TSP Specification Conformance

| _  | Description                                                           | Rationale                                  | Consequence                                                                                         |
|----|-----------------------------------------------------------------------|--------------------------------------------|-----------------------------------------------------------------------------------------------------|
| S1 | TSP can be run over many different transport protocol                 | TSP must be a flexible protocol            | Code will be designed so it is not tightly tied to a single transport layer.                        |
| S2 | The SDK will support "direct mode", "nested mode" and "routed mode" | This is essential for achieving TSP's aims | Some design discussion around control messages setting up routed mode will be needed in the future. |

### Verified Identifiers

| _  | Description                                                                                             | Rationale                                                                                                                       | Consequence                                                                                                                                                |
|----|---------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| V1 | VID can contain no identifying information, with the exception of "Well Known VIDs"                     | Non-correlation of VID's is required by the TSP spec                                                                            | Cryptographic means and entropy means must be used for creating unpredictable "inner VIDs"                                                                 |
| V2 | VID is a probabilistically unique identifier                                                            | There must be an extremely low change of two VID's being the same; but this chance cannot be made 0                             | An "inner VIDs" must represent at least 128 bits of entropy                                                                                                |
| V3 | The specific style of VID is out of scope                                                               | This is part of the TSP "support system"                                                                                        | We need to model an interface for VID's at a sufficiently usable and abstract level; and pick a sufficiently general type of VID for the demo application. |
| V4 | A verified VID can be resolved to a pair of public encryption and public verification keys              | VIDs are used instead of public keys in TSP                                                                                     | In the SDK, a known VID has been resolved to a pair of public keys                                                                                         |
| V5 | A verified VID can be resolved to a "transport layer address"                                           | TSP is a communication protocol                                                                                                 | In the SDK, a known VID has been resolved to a form of resource locator such as an e-mail address or URI.                                                  |
| V6 | A verified VID may also provide additional information about the entity it identifies                   | This is what identifiers are typically used for (see DID and X509)                                                              | The VID interface must support this                                                                                                                        |
| V7 | The information about resolved VID's in the TSP SDK must be treated as confidential and securely stored | This "routing information" links VIDs to addresses and public keys and can compromise the non-correlation requirement for VID's | This information will be stored in a secure manner (such as in a secure wallet)                                                                            |
| V8 | TSP messages may also be "broadcast", without a designated received                                     | This is under consideration in the TSP specification                                                                            | Our SDK will support the *creation* of TSP broadcast messages.                                                                                             |

### Demo

| _  | Description                                                   | Rationale                                                | Consequence                                                                                 |
|----|---------------------------------------------------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------------|
| D1 | The demo must be a good example of how to use the SDK         | TSP is easier to adopt if developers can 'copy code'     | The "trust application" side of the demo must not be fairly simple.                         |
| D2 | The demo must be able to demonstrate the particular features of TSP | This will make it easier to understand what TSP achieves | The demo must involve the three pillars of TSP: confidentiality, authenticity, and privacy. |

## Security properties

The goal of TSP is to provide security guarantees for

- Authenticity
- Confidentiality
- Privacy

of communication between two parties.

Privacy in communication can be optionally enabled by using the "Routed" mode of the TSP protocol.

To get a high degree of confidence, a modern and well-analyzed cryptographic standard for signcryption is chosen. In
signcryption asymmetric cryptography is used to encrypt and sign the contents of a message.

Hybrid Public Key Encryption (HPKE, RFC 9180) is a robust method of signcryption using modern cryptographic
primitives [^1]. It combined a "Key encapsulation Mechanism", with a "Key Derivation Function" and primitive for
"Authenticated encryption with associated data" to combine asymmetric with symmetric cryptography, to obtain certain
security and performance characteristics. HPKE offers the highest notion of confidentiality, namely IN-CCA2.

HPKE offers the possibility to create authenticated plaintext and authenticated ciphertext in one signcryption
operation.
In TSP a header (containing the sender and receiver VID's) must be authenticated but not encrypted.

Although HPKE offers authentication and confidentiality between two parties, there are two characteristics that are not
desirable for TSP:

- HPKE is vulnerable to key compromise impersonation (KCI). Which means that if Bob's private key is leaked to Eve, Eve
  can impersonate Alice toward bob.
- Although two parties communicating can verify the authenticity of messages, an outsider cannot verify that, for
  instance, the sender as specified in the header of the message really sends the message. Thereby a receiver can also
  not prove a message was sent by a particular sender to them. This is called receiver unforgeability (RUF).

The overcome to above, an additional signature is created over both the header and the (HPKE) ciphertext of a TSP
message. Since both the sender and receiver's VID are present in the header of a message, one can always verify the
message was created by the specified sender and that it was intended for the specified receiver. This is a method first
proposed in [^2].

The additional "outer" signature over the message header (or envelope) plus the ciphertext makes TSP secure against KCI
and RUF secure.

A modern and secure public-key signature scheme is used to construct the "outer" signature, namely
`Ed25519` [^3], based in the same elliptic-curve cryptography as HPKE. Ed25519 satisfies properties such as EUF-CMA or
SUF-CMA (existentially unforgeable under chosen message attacks, strong unforgeability).

### Non goals

#### Hiding plaintext length

By default, TSP does not hide the length of plaintext messages. If the size of the plaintext is confidential, the
application layer could take measures to hide the length by, for instance, always sending fixed size messages.

### Bidirectional mode

TSP messages are unidirectional. There is no default way of "responding" to a TSP message, other than constructing a new
unidirectional message.

### Cryptographic primitives

The following underlying cryptographic primitives are chosen for the TSP.

Key Encapsulation Method:
`DHKEM(X25519, HKDF-SHA256)`

Key Derivation Function:
`HKDF-SHA256`

Authenticated Encryption with Associated Data (AEAD) Function:
`ChaCha20Poly1305`

Signature scheme:
`Ed25519 SHA512`

HPKE operation mode:
`Auth`

### Encoding

By default, TSP messages are encoded using CESR [^4] with a specific extension for TSP [^5].

The methods the seal (encrypt, sign) and open (decrypt, verify) a message also encode and decode the message using CESR
in the binary domain.

Using a deterministic and predictable binary encoding helps to reliably sign and verify a TSP message.

### HPKE usage

The notation below is based on RFC 9180 [^6].

We create the message header:

```
Envelope = ConcatCESR(
    [VID sender, VID receiver, Additional header data]
)
```

We perform a HPKE Seal operation using the single-shot API in Auth mode:

```
Ciphertext = SealAuth(
    skS = Sender private key,
    pkR = Receiver public key,
    aad = Envelope,
    pt = Message plaintext
)
```

We sign the header information together with the ciphertext and encapsulated key:

```
Signature = Sign(
    skS = Sender private key,
    msg = Concat<CESR>(Envelope, Ciphertext),
)
```

We construct the final message:

```
Ciphertext Message = ConcatCESR(
    [Envelope, Ciphertext, Signature]
)
```

The receiver performs verification and decryption as follows.

Parse the CESR encoded message:

```
[Envelope, Ciphertext, Signature] = SplitCESR(Ciphertext Message)

[VID sender, VID receiver, Additional header data] = SplitCESR(Envelope)
```

Verify the outer signature:

```
Verify(
    pkS = Sender public key,
    msg = ConcatCESR(Envelope, Ciphertext)
)
```

We perform a HPKE Open operation using the single-shot API in Auth mode:

```
Message plaintext = OpenAuth(
    pkS = Sender public key,
    skR = Receiver private key,
    aad = Envelope,
    ct = Ciphertext
)
```

### Streaming mode

HPKE allows sealing a stream of messages efficiently by only using symmetric cryptography for subsequent messages. We
could extend TSP to allow such a streaming mode by setting up a sender and a receiver context. This context holds the
key
material for the current stream or "session", as described in session 5.1 of RFC 9180. When using a streaming mode in
TSP, only the first message contains the full header and the outer signature.

Note that KCI is not a problem for this mode, since the first message still contains the outer signature (created using
the senders’ private key). However, naively implementing a streaming mode using HPKE breaks RUF for subsequent messages.
One
could include a hash of the next message in each streaming message, and thereby securely links each message back to the
initial, signed TSP message. In that case RUF still holds.

## API overview

The `rust-tsp` library should allow users to seal and open TSP messages. Note that the provided code is pseudo-Rust
code;
we abstract away from some implementation details.

### Create a VID database and context

A VID database allows the user to store VID / public key pairs and optionally metadata related to the VID, like a name
or transport specification.

We do not yet make assumptions on the type of database (whether on disk, in memory or a relational database, or in a
wallet), except that it must be treated as confidential data.

```rust

/// Create a new VID database
pub fn create_database() -> Result<VidDatabase, Error>;

/// Open an existing VID database
pub fn open_database(...) -> Result<VidDatabase, Error>;

/// Persist a VID database (might only be available for on-disk databases)
pub fn persist_database(..., db: &VidDatabase) -> Result<(), Error>;

struct PublicIdentity {
    public_key: PublicKey,
    resource: TransportDestination,
    info: Option<Metadata>,
    vid: Vid,
}

// Resolve a VID: verify the vid and resolve a public key
// and possibly a transport method
pub fn resolve_vid(db: &mut VidDatabase, vid: &Vid) -> Result<PublicIdentity, Error>;
```

A context provides a place to store the sender/receiver key material and VID. Note that a sender/receiver could have
multiple VID's and thereby multiple contexts.

```rust
struct PrivateIdentity {
    private_key: PrivateKey,
    public_key: PublicKey,
    vid: Vid,
}

/// Create a new context
pub fn create_context(identity: &Identity, db: &VidDatabase) -> Result<Context, Error>;
```

### Seal and open a TSP message

Seal means encrypting, authenticating, signing, and encoding a message; open is the reverse operation. Note that the
`Header` type may contain additional authenticated data. The sender and receiver VID are added to the header by this
method.

```rust
/// Encrypt, authenticate and sign, and CESR encode a TSP message
/// The `header` parameter is added to the message header;
/// the header data is not encrypted, only authenticated
pub fn seal(ctx: &Context, receiver_vid: &Vid, header: &Header, message: &[u8]) -> Result<TspConfidentialMessage, Error>;

/// Decode a CESR Authentic Confidential Message, verify the signature and decrypt its contents
/// Returns the header, receiver VID, and message contents
/// Returns an error if the receiver VID did not match the current context
pub fn open(ctx: &Context, message: &TspMessage) -> Result<(Header, Vid, Vec<u8>), Error>;

/// Inspect the header of a message, return the header data, the sender and optional receiver VID
pub fn peek_header(message: &TspMessage) -> Result<(Header, Vid, Option<Vid>), Error>;
```

### Sign messages

The following methods allow encoding and signing a message without an encrypted payload.

```rust

/// Construct and sign a non-confidential TSP message, the receiver VID is optional
pub fn sign(ctx: &Context, header: &Header, message: &[u8]) -> Result<TspNonconfidentialMessage, Error>;

/// Decode a CESR Authentic Non-Confidential Message, verify the signature, and return its contents
/// Returns the header, optional receiver VID, and message contents
/// Returns an error if the receiver VID was defined and did not match the current context
pub fn verify(ctx: &Context, message: &TspMessage) -> Result<(Header, Option<Vid>, Vec<u8>), Error>;
```

### Managing VID's

The following methods will be supported on Verified Identifiers and Secret Keys:

```rust
/// Generates a new keypair for an existing VID; returns the key bytes from the old private key as an indication
/// That this key is now essentially compromised. The new public key must be communicated to the (out of scope)
/// support system in a support-system-dependent manner by the caller (but see Milestone 5)
pub fn rotate_key(db: &mut VidDatabase, identity: &mut PrivateIdentity) -> Result<Vec<u8>, Error>;

/// Removes a Vid from the database; this can be a public, hidden, or a Vid owned by a `PrivateIdentity`
pub fn forget_vid(db: &mut VidDatabase, vid: &Vid) -> Result<(), Error>;
```

Also see Milestone 5, where this interface will probably need to be expanded.

### Extended API

The previous section described API's that can be used to send and receive messages in "Direct Mode",
see [Modes of operation](#modes-of-operation).

Note that additional API methods are necessary to enable the other modes. These will be added as part of Milestone 2.

TSP should also allow a "streaming" mode, in which a stream of messages is encrypted efficiently. The methods
for this mode will also be added in a later milestone.

## Library architecture

### Dependencies

A software library offering security operations is very prone to mistakes / bugs that compromise the security of the
cryptographic protocol as a whole in operation.

One of the ways to reduce the amount of code, and thereby reduce the number of possible security bugs, is reducing the
number of dependencies on other libraries.

The dependencies that are included should adhere to our quality standards, that is, we should have confidence in the
authors, and the library must not be abandoned and must have enough active users, i.e., must be popular.

We intend to use the following Rust crates (library dependencies) in our implementation:

- [rand](https://crates.io/crates/rand): Random number generators and other randomness functionality.
- [hpke](https://crates.io/crates/hpke): An implementation of the HPKE hybrid encryption standard (RFC 9180) in pure
  Rust
- [ed25519-dalek](https://crates.io/crates/ed25519-dalek): Fast and efficient Rust implementation of ed25519 key
  generation, signing, and verification.

### Bindings

The library should be usable in other languages. We therefore design the API in a way that allows the use within:

- C
- Python
- Javascript

## Demo

The first demo for TSP will consist of a simple messaging application, which has as a benefit that it closely follows
the TSP message architecture. To give insight into the privacy-protecting features, this chat application will consist
of
at least 3 "intermediaries". A simulated mode will also be provided, where simulated users can be added that establish
TSP channels with each other, and the demo itself can produce a log of all interactions that happen between each node.
The VID type for this demo will be relatively simple. However, support for a second, more realistic VID type will be
added,
so TSP messages can be exchanged both within the simulated environment and with the 'outside world'.

This satisfies the benefits that it will give insight into how TSP preserves privacy (that is achieves confidentiality
and authenticity is better understood), as well as being reasonably "simple" enough that the example itself will not
distract any future developers from how to apply the TSP SDK.


## References

[^1]: Richard Barnes and Karthikeyan Bhargavan and Benjamin Lipp and Christopher A. Wood, 2022, "Hybrid Public Key
Encryption", https://www.rfc-editor.org/info/rfc9180

[^2]: Jee Hea An, 2001, "Authenticated Encryption in the Public-Key Setting: Security Notions and
Analyses", https://eprint.iacr.org/2001/079

[^3]: Simon Josefsson and Ilari Liusvaara, 2017, "Edwards-Curve Digital Signature Algorithm (
EdDSA)", https://www.rfc-editor.org/info/rfc8032

[^4]: Samuel M. Smith, 2021, "Composable Event Streaming Representation (
CESR)", https://datatracker.ietf.org/doc/draft-ssmith-cesr

[^5]: https://github.com/WebOfTrust/keripy/discussions/612#discussioncomment-7739043

[^6]: https://www.rfc-editor.org/rfc/rfc9180.html#name-notation