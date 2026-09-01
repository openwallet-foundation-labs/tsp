TSP CESR Encoding
=================

TSP messages are encoded using CESR, in the code table genus `AAA` at version 2.00
(`-_AAACAA`). The genus code is not emitted per message: it is the table this
implementation is read against.

The SDK seals, signs, verifies and opens in the **binary domain**. The text domain
is the base64url of those bytes and is quadlet aligned, so every primitive starts on
a four-character boundary and the two domains map onto each other exactly. That is
what makes it safe to talk about a message as a string of characters below, and what
lets `tsp_sdk::cesr::segments` walk a message into named fields.

Fixed-length codes occupy the leading *bits* of the aligned block they share with
their data, not whole bytes. Slicing the text of such a primitive before decoding it
shifts the value; code and data have to be decoded together and the value taken off
the end.

CESR Code Tables
----------------

Codes used by TSP that come from the CESR tables:

| Code   | Description                | Code chars | Total chars |
|--------|----------------------------|------------|-------------|
| `I`    | SHA2-256 digest            | 1          | 44          |
| `F`    | Blake2b-256 digest         | 1          | 44          |
| `0A`   | 128-bit nonce              | 2          | 24          |
| `B#`   | Ed25519 signature, indexed | 2          | 88          |
| `1AAQ` | ML-DSA-65 signature        | 4          | 4416        |

The Ed25519 signature is an *indexed* primitive: the character after `B` is the
position of the signing key in the sender's VID document.

Fixed-length codes introduced by TSP:

| Code   | Description                                       | Total chars |
|--------|---------------------------------------------------|-------------|
| `X###` | Payload type code (`XSCS`, `XCTL`, …)             | 4           |
| `YTSP` | TSP genus, followed by the version count code     | 4           |

Variable-length codes introduced by TSP. The leading digit gives the number of lead
pad bytes; the trailing digits give the length of the data in quadlets. The `4/5/6`
forms carry a 12-bit length, the `7/8/9` forms a 24-bit one and are used only when
the data does not fit the short form.

| Code      | Description                        | Code chars |
|-----------|------------------------------------|------------|
| `4B##`    | TSP bytes, lead 0                  | 4          |
| `5B##`    | TSP bytes, lead 1                  | 4          |
| `6B##`    | TSP bytes, lead 2                  | 4          |
| `7AAB####`| TSP bytes, large, lead 0           | 8          |
| `8AAB####`| TSP bytes, large, lead 1           | 8          |
| `9AAB####`| TSP bytes, large, lead 2           | 8          |
| `4C##`    | Sealed-box ciphertext, lead 0      | 4          |
| `5C##`    | Sealed-box ciphertext, lead 1      | 4          |
| `6C##`    | Sealed-box ciphertext, lead 2      | 4          |
| `4F##`    | HPKE-Base ciphertext, lead 0       | 4          |
| `5F##`    | HPKE-Base ciphertext, lead 1       | 4          |
| `6F##`    | HPKE-Base ciphertext, lead 2       | 4          |
| `7AAC####`| Sealed-box ciphertext, large       | 8          |
| `7AAF####`| HPKE-Base ciphertext, large        | 8          |

Two things follow from this table.

**A VID, a payload and a padding field share one code.** `B` is the generic bytes
primitive; `TSP_VID` and `TSP_PLAINTEXT` are the same code. What a `4B##` run holds
is decided entirely by where it sits, never by its code.

**The ciphertext code names the cipher suite.** There is no separate field saying
which was used: `4C/5C/6C` is the libsodium anonymous sealed box, `4F/5F/6F` is
HPKE-Base — including the post-quantum KEM, which is selected by the recipient's
encryption key type rather than by a code point of its own.

Framing (count) codes introduced by TSP. A count gives the number of quadlets of
content that follow, and that content is parsed in turn rather than being data of the
group's own. Counts below 4096 take the short form `-X##`; larger counts take the
long form `--X#####`.

| Code   | Description                    |
|--------|--------------------------------|
| `-E##` | TSP message frame              |
| `-Z##` | TSP payload                    |
| `-J##` | TSP hop list                   |
| `-A##` | Generic CESR stream            |
| `-C##` | Attachment group               |
| `-K##` | Indexed signature group        |

TSP message format
------------------

A TSP message is a frame, its signable content, and an attached signature:

    MESSAGE ::= -E## <ENVELOPE> <BODY> <SIGNATURE>

    ENVELOPE ::= YTSP <VERSION> <VID_sndr> <VID_rcvr>
    BODY     ::= <CIPHERTEXT> | <PAYLOAD>

`YTSP` is the genus, and `VERSION` is the count code that follows it: its identifier
character carries MAJOR, and its count carries MINOR and PATCH, six bits each. The
current version is `0.0.1`, encoded `YTSP-AAB`.

`VID_rcvr` is present in every envelope. Where there is no receiver it is the NULL
VID — the empty bytes primitive, `4BAA`.

The `-E##` count covers everything the signature is computed over: the envelope and
the body, but not the signature itself. The signature is attached after the frame as
`-C##` holding a `-K##` group of indexed signatures.

An encrypted message carries a `CIPHERTEXT` whose code names the suite. A signed-only
message carries its `PAYLOAD` in the clear, in the same position.

Payload format
--------------

Decrypting a ciphertext yields a payload, which is itself a counted group:

    PAYLOAD ::= -Z## <TYPE> <VID_sndr> <Padding_Field> <FIELDS...>

`TYPE` is a four-character payload type code. `VID_sndr` repeats the sender inside the
encryption — this is the ESSR construction, and it is what binds the sender to the
plaintext rather than only to the envelope. Under the sealed box, which is anonymous,
it MUST carry the sender. Under HPKE-Base the sender is already bound through the aad,
so the sender defaults to the NULL VID `4BAA`; a sender MAY still include it, and a
receiver MUST accept either.

`Padding_Field` is a bytes primitive reserved for length hiding; it is empty unless an
upper layer asks for padding.

The payload types, and the fields each carries after the padding field:

| Type   | Name       | Fields                                                  |
|--------|------------|---------------------------------------------------------|
| `XSCS` | `TSP_GEN`  | the application payload, carried opaquely               |
| `XCTL` | `TSP_CTL`  | an upper-layer control payload, carried opaquely        |
| `XPAD` | `TSP_PAD`  | a nonce; the receiver discards the message              |
| `XHOP` | `TSP_HOP`  | a hop list `-J##`, then a complete inner TSP message    |
| `XRFI` | `TSP_RFI`  | relationship forming invite                             |
| `XRFA` | `TSP_RFA`  | relationship forming accept                             |
| `XRFD` | `TSP_RFD`  | relationship forming decline or cancel                  |

`XHOP` covers both nesting and routing: a nested message has an empty hop list, a
routed message names the intermediaries it travels through. Either way the inner
message is a complete TSP message, opaque to everyone but its own recipient — not to
the intermediary that forwards it, nor to the endpoints of the enclosing relationship.

Reading a message
-----------------

`tsp_sdk::cesr::segments` walks a message into every code and every run of data it is
built from, with the field name each has and the value it decodes to. It is a
presentation aid rather than a parser — decoding for use goes through the packet
decoder, which rejects what the walker will happily describe — but it is the same
implementation the SDK ships, so it cannot drift from the encoder.

The CLI's `--verbose` flag colours a message with it: codes bold, the data they
introduce normal, one colour per field.

Test vectors
------------

`tsp_sdk/test_vectors/rev3.json` holds worked examples of each of the shapes above:
sealed box, HPKE-Base, signed-only, the three relationship-forming messages, nested
and routed. Every vector records the identifiers with their private keys, so it can be
opened, and the key material every random value was drawn from, so the exact bytes can
be regenerated rather than only decrypted. The SDK's own tests do both, and require the
segmenter to account for every code in every vector.

Regenerate them with:

```sh
cargo run -q -p tsp_sdk --example generate_test_vectors > tsp_sdk/test_vectors/rev3.json
```

The output is byte-for-byte identical unless the wire format has changed.
