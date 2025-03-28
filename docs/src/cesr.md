TSP CESR Encoding
=================

CESR Code Tables
----------------
Codes used by TSP that are already in the CESR draft:

| Code | Description        | Code Length | Count Length | Total Length |
|------|--------------------|-------------|--------------|--------------|
| I    | SHA-256 Digest     |             | 1            | 44           |
| F    | Blake2b256 Digest	|             | 1            | 44           |
| 0A   | 128 bit Nonce      |             | 2            | 24           |
| 0B   | Ed25519 signature	|             | 2            | 88           |

Fixed-length codes introduced by TSP:

| Code | Description | Code Length | Count Length | Total Length |
|------|-------------|-------------|--------------|--------------|
| X    | Type code   |             | 1            | 4            |

Variable-length codes introduces by TSP (note: this just introduces the code "B", "C" and "VID", the length of the table
below is caused by the regular CESR encoding scheme for variable length codes).

The type for "VID" is temporary, pending a decision on how to choose/encode VID types; but the code for "VID" dictates
that only a "large" encoding is available. For non-post-quantum, non-`did:peer` VID's, a shorter encoding will usually
suffice.

| Code | Description                      | Code Length | Count Length | Total Length |
|------|----------------------------------|-------------|--------------|--------------|
| 4B   | TSP Plaintext Lead Size 0        | 4           | 2            |              |
| 5B   | TSP Plaintext Lead Size 1        | 4           | 2            |              |
| 6B   | TSP Plaintext Lead Size 2        | 4           | 2            |              |
| 7AAB | TSP Large Plaintext Lead Size 0  | 8           | 4            |              |
| 8AAB | TSP Large Plaintext Lead Size 1  | 8           | 4            |              |
| 9AAB | TSP Large Plaintext Lead Size 2  | 8           | 4            |              |
| 4C   | TSP Ciphertext Lead Size 0       | 4           | 2            |              |
| 5C   | TSP Ciphertext Lead Size 1       | 4           | 2            |              |
| 6C   | TSP Ciphertext Lead Size 2       | 4           | 2            |              |
| 7AAC | TSP Large Ciphertext Lead Size 0 | 8           | 4            |              |
| 8AAC | TSP Large Ciphertext Lead Size 1 | 8           | 4            |              |
| 9AAC | TSP Large Ciphertext Lead Size 2 | 8           | 4            |              |
| 7VID | TSP Verifiable ID Lead Size 0    | 8           | 4            |              |
| 8VID | TSP Verifiable ID Lead Size 1    | 8           | 4            |              |
| 9VID | TSP Verifiable ID Lead Size 2    | 8           | 4            |              |

Framing codes introduces by TSP:

| Code | Description                 | Code Length | Count Length | Total Length |
|------|-----------------------------|-------------|--------------|--------------|
| -E## | TSP Encrypt&Signed Envelope | 4           | 2            | 4            |
| -S## | TSP Signed-Only Envelope    | 4           | 2            | 4            |
| -I## | TSP Hop List                | 4           | 2            | 4            |
| -Z## | TSP Payload                 | 4           | 2            | 4            |

TSP Message format
------------------
An encrypted TSP message is encoded as:

	<ETS-ENVELOPE> <TSP-CIPHERTEXT> <SIGNATURE> 

a non-encrypted TSP message is encoded as:

    <S-ENVELOPE> <TSP-PLAINTEXT> <SIGNATURE>

where,

    ETS-ENVELOPE ::= -E01 Xvvv Xttt <SENDER-VID> <RECEIVER-VID> <OPTIONAL:TSP-PLAINTEXT>
    S-ENVELOPE   ::= -S01 Xvvv Xttt <SENDER-VID> <OPTIONAL:RECEIVER-VID>

vvv contains the two-byte "major.minor" version of TSP (currently "0.0").
ttt contains a two-byte "encryption `scheme.signature` scheme" type indicator:

encryption scheme\
0 — Unencrypted (for "S" envelopes" only)\
1 — HPKE in Auth mode\
2 — HPKE in Base mode with ESSR\
3 — Libsodium in Auth mode\
4 — Libsodium in ESSR mode

Specifying an encryption scheme in an "S" envelope is technically an error (since there will be no ciphertext anyway)

signature scheme\
0 — Unsigned (Reserved for future use)\
1 — Ed25519

A `TSP-CIPHERTEXT` must, after successful decryption, have one of the two encodings:

    AUTH-PAYLOAD ::= -Z01 Xppp <PAYLOAD>
    ESSR-PAYLOAD ::= -Z02 <SENDER-VID> Xppp <PAYLOAD>

where ppp contains a two-byte "type.subtype" indicator of the control fields present in the
payload, which currently are:

| type.subtype | description        | `PAYLOAD` (after decrypting)                                                                                                                                                       |
|--------------|--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0.0          | generic message    | `<TSP-PLAINTEXT>` for direct, <br> `-I## <VID> <VID>... <TSP-PLAINTEXT>` for routed, with the plaintext holding the tsp message                                                    |
| 0.1          | nested message     | `<TSP-PLAINTEXT>` <br> the plaintext holds a (signed, or signed-and-encrypted) TSP message                                                                                         |
| 0.1          | routed message     |                                                                                                                                                                                    |
| 1.0          | NEW_REL            | `<NONCE>`                                                                                                                                                                          |
| 1.1          | NEW_REL_REPLY      | `<DIGEST>`                                                                                                                                                                         |
| 1.2          | NEW_NEST_REL       | `<TSP-PLAINTEXT> <NONCE>` <br> the plaintext holds a signed-only TSP message where the sender field has the new nested VID, and an empty receiver                                  |
| 1.3          | NEW_NEST_REL_REPLY | `<TSP-PLAINTEXT> <DIGEST>` <br> the plaintext holds a signed-only TSP message where the sender field has the new nested VID, and the receiver is the nested VID of the other party |
| 1.4          | NEW_REFER_REL      | `<DIGEST>` `<VID>`                                                                                                                                                                 |
| 1.5          | 3P_REFER_REL       | `<VID>`                                                                                                                                                                            |
| 1.255        | REL_CANCEL         | `<DIGEST>`                                                                                                                                                                         |
