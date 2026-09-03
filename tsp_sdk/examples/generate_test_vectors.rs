//! Generate the Rev 3 test vectors.
//!
//! ```sh
//! cargo run -p tsp_sdk --example generate_test_vectors > tsp_sdk/test_vectors/rev3.json
//! ```
//!
//! Running this twice produces identical output: every random value is drawn
//! from a recorded seed, and the identifiers themselves are derived from seeds
//! too, so a verifier holding the file can regenerate each vector's bytes
//! rather than only decrypt them.
//!
//! What the vectors pin is the wire format: field order, code points, counts,
//! and the payload structure each message type carries.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;
use tsp_sdk::cesr;
use tsp_sdk::definitions::{Payload, RelationshipForm, VerifiedVid};
use tsp_sdk::vid::OwnedVid;

fn b64(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
}

/// Every VID in these vectors is a `did:peer`, whose long form embeds its own
/// document. A verifier therefore needs no resolver, no server and no network
/// to check a vector — everything it must know is in the file. `did:web` is
/// deliberately absent: it publishes no key history, so it cannot satisfy the
/// requirement in spec 2 that a VID's key state be verifiable, and spec 2.2
/// does not list it among the types suitable as VIDs.
fn peer_vid(n: u8) -> OwnedVid {
    let mut seed = [0_u8; 32];
    seed[0] = 0xA0 | n;

    OwnedVid::new_did_peer_from_seed("tsp://".parse().unwrap(), seed)
}

/// The same, with post-quantum key types. ML-DSA generates deterministically
/// from a seed by FIPS 204, and the hybrid KEM by HPKE's `DeriveKeyPair`, so a
/// post-quantum VID is as reproducible as a classical one.
fn pq_peer_vid(n: u8) -> OwnedVid {
    let mut seed = [0_u8; 32];
    seed[0] = 0xB0 | n;

    OwnedVid::new_did_peer_from_seed_with_key_types(
        "tsp://".parse().unwrap(),
        seed,
        tsp_sdk::definitions::VidSignatureKeyType::MlDsa65,
        tsp_sdk::definitions::VidEncryptionKeyType::X25519MlKem768,
    )
}

/// A stream walked into its CESR primitives by [`cesr::segments`], so the
/// breakdown a reader sees is the SDK's own rather than a hand annotation, or a
/// second walker outside the repository, that can drift.
fn segments(stream: &[u8]) -> serde_json::Value {
    json!(
        cesr::segments(stream)
            .into_iter()
            .map(|s| json!({
                "kind": match s.kind {
                    cesr::SegmentKind::Code => "code",
                    cesr::SegmentKind::Data => "data",
                    cesr::SegmentKind::Unparsed => "unparsed",
                },
                "field": s.label,
                "chars": s.text.len(),
                "text": s.text,
                "note": s.note,
                "value": s.value,
            }))
            .collect::<Vec<_>>()
    )
}

/// The payload as it stands inside the ciphertext, which is what a receiver
/// sees once it has decrypted. Reconstructed from the same inputs the message
/// was sealed with; `add` checks the length against the ciphertext, so a
/// reconstruction that did not match would not go unnoticed.
fn payload_plaintext(
    payload: &cesr::Payload<'_, &[u8], &[u8]>,
    sender_identity: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    cesr::encode_payload(payload, sender_identity, None, &mut buf).expect("encode payload");

    buf
}

/// The digest code a suite uses: the sealed box hashes with Blake2b-256,
/// HPKE-Base with SHA2-256 (spec 7.2.1).
fn digest_of(bytes: &[u8; 32], crypto_type: cesr::CryptoType) -> cesr::Digest<'_> {
    match crypto_type {
        cesr::CryptoType::SealedBox => cesr::Digest::Blake2b256(bytes),
        _ => cesr::Digest::Sha2_256(bytes),
    }
}

/// A VID as the file records it: the short form it is known by, the long form
/// that carries its document, and its keys. A reader needs all three — the
/// short form alone resolves to nothing, and without the private keys nothing
/// can be opened or regenerated.
fn described(vid: &OwnedVid) -> serde_json::Value {
    let long_form = tsp_sdk::vid::introduction_identifier(vid.vid());

    // everything after the second colon of the long form is the document,
    // base58btc of the JSON behind a multicodec prefix; decoding it is what a
    // reader would do to check that the short form is its hash
    let document = long_form
        .split(':')
        .nth(3)
        .and_then(|encoded| encoded.strip_prefix('z'))
        .and_then(|body| {
            bs58::decode(body)
                .with_alphabet(bs58::Alphabet::BITCOIN)
                .into_vec()
                .ok()
        })
        .and_then(|bytes| {
            // strip the multicodec identifier for JSON, varint 0x0200
            let json = bytes.strip_prefix(&[0x80, 0x04])?.to_vec();
            serde_json::from_slice::<serde_json::Value>(&json).ok()
        });

    let mut value = serde_json::to_value(vid).expect("VID serializes");
    value["idLongForm"] = json!(long_form);
    value["document"] = json!(document);

    value
}

/// The ephemeral key a seeded message drew, recovered by replaying the seed.
///
/// Publishing this rather than the seed is what makes a vector reproducible by
/// an implementation other than this one: a seed is only meaningful to the
/// generator that consumed it, whereas an ephemeral secret is a key any
/// implementation can use — which is why RFC 9180 publishes `skEm` for its own
/// HPKE vectors rather than a seed.
///
/// Both schemes place the ephemeral public key at the front of the ciphertext,
/// so the derivation is checked against the message itself: a mismatch means
/// the RNG was consumed in some other order and nothing is published.
fn ephemeral_key(seed: [u8; 32], message: &[u8]) -> Option<serde_json::Value> {
    use hpke::{Serializable, kem::Kem};
    use rand::{RngCore, SeedableRng};

    let mut rng = rand::rngs::StdRng::from_seed(seed);
    let mut drawn = [0_u8; 32];
    rng.fill_bytes(&mut drawn);

    let parts = cesr::open_message_into_parts(message).ok()?;
    let on_the_wire = parts.ciphertext?.data.get(..32)?.to_vec();

    match parts.crypto_type {
        // the sealed box draws the ephemeral secret directly
        cesr::CryptoType::SealedBox => {
            let public = crypto_box::PublicKey::from(&crypto_box::SecretKey::from(drawn));
            (public.to_bytes()[..] == on_the_wire[..]).then(|| {
                json!({
                    "kind": "ephemeral X25519 secret",
                    "secret": b64(&drawn),
                    "public": b64(&public.to_bytes()),
                })
            })
        }
        // HPKE over X25519 draws keying material and derives the keypair from
        // it, which is the ikmE that RFC 9180 publishes for its own vectors.
        //
        // The post-quantum hybrid KEM works differently: it derives no
        // ephemeral keypair at all, drawing 64 bytes of encapsulation
        // randomness and feeding them to a deterministic encapsulation whose
        // entry point the hpke crate does not expose. Nothing here can then be
        // checked against the wire, and an unverified value is not worth
        // publishing — so that vector carries its seed alone, and
        // `every_vector_regenerates_from_what_the_file_records` is what
        // establishes that its bytes reproduce.
        cesr::CryptoType::HpkeBase => {
            let (_, public) = hpke::kem::X25519HkdfSha256::derive_keypair(&drawn);
            (public.to_bytes()[..] == on_the_wire[..]).then(|| {
                json!({
                    "kind": "ikmE, the HPKE encapsulation keying material",
                    "ikmE": b64(&drawn),
                    "public": b64(&public.to_bytes()),
                })
            })
        }
        cesr::CryptoType::Plaintext => None,
    }
}

fn main() {
    let alice = peer_vid(1);
    let bob = peer_vid(2);
    // the private VIDs a nested relationship runs over
    let nested_alice = peer_vid(3);
    let nested_bob = peer_vid(4);
    // the intermediaries a routed message traverses
    let p = peer_vid(5);
    let q = peer_vid(6);
    // post-quantum endpoints: the same HPKE-Base mode, a different KEM
    let pq_alice = pq_peer_vid(1);
    let pq_bob = pq_peer_vid(2);

    // one fixed seed per vector, so the file records every random value the
    // message drew and a verifier can regenerate the bytes exactly
    fn seed(n: u8) -> [u8; 32] {
        let mut seed = [0_u8; 32];
        seed[0] = n;
        seed
    }
    const NONCE: [u8; 16] = [0x11; 16];

    let mut vectors = Vec::new();
    let mut add = |name: &str,
                   spec: &str,
                   description: &str,
                   sender: &str,
                   receiver: Option<&str>,
                   message: &[u8],
                   plaintext: Vec<u8>,
                   inner: Option<(&[u8], Vec<u8>)>,
                   seed_used: Option<u8>,
                   nonce_used: Option<&str>,
                   layout: Vec<&str>,
                   expect: serde_json::Value| {
        // A ciphertext is the encoded payload plus the scheme's encapsulation
        // and a 16-byte AEAD tag. The sealed box and HPKE over X25519 both
        // prepend 32 bytes; the post-quantum hybrid KEM prepends 1120. Checking
        // the length here means a wrong reconstruction shows up now rather than
        // silently on the page.
        const X25519_OVERHEAD: usize = 32 + 16;
        const HYBRID_KEM_OVERHEAD: usize = 1120 + 16;
        let parts = cesr::open_message_into_parts(message).expect("message parses");
        if let Some(ct) = parts.ciphertext {
            match parts.crypto_type {
                // a signed-only message carries its payload in the clear, and
                // the -Z## code is the part's own prefix rather than data
                cesr::CryptoType::Plaintext => assert_eq!(
                    ct.prefix.len() + ct.data.len(),
                    plaintext.len(),
                    "{name}: reconstructed plaintext does not match the payload on the wire"
                ),
                _ => {
                    let overhead = ct.data.len() - plaintext.len();
                    assert!(
                        overhead == X25519_OVERHEAD || overhead == HYBRID_KEM_OVERHEAD,
                        "{name}: reconstructed plaintext does not match the payload on the wire \
                         (ciphertext is {overhead} bytes longer, expected {X25519_OVERHEAD} or \
                         {HYBRID_KEM_OVERHEAD})"
                    );
                }
            }
        }

        vectors.push(json!({
            "name": name,
            "spec": spec,
            "description": description,
            "sender": sender,
            "receiver": receiver,
            "message": b64(message),
            "segments": segments(message),
            "payload_plaintext": b64(&plaintext),
            "payload_segments": segments(&plaintext),
            // for a nested or routed message, the payload of the message
            // carried inside: without it the inner ciphertext stays opaque and
            // the content the vector actually conveys cannot be seen
            "inner": inner.map(|(message, plaintext)| {
                let parts = cesr::open_message_into_parts(message).expect("inner parses");
                if let Some(ct) = parts.ciphertext {
                    assert_eq!(
                        ct.data.len(),
                        plaintext.len() + 48,
                        "{name}: reconstructed inner plaintext does not match its ciphertext"
                    );
                }
                json!({
                    "payload_plaintext": b64(&plaintext),
                    "payload_segments": segments(&plaintext),
                })
            }),
            "seed": seed_used.map(|n| b64(&seed(n))),
            "ephemeral": seed_used.and_then(|n| ephemeral_key(seed(n), message)),
            "nonce": nonce_used,
            "layout": layout,
            "expect": expect,
        }));
    };

    // 1. sealed box, application payload
    let m = tsp_sdk::crypto::seal_reproducibly(
        &alice,
        &bob,
        Payload::Content(b"hello world"),
        None,
        cesr::CryptoType::SealedBox,
        seed(1),
        None,
    )
    .unwrap();
    add(
        "direct-sealed-box",
        "8.3, 9.1, 9.2.8, 9.5",
        "A confidential application message under the libsodium anonymous sealed box. \
         The sender's static keys play no part in the encryption, so sender authenticity \
         rests on the ESSR sender VID inside the payload, which this suite requires, \
         together with the outer signature.",
        "alice",
        Some("bob"),
        &m,
        payload_plaintext(
            &cesr::Payload::GenericMessage(&b"hello world"[..]),
            Some(alice.identifier().as_bytes()),
        ),
        None,
        Some(1),
        None,
        vec![
            "-Z##",
            "XSCS",
            "VID_sndr | 4BAA",
            "Padding_Field",
            "-A##",
            "Bytes",
        ],
        json!({"crypto": "SealedBox", "signature": "Ed25519", "payload": {"content": "hello world"}}),
    );

    // 2. HPKE-Base, application payload
    let m = tsp_sdk::crypto::seal_reproducibly(
        &alice,
        &bob,
        Payload::Content(b"hello world"),
        None,
        cesr::CryptoType::HpkeBase,
        seed(2),
        None,
    )
    .unwrap();
    add(
        "direct-hpke-base",
        "8.2, 9.1, 9.2.8",
        "The same message under HPKE-Base. The aad is CONCAT(TSP_Version, VID_sndr, VID_rcvr), \
         which is exactly the envelope preceding the ciphertext; info is the five bytes YTSP-. \
         The ciphertext field is enc followed by ct, with the AEAD tag inside ct.",
        "alice",
        Some("bob"),
        &m,
        payload_plaintext(
            &cesr::Payload::GenericMessage(&b"hello world"[..]),
            // NULL by default under HPKE-Base: the aad already binds the sender
            None,
        ),
        None,
        Some(2),
        None,
        vec![
            "-Z##",
            "XSCS",
            "VID_sndr | 4BAA",
            "Padding_Field",
            "-A##",
            "Bytes",
        ],
        json!({"crypto": "HpkeBase", "signature": "Ed25519", "payload": {"content": "hello world"}}),
    );

    // 3. signed-only
    let m = tsp_sdk::crypto::sign(&alice, Some(&bob), b"public announcement!").unwrap();
    add(
        "direct-signed-only",
        "3.5, 9.1",
        "A non-confidential message. The payload sits in the payload position in the clear, \
         under the same -Z## framing a confidential payload uses once decrypted; there is no \
         separate non-confidential field.",
        "alice",
        Some("bob"),
        &m,
        payload_plaintext(
            &cesr::Payload::GenericMessage(&b"public announcement!"[..]),
            None,
        ),
        None,
        None,
        None,
        vec![
            "-Z##",
            "XSCS",
            "VID_sndr | 4BAA",
            "Padding_Field",
            "-A##",
            "Bytes",
        ],
        json!({"crypto": "Plaintext", "signature": "Ed25519", "payload": {"content": "public announcement!"}}),
    );

    // 4. relationship request, carrying its own SAID
    let mut request_digest = [0_u8; 32];
    let m = tsp_sdk::crypto::seal_reproducibly(
        &alice,
        &bob,
        Payload::RequestRelationship {
            thread_id: Default::default(),
            reply_path: vec![],
            form: RelationshipForm::Direct,
        },
        Some(&mut request_digest),
        cesr::CryptoType::HpkeBase,
        seed(8),
        Some(NONCE),
    )
    .unwrap();
    add(
        "control-rfi-direct",
        "7.2.1, 7.2.2, 9.4.1",
        "A TSP_RFI. Its Digest is the message's own self-addressing identifier: computed over \
         the version, both envelope VIDs and the payload fields, with the digest's own slot \
         filled with the 0x23 dummy and the padding field excluded. A direct invite has an \
         empty Reply_Path and an empty Referral_Field, both -JAA.",
        "alice",
        Some("bob"),
        &m,
        payload_plaintext(
            &cesr::Payload::RelationProposal {
                request_digest: digest_of(&request_digest, cesr::CryptoType::HpkeBase),
                nonce: cesr::Nonce::generate(|dst| *dst = NONCE),
                reply_path: vec![],
                referral: None,
            },
            None,
        ),
        None,
        Some(8),
        Some(&b64(&NONCE)),
        vec![
            "-Z##",
            "XRFI",
            "VID_sndr | 4BAA",
            "Digest",
            "Nonce",
            "Reply_Path",
            "Referral_Field",
            "Padding_Field",
        ],
        json!({
            "crypto": "HpkeBase",
            "payload": {"request_relationship": {"thread_id": b64(&request_digest), "reply_path": [], "referral": null}}
        }),
    );

    // 5. relationship accept, echoing that digest and carrying its own
    let mut reply_digest = [0_u8; 32];
    let m = tsp_sdk::crypto::seal_reproducibly(
        &bob,
        &alice,
        Payload::AcceptRelationship {
            thread_id: request_digest,
            reply_thread_id: Default::default(),
            form: RelationshipForm::Direct,
        },
        Some(&mut reply_digest),
        cesr::CryptoType::HpkeBase,
        seed(9),
        Some(NONCE),
    )
    .unwrap();
    add(
        "control-rfa-direct",
        "7.2.2, 9.4.2",
        "A TSP_RFA. The Digest is copied verbatim from the invite it answers; the Reply_Digest \
         is this message's own SAID, derived the same way. The two digests are what identify \
         the two directions of the relationship thereafter.",
        "bob",
        Some("alice"),
        &m,
        payload_plaintext(
            &cesr::Payload::RelationAffirm {
                request_digest: digest_of(&request_digest, cesr::CryptoType::HpkeBase),
                reply_digest: digest_of(&reply_digest, cesr::CryptoType::HpkeBase),
            },
            None,
        ),
        None,
        Some(9),
        Some(&b64(&NONCE)),
        vec![
            "-Z##",
            "XRFA",
            "VID_sndr | 4BAA",
            "Digest",
            "Reply_Digest",
            "Padding_Field",
        ],
        json!({
            "crypto": "HpkeBase",
            "payload": {"accept_relationship": {"thread_id": b64(&request_digest), "reply_thread_id": b64(&reply_digest)}}
        }),
    );

    // 6. relationship cancel
    let m = tsp_sdk::crypto::seal_reproducibly(
        &alice,
        &bob,
        Payload::CancelRelationship {
            thread_id: request_digest,
        },
        None,
        cesr::CryptoType::HpkeBase,
        seed(3),
        None,
    )
    .unwrap();
    add(
        "control-rfd",
        "7.3, 9.4.5",
        "A TSP_RFD. It carries one digest, naming the relationship being cancelled, and no \
         nonce: the nonce this message once had was removed, since a cancellation needs no \
         freshness of its own.",
        "alice",
        Some("bob"),
        &m,
        payload_plaintext(
            &cesr::Payload::RelationshipCancel {
                reply: digest_of(&request_digest, cesr::CryptoType::HpkeBase),
            },
            None,
        ),
        None,
        Some(3),
        None,
        vec!["-Z##", "XRFD", "VID_sndr | 4BAA", "Digest", "Padding_Field"],
        json!({"crypto": "HpkeBase", "payload": {"cancel_relationship": {"thread_id": b64(&request_digest)}}}),
    );

    // 6b. the same invite under the sealed box, which the specification keeps
    // for existing implementations. Its payload rules differ from HPKE-Base in
    // two ways that nothing else in these vectors exercises: the digest is
    // Blake2b-256 rather than SHA2-256, and VID_sndr MUST be carried in the
    // payload because the construction is anonymous.
    let mut sealed_request_digest = [0_u8; 32];
    let m = tsp_sdk::crypto::seal_reproducibly(
        &alice,
        &bob,
        Payload::RequestRelationship {
            thread_id: Default::default(),
            reply_path: vec![],
            form: RelationshipForm::Direct,
        },
        Some(&mut sealed_request_digest),
        cesr::CryptoType::SealedBox,
        seed(10),
        Some(NONCE),
    )
    .unwrap();
    add(
        "control-rfi-sealed-box",
        "7.2.1, 8, 9.4.1",
        "A TSP_RFI under the libsodium sealed box, the suite the specification keeps only for \
         existing implementations. Two payload rules differ from HPKE-Base: the Digest is \
         Blake2b-256, whose CESR code is F rather than I, and VID_sndr MUST carry the sender \
         because the sealed box is anonymous, where HPKE-Base defaults it to the NULL VID.",
        "alice",
        Some("bob"),
        &m,
        payload_plaintext(
            &cesr::Payload::RelationProposal {
                request_digest: digest_of(&sealed_request_digest, cesr::CryptoType::SealedBox),
                nonce: cesr::Nonce::generate(|dst| *dst = NONCE),
                reply_path: vec![],
                referral: None,
            },
            Some(alice.identifier().as_bytes()),
        ),
        None,
        Some(10),
        Some(&b64(&NONCE)),
        vec![
            "-Z##",
            "XRFI",
            "VID_sndr",
            "Digest",
            "Nonce",
            "Reply_Path",
            "Referral_Field",
            "Padding_Field",
        ],
        json!({
            "crypto": "SealedBox",
            "payload": {"request_relationship": {"thread_id": b64(&sealed_request_digest), "reply_path": [], "referral": null}}
        }),
    );

    // 7. nested message: an XHOP payload wrapping a complete inner TSP message
    let inner = tsp_sdk::crypto::seal_reproducibly(
        &nested_alice,
        nested_bob.vid(),
        Payload::Content(b"hello world"),
        None,
        cesr::CryptoType::HpkeBase,
        seed(4),
        None,
    )
    .unwrap();
    let m = tsp_sdk::crypto::seal_reproducibly(
        &alice,
        &bob,
        Payload::NestedMessage(&inner),
        None,
        cesr::CryptoType::HpkeBase,
        seed(5),
        None,
    )
    .unwrap();
    add(
        "nested-direct",
        "4, 9.4.15",
        "A nested message. The outer payload is XHOP: sender VID, an empty hop list -JAA \
         because the outer relationship is direct, a padding field, then a complete inner TSP \
         message with its own envelope, payload and signature. The inner VIDs are did:peer \
         short forms, 57 characters each, which is what the two endpoints use once they have \
         exchanged the long form that carries the document.",
        "alice",
        Some("bob"),
        &m,
        payload_plaintext(&cesr::Payload::NestedMessage(&inner[..]), None),
        Some((
            &inner,
            payload_plaintext(&cesr::Payload::GenericMessage(&b"hello world"[..]), None),
        )),
        Some(5),
        None,
        vec![
            "-Z##",
            "XHOP",
            "VID_sndr | 4BAA",
            "-JAA",
            "Padding_Field",
            "Encoded_TSP_Message",
        ],
        json!({
            "crypto": "HpkeBase",
            "payload": {"nested": {"inner_sender": nested_alice.identifier(), "inner_receiver": nested_bob.identifier(), "inner_content": "hello world"}}
        }),
    );

    // 8. routed message: the endpoint-to-endpoint message inside an XHOP
    // payload whose hop list names the rest of the path
    let e2e = tsp_sdk::crypto::seal_reproducibly(
        &nested_alice,
        nested_bob.vid(),
        Payload::Content(b"hello world"),
        None,
        cesr::CryptoType::HpkeBase,
        seed(6),
        None,
    )
    .unwrap();
    let hops: Vec<&[u8]> = vec![
        q.identifier().as_bytes(),
        nested_bob.identifier().as_bytes(),
    ];
    let m = tsp_sdk::crypto::seal_reproducibly(
        &alice,
        p.vid(),
        Payload::RoutedMessage(hops, &e2e),
        None,
        cesr::CryptoType::HpkeBase,
        seed(7),
        None,
    )
    .unwrap();
    add(
        "routed",
        "5.2, 5.3.3, 9.4.16",
        "A routed message. The outer message goes to the first intermediary, and its XHOP \
         payload carries the rest of the path as a hop list followed by the complete \
         endpoint-to-endpoint message. The last entry of the hop list is the destination's own \
         VID at its intermediary, not the intermediary's VID; the list shrinks by one at each \
         hop. The hop list count is the byte length of the concatenated VIDs, not the number \
         of them.",
        "alice",
        Some("p"),
        &m,
        payload_plaintext(
            &cesr::Payload::RoutedMessage(
                vec![
                    q.identifier().as_bytes(),
                    nested_bob.identifier().as_bytes(),
                ],
                &e2e[..],
            ),
            None,
        ),
        Some((
            &e2e,
            payload_plaintext(&cesr::Payload::GenericMessage(&b"hello world"[..]), None),
        )),
        Some(7),
        None,
        vec![
            "-Z##",
            "XHOP",
            "VID_sndr | 4BAA",
            "-J##",
            "VID_1",
            "...",
            "Padding_Field",
            "Encoded_TSP_Message",
        ],
        json!({
            "crypto": "HpkeBase",
            "payload": {"routed": {
                "hops": [q.identifier(), nested_bob.identifier()],
                "inner_sender": nested_alice.identifier(),
                "inner_receiver": nested_bob.identifier(),
                "inner_content": "hello world"
            }}
        }),
    );

    // 9. the same HPKE-Base message with post-quantum keys. Last, so that
    // a reader meets every classical vector before the one whose keys and
    // signature are an order of magnitude larger.
    let m = tsp_sdk::crypto::seal_reproducibly(
        &pq_alice,
        &pq_bob,
        Payload::Content(b"hello world"),
        None,
        cesr::CryptoType::HpkeBase,
        seed(11),
        None,
    )
    .unwrap();
    add(
        "direct-hpke-base-pq",
        "8.2, 8.3, 9.2.8",
        "The same message as direct-hpke-base, to endpoints whose VIDs declare post-quantum \
         key types. Post-quantum support is not a separate mode: this is HPKE-Base with the \
         X25519MLKEM768 hybrid KEM, selected by the recipient VID's encryption key type, and \
         the ciphertext code is the same 4F as any other HPKE-Base message. What changes is \
         size — the encapsulation is 1120 bytes rather than 32 — and the signature, which is \
         ML-DSA-65 under the code 1AAQ rather than an indexed Ed25519 signature. There is no \
         sealed-box counterpart to this vector; that suite has no post-quantum option. This is \
         the one vector with no published ephemeral value: the hybrid KEM derives no ephemeral \
         keypair, drawing encapsulation randomness instead, so there is nothing of that shape to \
         publish and check. Its bytes reproduce from the recorded seed.",
        "pq_alice",
        Some("pq_bob"),
        &m,
        payload_plaintext(&cesr::Payload::GenericMessage(&b"hello world"[..]), None),
        None,
        Some(11),
        None,
        vec![
            "-Z##",
            "XSCS",
            "VID_sndr | 4BAA",
            "Padding_Field",
            "-A##",
            "Bytes",
        ],
        json!({"crypto": "HpkeBase", "signature": "MlDsa65", "payload": {"content": "hello world"}}),
    );

    let doc = json!({
        "tsp_version": "0.1.0",
        "generated_by": "cargo run -p tsp_sdk --example generate_test_vectors",
        "note": "Every value a message depends on is recorded here: the identifiers with their \
                 private keys, the seed each random value was drawn from, and the nonce where one \
                 applies. A verifier can therefore regenerate the exact bytes of a vector, not \
                 only decrypt them. Regenerate with the command in generated_by; the output is \
                 byte-for-byte identical.",
        "vids": {
            "alice": described(&alice),
            "bob": described(&bob),
            "nested_alice": described(&nested_alice),
            "nested_bob": described(&nested_bob),
            "p": described(&p),
            "q": described(&q),
            "pq_alice": described(&pq_alice),
            "pq_bob": described(&pq_bob),
        },
        "vectors": vectors,
    });

    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
