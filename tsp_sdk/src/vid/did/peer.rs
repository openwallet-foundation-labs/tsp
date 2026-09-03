use crate::definitions::{VidEncryptionKeyType, VidSignatureKeyType};
use crate::{Vid, definitions::VerifiedVid, vid::error::VidError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "async")]
use tracing::log::trace;
use url::Url;

pub(crate) const SCHEME: &str = "peer";

/// The service type TSP publishes its transport under
const TSP_SERVICE_TYPE: &str = "tsp";

/// Multicodec identifier for JSON, as an unsigned varint of the value 0x0200
const MULTICODEC_JSON: [u8; 2] = [0x80, 0x04];

/// Multihash prefix for SHA2-256 (0x12) at 32 bytes (0x20)
const MULTIHASH_SHA2_256: [u8; 2] = [0x12, 0x20];

/// The "Input Document" of a `did:peer:4` (did:peer method spec, Method 4): a
/// DID document with no `id` at the root and only relative references, from
/// which both forms of the identifier are derived.
///
/// The field order here is the serialized order, and the serialized bytes are
/// what the identifier hashes over, so this declaration fixes the identifier a
/// given key pair produces. Do not reorder it.
#[derive(Serialize, Deserialize)]
struct InputDocument {
    #[serde(rename = "@context")]
    context: String,
    #[serde(rename = "verificationMethod")]
    verification_method: Vec<VerificationMethod>,
    authentication: Vec<String>,
    #[serde(rename = "keyAgreement")]
    key_agreement: Vec<String>,
    service: Vec<Service>,
}

#[derive(Serialize, Deserialize)]
struct VerificationMethod {
    id: String,
    #[serde(rename = "type")]
    key_type: String,
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: String,
}

#[derive(Serialize, Deserialize)]
struct Service {
    id: String,
    #[serde(rename = "type")]
    service_type: String,
    #[serde(rename = "serviceEndpoint")]
    service_endpoint: ServiceEndpoint,
}

#[derive(Serialize, Deserialize)]
struct ServiceEndpoint {
    uri: String,
}

const SIGNING_KEY_REF: &str = "#key-1";
const ENCRYPTION_KEY_REF: &str = "#key-2";

fn base58btc(bytes: &[u8]) -> String {
    format!(
        "z{}",
        bs58::encode(bytes)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string()
    )
}

fn decode_base58btc(value: &str) -> Result<Vec<u8>, VidError> {
    let Some(body) = value.strip_prefix('z') else {
        return Err(VidError::ResolveVid("did:peer value is not base58btc"));
    };

    bs58::decode(body)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|_| VidError::ResolveVid("invalid base58btc value in did:peer"))
}

fn signature_key_multicodec(key_type: VidSignatureKeyType) -> &'static [u8] {
    match key_type {
        // ed25519-pub
        VidSignatureKeyType::Ed25519 => &[0xed, 0x01],
        // private use area (0x300001), as an unsigned varint
        VidSignatureKeyType::MlDsa65 => &[0x81, 0x80, 0xc0, 0x01],
    }
}

fn encryption_key_multicodec(key_type: VidEncryptionKeyType) -> &'static [u8] {
    match key_type {
        // x25519-pub
        VidEncryptionKeyType::X25519 => &[0xec, 0x01],
        // private use area (0x300000), as an unsigned varint
        VidEncryptionKeyType::X25519MlKem768 => &[0x80, 0x80, 0xc0, 0x01],
    }
}

fn multikey(multicodec: &[u8], key: &[u8]) -> String {
    let mut buf = Vec::with_capacity(multicodec.len() + key.len());
    buf.extend_from_slice(multicodec);
    buf.extend_from_slice(key);

    base58btc(&buf)
}

fn split_multikey<'a>(
    decoded: &'a [u8],
    multicodec: &[u8],
    expected_len: usize,
) -> Option<&'a [u8]> {
    decoded
        .strip_prefix(multicodec)
        .filter(|key| key.len() == expected_len)
}

fn input_document(vid: &dyn VerifiedVid) -> InputDocument {
    InputDocument {
        context: "https://www.w3.org/ns/did/v1".to_string(),
        verification_method: vec![
            VerificationMethod {
                id: SIGNING_KEY_REF.to_string(),
                key_type: "Multikey".to_string(),
                public_key_multibase: multikey(
                    signature_key_multicodec(vid.signature_key_type()),
                    vid.verifying_key().as_ref(),
                ),
            },
            VerificationMethod {
                id: ENCRYPTION_KEY_REF.to_string(),
                key_type: "Multikey".to_string(),
                public_key_multibase: multikey(
                    encryption_key_multicodec(vid.encryption_key_type()),
                    vid.encryption_key().as_ref(),
                ),
            },
        ],
        authentication: vec![SIGNING_KEY_REF.to_string()],
        key_agreement: vec![ENCRYPTION_KEY_REF.to_string()],
        service: vec![Service {
            id: "#tsp".to_string(),
            service_type: TSP_SERVICE_TYPE.to_string(),
            service_endpoint: ServiceEndpoint {
                uri: vid.endpoint().to_string(),
            },
        }],
    }
}

/// The `encoded document` of a `did:peer:4`: the Input Document as JSON with no
/// whitespace, prefixed with the multicodec identifier for JSON and encoded as
/// base58btc.
fn encode_document(document: &InputDocument) -> Result<String, VidError> {
    let json = serde_json::to_vec(document)
        .map_err(|_| VidError::ResolveVid("could not encode a did:peer document"))?;

    let mut buf = Vec::with_capacity(MULTICODEC_JSON.len() + json.len());
    buf.extend_from_slice(&MULTICODEC_JSON);
    buf.extend_from_slice(&json);

    Ok(base58btc(&buf))
}

/// The `hash` of a `did:peer:4`: SHA2-256 over the encoded document as it
/// stands, as a base58btc multihash.
fn hash_document(encoded_document: &str) -> String {
    let digest = Sha256::digest(encoded_document.as_bytes());

    let mut buf = Vec::with_capacity(MULTIHASH_SHA2_256.len() + digest.len());
    buf.extend_from_slice(&MULTIHASH_SHA2_256);
    buf.extend_from_slice(&digest);

    base58btc(&buf)
}

/// Encode a VID as the long form of a `did:peer:4`, which embeds the whole
/// document and so can be verified by a receiver that has never seen it.
///
/// A VID is introduced in this form once; thereafter it is referred to by
/// [`encode_did_peer`], its short form. See <https://identity.foundation/peer-did-method-spec/>
pub fn encode_did_peer_long_form(vid: &dyn VerifiedVid) -> String {
    let Ok(encoded_document) = encode_document(&input_document(vid)) else {
        return String::new();
    };
    let hash = hash_document(&encoded_document);

    format!("did:peer:4{hash}:{encoded_document}")
}

/// Encode a VID as the short form of a `did:peer:4`: the hash of its document,
/// without the document. This is a VID's identity; it is resolvable only by an
/// endpoint that has already seen the long form.
pub fn encode_did_peer(vid: &dyn VerifiedVid) -> String {
    let Ok(encoded_document) = encode_document(&input_document(vid)) else {
        return String::new();
    };

    format!("did:peer:4{}", hash_document(&encoded_document))
}

/// The short form of a `did:peer:4` long form, or `None` if this is not one.
pub fn short_form(identifier: &str) -> Option<String> {
    match identifier.split(':').collect::<Vec<_>>()[..] {
        ["did", SCHEME, hash, _document] if hash.starts_with('4') => {
            Some(format!("did:peer:{hash}"))
        }
        _ => None,
    }
}

/// The form of a VID's identifier to put on the wire when introducing it: a
/// `did:peer` is introduced in long form, since its short form cannot be
/// resolved by an endpoint that has not seen it. Every other VID type is
/// resolvable by its identifier, so that is what it uses.
pub fn introduction_identifier(vid: &dyn VerifiedVid) -> String {
    if vid.identifier().starts_with("did:peer:") {
        encode_did_peer_long_form(vid)
    } else {
        vid.identifier().to_string()
    }
}

/// Resolve a `did:peer:4`. Only the long form carries the document, so only the
/// long form can be resolved on its own; the returned VID is identified by its
/// short form, which is what the two endpoints use thereafter.
pub fn verify_did_peer(parts: &[&str]) -> Result<Vid, VidError> {
    let Some(hash) = parts[2].strip_prefix('4') else {
        return Err(VidError::ResolveVid(
            "only numalgo 4 is supported for did:peer",
        ));
    };

    let Some(encoded_document) = parts.get(3) else {
        return Err(VidError::ResolveVid(
            "a short form did:peer:4 cannot be resolved on its own; the long form must be known",
        ));
    };

    if parts.len() > 4 {
        return Err(VidError::ResolveVid("trailing data in did:peer"));
    }

    // the identifier commits to its own document (did:peer method spec,
    // Method 4, "Resolving a DID"), so recomputing the hash both verifies the
    // document and is what makes the short form usable in its place
    if hash_document(encoded_document) != hash {
        return Err(VidError::ResolveVid(
            "did:peer:4 document does not match its hash",
        ));
    }

    let decoded = decode_base58btc(encoded_document)?;
    let Some(json) = decoded.strip_prefix(&MULTICODEC_JSON) else {
        return Err(VidError::ResolveVid("did:peer:4 document is not JSON"));
    };

    let document: InputDocument = serde_json::from_slice(json)
        .map_err(|_| VidError::ResolveVid("invalid did:peer:4 document"))?;

    let mut public_sigkey = None;
    let mut sig_key_type = None;
    let mut public_enckey = None;
    let mut enc_key_type = None;

    for method in &document.verification_method {
        let decoded = decode_base58btc(&method.public_key_multibase)?;

        if document.authentication.contains(&method.id) {
            if let Some(key) = split_multikey(
                &decoded,
                signature_key_multicodec(VidSignatureKeyType::Ed25519),
                32,
            ) {
                #[cfg(feature = "async")]
                trace!("found Ed25519 signature key");
                public_sigkey = Some(key.to_vec());
                sig_key_type = Some(VidSignatureKeyType::Ed25519);
            } else if let Some(key) = split_multikey(
                &decoded,
                signature_key_multicodec(VidSignatureKeyType::MlDsa65),
                1952,
            ) {
                #[cfg(feature = "async")]
                trace!("found ML-DSA-65 signature key");
                public_sigkey = Some(key.to_vec());
                sig_key_type = Some(VidSignatureKeyType::MlDsa65);
            } else {
                return Err(VidError::ResolveVid(
                    "invalid signature key type in did:peer",
                ));
            }
        }

        if document.key_agreement.contains(&method.id) {
            if let Some(key) = split_multikey(
                &decoded,
                encryption_key_multicodec(VidEncryptionKeyType::X25519),
                32,
            ) {
                #[cfg(feature = "async")]
                trace!("found x25519 encryption key");
                public_enckey = Some(key.to_vec());
                enc_key_type = Some(VidEncryptionKeyType::X25519);
            } else if let Some(key) = split_multikey(
                &decoded,
                encryption_key_multicodec(VidEncryptionKeyType::X25519MlKem768),
                1216,
            ) {
                #[cfg(feature = "async")]
                trace!("found X25519MlKem768 encryption key");
                public_enckey = Some(key.to_vec());
                enc_key_type = Some(VidEncryptionKeyType::X25519MlKem768);
            } else {
                return Err(VidError::ResolveVid(
                    "invalid encryption key type in did:peer",
                ));
            }
        }
    }

    let transport = document
        .service
        .iter()
        .find(|service| service.service_type == TSP_SERVICE_TYPE)
        .and_then(|service| Url::parse(&service.service_endpoint.uri).ok());

    // the VID is known by its short form once its document has been seen
    let id = format!("did:peer:4{hash}");

    match (public_sigkey, public_enckey, transport) {
        (Some(public_sigkey), Some(public_enckey), Some(mut transport)) => {
            let path = transport.path().replace("[vid_placeholder]", &id);
            transport.set_path(&path);

            Ok(Vid {
                id,
                transport,
                sig_key_type: sig_key_type.unwrap_or(VidSignatureKeyType::Ed25519),
                public_sigkey: public_sigkey.into(),
                enc_key_type: enc_key_type.unwrap_or(VidEncryptionKeyType::X25519),
                public_enckey: public_enckey.into(),
            })
        }
        (None, _, _) => Err(VidError::ResolveVid("missing verification key in did:peer")),
        (_, None, _) => Err(VidError::ResolveVid("missing encryption key in did:peer")),
        (_, _, None) => Err(VidError::ResolveVid("missing transport in did:peer")),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(not(feature = "pq"))]
    use crate::definitions::VerifiedVid;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[test]
    #[wasm_bindgen_test]
    fn matches_the_method_specs_own_example() {
        // The worked example from the did:peer method spec, Method 4. Its
        // document is not a TSP one, so this pins the derivation itself: the
        // JSON multicodec prefix, the hash over the encoded document as it
        // stands, and both forms.
        let encoded_document = "z2M1k7h4psgp4CmJcnQn2Ljp7Pz7ktsd7oBhMU3dWY5s4fhFNj17qcRTQ427C7QHNT6cQ7T3XfRh35Q2GhaNFZmWHVFq4vL7F8nm36PA9Y96DvdrUiRUaiCuXnBFrn1o7mxFZAx14JL4t8vUWpuDPwQuddVo1T8myRiVH7wdxuoYbsva5x6idEpCQydJdFjiHGCpNc2UtjzPQ8awSXkctGCnBmgkhrj5gto3D4i3EREXYq4Z8r2cWGBr2UzbSmnxW2BuYddFo9Yfm6mKjtJyLpF74ytqrF5xtf84MnGFg1hMBmh1xVx1JwjZ2BeMJs7mNS8DTZhKC7KH38EgqDtUZzfjhpjmmUfkXg2KFEA3EGbbVm1DPqQXayPYKAsYPS9AyKkcQ3fzWafLPP93UfNhtUPL8JW5pMcSV3P8v6j3vPXqnnGknNyBprD6YGUVtgLiAqDBDUF3LSxFQJCVYYtghMTv8WuSw9h1a1SRFrDQLGHE4UrkgoRvwaGWr64aM87T1eVGkP5Dt4L1AbboeK2ceLArPScrdYGTpi3BpTkLwZCdjdiFSfTy9okL1YNRARqUf2wm8DvkVGUU7u5nQA3ZMaXWJAewk6k1YUxKd7LvofGUK4YEDtoxN5vb6r1Q2godrGqaPkjfL3RoYPpDYymf9XhcgG8Kx3DZaA6cyTs24t45KxYAfeCw4wqUpCH9HbpD78TbEUr9PPAsJgXBvBj2VVsxnr7FKbK4KykGcg1W8M1JPz21Z4Y72LWgGQCmixovrkHktcTX1uNHjAvKBqVD5C7XmVfHgXCHj7djCh3vzLNuVLtEED8J1hhqsB1oCBGiuh3xXr7fZ9wUjJCQ1HYHqxLJKdYKtoCiPmgKM7etVftXkmTFETZmpM19aRyih3bao76LdpQtbw636r7a3qt8v4WfxsXJetSL8c7t24SqQBcAY89FBsbEnFNrQCMK3JEseKHVaU388ctvRD45uQfe5GndFxthj4iSDomk4uRFd1uRbywoP1tRuabHTDX42UxPjz";

        assert_eq!(
            hash_document(encoded_document),
            "zQmd8CpeFPci817KDsbSAKWcXAE2mjvCQSasRewvbSF54Bd"
        );

        let decoded = decode_base58btc(encoded_document).unwrap();
        let json = decoded.strip_prefix(&MULTICODEC_JSON).unwrap();
        let value: serde_json::Value = serde_json::from_slice(json).unwrap();
        assert_eq!(value["verificationMethod"][0]["id"], "#6LSqPZfn");
    }

    #[cfg(not(feature = "pq"))]
    fn test_vid() -> Vid {
        let (_sigkey, public_sigkey) = crate::crypto::gen_sign_keypair();
        let (_enckey, public_enckey) = crate::crypto::gen_encrypt_keypair();

        let mut vid = Vid {
            id: Default::default(),
            transport: Url::parse("tcp://127.0.0.1:1337").unwrap(),
            sig_key_type: VidSignatureKeyType::Ed25519,
            public_sigkey,
            enc_key_type: VidEncryptionKeyType::X25519,
            public_enckey,
        };
        vid.id = encode_did_peer(&vid);

        vid
    }

    #[cfg(not(feature = "pq"))]
    #[test]
    #[wasm_bindgen_test]
    fn long_form_resolves_to_the_short_form() {
        let vid = test_vid();
        let long_form = encode_did_peer_long_form(&vid);

        assert!(long_form.starts_with(&vid.id));

        let parts = long_form.split(':').collect::<Vec<&str>>();
        let resolved = verify_did_peer(&parts).unwrap();

        // resolving the long form yields a VID identified by its short form
        assert_eq!(resolved.identifier(), vid.id);
        assert_eq!(vid.verifying_key(), resolved.verifying_key());
        assert_eq!(vid.encryption_key(), resolved.encryption_key());
        assert_eq!(vid.endpoint(), resolved.endpoint());
    }

    #[cfg(not(feature = "pq"))]
    #[test]
    #[wasm_bindgen_test]
    fn short_form_alone_does_not_resolve() {
        let vid = test_vid();
        let parts = vid.id.split(':').collect::<Vec<&str>>();

        assert!(verify_did_peer(&parts).is_err());
    }

    #[cfg(not(feature = "pq"))]
    #[test]
    #[wasm_bindgen_test]
    fn a_tampered_document_is_rejected() {
        let vid = test_vid();
        let long_form = encode_did_peer_long_form(&vid);

        // a document that no longer hashes to the identifier's hash is not the
        // document that identifier names
        let (head, tail) = long_form.split_at(long_form.len() - 4);
        let tampered = format!(
            "{head}{}",
            if tail.starts_with('A') {
                "BBBB"
            } else {
                "AAAA"
            }
        );

        let parts = tampered.split(':').collect::<Vec<&str>>();
        assert!(verify_did_peer(&parts).is_err());
    }

    #[cfg(not(feature = "pq"))]
    #[test]
    #[wasm_bindgen_test]
    fn numalgo_2_is_not_accepted() {
        let legacy = "did:peer:2.Vz6Muyi75snjJxpBzSheqWX7kD2W23kDxZqh5PKMNVEBV4M79.Ez6LbvHWzhVvS39kwtKnBqcEaEtJy6MSMJfEr5kv26S8n9rXi.SeyJzIjp7InVyaSI6InRzcDovLyJ9LCJ0IjoidHNwIn0";
        let parts = legacy.split(':').collect::<Vec<&str>>();

        assert!(verify_did_peer(&parts).is_err());
    }
}
