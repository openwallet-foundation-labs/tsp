use crate::definitions::{PUBLIC_VERIFICATION_KEY_SIZE, VerifiedVid, VidEncryptionKeyType};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use crate::vid::{OwnedVid, Vid, error::VidError};

pub(crate) const SCHEME: &str = "web";

const PROTOCOL: &str = "https://";
const DEFAULT_PATH: &str = ".well-known";
const DOCUMENT: &str = "did.json";

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub authentication: Vec<String>,
    pub id: String,
    pub key_agreement: Vec<String>,
    pub service: Vec<Service>,
    pub verification_method: Vec<VerificationMethod>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    pub service_endpoint: Url,
    #[serde(rename = "type")]
    pub service_type: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub controller: String,
    pub id: String,
    pub public_key_jwk: PublicKeyJwk,
    #[serde(rename = "type")]
    pub method_type: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJwk {
    pub crv: Curve,
    pub kty: KeyType,
    #[serde(rename = "use")]
    pub usage: Usage,
    pub x: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateKeyJwk {
    pub crv: Curve,
    pub kty: KeyType,
    #[serde(rename = "use")]
    pub usage: Usage,
    pub x: String,
    pub y: String,
}

impl From<VidEncryptionKeyType> for KeyType {
    fn from(value: VidEncryptionKeyType) -> Self {
        match value {
            VidEncryptionKeyType::X25519 => KeyType::OKP,
            #[cfg(feature = "pq")]
            VidEncryptionKeyType::X25519Kyber768Draft00 => KeyType::X25519Kyber768Draft00,
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum KeyType {
    OKP,
    X25519Kyber768Draft00,
}

impl From<VidEncryptionKeyType> for Curve {
    fn from(value: VidEncryptionKeyType) -> Self {
        match value {
            VidEncryptionKeyType::X25519 => Curve::X25519,
            #[cfg(feature = "pq")]
            VidEncryptionKeyType::X25519Kyber768Draft00 => Curve::X25519,
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum Curve {
    X25519,
    Ed25519,
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Usage {
    Sig,
    Enc,
}

pub async fn resolve(id: &str, parts: Vec<&str>) -> Result<Vid, VidError> {
    #[cfg(test)]
    {
        let did_doc = std::fs::read_to_string(format!(
            "../examples/test/{}/did.json",
            parts.last().unwrap_or(&"invalid")
        ))
        .map_err(|_| VidError::ResolveVid("JSON not found in test dir"))?;

        let did_doc: DidDocument = serde_json::from_str(&did_doc).unwrap();

        resolve_document(did_doc, id)
    }

    #[cfg(not(test))]
    {
        let url = resolve_url(&parts)?;

        let client = reqwest::Client::builder();

        #[cfg(feature = "use_local_certificate")]
        let cert = {
            tracing::warn!("Using local root CA! (should only be used for local testing)");
            reqwest::Certificate::from_pem(include_bytes!("../../../../examples/test/root-ca.pem"))
                .unwrap()
        };

        #[cfg(feature = "use_local_certificate")]
        let client = client.add_root_certificate(cert);

        let response = client
            .build()
            .map_err(|e| VidError::Http("Client build error".to_string(), e))?
            .get(url.as_ref())
            .send()
            .await
            .map_err(|e| VidError::Http(url.to_string(), e))?;

        let did_document = match response.error_for_status() {
            Ok(r) => r
                .json::<DidDocument>()
                .await
                .map_err(|e| VidError::Json(url.to_string(), e))?,
            Err(e) => Err(VidError::Http(url.to_string(), e))?,
        };

        resolve_document(did_document, id)
    }
}

pub fn get_resolve_url(did: &str) -> Result<Url, VidError> {
    let parts = did.split(":").collect::<Vec<_>>();
    resolve_url(&parts)
}

fn resolve_url(parts: &[&str]) -> Result<Url, VidError> {
    match parts {
        ["did", "web", domain] => format!(
            "{PROTOCOL}{}/{DEFAULT_PATH}/{DOCUMENT}",
            domain.replace("%3A", ":")
        ),
        ["did", "web", domain, path @ ..] => {
            format!(
                "{PROTOCOL}{}/{}/{DOCUMENT}",
                domain.replace("%3A", ":"),
                path.join("/")
            )
        }
        ["did", "webvh", _scid, domain] => format!(
            "{PROTOCOL}{}/{DEFAULT_PATH}/{DOCUMENT}",
            domain.replace("%3A", ":")
        ),
        ["did", "webvh", _scid, domain, path @ ..] => {
            format!(
                "{PROTOCOL}{}/{}/{DOCUMENT}",
                domain.replace("%3A", ":"),
                path.join("/")
            )
        }
        _ => return Err(VidError::InvalidVid(parts.join(":"))),
    }
    .parse()
    .map_err(|_| VidError::InvalidVid(parts.join(":")))
}

fn find_first_key_to_be_removed<const N: usize>(
    did_document: &DidDocument,
    method: &[String],
    curve: Curve,
    usage: Usage,
) -> Option<[u8; N]> {
    method
        .iter()
        .next()
        .and_then(|id| {
            did_document
                .verification_method
                .iter()
                .find(|item| &item.id == id)
        })
        .and_then(|method| {
            if method.public_key_jwk.crv == curve && method.public_key_jwk.usage == usage {
                Base64UrlUnpadded::decode_vec(&method.public_key_jwk.x).ok()
            } else {
                None
            }
        })
        .and_then(|key| <[u8; N]>::try_from(key).ok())
}

fn find_first_key(
    did_document: &DidDocument,
    method: &[String],
    usage: Usage,
) -> Option<(Vec<u8>, KeyType, Curve)> {
    method
        .iter()
        .next()
        .and_then(|id| {
            did_document
                .verification_method
                .iter()
                .find(|item| &item.id == id)
        })
        .and_then(|method| {
            if method.public_key_jwk.usage == usage {
                Base64UrlUnpadded::decode_vec(&method.public_key_jwk.x)
                    .map(|b| (b, method.public_key_jwk.kty, method.public_key_jwk.crv))
                    .ok()
            } else {
                None
            }
        })
}

pub fn resolve_document(did_document: DidDocument, target_id: &str) -> Result<Vid, VidError> {
    if did_document.id != target_id {
        return Err(VidError::ResolveVid("Invalid id specified in DID document"));
    }

    let Some(public_sigkey) = find_first_key_to_be_removed::<PUBLIC_VERIFICATION_KEY_SIZE>(
        &did_document,
        &did_document.authentication,
        Curve::Ed25519,
        Usage::Sig,
    ) else {
        return Err(VidError::ResolveVid(
            "No valid sign key found in DID document",
        ));
    };

    let Some((public_enckey, key_type, curve)) =
        find_first_key(&did_document, &did_document.key_agreement, Usage::Enc)
    else {
        return Err(VidError::ResolveVid(
            "No valid encryption key found in DID document",
        ));
    };

    let transport = match did_document.service.into_iter().next().and_then(|service| {
        if service.service_type == "TSPTransport" {
            Some(service)
        } else {
            None
        }
    }) {
        Some(service) => service.service_endpoint,
        None => {
            return Err(VidError::ResolveVid(
                "No transport found in the DID document",
            ));
        }
    };

    let enc_key_type = match (key_type, curve) {
        (KeyType::OKP, Curve::X25519) => VidEncryptionKeyType::X25519,
        #[cfg(feature = "pq")]
        (KeyType::X25519Kyber768Draft00, Curve::X25519) => {
            VidEncryptionKeyType::X25519Kyber768Draft00
        }
        _ => return Err(VidError::ResolveVid("Unsupported key type or curve")),
    };

    Ok(Vid {
        id: did_document.id,
        transport,
        public_sigkey: public_sigkey.into(),
        enc_key_type,
        public_enckey: public_enckey.into(),
    })
}

pub fn vid_to_did_document(vid: &impl VerifiedVid) -> serde_json::Value {
    let id = vid.identifier();

    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": id,
        "verificationMethod": [
            {
                "id": format!("{id}#verification-key"),
                "type": "JsonWebKey2020",
                "controller":  format!("{id}"),
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "x": Base64UrlUnpadded::encode_string(vid.verifying_key().as_ref()),
                }
            },
            {
                "id": format!("{id}#encryption-key"),
                "type": "JsonWebKey2020",
                "controller": format!("{id}"),
                "publicKeyJwk": vid.encryption_key_jwk()
            },
        ],
        "authentication": [
            format!("{id}#verification-key"),
        ],
        "keyAgreement": [
            format!("{id}#encryption-key"),
        ],
        "service": [{
            "id": "#tsp-transport",
            "type": "TSPTransport",
            "serviceEndpoint": vid.endpoint()
        }]
    })
}

pub fn create_did_web(
    name: &str,
    domain: &str,
    transport: &str,
) -> (serde_json::Value, serde_json::Value, OwnedVid) {
    let did = format!("did:web:{}:endpoint:{name}", domain.replace(":", "%3A"));
    let private_vid = OwnedVid::bind(did, Url::parse(transport).unwrap());
    let private_doc = serde_json::to_value(&private_vid).unwrap();
    let did_doc = vid_to_did_document(private_vid.vid());

    (did_doc, private_doc, private_vid)
}

#[cfg(test)]
mod tests {
    use super::resolve_url;
    use crate::vid::error::VidError;
    use url::Url;
    #[cfg(not(feature = "pq"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    fn resolve_did_string(did: &str) -> Result<Url, VidError> {
        let parts = did.split(':').collect::<Vec<&str>>();

        resolve_url(&parts)
    }

    #[test]
    fn test_resolve_url() {
        assert_eq!(
            resolve_did_string("did:web:example.com")
                .unwrap()
                .to_string(),
            "https://example.com/.well-known/did.json"
        );

        assert_eq!(
            resolve_did_string("did:web:example.com:endpoint:bob")
                .unwrap()
                .to_string(),
            "https://example.com/endpoint/bob/did.json"
        );

        assert!(resolve_did_string("did:web:example%20.com").is_err());
        assert!(resolve_did_string("did:web:example.com:endpoint:user:user").is_ok());
    }

    #[cfg(not(feature = "pq"))]
    #[test]
    #[wasm_bindgen_test]
    fn test_resolve_document() {
        use crate::{
            VerifiedVid,
            vid::did::web::{DidDocument, resolve_document},
        };

        let alice_did_doc = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../examples/test/alice/did.json"
        ));
        let alice_did_doc: DidDocument = serde_json::from_str(alice_did_doc).unwrap();

        let alice = resolve_document(
            alice_did_doc,
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
        );

        assert_eq!(
            alice.unwrap().identifier(),
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice"
        );

        let bob_did_doc = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../examples/test/bob/did.json"
        ));
        let bob_did_doc: DidDocument = serde_json::from_str(bob_did_doc).unwrap();

        let bob = resolve_document(
            bob_did_doc,
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
        );

        assert_eq!(
            bob.unwrap().identifier(),
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob"
        );
    }
}
