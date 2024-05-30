use crate::definitions::VerifiedVid;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Deserialize;
use serde_json::json;
use url::Url;

use crate::vid::{error::VidError, OwnedVid, Vid};

pub(crate) const SCHEME: &str = "web";

const PROTOCOL: &str = "https://";
const DEFAULT_PATH: &str = ".well-known";
const DOCUMENT: &str = "did.json";

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    pub service_endpoint: Url,
    #[serde(rename = "type")]
    pub service_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub controller: String,
    pub id: String,
    pub public_key_jwk: PublicKeyJwk,
    #[serde(rename = "type")]
    pub method_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJwk {
    pub crv: String,
    pub kty: String,
    #[serde(rename = "use")]
    pub usage: String,
    pub x: String,
}

pub async fn resolve(id: &str, parts: Vec<&str>) -> Result<Vid, VidError> {
    #[cfg(test)]
    {
        let did_doc = tokio::fs::read_to_string(format!(
            "../examples/test/{}-did.json",
            parts.get(4).unwrap_or(&"invalid")
        ))
        .await
        .map_err(|_| VidError::ResolveVid("JSON not found in test dir"))?;

        let did_doc: DidDocument = serde_json::from_str(&did_doc).unwrap();

        resolve_document(did_doc, id)
    }

    #[cfg(not(test))]
    {
        let url = resolve_url(&parts)?;

        let response = reqwest::get(url.as_ref())
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

pub fn resolve_url(parts: &[&str]) -> Result<Url, VidError> {
    match parts {
        ["did", "web", domain] => format!("{PROTOCOL}{domain}/{DEFAULT_PATH}/{DOCUMENT}"),
        ["did", "web", domain, "user", username] => {
            format!("{PROTOCOL}{domain}/user/{username}/{DOCUMENT}")
        }
        _ => return Err(VidError::InvalidVid(parts.join(":"))),
    }
    .parse()
    .map_err(|_| VidError::InvalidVid(parts.join(":")))
}

pub fn find_first_key(
    did_document: &DidDocument,
    method: &[String],
    curve: &str,
    usage: &str,
) -> Option<[u8; 32]> {
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
        .and_then(|key| <[u8; 32]>::try_from(key).ok())
}

pub fn resolve_document(did_document: DidDocument, target_id: &str) -> Result<Vid, VidError> {
    if did_document.id != target_id {
        return Err(VidError::ResolveVid("Invalid id specified in DID document"));
    }

    let Some(public_sigkey) = find_first_key(
        &did_document,
        &did_document.authentication,
        "Ed25519",
        "sig",
    )
    .and_then(|key| ed25519_dalek::VerifyingKey::from_bytes(&key).ok()) else {
        return Err(VidError::ResolveVid(
            "No valid sign key found in DID document",
        ));
    };

    let Some(public_enckey) =
        find_first_key(&did_document, &did_document.key_agreement, "X25519", "enc")
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
            ))
        }
    };

    Ok(Vid {
        id: did_document.id,
        transport,
        public_sigkey,
        public_enckey,
    })
}

pub fn vid_to_did_document(vid: &Vid) -> serde_json::Value {
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
                    "x": Base64UrlUnpadded::encode_string(vid.verifying_key()),
                }
            },
            {
                "id": format!("{id}#encryption-key"),
                "type": "JsonWebKey2020",
                "controller": format!("{id}"),
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": Base64UrlUnpadded::encode_string(vid.encryption_key()),
                }
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
            "serviceEndpoint": vid.transport.to_string()
        }]
    })
}

pub fn create_did_web(
    name: &str,
    domain: &str,
    transport: &str,
) -> (serde_json::Value, serde_json::Value, OwnedVid) {
    let did = format!("did:web:{domain}:user:{name}");
    let private_vid = OwnedVid::bind(did, Url::parse(transport).unwrap());
    let private_doc = serde_json::to_value(&private_vid).unwrap();
    let did_doc = vid_to_did_document(private_vid.vid());

    (did_doc, private_doc, private_vid)
}

#[cfg(test)]
mod tests {
    use super::resolve_url;
    use crate::{
        definitions::VerifiedVid,
        vid::{
            did::web::{resolve_document, DidDocument},
            error::VidError,
        },
    };
    use std::fs;
    use url::Url;

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
            resolve_did_string("did:web:example.com:user:bob")
                .unwrap()
                .to_string(),
            "https://example.com/user/bob/did.json"
        );

        assert!(resolve_did_string("did:web:example%20.com").is_err());
        assert!(resolve_did_string("did:web:example.com:user:user:user").is_err());
    }

    #[test]
    fn test_resolve_document() {
        let alice_did_doc = fs::read_to_string("../examples/test/alice-did.json").unwrap();
        let alice_did_doc: DidDocument = serde_json::from_str(&alice_did_doc).unwrap();

        let alice = resolve_document(alice_did_doc, "did:web:did.tsp-test.org:user:alice");

        assert_eq!(
            alice.unwrap().identifier(),
            "did:web:did.tsp-test.org:user:alice"
        );

        let bob_did_doc = fs::read_to_string("../examples/test/bob-did.json").unwrap();
        let bob_did_doc: DidDocument = serde_json::from_str(&bob_did_doc).unwrap();

        let bob = resolve_document(bob_did_doc, "did:web:did.tsp-test.org:user:bob");

        assert_eq!(
            bob.unwrap().identifier(),
            "did:web:did.tsp-test.org:user:bob"
        );
    }
}
