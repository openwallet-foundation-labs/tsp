use crate::definitions::{PUBLIC_KEY_SIZE, PUBLIC_VERIFICATION_KEY_SIZE};
use serde::Deserialize;
use url::Url;

use crate::vid::{error::VidError, Vid};

pub(crate) const SCHEME: &str = "tdw";

const PROTOCOL: &str = "https://";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdwDocument {
    pub doc: Doc,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Doc {
    pub key_agreement: Vec<String>,
    pub authentication: Vec<String>,
    pub verification_method: Vec<VerificationMethod>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    pub public_key_multibase: String,
}

pub async fn resolve(id: &str, parts: Vec<&str>) -> Result<Vid, VidError> {
    let url = resolve_url(&parts)?;

    let response = reqwest::get(url.as_ref())
        .await
        .map_err(|e| VidError::Http(url.to_string(), e))?;

    let did_document: TdwDocument = match response.error_for_status() {
        Ok(r) => r
            .json()
            .await
            .map_err(|e| VidError::Json(url.to_string(), e))?,
        Err(e) => Err(VidError::Http(url.to_string(), e))?,
    };

    // At this time there is no servce/transport in the TDW document
    let transport = format!("{PROTOCOL}tsp-test.org/user/{}", parts[2]);

    let sig_key_id = &did_document.doc.authentication[0];
    let enc_key_id = &did_document.doc.key_agreement[0];

    let sig_key = did_document
        .doc
        .verification_method
        .iter()
        .find(|vm| vm.id == *sig_key_id)
        .map(|k| &k.public_key_multibase)
        .ok_or_else(|| VidError::ResolveVid("No valid signing key found in DID document"))?;

    let enc_key = did_document
        .doc
        .verification_method
        .iter()
        .find(|vm| vm.id == *enc_key_id)
        .map(|k| &k.public_key_multibase)
        .ok_or_else(|| VidError::ResolveVid("No valid encryption key found in DID document"))?;

    dbg!(sig_key, enc_key);

    let mut public_sigkey= Vec::new();

    bs58::decode(&sig_key[1..])
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .onto(&mut public_sigkey)
        .map_err(|_| VidError::ResolveVid("invalid encoded signing key in did:tdw"))?;

    let mut public_enckey= Vec::new();

    bs58::decode(&enc_key[1..])
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .onto(&mut public_enckey)
        .map_err(|_| VidError::ResolveVid("invalid encoded encryption key in did:tdw"))?;

    let public_sigkey: [u8; PUBLIC_VERIFICATION_KEY_SIZE] = public_sigkey[2..].try_into()
        .map_err(|_| VidError::ResolveVid("invalid encoded signing key in did:tdw"))?;

    let public_enckey: [u8; PUBLIC_KEY_SIZE] = public_enckey[2..].try_into()
        .map_err(|_| VidError::ResolveVid("invalid encoded encryption key in did:tdw"))?;

    Ok(Vid {
        id: id.to_string(),
        transport: Url::parse(&transport).map_err(|_| VidError::InvalidVid(parts.join(":")))?,
        public_sigkey: public_sigkey.into(),
        public_enckey: public_enckey.into(),
    })
}

pub fn resolve_url(parts: &[&str]) -> Result<Url, VidError> {
    let full = parts.join(":");

    match parts {
        ["did", "tdw", _id, domain] => format!("https://{domain}/get/{full}"),
        _ => return Err(VidError::InvalidVid(parts.join(":"))),
    }
    .parse()
    .map_err(|_| VidError::InvalidVid(parts.join(":")))
}