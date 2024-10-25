use crate::definitions::{PUBLIC_KEY_SIZE, PUBLIC_VERIFICATION_KEY_SIZE};
use serde::Deserialize;
use url::Url;

use crate::vid::{error::VidError, Vid};

pub(crate) const SCHEME: &str = "twd";

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
    let transport = format!("{PROTOCOL}{}/user/{}", parts[3], parts[2]);

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

    bs58::decode(&sig_key)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .onto(&mut public_sigkey)
        .map_err(|_| VidError::ResolveVid("invalid encoded signing key in did:tdw"))?;

    let mut public_enckey= Vec::new();

    bs58::decode(&enc_key)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .onto(&mut public_enckey)
        .map_err(|_| VidError::ResolveVid("invalid encoded encryption key in did:tdw"))?;

    dbg!(&public_sigkey);
    dbg!(&public_enckey);

    Ok(Vid {
        id: id.to_string(),
        transport: Url::parse(&transport).map_err(|_| VidError::InvalidVid(parts.join(":")))?,
        public_sigkey: [0; 32].into(), //public_sigkey.into(),
        public_enckey: [0; 32].into(), //public_enckey.into(),
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


#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_resolve() {
        let id = "did:tdw:QmWzWa51Ux2B4XPiuTWD9phFMrL7VA5wwDnrMeogupZrSG:tdw.tsp-test.org";
        let parts = id.split(':').collect::<Vec<&str>>();

        let vid = resolve(id, parts).await.unwrap();

        dbg!(&vid);

        assert_eq!(vid.id, id);
        assert_eq!(vid.transport, "https://tdw.tsp-test.org/user/QmWzWa51Ux2B4XPiuTWD9phFMrL7VA5wwDnrMeogupZrSG".parse().unwrap());
    }

    // expected output
    // [253, 43, 196, 7, 93, 252, 40, 49, 141, 115, 87, 164, 50, 233, 4, 212, 70, 84, 130, 217, 118, 141, 241, 39, 74, 194, 49, 231, 107, 140, 150, 158 ]
    // _SvEB138KDGNc1ekMukE1EZUgtl2jfEnSsIx52uMlp4
    // [167, 206, 200, 176, 80, 7, 157, 28, 189, 205, 96, 63, 34, 133, 93, 104, 137, 1, 187, 107, 214, 38, 127, 232, 120, 65, 7, 173, 42, 75, 13, 4 ]
    // p87IsFAHnRy9zWA_IoVdaIkBu2vWJn_oeEEHrSpLDQQ

}