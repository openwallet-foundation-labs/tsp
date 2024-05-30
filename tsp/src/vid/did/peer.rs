use crate::{definitions::VerifiedVid, vid::error::VidError, Vid};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;
use url::Url;

pub(crate) const SCHEME: &str = "peer";

/// Encode VID as did:peer,include verification end encryption key
/// The service definition has type `tsp`
/// See https://identity.foundation/peer-did-method-spec/
pub(crate) fn encode_did_peer(vid: &Vid) -> String {
    let mut v = Vec::with_capacity(34);
    // multicodec for ed25519-pub
    v.push(0xed);
    // 32 bytes length
    v.push(0x20);
    v.extend_from_slice(vid.verifying_key());

    let verification_key = bs58::encode(&v)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();

    v.clear();
    // multicodec for x25519-pub
    v.push(0xec);
    // 32 bytes length
    v.push(0x20);
    v.extend_from_slice(vid.encryption_key());

    let encryption_key = bs58::encode(&v)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();

    let service = Base64UrlUnpadded::encode_string(
        json!({
            "t": "tsp",
            "s": {
                "uri": vid.endpoint()
            }
        })
        .to_string()
        .as_bytes(),
    );

    format!("did:peer:2.Vz{verification_key}.Ez{encryption_key}.S{service}")
}

pub(crate) fn verify_did_peer(parts: &[&str]) -> Result<Vid, VidError> {
    let mut peer_parts = parts[2].split('.');

    // only numalgo 2 is supported
    if peer_parts.next() != Some("2") {
        return Err(VidError::ResolveVid(
            "only numalgo 2 is supported for did:peer",
        ));
    }

    let mut public_sigkey = None;
    let mut public_enckey = None;
    let mut transport = None;

    let mut buf = [0; 34];

    for part in peer_parts {
        match &part[0..2] {
            // Key Agreement (Encryption) + base58 multibase prefix
            "Ez" => {
                let count = bs58::decode(&part[2..])
                    .with_alphabet(bs58::Alphabet::BITCOIN)
                    .onto(&mut buf)
                    .map_err(|_| {
                        VidError::ResolveVid("invalid encoded encryption key in did:peer")
                    })?;

                debug_assert_eq!(count, 34);

                // multicodec for x25519-pub + length 32 bytes
                if let [0xec, 0x20, rest @ ..] = buf {
                    public_enckey = rest.last_chunk::<32>().copied();
                } else {
                    return Err(VidError::ResolveVid(
                        "invalid encryption key type in did:peer",
                    ));
                }
            }
            // Authentication (Verification) + base58 multibase prefix
            "Vz" => {
                let count = bs58::decode(&part[2..])
                    .with_alphabet(bs58::Alphabet::BITCOIN)
                    .onto(&mut buf)
                    .map_err(|_| {
                        VidError::ResolveVid("invalid encoded verification key in did:peer")
                    })?;

                debug_assert_eq!(count, 34);

                // multicodec for ed25519-pub + length 32 bytes
                if let [0xed, 0x20, rest @ ..] = buf {
                    if let Some(sigkey_bytes) = rest.last_chunk::<32>() {
                        public_sigkey = ed25519_dalek::VerifyingKey::from_bytes(sigkey_bytes).ok();
                    }
                } else {
                    return Err(VidError::ResolveVid(
                        "invalid verification key type in did:peer",
                    ));
                }
            }
            // start of base64url encoded service definition
            "Se" => {
                let transport_bytes = Base64UrlUnpadded::decode_vec(&part[1..])
                    .map_err(|_| VidError::ResolveVid("invalid encoded transport in did:peer"))?;

                let transport_json: serde_json::Value = serde_json::from_slice(&transport_bytes)
                    .map_err(|_| VidError::ResolveVid("invalid encoded transport in did:peer"))?;

                if transport_json["t"] != "tsp" {
                    return Err(VidError::ResolveVid("invalid transport type in did:peer"));
                }

                if let Some(transport_bytes) = &transport_json["s"]["uri"].as_str() {
                    transport = Url::parse(transport_bytes).ok();
                }
            }
            _ => {
                return Err(VidError::ResolveVid("invalid part in did:peer"));
            }
        }
    }

    match (public_sigkey, public_enckey, transport) {
        (Some(public_sigkey), Some(public_enckey), Some(transport)) => Ok(Vid {
            id: parts.join(":"),
            transport,
            public_sigkey,
            public_enckey,
        }),
        (None, _, _) => Err(VidError::ResolveVid("missing verification key in did:peer")),
        (_, None, _) => Err(VidError::ResolveVid("missing encryption key in did:peer")),
        (_, _, None) => Err(VidError::ResolveVid("missing transport in did:peer")),
    }
}

#[cfg(test)]
mod test {
    use crate::definitions::VerifiedVid;
    use ed25519_dalek::{self as Ed};
    use hpke::{kem::X25519HkdfSha256 as KemType, Kem, Serializable};
    use rand::rngs::OsRng;
    use url::Url;

    use crate::Vid;

    use super::{encode_did_peer, verify_did_peer};

    #[test]
    fn encode_decode() {
        let sigkey = Ed::SigningKey::generate(&mut OsRng);
        let (_enckey, public_enckey) = KemType::gen_keypair(&mut OsRng);

        let mut vid = Vid {
            id: Default::default(),
            transport: Url::parse("tcp://127.0.0.1:1337").unwrap(),
            public_sigkey: sigkey.verifying_key(),
            public_enckey: public_enckey.to_bytes().into(),
        };

        vid.id = encode_did_peer(&vid);

        let parts = vid.id.split(':').collect::<Vec<&str>>();

        let resolved_vid = verify_did_peer(&parts).unwrap();

        assert_eq!(vid.verifying_key(), resolved_vid.verifying_key());
        assert_eq!(vid.encryption_key(), resolved_vid.encryption_key());
        assert_eq!(vid.endpoint(), resolved_vid.endpoint());
    }
}
