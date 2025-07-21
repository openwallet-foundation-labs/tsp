use crate::definitions::{VidEncryptionKeyType, VidSignatureKeyType};
use crate::{Vid, definitions::VerifiedVid, vid::error::VidError};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;
#[cfg(feature = "async")]
use tracing::log::trace;
use url::Url;

pub(crate) const SCHEME: &str = "peer";

/// Encode VID as did:peer,include verification end encryption key
/// The service definition has type `tsp`
/// See <https://identity.foundation/peer-did-method-spec/>
pub fn encode_did_peer(vid: &Vid) -> String {
    let mut v = Vec::with_capacity(34);

    match vid.sig_key_type {
        VidSignatureKeyType::Ed25519 => {
            // multicodec for ed25519-pub
            v.push(0xed);
            // key bytes length
            v.push(0x20);
        }
        #[cfg(feature = "pq")]
        VidSignatureKeyType::MlDsa65 => {
            // private use area (0x300001) => encoded as unsigned varint, see: https://github.com/multiformats/unsigned-varint
            v.extend_from_slice(&0x8180c001u32.to_be_bytes());
            // key bytes length (1952 bytes) => encoded as unsigned varint, see: https://github.com/multiformats/unsigned-varint
            v.extend_from_slice(&0xa00fu16.to_be_bytes());
        }
    };

    v.extend_from_slice(vid.verifying_key().as_ref());

    let verification_key = bs58::encode(&v)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();

    v.clear();
    match vid.enc_key_type {
        VidEncryptionKeyType::X25519 => {
            #[cfg(feature = "async")]
            trace!("serializing x25519 encryption key");
            // multicodec for x25519-pub
            v.push(0xec);
            // key bytes length
            v.push(0x20);
        }
        #[cfg(feature = "pq")]
        VidEncryptionKeyType::X25519Kyber768Draft00 => {
            #[cfg(feature = "async")]
            trace!("serializing X25519Kyber768Draft00 encryption key");
            // private use area (0x300000) => encoded as unsigned varint, see: https://github.com/multiformats/unsigned-varint
            v.extend_from_slice(&0x8080c001u32.to_be_bytes());
            // key bytes length (1216 bytes) => encoded as unsigned varint, see: https://github.com/multiformats/unsigned-varint
            v.extend_from_slice(&0xc009u16.to_be_bytes());
        }
    }

    v.extend_from_slice(vid.encryption_key().as_ref());

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

pub fn verify_did_peer(parts: &[&str]) -> Result<Vid, VidError> {
    let mut peer_parts = parts[2].split('.');

    // only numalgo 2 is supported
    if peer_parts.next() != Some("2") {
        return Err(VidError::ResolveVid(
            "only numalgo 2 is supported for did:peer",
        ));
    }

    let mut public_sigkey = None;
    let mut public_enckey = None;
    let mut enc_key_type = None;
    let mut sig_key_type = None;
    let mut transport = None;

    let mut buf = [0; 3309 + 6];

    for part in peer_parts {
        match &part[0..2] {
            // Key Agreement (Encryption) + base58 multibase prefix
            "Ez" => {
                bs58::decode(&part[2..])
                    .with_alphabet(bs58::Alphabet::BITCOIN)
                    .onto(&mut buf)
                    .map_err(|_| {
                        VidError::ResolveVid("invalid encoded encryption key in did:peer")
                    })?;

                match buf {
                    // multicodec for x25519-pub + length 32 bytes
                    [0xec, 0x20, rest @ ..] => {
                        #[cfg(feature = "async")]
                        trace!("found x25519 encryption key");
                        public_enckey = Some(rest[..0x20].to_vec());
                        enc_key_type = Some(VidEncryptionKeyType::X25519)
                    }
                    #[cfg(feature = "pq")]
                    // multicodec reserved range (0x300000), followed by length (1216)
                    [
                        0b10000000,
                        0b10000000,
                        0b11000000,
                        0b00000001,
                        0b11000000,
                        0b00001001,
                        rest @ ..,
                    ] => {
                        #[cfg(feature = "async")]
                        trace!("found X25519Kyber768Draft00 encryption key");
                        public_enckey = rest[..1216].to_vec().into();
                        enc_key_type = Some(VidEncryptionKeyType::X25519Kyber768Draft00)
                    }
                    _ => {
                        return Err(VidError::ResolveVid(
                            "invalid encryption key type in did:peer",
                        ));
                    }
                }
            }
            // Authentication (Verification) + base58 multibase prefix
            "Vz" => {
                bs58::decode(&part[2..])
                    .with_alphabet(bs58::Alphabet::BITCOIN)
                    .onto(&mut buf)
                    .map_err(|_| {
                        VidError::ResolveVid("invalid encoded verification key in did:peer")
                    })?;

                match buf {
                    // multicodec for ed25519-pub + length 32 bytes
                    [0xed, 0x20, rest @ ..] => {
                        #[cfg(feature = "async")]
                        trace!("found Ed25519 signature key");
                        public_sigkey = Some(rest[..0x20].to_vec());
                        sig_key_type = Some(VidSignatureKeyType::Ed25519)
                    }
                    #[cfg(feature = "pq")]
                    // multicodec reserved range (0x300001), followed by length (1952) (https://go.dev/play/p/KskwkAiBV7D)
                    [
                        0b10000001,
                        0b10000000,
                        0b11000000,
                        0b00000001,
                        0b10100000,
                        0b00001111,
                        rest @ ..,
                    ] => {
                        #[cfg(feature = "async")]
                        trace!("found ML-DSA-65 signature key");
                        public_sigkey = rest[..1952].to_vec().into();
                        sig_key_type = Some(VidSignatureKeyType::MlDsa65)
                    }
                    _ => {
                        return Err(VidError::ResolveVid(
                            "invalid signature key type in did:peer",
                        ));
                    }
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
        (Some(public_sigkey), Some(public_enckey), Some(mut transport)) => {
            let path = transport
                .path()
                .replace("[vid_placeholder]", &parts.join(":"));
            transport.set_path(&path);
            Ok(Vid {
                id: parts.join(":"),
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

#[cfg(not(feature = "pq"))]
#[cfg(test)]
mod test {
    use crate::definitions::{VerifiedVid, VidEncryptionKeyType, VidSignatureKeyType};
    use url::Url;
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::Vid;

    use super::{encode_did_peer, verify_did_peer};

    #[test]
    #[wasm_bindgen_test]
    fn encode_decode() {
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

        let parts = vid.id.split(':').collect::<Vec<&str>>();

        let resolved_vid = verify_did_peer(&parts).unwrap();

        assert_eq!(vid.verifying_key(), resolved_vid.verifying_key());
        assert_eq!(vid.encryption_key(), resolved_vid.encryption_key());
        assert_eq!(vid.endpoint(), resolved_vid.endpoint());
    }
}
