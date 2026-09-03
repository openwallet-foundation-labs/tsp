use crate::{
    cesr::{CryptoType, DecodedPayload, Envelope},
    definitions::{Payload, PrivateVid, TSPMessage, VerifiedVid, VidEncryptionKeyType},
};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::AeadTag,
    inout::InOutBuf, single_shot_open_inout_detached, single_shot_seal_inout_detached_with_rng,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};

use super::{
    CryptoError, MessageContents, ParallelSignatureInfo, RelationshipDigestAlgorithm,
    append_signature, build_relationship_accept_payload, build_relationship_request_payload,
    signature_type,
};

type Aead = hpke::aead::ChaCha20Poly1305;
type Kdf = hpke::kdf::HkdfSha256;
type X25519Kem = hpke::kem::X25519HkdfSha256;
/// The PQ/T hybrid KEM X25519MLKEM768 (HPKE KEM id 0x647a); there is no separate
/// post-quantum ciphertext code or mode -- only the KEM differs (spec 8.2.3)
type PqKem = hpke::kem::XWing;

/// The HPKE `info` input: the TSP protocol CESR code (spec 8.2.2, 9.1)
const HPKE_INFO: &[u8] = b"YTSP-";

type SealPayload<'a> = crate::cesr::Payload<'a, &'a [u8], &'a [u8]>;
type PreparedPayload<'a> = (SealPayload<'a>, Option<super::Digest>);

#[allow(clippy::too_many_arguments)]
fn payload_for_seal<'a>(
    secret_payload: &'a Payload<'a, &'a [u8]>,
    sender_in_payload: Option<&'a [u8]>,
    digest_algorithm: RelationshipDigestAlgorithm,
    envelope_prefix: &[u8],
    request_nonce_override: Option<[u8; 16]>,
    csprng: &mut StdRng,
    request_digest_storage: &'a mut super::Digest,
    reply_digest_storage: &'a mut super::Digest,
) -> Result<PreparedPayload<'a>, CryptoError> {
    let mut payload_digest_override = None;

    let payload = match secret_payload {
        Payload::Content(data) => crate::cesr::Payload::GenericMessage(*data),
        Payload::ControlMessage(data) => crate::cesr::Payload::ControlMessage(*data),
        // a padding message is nothing but a fresh nonce: it exists to be
        // indistinguishable from traffic that means something (spec 7.5)
        Payload::Padding => crate::cesr::Payload::Padding {
            nonce: crate::cesr::Nonce::generate(|dst| csprng.fill_bytes(dst)),
        },
        Payload::RequestRelationship {
            thread_id: _ignored,
            form,
            reply_path,
        } => {
            let nonce_bytes = request_nonce_override.unwrap_or_else(|| {
                let mut nonce_bytes = [0_u8; 16];
                csprng.fill_bytes(&mut nonce_bytes);
                nonce_bytes
            });

            let (payload, payload_digest) = build_relationship_request_payload(
                form,
                sender_in_payload,
                digest_algorithm,
                nonce_bytes,
                reply_path,
                envelope_prefix,
                request_digest_storage,
            )?;
            payload_digest_override = Some(payload_digest);
            payload
        }
        Payload::AcceptRelationship {
            thread_id,
            reply_thread_id: _ignored,
            form,
        } => {
            let (payload, payload_digest) = build_relationship_accept_payload(
                thread_id,
                form,
                sender_in_payload,
                digest_algorithm,
                envelope_prefix,
                reply_digest_storage,
            )?;
            payload_digest_override = Some(payload_digest);
            payload
        }
        Payload::CancelRelationship { thread_id } => crate::cesr::Payload::RelationshipCancel {
            reply: digest_algorithm.field(thread_id),
        },
        Payload::NestedMessage(data) => crate::cesr::Payload::NestedMessage(*data),
        Payload::RoutedMessage(hops, data) => {
            crate::cesr::Payload::RoutedMessage(hops.clone(), *data)
        }
    };

    Ok((payload, payload_digest_override))
}

/// Seal a message with HPKE-Base (spec 8.2.2). The KEM is selected by the
/// recipient VID's encryption key type; everything else is identical.
pub(crate) fn seal(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    secret_payload: Payload<&[u8]>,
    digest: Option<&mut super::Digest>,
    request_nonce_override: Option<[u8; 16]>,
    seed: Option<[u8; 32]>,
    selection: super::OutboundCryptoSelection,
) -> Result<TSPMessage, CryptoError> {
    match receiver.encryption_key_type() {
        VidEncryptionKeyType::X25519 => seal_with_kem::<X25519Kem>(
            sender,
            receiver,
            secret_payload,
            digest,
            request_nonce_override,
            seed,
            selection,
        ),
        VidEncryptionKeyType::X25519MlKem768 => seal_with_kem::<PqKem>(
            sender,
            receiver,
            secret_payload,
            digest,
            request_nonce_override,
            seed,
            selection,
        ),
    }
}

/// `hpke` and this crate depend on different major versions of `rand_core`,
/// so a seeded generator cannot be handed to it directly. This forwards the
/// bytes, which is all the encapsulation asks of it.
struct SeededRng<'a>(&'a mut StdRng);

impl hpke::rand_core::TryRng for SeededRng<'_> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(RngCore::next_u32(self.0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(RngCore::next_u64(self.0))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        RngCore::fill_bytes(self.0, dst);

        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for SeededRng<'_> {}

fn seal_with_kem<Kem: KemTrait>(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    secret_payload: Payload<&[u8]>,
    digest: Option<&mut super::Digest>,
    request_nonce_override: Option<[u8; 16]>,
    seed: Option<[u8; 32]>,
    selection: super::OutboundCryptoSelection,
) -> Result<TSPMessage, CryptoError> {
    let crypto_type = CryptoType::HpkeBase;
    // see the note in tsp_nacl::seal: a seed makes a test vector reproducible
    let mut csprng = match seed {
        Some(seed) => StdRng::from_seed(seed),
        None => StdRng::from_entropy(),
    };
    let mut data = Vec::with_capacity(64);

    // the envelope fields (version, sender VID, receiver VID); these are
    // exactly the aad of the spec: aad = CONCAT(TSP_Version, VID_sndr, VID_rcvr)
    crate::cesr::encode_envelope(
        crate::cesr::Envelope {
            crypto_type,
            signature_type: signature_type(sender),
            sender: sender.identifier(),
            receiver: Some(receiver.identifier()),
        },
        &mut data,
    )?;

    // Under HPKE-Base the aad is CONCAT(TSP_Version, VID_sndr, VID_rcvr), so
    // the envelope already binds the sender and the ESSR field inside the
    // ciphertext adds nothing. The specification makes it optional here for
    // that reason (spec 3.2), so it is NULL unless the caller asks for it; a
    // receiver accepts either and checks it only when present (spec 3.7 step 7).
    let sender_in_payload = selection.essr_sender_in_payload(sender);
    let mut request_digest_storage = [0_u8; 32];
    let mut reply_digest_storage = [0_u8; 32];
    let digest_algorithm = RelationshipDigestAlgorithm::for_crypto_type(crypto_type)?;
    let (secret_payload, payload_digest_override) = payload_for_seal(
        &secret_payload,
        sender_in_payload,
        digest_algorithm,
        &data,
        request_nonce_override,
        &mut csprng,
        &mut request_digest_storage,
        &mut reply_digest_storage,
    )?;

    let mut cesr_message = Vec::with_capacity(secret_payload.calculate_size(sender_in_payload));
    crate::cesr::encode_payload(
        &secret_payload,
        sender_in_payload,
        selection.padding,
        &mut cesr_message,
    )?;

    if let Some(digest) = digest {
        *digest = payload_digest_override.unwrap_or_else(|| digest_algorithm.hash(&cesr_message));
    }

    let message_receiver = Kem::PublicKey::from_bytes(receiver.encryption_key().as_ref())?;

    // the encapsulation draws randomness too, so a seeded caller has to reach
    // the variant that takes the generator, or the message is not reproducible
    let (encapped_key, tag) = single_shot_seal_inout_detached_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &message_receiver,
        HPKE_INFO,
        InOutBuf::from(cesr_message.as_mut_slice()),
        &data,
        &mut SeededRng(&mut csprng),
    )?;

    // the wire ciphertext is CONCAT(enc, ct), with the AEAD tag inside ct (spec 9.2.8)
    let encapped_key = encapped_key.to_bytes();
    let mut ciphertext =
        Vec::with_capacity(encapped_key.len() + cesr_message.len() + AeadTag::<Aead>::size());
    ciphertext.extend(encapped_key.as_slice());
    ciphertext.extend(&cesr_message);
    ciphertext.extend(tag.to_bytes());

    crate::cesr::encode_ciphertext(&ciphertext, crypto_type, &mut data)?;
    crate::cesr::finalize_envelope_frame(&mut data);
    append_signature(sender, &mut data)?;

    Ok(data)
}

/// Open an HPKE-Base message; the KEM is selected by the receiving VID's key type
pub(crate) fn open<'a>(
    receiver: &dyn PrivateVid,
    raw_header: &'a [u8],
    envelope: Envelope<&[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
    match receiver.encryption_key_type() {
        VidEncryptionKeyType::X25519 => {
            open_with_kem::<X25519Kem>(receiver, raw_header, envelope, ciphertext)
        }
        VidEncryptionKeyType::X25519MlKem768 => {
            open_with_kem::<PqKem>(receiver, raw_header, envelope, ciphertext)
        }
    }
}

fn open_with_kem<'a, Kem: KemTrait>(
    receiver: &dyn PrivateVid,
    raw_header: &'a [u8],
    envelope: Envelope<&[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
    // the wire ciphertext is CONCAT(enc, ct); the encapsulated key size is
    // known from the KEM, and the AEAD tag sits at the end of ct
    let enc_size = Kem::EncappedKey::size();
    let tag_size = AeadTag::<Aead>::size();
    if ciphertext.len() < enc_size + tag_size {
        return Err(CryptoError::MissingCiphertext);
    }
    let (encapped_key, rest) = ciphertext.split_at_mut(enc_size);
    let (ciphertext, tag) = rest.split_at_mut(rest.len() - tag_size);

    let receiver_decryption_key = Kem::PrivateKey::from_bytes(receiver.decryption_key().as_ref())?;
    let encapped_key = Kem::EncappedKey::from_bytes(encapped_key)?;
    let tag = AeadTag::<Aead>::from_bytes(tag)?;

    single_shot_open_inout_detached::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &receiver_decryption_key,
        &encapped_key,
        HPKE_INFO,
        InOutBuf::from(&mut *ciphertext),
        raw_header,
        &tag,
    )?;

    open_payload(raw_header, envelope, ciphertext)
}

fn open_payload<'a>(
    raw_header: &[u8],
    envelope: Envelope<&[u8]>,
    ciphertext: &'a mut [u8],
) -> Result<(MessageContents<'a>, Option<ParallelSignatureInfo<'a>>), CryptoError> {
    #[allow(unused_variables)]
    let DecodedPayload {
        payload,
        sender_identity,
    } = crate::cesr::decode_payload(ciphertext)?;

    // verify the embedded self-referencing digest of relationship payloads
    super::verify_relationship_digest(&payload, sender_identity, raw_header)?;

    // In HPKE-Base the sender-VID confidential field is optional (the aad binds
    // the sender identity); when present it MUST match the envelope (spec 8.2.2)
    // it is compared against the envelope rather than the resolved VID's own
    // identifier: a VID being introduced is named in the envelope by the form
    // that carries its verification material, which is not the identifier it
    // resolves to
    if let Some(id) = sender_identity
        && id != envelope.sender
    {
        return Err(CryptoError::UnexpectedSender);
    }

    let (secret_payload, parallel_signature_info) = super::open_payload(payload, sender_identity)?;

    Ok((
        (
            secret_payload,
            envelope.crypto_type,
            envelope.signature_type,
        ),
        parallel_signature_info,
    ))
}

#[cfg(test)]
mod known_answer_tests {
    use super::{Aead, Deserializable, Kdf, KemTrait, PqKem, X25519Kem};
    use hpke::{OpModeR, aead::AeadTag, inout::InOutBuf, single_shot_open_inout_detached};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Decrypt one known-answer encryption: the vector's `ct` carries the AEAD
    /// tag in its final 16 bytes, matching the TSP wire convention (spec 9.2.8)
    fn open_kat<Kem: KemTrait>(skr: &str, enc: &str, info: &str, aad: &str, ct: &str, pt: &str) {
        let secret_key = Kem::PrivateKey::from_bytes(&hex(skr)).unwrap();
        let encapped_key = Kem::EncappedKey::from_bytes(&hex(enc)).unwrap();
        let ct = hex(ct);
        let (mut ciphertext, tag) = {
            let (c, t) = ct.split_at(ct.len() - 16);
            (c.to_vec(), AeadTag::<Aead>::from_bytes(t).unwrap())
        };

        single_shot_open_inout_detached::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &secret_key,
            &encapped_key,
            &hex(info),
            InOutBuf::from(ciphertext.as_mut_slice()),
            &hex(aad),
            &tag,
        )
        .unwrap();

        assert_eq!(ciphertext, hex(pt));
    }

    /// RFC 9180 test vector A.2 (base mode, DHKEM(X25519, HKDF-SHA256),
    /// HKDF-SHA256, ChaCha20Poly1305): the classical TSP cipher suite
    #[test]
    fn rfc_9180_base_x25519_hkdf_sha256_chacha20poly1305() {
        open_kat::<X25519Kem>(
            "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
            "4f6465206f6e2061204772656369616e2055726e",
            "436f756e742d30",
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
            "4265617574792069732074727574682c20747275746820626561757479",
        );
    }

    /// draft-ietf-hpke-pq test vector (base mode, X25519MLKEM768 KEM 0x647a,
    /// HKDF-SHA256, ChaCha20Poly1305): the post-quantum TSP cipher suite.
    /// Source: test-vectors.json of the hpkewg/hpke-pq draft repository
    #[test]
    fn hpke_pq_base_x25519mlkem768_hkdf_sha256_chacha20poly1305() {
        open_kat::<PqKem>(
            "b6bfa0299b955e85224df2e468f29eeab377ff3b96d4462b39447a22d32b91be",
            "ab354dd589f74ee0eab7718a630cbec5df1d09058e177cd6dd141d883450ddd70c050d88bed3d07cce23415cab411108cc30906482a71adcb134a56e978a6152a8e063b24acd1534f264f10458152a9ed4f1f32b3d480c4f2453b7fdea7720146b3ee92cf8a13a4840076f68c911c65fa3db5053fb0aabf79e64cd5e7aa71b2b9641e713ec7df552e17d5020f8721ee449b42c888e2a3f87cfd96e3a98c3e7c4cd8f647f899570f596bf17d2b6fa2cad19706d9cc3cf09493e1c7ffa0eb2a4559ae1d940fdbef97bed383e6ccfdb448d9f1a81805166b32c2af2e16878c6dc46ab43323ed9c136b925239782e3c329c31a5cf2a80faf025a80766e244605c27afe4b624d9d8ca99b6ef5439ed1ad044b518c434385acd49f1369ded6624a2832a571ccdd70d08b3c04cb1cd3136166f9a485f536f69ec66f0293e840025ccaac42f8e5f7c9cb818076c272797047f5e50c1e9f1dab81cfb48fe4c4998b2427f009702b145f34ad8dbc3e7ad4e4023057ba31cd02c4c0545ebf71eb02533e8eaa2b2f2690ee1407bf1f66dc5f4d836c45b82f10b720df72d237488a9af1b6dfb4741fd613379c2e211e77f7fae6b3734ad81de2d452005334857c4a3cbc82afc7428fe510495969b296d24e1a7431f557d48578cf92ae86c0392f0ba73755a9e5465c8e3495e4cd2a82d463244341e39414e26c9b242f31d2cf0e46b2aeb11dd5e56ec44834350d151344229e410faff2b2ace5c9b3fa12571db1d28da2c7133492781dac41b7a7e2bac2260fd12f56939033587824c9dfb17d41b3bceea53763193abe0c7c184d5de161ef5312f31fab42478c9a193b868e4d29b2b7624f3ebe740f393d03d843cd5327286a579fd2a6e37aca5b64f9316115d612c7781e704ea7d182701c5019975cad14fbf4ab3904d4a35acaf0be32d716a1ef5d7188fc418ae9e60744325a3e8001655b756df94c24031c3ce32bd90c0ecdac52ca140fdad7f44d04bd0a7e2a726c54cf9793f8784a23296f65da3fd1cbc18300d503c5b27be99b9b0e32d20b3614dc8a999f30c2779dd7886cfd486dc1c93ebcf517b5210a4359d9fa1805381f0f2261ff47de01de555d98bc1a30dda557a83007b61636abaf9041f96890f0f565eefc45859fbcd32d91b203215541227a4fcc3d95be2ddb0702878caa20f2da62c4ff9fe33af591ba1ec241fbe2208e0480f8b1cca1679c096f8f5a02a33e9df445b3274ac112b43d51510135cd3f532a3379e90bb7f0cb43717e90555bb1a80924cc69577455687cceb9b1610c05839541e87ad83d79ef3ff24ace1934cfbe989691959d93ac48c716b672b370dd4c144ca1e32508707a6ef8aa29b55759b3d054c56bee1baa6f41b84b9fc3fd681a1a1528eac578141529836a29dda1501a49ba2455367256d2fe6f74ebb74ef9a49a94a4c6cd1dd09810f0e9bffa69dd8c94d226d0b2977b11a35382888961004a44c60fd602e9ff4271287e9240ba96146515b9db9da60375aeeafeac1eeb764faebacd197df27817c35fe4c5c802e43349d7bc95c8b40c001449d3251c1d92ff6d5c3b08c4b27c",
            "34663634363532303666366532303631323034373732363536333639363136653230353537323665",
            "436f756e742d30",
            "a4ab74475a498ed725f685421f67c09a4783fe76f67bd251e1e73db8eb1452dfad4df3c6453f7edecc7bb055dde561e2efd54d73a3d4f1f2f02eac90ba1e9b84ded66d43aee6393524db",
            "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739",
        );
    }
}
