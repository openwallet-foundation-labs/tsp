use super::*;

#[derive(Debug)]
pub struct Wrapper(pub Payload<'static, Vec<u8>, Vec<u8>>);

impl<'a> arbitrary::Arbitrary<'a> for Wrapper {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        const DIGEST: [u8; 32] = {
            let mut buf = [0; 32];
            let mut i = 0;
            while i < buf.len() {
                buf[i] = i as u8;
                i += 1;
            }

            buf
        };

        #[derive(arbitrary::Arbitrary)]
        enum Variants {
            GenericMessage,
            ControlMessage,
            Padding,
            NestedMessage,
            RoutedMessage,
            RelationProposal,
            RelationAffirm,
            RelationshipCancel,
        }

        #[allow(dead_code)]
        fn check_exhaustive(payload: Payload<Vec<u8>, Vec<u8>>) -> Variants {
            match payload {
                Payload::GenericMessage(_) => Variants::GenericMessage,
                Payload::ControlMessage(_) => Variants::ControlMessage,
                Payload::Padding { .. } => Variants::Padding,
                Payload::NestedMessage(_) => Variants::NestedMessage,
                Payload::RoutedMessage(_, _) => Variants::RoutedMessage,
                Payload::RelationProposal { .. } => Variants::RelationProposal,
                Payload::RelationAffirm { .. } => Variants::RelationAffirm,
                Payload::RelationshipCancel { .. } => Variants::RelationshipCancel,
            }
        }

        let variant = Variants::arbitrary(u)?;

        let digest = if Arbitrary::arbitrary(u)? {
            Digest::Sha2_256
        } else {
            Digest::Blake2b256
        };

        use arbitrary::Arbitrary;
        let payload = match variant {
            Variants::GenericMessage => Payload::GenericMessage(Arbitrary::arbitrary(u)?),
            Variants::ControlMessage => Payload::ControlMessage(Arbitrary::arbitrary(u)?),
            Variants::Padding => Payload::Padding {
                nonce: Nonce(Arbitrary::arbitrary(u)?),
            },
            Variants::NestedMessage => Payload::NestedMessage(Arbitrary::arbitrary(u)?),
            Variants::RoutedMessage => {
                Payload::RoutedMessage(Arbitrary::arbitrary(u)?, Arbitrary::arbitrary(u)?)
            }
            Variants::RelationProposal => Payload::RelationProposal {
                request_digest: digest(&DIGEST),
                nonce: Nonce(Arbitrary::arbitrary(u)?),
                reply_path: Arbitrary::arbitrary(u)?,
                referral: if Arbitrary::arbitrary(u)? {
                    Some((Arbitrary::arbitrary(u)?, &[42; 64]))
                } else {
                    None
                },
            },
            Variants::RelationAffirm => Payload::RelationAffirm {
                request_digest: digest(&DIGEST),
                reply_digest: digest(&DIGEST),
            },
            Variants::RelationshipCancel => Payload::RelationshipCancel {
                reply: digest(&DIGEST),
            },
        };

        Ok(Wrapper(payload))
    }
}

impl<'a> PartialEq<Payload<'a, &'a mut [u8], &'a [u8]>> for Wrapper {
    fn eq(&self, other: &Payload<'a, &'a mut [u8], &'a [u8]>) -> bool {
        match (&self.0, other) {
            (Payload::GenericMessage(l0), Payload::GenericMessage(r0)) => l0 == r0,
            (Payload::ControlMessage(l0), Payload::ControlMessage(r0)) => l0 == r0,
            (Payload::Padding { nonce: l_nonce }, Payload::Padding { nonce: r_nonce }) => {
                l_nonce.0 == r_nonce.0
            }
            (Payload::NestedMessage(l0), Payload::NestedMessage(r0)) => l0 == r0,
            (Payload::RoutedMessage(l0, l1), Payload::RoutedMessage(r0, r1)) => {
                l0 == r0 && l1 == r1
            }
            (
                Payload::RelationProposal {
                    request_digest: l_request,
                    nonce: l_nonce,
                    reply_path: l_path,
                    referral: l_referral,
                },
                Payload::RelationProposal {
                    request_digest: r_request,
                    nonce: r_nonce,
                    reply_path: r_path,
                    referral: r_referral,
                },
            ) => {
                l_request == r_request
                    && l_nonce.0 == r_nonce.0
                    && l_path == r_path
                    // the signature bytes are not carried through the wrapper
                    && l_referral.as_ref().map(|(vid, _)| vid.as_slice())
                        == r_referral.as_ref().map(|(vid, _)| *vid)
            }
            (
                Payload::RelationAffirm {
                    request_digest: l_request,
                    reply_digest: l_reply,
                },
                Payload::RelationAffirm {
                    request_digest: r_request,
                    reply_digest: r_reply,
                },
            ) => l_request == r_request && l_reply == r_reply,
            (
                Payload::RelationshipCancel { reply: l_reply },
                Payload::RelationshipCancel { reply: r_reply },
            ) => l_reply == r_reply,
            _ => false,
        }
    }
}

#[cfg(feature = "fuzzing")]
#[derive(Debug, arbitrary::Arbitrary)]
pub struct FuzzInput {
    pub sender_sign_key: [u8; 32],
    pub sender_enc_key: [u8; 32],
    pub receiver_sign_key: [u8; 32],
    pub receiver_enc_key: [u8; 32],
    pub payload: Vec<u8>,
}
