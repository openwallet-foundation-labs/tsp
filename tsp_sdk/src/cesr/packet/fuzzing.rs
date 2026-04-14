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
            NestedMessage,
            RoutedMessage,
            DirectRelationProposal,
            DirectRelationAffirm,
            ParallelRelationProposal,
            ParallelRelationAffirm,
            RelationshipCancel,
        }

        #[allow(dead_code)]
        fn check_exhaustive(payload: Payload<Vec<u8>, Vec<u8>>) -> Variants {
            match payload {
                Payload::GenericMessage(_) => Variants::GenericMessage,
                Payload::NestedMessage(_) => Variants::NestedMessage,
                Payload::RoutedMessage(_, _) => Variants::RoutedMessage,
                Payload::DirectRelationProposal { .. } => Variants::DirectRelationProposal,
                Payload::DirectRelationAffirm { .. } => Variants::DirectRelationAffirm,
                Payload::ParallelRelationProposal { .. } => Variants::ParallelRelationProposal,
                Payload::ParallelRelationAffirm { .. } => Variants::ParallelRelationAffirm,
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
            Variants::NestedMessage => Payload::NestedMessage(Arbitrary::arbitrary(u)?),
            Variants::RoutedMessage => {
                Payload::RoutedMessage(Arbitrary::arbitrary(u)?, Arbitrary::arbitrary(u)?)
            }
            Variants::DirectRelationProposal => Payload::DirectRelationProposal {
                nonce: Nonce(Arbitrary::arbitrary(u)?),
                request_digest: digest(&DIGEST),
            },
            Variants::DirectRelationAffirm => Payload::DirectRelationAffirm {
                request_digest: digest(&DIGEST),
                reply_digest: digest(&DIGEST),
            },
            Variants::ParallelRelationProposal => Payload::ParallelRelationProposal {
                nonce: Nonce(Arbitrary::arbitrary(u)?),
                request_digest: digest(&DIGEST),
                new_vid: Arbitrary::arbitrary(u)?,
                sig_new_vid: &[42; 64],
            },
            Variants::ParallelRelationAffirm => Payload::ParallelRelationAffirm {
                request_digest: digest(&DIGEST),
                reply_digest: digest(&DIGEST),
                new_vid: Arbitrary::arbitrary(u)?,
                sig_new_vid: &[24; 64],
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
            (Payload::NestedMessage(l0), Payload::NestedMessage(r0)) => l0 == r0,
            (Payload::RoutedMessage(l0, l1), Payload::RoutedMessage(r0, r1)) => {
                l0 == r0 && l1 == r1
            }
            (
                Payload::DirectRelationProposal {
                    nonce: l_nonce,
                    request_digest: l_request_digest,
                },
                Payload::DirectRelationProposal {
                    nonce: r_nonce,
                    request_digest: r_request_digest,
                },
            ) => l_nonce.0 == r_nonce.0 && l_request_digest == r_request_digest,
            (
                Payload::DirectRelationAffirm {
                    request_digest: l_request,
                    reply_digest: l_reply,
                },
                Payload::DirectRelationAffirm {
                    request_digest: r_request,
                    reply_digest: r_reply,
                },
            ) => l_request == r_request && l_reply == r_reply,
            (
                Payload::ParallelRelationProposal {
                    new_vid: l_vid,
                    request_digest: l_request,
                    sig_new_vid: _l_sig,
                    nonce: l_nonce,
                },
                Payload::ParallelRelationProposal {
                    new_vid: r_vid,
                    request_digest: r_request,
                    sig_new_vid: _r_sig,
                    nonce: r_nonce,
                },
            ) => l_vid == r_vid && l_request == r_request && l_nonce == r_nonce,
            (
                Payload::ParallelRelationAffirm {
                    request_digest: l_request,
                    reply_digest: l_reply,
                    new_vid: l_vid,
                    sig_new_vid: _l_sig,
                },
                Payload::ParallelRelationAffirm {
                    request_digest: r_request,
                    reply_digest: r_reply,
                    new_vid: r_vid,
                    sig_new_vid: _r_sig,
                },
            ) => l_request == r_request && l_reply == r_reply && l_vid == r_vid,
            (
                Payload::RelationshipCancel { reply: l_reply },
                Payload::RelationshipCancel { reply: r_reply },
            ) => l_reply == r_reply,
            _ => false,
        }
    }
}
