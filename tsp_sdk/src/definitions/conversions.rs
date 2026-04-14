use super::{ReceivedRelationshipDelivery, ReceivedRelationshipForm, ReceivedTspMessage};
use bytes::BytesMut;

// Rust, there has to be a better way.
impl<T: AsRef<[u8]>> ReceivedTspMessage<T> {
    /// Turn a ReceivedTspMessage that contains references to borrowed data into a freestanding version;
    /// if it already was a freestanding version, nothing happens.
    // We only offer this version as the 'public' version, since the second can be confusing
    pub fn into_owned(self) -> ReceivedTspMessage
    where
        T: Into<BytesMut>,
    {
        self.map(|x| x.into())
    }

    /// Convert the data representation used by a ReceivedTspMessage; we are careful with the payload data
    /// since it may be very large.
    pub(crate) fn map<U: AsRef<[u8]>>(self, f: impl Fn(T) -> U) -> ReceivedTspMessage<U> {
        use ReceivedTspMessage::*;
        match self {
            GenericMessage {
                sender,
                receiver,
                nonconfidential_data,
                message,
                message_type,
            } => GenericMessage {
                sender,
                receiver,
                nonconfidential_data: nonconfidential_data.map(&f),
                message: f(message),
                message_type,
            },
            RequestRelationship {
                sender,
                receiver,
                thread_id,
                form,
                delivery,
            } => RequestRelationship {
                sender,
                receiver,
                thread_id,
                form: match form {
                    ReceivedRelationshipForm::Direct => ReceivedRelationshipForm::Direct,
                    ReceivedRelationshipForm::Parallel {
                        new_vid,
                        sig_new_vid,
                    } => ReceivedRelationshipForm::Parallel {
                        new_vid,
                        sig_new_vid: f(sig_new_vid),
                    },
                },
                delivery: match delivery {
                    ReceivedRelationshipDelivery::Direct => ReceivedRelationshipDelivery::Direct,
                    ReceivedRelationshipDelivery::Nested { nested_vid } => {
                        ReceivedRelationshipDelivery::Nested { nested_vid }
                    }
                    ReceivedRelationshipDelivery::Routed => ReceivedRelationshipDelivery::Routed,
                },
            },
            AcceptRelationship {
                sender,
                receiver,
                thread_id,
                reply_thread_id,
                form,
                delivery,
            } => AcceptRelationship {
                sender,
                receiver,
                thread_id,
                reply_thread_id,
                form: match form {
                    ReceivedRelationshipForm::Direct => ReceivedRelationshipForm::Direct,
                    ReceivedRelationshipForm::Parallel {
                        new_vid,
                        sig_new_vid,
                    } => ReceivedRelationshipForm::Parallel {
                        new_vid,
                        sig_new_vid: f(sig_new_vid),
                    },
                },
                delivery: match delivery {
                    ReceivedRelationshipDelivery::Direct => ReceivedRelationshipDelivery::Direct,
                    ReceivedRelationshipDelivery::Nested { nested_vid } => {
                        ReceivedRelationshipDelivery::Nested { nested_vid }
                    }
                    ReceivedRelationshipDelivery::Routed => ReceivedRelationshipDelivery::Routed,
                },
            },
            CancelRelationship { sender, receiver } => CancelRelationship { sender, receiver },
            ForwardRequest {
                sender,
                receiver,
                next_hop,
                route,
                opaque_payload,
            } => ForwardRequest {
                sender,
                receiver,
                next_hop,
                route,
                opaque_payload,
            },
            #[cfg(feature = "async")]
            PendingMessage {
                unknown_vid,
                payload,
            } => PendingMessage {
                unknown_vid,
                payload,
            },
        }
    }
}
