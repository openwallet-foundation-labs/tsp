use super::ReceivedTspMessage;

// Rust, there has to be a better way.
impl<T: AsRef<[u8]>> ReceivedTspMessage<T> {
    /// Turn a ReceivedTspMessage that contains references to borrowed data into a freestanding version;
    /// if it already was a freestanding version, nothing happens.
    // We only offer this version as the 'public' version, since the second can be confusing
    pub fn into_owned(self) -> ReceivedTspMessage
    where
        T: Into<Vec<u8>>,
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
                nonconfidential_data,
                message,
                message_type,
            } => GenericMessage {
                sender,
                nonconfidential_data: nonconfidential_data.map(&f),
                message: f(message),
                message_type,
            },
            RequestRelationship {
                sender,
                route,
                nested_vid,
                thread_id,
            } => RequestRelationship {
                sender,
                route,
                nested_vid,
                thread_id,
            },
            AcceptRelationship { sender, nested_vid } => AcceptRelationship { sender, nested_vid },
            CancelRelationship { sender } => CancelRelationship { sender },
            ForwardRequest {
                sender,
                next_hop,
                route,
                opaque_payload,
            } => ForwardRequest {
                sender,
                next_hop,
                route,
                opaque_payload,
            },
            NewIdentifier { sender, new_vid } => NewIdentifier { sender, new_vid },
            Referral {
                sender,
                referred_vid,
            } => Referral {
                sender,
                referred_vid,
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
