use crate::{
    ExportVid, OwnedVid, PrivateVid,
    definitions::{Digest, ReceivedTspMessage, TSPStream, VerifiedVid},
    error::Error,
    store::Store,
};
use bytes::BytesMut;
use futures::StreamExt;
use url::Url;

/// Holds private and verified VIDs
///
/// A Store contains verified VIDs, our relationship status to them,
/// as well as the private VIDs that this application has control over.
///
/// # Example
///
/// ```rust
/// use tsp::{AsyncStore, OwnedVid, Error, ReceivedTspMessage};
///
/// #[tokio::main]
/// async fn main() {
///     // alice database
///     let mut db = AsyncStore::new();
///     let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json").await.unwrap();
///     db.add_private_vid(alice_vid).unwrap();
///     db.verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob").await.unwrap();
///
///     // send a message
///     let result = db.send(
///         "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
///         "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
///         Some(b"extra non-confidential data"),
///         b"hello world",
///     ).await;
/// }
/// ```
#[derive(Default)]
pub struct AsyncStore {
    inner: Store,
}

impl AsyncStore {
    /// Create a new and empty store
    pub fn new() -> Self {
        Default::default()
    }

    /// Export the database to serializable default types
    pub fn export(&self) -> Result<Vec<ExportVid>, Error> {
        self.inner.export()
    }

    /// Expose the inner non-async database
    pub fn as_store(&self) -> &Store {
        &self.inner
    }

    /// Import the database from serializable default types
    pub fn import(&self, vids: Vec<ExportVid>) -> Result<(), Error> {
        self.inner.import(vids)
    }

    /// Adds a relation to an already existing VID, making it a nested VID
    pub fn set_relation_for_vid(&self, vid: &str, relation_vid: Option<&str>) -> Result<(), Error> {
        self.inner.set_relation_for_vid(vid, relation_vid)
    }

    /// Adds a route to an already existing VID, making it a nested VID
    pub fn set_route_for_vid(&self, vid: &str, route: &[&str]) -> Result<(), Error> {
        self.inner.set_route_for_vid(vid, route)
    }

    /// Sets the parent for a VID. This is used to create a nested message.
    pub fn set_parent_for_vid(&self, vid: &str, parent: Option<&str>) -> Result<(), Error> {
        self.inner.set_parent_for_vid(vid, parent)
    }

    /// List all VIDs in the database
    pub fn list_vids(&self) -> Result<Vec<String>, Error> {
        self.inner.list_vids()
    }

    /// Adds `private_vid` to the database
    pub fn add_private_vid(
        &self,
        private_vid: impl PrivateVid + Clone + 'static,
    ) -> Result<(), Error> {
        self.inner.add_private_vid(private_vid)
    }

    /// Remove a VID from the [`AsyncStore`]
    pub fn forget_vid(&self, vid: &str) -> Result<(), Error> {
        self.inner.forget_vid(vid)
    }

    /// Add the already resolved `verified_vid` to the database as a relationship
    pub fn add_verified_vid(&self, verified_vid: impl VerifiedVid + 'static) -> Result<(), Error> {
        self.inner.add_verified_vid(verified_vid)
    }

    /// Check whether the [PrivateVid] identified by `vid` exists in the database
    pub fn has_private_vid(&self, vid: &str) -> Result<bool, Error> {
        self.inner.has_private_vid(vid)
    }

    /// Resolve and verify public key material for a VID identified by `vid` and add it to the database as a relationship
    pub async fn verify_vid(&mut self, vid: &str) -> Result<(), Error> {
        let verified_vid = crate::vid::verify_vid(vid).await?;

        self.inner.add_verified_vid(verified_vid)?;

        Ok(())
    }

    /// Send a TSP message given earlier resolved VIDs
    /// Encodes, encrypts, signs, and sends a TSP message
    ///
    /// # Arguments
    ///
    /// * `sender`               - A sender VID
    /// * `receiver`             - A receiver VID
    /// * `nonconfidential_data` - Optional extra non-confidential data
    /// * `payload`              - The raw message payload as byte slice
    ///
    /// # Example
    ///
    /// ```rust
    /// use tsp::{AsyncStore, OwnedVid};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut db = AsyncStore::new();
    ///     let private_vid = OwnedVid::from_file("../examples/test/bob/piv.json").await.unwrap();
    ///     db.add_private_vid(private_vid).unwrap();
    ///     db.verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice").await.unwrap();
    ///
    ///     let sender = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob";
    ///     let receiver = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice";
    ///
    ///     let result = db.send(sender, receiver, None, b"hello world").await;
    /// }
    /// ```
    pub async fn send(
        &self,
        sender: &str,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<(), Error> {
        let (endpoint, message) =
            self.inner
                .seal_message(sender, receiver, nonconfidential_data, message)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(())
    }

    /// Request a direct relationship with a resolved VID using the TSP
    /// Encodes the control message, encrypts, signs, and sends a TSP message
    ///
    /// # Arguments
    ///
    /// * `sender`               - A sender VID
    /// * `receiver`             - A receiver VID
    ///
    /// # Example
    ///
    /// ```rust
    /// use tsp::{AsyncStore, OwnedVid};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut db = AsyncStore::new();
    ///     let private_vid = OwnedVid::from_file("../examples/test/bob/piv.json").await.unwrap();
    ///     db.add_private_vid(private_vid).unwrap();
    ///     db.verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice").await.unwrap();
    ///
    ///     let sender = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob";
    ///     let receiver = "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice";
    ///
    ///     let result = db.send_relationship_request(sender, receiver, None).await;
    /// }
    /// ```
    pub async fn send_relationship_request(
        &self,
        sender: &str,
        receiver: &str,
        route: Option<&[&str]>,
    ) -> Result<(), Error> {
        let (endpoint, message) = self
            .inner
            .make_relationship_request(sender, receiver, route)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(())
    }

    /// Accept a direct relationship between the resolved VIDs identifier by `sender` and `receiver`.
    /// `thread_id` must be the same as the one that was present in the relationship request.
    /// Encodes the control message, encrypts, signs, and sends a TSP message
    pub async fn send_relationship_accept(
        &self,
        sender: &str,
        receiver: &str,
        thread_id: Digest,
        route: Option<&[&str]>,
    ) -> Result<(), Error> {
        let (endpoint, message) = self
            .inner
            .make_relationship_accept(sender, receiver, thread_id, route)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(())
    }

    /// Cancels a direct relationship between the resolved `sender` and `receiver` VIDs.
    /// Encodes the control message, encrypts, signs, and sends a TSP message
    pub async fn send_relationship_cancel(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(), Error> {
        let (endpoint, message) = self.inner.make_relationship_cancel(sender, receiver)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(())
    }

    /// Send a new identifier introduction notice
    pub async fn send_new_identifier_notice(
        &self,
        sender: &str,
        receiver: &str,
        sender_new_vid: &str,
    ) -> Result<(), Error> {
        let (endpoint, message) =
            self.inner
                .make_new_identifier_notice(sender, receiver, sender_new_vid)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(())
    }

    /// Send a relationship referral message to `receiver`
    pub async fn send_relationship_referral(
        &self,
        sender: &str,
        receiver: &str,
        referred_vid: &str,
    ) -> Result<(), Error> {
        let (endpoint, message) =
            self.inner
                .make_relationship_referral(sender, receiver, referred_vid)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(())
    }

    /// Send a nested relationship request to `receiver`, creating a new nested vid with `outer_sender` as a parent.
    pub async fn send_nested_relationship_request(
        &self,
        parent_sender: &str,
        receiver: &str,
    ) -> Result<OwnedVid, Error> {
        let ((endpoint, message), vid) = self
            .inner
            .make_nested_relationship_request(parent_sender, receiver)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(vid)
    }

    /// Accept a nested relationship with the (nested) VID identified by `nested_receiver`.
    /// Generate a new nested VID that will have `parent_sender` as its parent.
    /// `thread_id` must be the same as the one that was present in the relationship request.
    /// Encodes the control message, encrypts, signs, and sends a TSP message
    pub async fn send_nested_relationship_accept(
        &self,
        parent_sender: &str,
        nested_receiver: &str,
        thread_id: Digest,
    ) -> Result<OwnedVid, Error> {
        let ((endpoint, message), vid) = self.inner.make_nested_relationship_accept(
            parent_sender,
            nested_receiver,
            thread_id,
        )?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(vid)
    }

    /// Pass along an in-transit routed TSP `opaque_message`
    /// that is not meant for us, given earlier resolved VIDs.
    /// The message is routed through the route that has been established with `receiver`.
    pub async fn forward_routed_message(
        &self,
        next_hop: &str,
        path: Vec<impl AsRef<[u8]>>,
        opaque_message: &[u8],
    ) -> Result<Url, Error> {
        let (transport, message) = self.inner.forward_routed_message(
            next_hop,
            path.iter().map(|x| x.as_ref()).collect(),
            opaque_message,
        )?;

        crate::transport::send_message(&transport, &message).await?;

        Ok(transport)
    }

    /// Decode an encrypted `message`, which has to be addressed to one of the VIDs in `receivers`,
    /// and has to have `verified_vids` as one of the senders.
    pub fn open_message<'a>(
        &self,
        message: &'a mut [u8],
    ) -> Result<ReceivedTspMessage<&'a [u8]>, Error> {
        self.inner.open_message(message)
    }

    /// Receive TSP messages for the private VID identified by `vid`, using the appropriate transport mechanism for it.
    /// Messages will be queued in a channel
    /// The returned channel contains a maximum of 16 messages
    pub async fn receive(&self, vid: &str) -> Result<TSPStream<ReceivedTspMessage, Error>, Error> {
        let receiver = self.inner.get_private_vid(vid)?;
        let mut transport = receiver.endpoint().clone();
        let path = transport.path().replace("[vid_placeholder]", vid);
        transport.set_path(&path);

        tracing::trace!("Listening for {vid} to {transport}");

        let messages = crate::transport::receive_messages(&transport).await?;

        let db = self.inner.clone();
        Ok(Box::pin(messages.then(move |message| {
            let db_inner = db.clone();
            async move {
                match message {
                    Ok(mut m) => match db_inner.open_message(&mut m) {
                        Err(Error::UnverifiedSource(unknown_vid, opaque_data)) => {
                            Ok(ReceivedTspMessage::PendingMessage {
                                unknown_vid,
                                payload: opaque_data.unwrap_or(m),
                            })
                        }
                        maybe_message => maybe_message.map(|msg| msg.into_owned()).map_err(|e| {
                            tracing::error!("{}", e);
                            e
                        }),
                    },
                    Err(e) => Err(e.into()),
                }
            }
        })))
    }

    /// Send a TSP broadcast message to the specified VIDs
    pub async fn send_anycast(
        &self,
        sender: &str,
        receivers: impl IntoIterator<Item = impl AsRef<str>>,
        nonconfidential_message: &[u8],
    ) -> Result<(), Error> {
        let message = self.inner.sign_anycast(sender, nonconfidential_message)?;

        for vid in receivers {
            let receiver = self.inner.get_verified_vid(vid.as_ref())?;

            crate::transport::send_message(receiver.endpoint(), &message).await?;
        }

        Ok(())
    }

    /// Process the payload from a 'PendingMessage' by resolving the unknown vid and retrying
    /// This takes a Vec as a payload; for a borrowing version the `as_inner()` version can be used;
    /// usually after unpacking a TSP message, you can't or need to do anything with it anyway.
    pub async fn verify_and_open(
        &mut self,
        vid: &str,
        mut payload: BytesMut,
    ) -> Result<ReceivedTspMessage, Error> {
        self.verify_vid(vid).await?;

        Ok(self.inner.open_message(&mut payload)?.into_owned())
    }
}
