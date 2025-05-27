use crate::store::WebvhUpdateKeys;
use crate::{
    ExportVid, OwnedVid, PrivateVid, RelationshipStatus,
    definitions::{Digest, ReceivedTspMessage, TSPStream, VerifiedVid},
    error::Error,
    store::{Aliases, SecureStore},
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
/// use tsp_sdk::{AsyncSecureStore, OwnedVid, Error, ReceivedTspMessage};
///
/// #[tokio::main]
/// async fn main() {
///     // alice wallet
///     let mut db = AsyncSecureStore::new();
///     let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json").await.unwrap();
///     db.add_private_vid(alice_vid, None).unwrap();
///     db.verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob", None).await.unwrap();
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
pub struct AsyncSecureStore {
    inner: SecureStore,
}

impl AsyncSecureStore {
    /// Create a new and empty store
    pub fn new() -> Self {
        Default::default()
    }

    /// Export the wallet to serializable default types
    pub fn export(&self) -> Result<(Vec<ExportVid>, Aliases, WebvhUpdateKeys), Error> {
        self.inner.export()
    }

    /// Expose the inner non-async wallet
    pub fn as_store(&self) -> &SecureStore {
        &self.inner
    }

    /// Import the wallet from serializable default types
    pub fn import(
        &self,
        vids: Vec<ExportVid>,
        aliases: Aliases,
        keys: WebvhUpdateKeys,
    ) -> Result<(), Error> {
        self.inner.import(vids, aliases, keys)
    }

    /// Adds a relation to an already existing VID, making it a nested VID
    pub fn set_relation_and_status_for_vid(
        &self,
        vid: &str,
        status: RelationshipStatus,
        relation_vid: &str,
    ) -> Result<(), Error> {
        self.inner
            .set_relation_and_status_for_vid(vid, status, relation_vid)
    }

    /// Adds a route to an already existing VID, making it a nested VID
    pub fn set_route_for_vid(&self, vid: &str, route: &[&str]) -> Result<(), Error> {
        self.inner.set_route_for_vid(vid, route)
    }

    /// Sets the parent for a VID. This is used to create a nested message.
    pub fn set_parent_for_vid(&self, vid: &str, parent: Option<&str>) -> Result<(), Error> {
        self.inner.set_parent_for_vid(vid, parent)
    }

    /// List all VIDs in the wallet
    pub fn list_vids(&self) -> Result<Vec<String>, Error> {
        self.inner.list_vids()
    }

    /// Adds `private_vid` to the wallet
    pub fn add_private_vid(
        &self,
        private_vid: impl PrivateVid + Clone + 'static,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        self.inner.add_private_vid(private_vid, metadata)
    }

    /// Remove a VID from the [`AsyncSecureStore`]
    pub fn forget_vid(&self, vid: &str) -> Result<(), Error> {
        self.inner.forget_vid(vid)
    }

    /// Add the already resolved `verified_vid` to the wallet as a relationship
    pub fn add_verified_vid(
        &self,
        verified_vid: impl VerifiedVid + 'static,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        self.inner.add_verified_vid(verified_vid, metadata)
    }

    /// Check whether the [PrivateVid] identified by `vid` exists in the wallet
    pub fn has_private_vid(&self, vid: &str) -> Result<bool, Error> {
        self.inner.has_private_vid(vid)
    }

    /// Check whether the [VerifiedVid] identified by `vid` exists in the wallet
    pub fn has_verified_vid(&self, vid: &str) -> Result<bool, Error> {
        self.inner.has_verified_vid(vid)
    }

    /// Resolve and verify public key material for a VID identified by `vid` and add it to the wallet as a relationship
    pub async fn verify_vid(&mut self, vid: &str, alias: Option<String>) -> Result<(), Error> {
        let (verified_vid, metadata) = crate::vid::verify_vid(vid).await?;

        self.inner.add_verified_vid(verified_vid, metadata)?;

        if let Some(alias) = alias {
            self.set_alias(alias, vid.to_owned())?;
        }

        Ok(())
    }

    /// Resolve alias to its corresponding DID
    pub fn resolve_alias(&self, alias: &str) -> Result<Option<String>, Error> {
        self.inner.resolve_alias(alias)
    }

    /// Resolve alias to its corresponding DID
    pub fn try_resolve_alias(&self, alias: &str) -> Result<String, Error> {
        self.inner.try_resolve_alias(alias)
    }

    /// Set alias for a DID
    pub fn set_alias(&self, alias: String, did: String) -> Result<(), Error> {
        self.inner.set_alias(alias, did)
    }

    pub fn add_secret_key(&self, kid: String, secret_key: Vec<u8>) -> Result<(), Error> {
        self.inner.add_secret_key(kid, secret_key)
    }

    pub fn get_secret_key(&self, kid: &str) -> Result<Option<Vec<u8>>, Error> {
        self.inner.get_secret_key(kid)
    }

    pub fn seal_message(
        &self,
        sender: &str,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<(Url, Vec<u8>), Error> {
        self.inner
            .seal_message(sender, receiver, nonconfidential_data, message)
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
    /// use tsp_sdk::{AsyncSecureStore, OwnedVid};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut db = AsyncSecureStore::new();
    ///     let private_vid = OwnedVid::from_file("../examples/test/bob/piv.json").await.unwrap();
    ///     db.add_private_vid(private_vid, None).unwrap();
    ///     db.verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None).await.unwrap();
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
        match self.inner.relation_status_for_vid_pair(sender, receiver) {
            Ok(relation) => {
                if matches!(relation, RelationshipStatus::Unrelated) {
                    self.send_relationship_request(sender, receiver, None)
                        .await?
                }
            }
            Err(Error::Relationship(_)) => {
                self.send_relationship_request(sender, receiver, None)
                    .await?
            }
            Err(e) => return Err(e),
        };

        let (endpoint, message) =
            self.inner
                .seal_message(sender, receiver, nonconfidential_data, message)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(())
    }

    pub fn make_relationship_request(
        &self,
        sender: &str,
        receiver: &str,
        route: Option<&[&str]>,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.inner
            .make_relationship_request(sender, receiver, route)
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
    /// use tsp_sdk::{AsyncSecureStore, OwnedVid};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut db = AsyncSecureStore::new();
    ///     let private_vid = OwnedVid::from_file("../examples/test/bob/piv.json").await.unwrap();
    ///     db.add_private_vid(private_vid, None).unwrap();
    ///     db.verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None).await.unwrap();
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

    pub fn make_relationship_accept(
        &self,
        sender: &str,
        receiver: &str,
        thread_id: Digest,
        route: Option<&[&str]>,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.inner
            .make_relationship_accept(sender, receiver, thread_id, route)
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
        let (endpoint, message) =
            self.make_relationship_accept(sender, receiver, thread_id, route)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(())
    }

    pub fn make_relationship_cancel(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.inner.make_relationship_cancel(sender, receiver)
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

    pub fn make_new_identifier_notice(
        &self,
        sender: &str,
        receiver: &str,
        sender_new_vid: &str,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.inner
            .make_new_identifier_notice(sender, receiver, sender_new_vid)
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

    pub fn make_relationship_referral(
        &self,
        sender: &str,
        receiver: &str,
        referred_vid: &str,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.inner
            .make_relationship_referral(sender, receiver, referred_vid)
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

    pub fn make_nested_relationship_request(
        &self,
        parent_sender: &str,
        receiver: &str,
    ) -> Result<((Url, Vec<u8>), OwnedVid), Error> {
        self.inner
            .make_nested_relationship_request(parent_sender, receiver)
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

    pub fn make_nested_relationship_accept(
        &self,
        parent_sender: &str,
        nested_receiver: &str,
        thread_id: Digest,
    ) -> Result<((Url, Vec<u8>), OwnedVid), Error> {
        self.inner
            .make_nested_relationship_accept(parent_sender, nested_receiver, thread_id)
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
        let ((endpoint, message), vid) =
            self.make_nested_relationship_accept(parent_sender, nested_receiver, thread_id)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(vid)
    }

    pub fn make_next_routed_message(
        &self,
        next_hop: &str,
        path: Vec<impl AsRef<[u8]>>,
        opaque_message: &[u8],
    ) -> Result<(Url, Vec<u8>), Error> {
        self.inner.forward_routed_message(
            next_hop,
            path.iter().map(|x| x.as_ref()).collect(),
            opaque_message,
        )
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
        let (transport, message) = self.make_next_routed_message(next_hop, path, opaque_message)?;

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
        let path = transport
            .path()
            .replace("[vid_placeholder]", &self.inner.try_resolve_alias(vid)?);
        transport.set_path(&path);

        tracing::trace!("Listening for {vid} on {transport}");

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
        self.verify_vid(vid, None).await?;

        Ok(self.inner.open_message(&mut payload)?.into_owned())
    }
}
