use crate::{
    definitions::{
        Digest, Payload, ReceivedTspMessage, RelationshipStatus, TSPStream, VerifiedVid,
    },
    error::Error,
    store::Store,
    ExportVid, OwnedVid, PrivateVid,
};
use futures::StreamExt;
use url::Url;

/// Holds private ands verified VIDs
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
///     let alice_vid = OwnedVid::from_file("../examples/test/bob.json").await.unwrap();
///     db.add_private_vid(alice_vid).unwrap();
///     db.verify_vid("did:web:did.tsp-test.org:user:bob").await.unwrap();
///
///     // send a message
///     let result = db.send(
///         "did:web:did.tsp-test.org:user:alice",
///         "did:web:did.tsp-test.org:user:bob",
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

    /// Import the database from serializable default types
    pub fn import(&self, vids: Vec<ExportVid>) -> Result<(), Error> {
        self.inner.import(vids)
    }

    /// Adds a relation to an already existing vid, making it a nested Vid
    pub fn set_relation_for_vid(&self, vid: &str, relation_vid: Option<&str>) -> Result<(), Error> {
        self.inner.set_relation_for_vid(vid, relation_vid)
    }

    /// Sets the relationship status for a VID
    pub(super) fn set_relation_status_for_vid(
        &self,
        vid: &str,
        relation_status: RelationshipStatus,
    ) -> Result<(), Error> {
        self.inner.set_relation_status_for_vid(vid, relation_status)
    }

    /// Adds a route to an already existing vid, making it a nested Vid
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

    /// Remove a VID from the database
    pub fn forget_vid(&self, vid: &str) -> Result<(), Error> {
        self.inner.forget_vid(vid)
    }

    /// Add the already resolved `verified_vid` to the database as a relationship
    pub fn add_verified_vid(&self, verified_vid: impl VerifiedVid + 'static) -> Result<(), Error> {
        self.inner.add_verified_vid(verified_vid)
    }

    /// Check whether the [PrivateVid] identified by `vid` exists inthe database
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
    /// Encodes, encrypts, signs and sends a TSP message
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
    ///     let private_vid = OwnedVid::from_file(format!("../examples/test/bob.json")).await.unwrap();
    ///     db.add_private_vid(private_vid).unwrap();
    ///     db.verify_vid("did:web:did.tsp-test.org:user:alice").await.unwrap();
    ///
    ///     let sender = "did:web:did.tsp-test.org:user:bob";
    ///     let receiver = "did:web:did.tsp-test.org:user:alice";
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
    ) -> Result<Vec<u8>, Error> {
        let (endpoint, message) =
            self.inner
                .seal_message(sender, receiver, nonconfidential_data, message)?;

        tracing::info!("sending message to {endpoint}");

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(message)
    }

    /// Request a direct relationship with a resolved VID using the TSP
    /// Encodes the control message, encrypts, signs and sends a TSP message
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
    ///     let private_vid = OwnedVid::from_file(format!("../examples/test/bob.json")).await.unwrap();
    ///     db.add_private_vid(private_vid).unwrap();
    ///     db.verify_vid("did:web:did.tsp-test.org:user:alice").await.unwrap();
    ///
    ///     let sender = "did:web:did.tsp-test.org:user:bob";
    ///     let receiver = "did:web:did.tsp-test.org:user:alice";
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
        let sender = self.inner.get_private_vid(sender)?;
        let receiver = self.inner.get_verified_vid(receiver)?;

        let path = route;
        let route = route.map(|collection| collection.iter().map(|vid| vid.as_ref()).collect());

        let (tsp_message, thread_id) = crate::crypto::seal_and_hash(
            &*sender,
            &*receiver,
            None,
            Payload::RequestRelationship { route },
        )?;

        if let Some(hop_list) = path {
            self.resolve_route_and_send(hop_list, &tsp_message).await?;
            self.set_route_for_vid(receiver.identifier(), hop_list)?;
        } else {
            crate::transport::send_message(receiver.endpoint(), &tsp_message).await?;
        }

        self.set_relation_status_for_vid(
            receiver.identifier(),
            RelationshipStatus::Unidirectional { thread_id },
        )?;

        Ok(())
    }

    /// Accept a direct relationship between the resolved VIDs identifier by `sender` and `receiver`.
    /// `thread_id` must be the same as the one that was present in the relationship request.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub async fn send_relationship_accept(
        &self,
        sender: &str,
        receiver: &str,
        thread_id: Digest,
        route: Option<&[&str]>,
    ) -> Result<(), Error> {
        let (transport, tsp_message) = self.inner.seal_message_payload(
            sender,
            receiver,
            None,
            Payload::AcceptRelationship { thread_id },
        )?;

        if let Some(hop_list) = route {
            self.resolve_route_and_send(hop_list, &tsp_message).await?;
            self.set_route_for_vid(receiver, hop_list)?;
        } else {
            crate::transport::send_message(&transport, &tsp_message).await?;
        }

        self.set_relation_status_for_vid(
            receiver,
            RelationshipStatus::Bidirectional {
                thread_id,
                outstanding_nested_thread_ids: Default::default(),
            },
        )?;

        Ok(())
    }

    /// Cancels a direct relationship between the resolved `sender` and `receiver` VIDs.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub async fn send_relationship_cancel(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(), Error> {
        self.set_relation_status_for_vid(receiver, RelationshipStatus::Unrelated)?;

        let thread_id = Default::default(); // FNORD

        let (transport, message) = self.inner.seal_message_payload(
            sender,
            receiver,
            None,
            Payload::CancelRelationship { thread_id },
        )?;

        crate::transport::send_message(&transport, &message).await?;

        Ok(())
    }

    /// Send a nested relationship request to `receiver`, creating a new nested vid with `outer_sender` as a parent.
    pub async fn send_nested_relationship_request(
        &self,
        parent_sender: &str,
        receiver: &str,
    ) -> Result<OwnedVid, Error> {
        let sender = self.inner.get_private_vid(parent_sender)?;
        let receiver = self.inner.get_verified_vid(receiver)?;

        let nested_vid = self.make_propositioning_vid(sender.identifier())?;

        let (tsp_message, thread_id) = crate::crypto::seal_and_hash(
            &*sender,
            &*receiver,
            None,
            Payload::RequestNestedRelationship {
                vid: nested_vid.vid().as_ref(),
            },
        )?;

        self.inner
            .add_nested_thread_id(receiver.identifier(), thread_id)?;

        crate::transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(nested_vid)
    }

    /// Accept a nested relationship with the (nested) VID identified by `nested_receiver`.
    /// Generate a new nested VID that will have `parent_sender` as its parent.
    /// `thread_id` must be the same as the one that was present in the relationship request.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub async fn send_nested_relationship_accept(
        &self,
        parent_sender: &str,
        nested_receiver: &str,
        thread_id: Digest,
    ) -> Result<OwnedVid, Error> {
        let nested_vid = self.make_propositioning_vid(parent_sender)?;
        self.set_relation_for_vid(nested_vid.identifier(), Some(nested_receiver))?;
        self.set_relation_for_vid(nested_receiver, Some(nested_vid.identifier()))?;

        let receiver_vid = self.inner.get_vid(nested_receiver)?;
        let parent_receiver = receiver_vid
            .get_parent_vid()
            .ok_or(Error::Relationship(format!(
                "missing parent for {nested_receiver}"
            )))?;

        let (transport, tsp_message) = self.inner.seal_message_payload(
            parent_sender,
            parent_receiver,
            None,
            Payload::AcceptNestedRelationship {
                thread_id,
                vid: nested_vid.vid().as_ref(),
                connect_to_vid: nested_receiver.as_ref(),
            },
        )?;

        crate::transport::send_message(&transport, &tsp_message).await?;

        self.set_relation_status_for_vid(
            nested_receiver,
            RelationshipStatus::Bidirectional {
                thread_id,
                outstanding_nested_thread_ids: Default::default(),
            },
        )?;

        Ok(nested_vid)
    }

    fn make_propositioning_vid(&self, parent_vid: &str) -> Result<OwnedVid, Error> {
        let transport = Url::from_file_path("/dev/null").expect("error generating a URL");

        let vid = OwnedVid::new_did_peer(transport);
        self.inner.add_private_vid(vid.clone())?;
        self.set_parent_for_vid(vid.identifier(), Some(parent_vid))?;

        Ok(vid)
    }

    /// Receive, open and forward a TSP message
    /// This method is used by intermediary nodes to receive a TSP message,
    /// open it and forward it to the next hop.
    pub async fn route_message(
        &self,
        sender: &str,
        receiver: &str,
        message: &mut [u8],
    ) -> Result<Url, Error> {
        let (transport, message) = self.inner.route_message(sender, receiver, message)?;

        crate::transport::send_message(&transport, &message).await?;

        Ok(transport)
    }

    /// Send a message given a route, extracting the next hop and verifying it in the process
    async fn resolve_route_and_send(
        &self,
        hop_list: &[&str],
        opaque_message: &[u8],
    ) -> Result<(), Error> {
        let (next_hop, path) = self.inner.resolve_route(hop_list)?;

        self.forward_routed_message(&next_hop, path, opaque_message)
            .await?;

        Ok(())
    }

    /// Pass along a in-transit routed TSP `opaque_message` that is not meant for us, given earlier resolved VIDs.
    /// The message is routed through the route that has been established with `receiver`.
    pub async fn forward_routed_message(
        &self,
        next_hop: &str,
        path: Vec<&[u8]>,
        opaque_message: &[u8],
    ) -> Result<Url, Error> {
        let (transport, message) =
            self.inner
                .forward_routed_message(next_hop, path, opaque_message)?;

        crate::transport::send_message(&transport, &message).await?;

        Ok(transport)
    }

    /// Decode an encrypted `message``, which has to be addressed to one of the VIDs in `receivers`, and has to have
    /// `verified_vids` as one of the senders.
    pub fn open_message(&self, message: &mut [u8]) -> Result<ReceivedTspMessage, Error> {
        self.inner.open_message(message)
    }

    /// Receive TSP messages for the private VID identified by `vid`, using the appropriate transport mechanism for it.
    /// Messages will be queued in a channel
    /// The returned channel contains a maximum of 16 messages
    pub async fn receive(&self, vid: &str) -> Result<TSPStream<ReceivedTspMessage, Error>, Error> {
        let receiver = self.inner.get_private_vid(vid)?;
        let messages = crate::transport::receive_messages(receiver.endpoint()).await?;

        let db = self.inner.clone();
        Ok(Box::pin(messages.then(move |message| {
            let db_inner = db.clone();
            async move {
                match message {
                    Ok(mut m) => match db_inner.open_message(&mut m) {
                        Err(Error::UnverifiedSource(unknown_vid)) => {
                            Ok(ReceivedTspMessage::PendingMessage {
                                unknown_vid,
                                payload: m,
                            })
                        }
                        maybe_message => maybe_message,
                    },
                    Err(e) => Err(e.into()),
                }
            }
        })))
    }

    /// Send TSP broadcast message to the specified VIDs
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

    /// Process the payload from a  'PendingMessage' by resolving the unknown vid and retrying
    pub async fn verify_and_open(
        &mut self,
        vid: &str,
        payload: &mut [u8],
    ) -> Result<ReceivedTspMessage, Error> {
        self.verify_vid(vid).await?;

        self.inner.open_message(payload)
    }
}
