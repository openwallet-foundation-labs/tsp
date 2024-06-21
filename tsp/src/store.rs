use crate::{
    cesr::EnvelopeType,
    crypto::CryptoError,
    definitions::{
        Digest, MessageType, Payload, PrivateVid, ReceivedTspMessage, RelationshipStatus,
        VerifiedVid,
    },
    error::Error,
    vid::VidError,
    ExportVid, OwnedVid,
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use url::Url;

#[derive(Clone)]
pub(crate) struct VidContext {
    pub(crate) vid: Arc<dyn VerifiedVid>,
    pub(crate) private: Option<Arc<dyn PrivateVid>>,
    pub(crate) relation_status: RelationshipStatus,
    pub(crate) relation_vid: Option<String>,
    pub(crate) parent_vid: Option<String>,
    pub(crate) tunnel: Option<Box<[String]>>,
}

impl VidContext {
    /// Set the parent VID for this VID. Used to create a nested TSP message
    fn set_parent_vid(&mut self, parent_vid: Option<&str>) {
        self.parent_vid = parent_vid.map(|r| r.to_string());
    }

    /// Set the relation VID for this VID. The relation VID wil be used as
    /// sender VID when sending messages to this VID
    fn set_relation_vid(&mut self, relation_vid: Option<&str>) {
        self.relation_vid = relation_vid.map(|r| r.to_string());
    }

    /// Set the relation status for this VID.
    fn set_relation_status(&mut self, relation_status: RelationshipStatus) {
        self.relation_status = relation_status;
    }

    /// Set the route for this VID. The route will be used to send routed messages to this VID
    fn set_route(&mut self, route: &[impl AsRef<str>]) {
        if route.is_empty() {
            self.tunnel = None;
        } else {
            self.tunnel = Some(route.iter().map(|x| x.as_ref().to_owned()).collect())
        }
    }

    /// Get the parent VID for this VID
    pub(crate) fn get_parent_vid(&self) -> Option<&str> {
        self.parent_vid.as_deref()
    }

    /// Get the relation VID for this VID
    pub(crate) fn get_relation_vid(&self) -> Option<&str> {
        self.relation_vid.as_deref()
    }

    /// Get the route for this VID
    pub(crate) fn get_route(&self) -> Option<&[String]> {
        self.tunnel.as_deref()
    }
}

/// Holds private ands verified VIDs
/// A Store contains verified vid's, our relationship status to them,
/// as well as the private vid's that this application has control over.
///
/// The struct is the primary interface to the VID database, in a synchronous
/// context (when no async runtime is available).
#[derive(Default, Clone)]
pub struct Store {
    pub(crate) vids: Arc<RwLock<HashMap<String, VidContext>>>,
}

/// This database is used to store and resolve VIDs
impl Store {
    /// Create a new, empty VID database
    pub fn new() -> Self {
        Default::default()
    }

    /// Export the database to serializable default types
    pub fn export(&self) -> Result<Vec<ExportVid>, Error> {
        self.vids
            .read()?
            .values()
            .map(|context| {
                Ok(ExportVid {
                    id: context.vid.identifier().to_string(),
                    transport: context.vid.endpoint().clone(),
                    public_sigkey: context.vid.verifying_key().clone(),
                    public_enckey: context.vid.encryption_key().clone(),
                    sigkey: context.private.as_ref().map(|x| x.signing_key().clone()),
                    enckey: context.private.as_ref().map(|x| x.decryption_key().clone()),
                    relation_status: context.relation_status.clone(),
                    relation_vid: context.relation_vid.clone(),
                    parent_vid: context.parent_vid.clone(),
                    tunnel: context.tunnel.clone(),
                })
            })
            .collect()
    }

    /// Import the database from serializable default types
    pub fn import(&self, vids: Vec<ExportVid>) -> Result<(), Error> {
        vids.into_iter().try_for_each(|vid| {
            self.vids.write()?.insert(
                vid.id.to_string(),
                VidContext {
                    vid: Arc::new(vid.verified_vid()),
                    private: match vid.private_vid() {
                        Some(private) => Some(Arc::new(private)),
                        None => None,
                    },
                    relation_status: vid.relation_status,
                    relation_vid: vid.relation_vid,
                    parent_vid: vid.parent_vid,
                    tunnel: vid.tunnel,
                },
            );

            Ok(())
        })
    }

    /// Add the already resolved `verified_vid` to the database as a relationship
    pub fn add_verified_vid(&self, verified_vid: impl VerifiedVid + 'static) -> Result<(), Error> {
        self.vids.write()?.insert(
            verified_vid.identifier().to_string(),
            VidContext {
                vid: Arc::new(verified_vid),
                private: None,
                relation_status: RelationshipStatus::Unrelated,
                relation_vid: None,
                parent_vid: None,
                tunnel: None,
            },
        );

        Ok(())
    }

    /// Adds `private_vid` to the database
    pub fn add_private_vid(&self, private_vid: impl PrivateVid + 'static) -> Result<(), Error> {
        let vid = Arc::new(private_vid);

        self.vids.write()?.insert(
            vid.identifier().to_string(),
            VidContext {
                vid: vid.clone(),
                private: Some(vid),
                relation_status: RelationshipStatus::Unrelated,
                relation_vid: None,
                parent_vid: None,
                tunnel: None,
            },
        );

        Ok(())
    }

    /// Remove a VID from the database
    pub fn forget_vid(&self, vid: &str) -> Result<(), Error> {
        self.vids.write()?.remove(vid);

        Ok(())
    }

    /// Sets the parent for a VID. This is used to create a nested message.
    pub fn set_parent_for_vid(&self, vid: &str, parent_vid: Option<&str>) -> Result<(), Error> {
        self.modify_vid(vid, |resolved| {
            resolved.set_parent_vid(parent_vid);

            Ok(())
        })
    }

    /// Adds a relation to an already existing vid, making it a nested Vid
    pub fn set_relation_for_vid(&self, vid: &str, relation_vid: Option<&str>) -> Result<(), Error> {
        self.modify_vid(vid, |resolved| {
            resolved.set_relation_vid(relation_vid);

            Ok(())
        })
    }

    /// List all VIDs in the database
    pub fn list_vids(&self) -> Result<Vec<String>, Error> {
        Ok(self.vids.read()?.keys().cloned().collect())
    }

    /// Sets the relationship status for a VID
    pub fn set_relation_status_for_vid(
        &self,
        vid: &str,
        relation_status: RelationshipStatus,
    ) -> Result<(), Error> {
        self.modify_vid(vid, |resolved| {
            resolved.set_relation_status(relation_status);

            Ok(())
        })
    }

    /// Adds a route to an already existing vid, making it a nested Vid
    pub fn set_route_for_vid(&self, vid: &str, route: &[&str]) -> Result<(), Error> {
        if route.len() == 1 {
            return Err(Error::InvalidRoute(
                "A route must have at least two VIDs".into(),
            ));
        }

        self.modify_vid(vid, |resolved| {
            resolved.set_route(route);

            Ok(())
        })
    }

    /// Modify a verified-vid by applying an operation to it (internal use only)
    pub(crate) fn modify_vid(
        &self,
        vid: &str,
        change: impl FnOnce(&mut VidContext) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self.vids.write()?.get_mut(vid) {
            Some(resolved) => change(resolved),
            None => Err(Error::UnverifiedVid(vid.to_string())),
        }
    }

    /// Check whether the [PrivateVid] identified by `vid` exists inthe database
    pub fn has_private_vid(&self, vid: &str) -> Result<bool, Error> {
        Ok(self.get_private_vid(vid).is_ok())
    }

    /// Retrieve the [PrivateVid] identified by `vid` from the database, if it exists.
    pub(crate) fn get_private_vid(&self, vid: &str) -> Result<Arc<dyn PrivateVid>, Error> {
        match self.get_vid(vid)?.private {
            Some(private) => Ok(private),
            None => Err(Error::MissingPrivateVid(vid.to_string())),
        }
    }

    /// Retrieve the [Vid] identified by `vid` from the database, if it exists.
    pub(crate) fn get_verified_vid(&self, vid: &str) -> Result<Arc<dyn VerifiedVid>, Error> {
        Ok(self.get_vid(vid)?.vid)
    }

    /// Retrieve the [VidContext] identified by `vid` from the database, if it exists.
    pub(super) fn get_vid(&self, vid: &str) -> Result<VidContext, Error> {
        match self.vids.read()?.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnverifiedVid(vid.to_string())),
        }
    }

    /// Seal a TSP message.
    /// The message is encrypted, encoded and signed using the key material
    /// of the sender and receiver, specified by their VIDs.
    ///
    /// Note that the the corresponsing VIDs should first be added and configured
    /// using this store.
    pub fn seal_message(
        &self,
        sender: &str,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<(url::Url, Vec<u8>), Error> {
        self.seal_message_payload(
            sender,
            receiver,
            nonconfidential_data,
            Payload::Content(message),
        )
    }

    /// Seal a TSP message.
    pub(crate) fn seal_message_payload(
        &self,
        sender: &str,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        payload: Payload<&[u8]>,
    ) -> Result<(url::Url, Vec<u8>), Error> {
        let sender = self.get_private_vid(sender)?;
        let receiver_context = self.get_vid(receiver)?;

        // send routed mode
        if let Some(intermediaries) = receiver_context.get_route() {
            let first_hop = self.get_vid(&intermediaries[0])?;

            let (sender, inner_message) = match (
                first_hop.get_relation_vid(),
                receiver_context.get_relation_vid(),
            ) {
                (Some(first_sender), Some(inner_sender)) => {
                    let inner_sender = self.get_private_vid(inner_sender)?;

                    let tsp_message: Vec<u8> = crate::crypto::seal(
                        &*inner_sender,
                        &*receiver_context.vid,
                        nonconfidential_data,
                        payload,
                    )?;

                    let first_sender = self.get_private_vid(first_sender)?;

                    (first_sender, tsp_message)
                }
                (None, _) => {
                    return Err(VidError::ResolveVid("missing sender VID for first hop").into())
                }
                (_, None) => {
                    return Err(VidError::ResolveVid("missing sender VID for receiver").into())
                }
            };

            let hops = intermediaries[1..]
                .iter()
                .map(|x| x.as_ref())
                .collect::<Vec<_>>();

            let tsp_message = crate::crypto::seal(
                &*sender,
                &*first_hop.vid,
                None,
                Payload::RoutedMessage(hops, &inner_message),
            )?;

            return Ok((first_hop.vid.endpoint().clone(), tsp_message));
        }

        // send nested mode
        if let Some(parent_receiver) = receiver_context.get_parent_vid() {
            let Some(inner_sender) = receiver_context.get_relation_vid() else {
                return Err(VidError::ResolveVid("missing sender VID for receiver").into());
            };

            let sender_context = self.get_vid(inner_sender)?;

            let Some(parent_sender) = sender_context.get_parent_vid() else {
                return Err(VidError::ResolveVid("missing parent for inner VID").into());
            };

            let inner_sender = self.get_private_vid(inner_sender)?;
            let inner_message = crate::crypto::sign(
                &*inner_sender,
                Some(&*receiver_context.vid),
                payload.as_bytes(),
            )?;

            let parent_sender = self.get_private_vid(parent_sender)?;
            let parent_receiver = self.get_verified_vid(parent_receiver)?;

            let tsp_message = crate::crypto::seal(
                &*parent_sender,
                &*parent_receiver,
                nonconfidential_data,
                Payload::NestedMessage(&inner_message),
            )?;

            return Ok((parent_receiver.endpoint().clone(), tsp_message));
        }

        // send direct mode
        let tsp_message = crate::crypto::seal(
            &*sender,
            &*receiver_context.vid,
            nonconfidential_data,
            payload,
        )?;

        Ok((receiver_context.vid.endpoint().clone(), tsp_message))
    }

    /// Sign a unencrypted message, without a specified recipient
    pub fn sign_anycast(&self, sender: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_anycast_payload(sender, Payload::Content(message))
    }

    /// Sign a unencrypted message payload, without a specified recipient
    pub(crate) fn sign_anycast_payload(
        &self,
        sender: &str,
        payload: Payload<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let sender = self.get_private_vid(sender)?;
        let message = crate::crypto::sign(&*sender, None, payload.as_bytes())?;

        Ok(message)
    }

    /// Resolve a route, extract the next hop and verify the route
    fn resolve_route<'a>(&'a self, hop_list: &'a [&str]) -> Result<(String, Vec<&'a [u8]>), Error> {
        let Some(next_hop) = hop_list.first() else {
            return Err(Error::InvalidRoute(
                "relationship route must not be empty".into(),
            ));
        };

        let next_hop = self.get_verified_vid(next_hop)?.identifier().to_owned();
        let path = hop_list[1..].iter().map(|x| x.as_bytes()).collect();

        Ok((next_hop, path))
    }

    /// Receive, open and forward a TSP message
    pub fn route_message(
        &self,
        sender: &str,
        receiver: &str,
        message: &mut [u8],
    ) -> Result<(Url, Vec<u8>), Error> {
        let Ok(sender) = self.get_verified_vid(sender) else {
            return Err(Error::UnverifiedVid(sender.to_string()));
        };

        let Ok(receiver) = self.get_private_vid(receiver) else {
            return Err(CryptoError::UnexpectedRecipient.into());
        };

        let (_, payload, _) = crate::crypto::open(&*receiver, &*sender, message)?;

        let (next_hop, path, inner_message) = match payload {
            Payload::RoutedMessage(hops, inner_message) => {
                let next_hop = std::str::from_utf8(hops[0])?;

                (next_hop, hops[1..].into(), inner_message)
            }
            _ => {
                return Err(Error::InvalidRoute(format!(
                    "expected a routed message, got {:?}",
                    payload
                )));
            }
        };

        self.forward_routed_message(next_hop, path, inner_message)
    }

    /// Pass along a in-transit routed TSP `opaque_message` that is not meant for us, given earlier resolved VIDs.
    /// The message is routed through the route that has been established with `receiver`.
    pub fn forward_routed_message(
        &self,
        next_hop: &str,
        path: Vec<&[u8]>,
        opaque_message: &[u8],
    ) -> Result<(Url, Vec<u8>), Error> {
        if path.is_empty() {
            // we are the final delivery point, we should be the 'next_hop'
            let sender = self.get_vid(next_hop)?;

            let Some(sender_private) = &sender.private else {
                return Err(Error::MissingPrivateVid(next_hop.to_string()));
            };

            let recipient = match sender.get_relation_vid() {
                Some(destination) => self.get_verified_vid(destination)?,
                None => return Err(Error::MissingDropOff(sender.vid.identifier().to_string())),
            };

            let tsp_message = crate::crypto::seal(
                &**sender_private,
                &*recipient,
                None,
                Payload::NestedMessage(opaque_message),
            )?;

            Ok((recipient.endpoint().clone(), tsp_message))
        } else {
            // we are an intermediary, continue sending the message
            let next_hop_context = self
                .get_vid(next_hop)
                .map_err(|_| Error::InvalidNextHop(next_hop.to_string()))?;

            let sender = match next_hop_context.get_relation_vid() {
                Some(first_sender) => self.get_private_vid(first_sender)?,
                None => return Err(Error::InvalidNextHop(next_hop.to_string())),
            };

            let tsp_message = crate::crypto::seal(
                &*sender,
                &*next_hop_context.vid,
                None,
                Payload::RoutedMessage(path, opaque_message),
            )?;

            Ok((next_hop_context.vid.endpoint().clone(), tsp_message))
        }
    }

    /// Decode an encrypted `message``, which has to be addressed to one of the VIDs in `receivers`, and has to have
    /// `verified_vids` as one of the senders.
    pub fn open_message(&self, message: &mut [u8]) -> Result<ReceivedTspMessage, Error> {
        let probed_message = crate::cesr::probe(message)?;

        match probed_message {
            EnvelopeType::EncryptedMessage {
                sender,
                receiver: intended_receiver,
            } => {
                let intended_receiver = std::str::from_utf8(intended_receiver)?;

                let Ok(intended_receiver) = self.get_private_vid(intended_receiver) else {
                    return Err(CryptoError::UnexpectedRecipient.into());
                };

                let sender = String::from_utf8(sender.to_vec())?;

                let Ok(sender_vid) = self.get_verified_vid(&sender) else {
                    return Err(Error::UnverifiedSource(sender));
                };

                let (nonconfidential_data, payload, raw_bytes) =
                    crate::crypto::open(&*intended_receiver, &*sender_vid, message)?;

                match payload {
                    Payload::Content(message) => Ok(ReceivedTspMessage::GenericMessage {
                        sender,
                        nonconfidential_data: nonconfidential_data.map(|v| v.to_vec()),
                        message: message.to_owned(),
                        message_type: MessageType::SignedAndEncrypted,
                    }),
                    Payload::NestedMessage(message) => {
                        let mut inner = message.to_owned();

                        let mut received_message = self.open_message(&mut inner)?;
                        if let ReceivedTspMessage::GenericMessage {
                            ref mut message_type,
                            ..
                        } = received_message
                        {
                            *message_type = MessageType::SignedAndEncrypted;
                        }

                        Ok(received_message)
                    }
                    Payload::RoutedMessage(hops, message) => {
                        let next_hop = std::str::from_utf8(hops[0])?;

                        Ok(ReceivedTspMessage::ForwardRequest {
                            sender,
                            next_hop: next_hop.to_string(),
                            route: hops[1..].iter().map(|x| x.to_vec()).collect(),
                            opaque_payload: message.to_owned(),
                        })
                    }
                    Payload::RequestRelationship { route } => {
                        Ok(ReceivedTspMessage::RequestRelationship {
                            sender,
                            route: route.map(|vec| vec.iter().map(|vid| vid.to_vec()).collect()),
                            thread_id: crate::crypto::sha256(raw_bytes),
                            nested_vid: None,
                        })
                    }
                    Payload::AcceptRelationship { thread_id } => {
                        self.upgrade_relation(&sender, thread_id)?;

                        Ok(ReceivedTspMessage::AcceptRelationship {
                            sender,
                            nested_vid: None,
                        })
                    }
                    Payload::CancelRelationship { thread_id } => {
                        if let Some(context) = self.vids.write()?.get_mut(&sender) {
                            match context.relation_status {
                                RelationshipStatus::Bidirectional {
                                    thread_id: digest, ..
                                }
                                | RelationshipStatus::Unidirectional { thread_id: digest } => {
                                    if thread_id != digest {
                                        return Err(Error::Relationship(
                                            "invalid attempt to end the relationship".into(),
                                        ));
                                    }
                                    context.relation_status = RelationshipStatus::Unrelated;
                                }
                                RelationshipStatus::_Controlled => {
                                    return Err(Error::Relationship(
                                        "you cannot cancel a relationship with yourself".into(),
                                    ))
                                }
                                RelationshipStatus::Unrelated => {}
                            }
                        }

                        Ok(ReceivedTspMessage::CancelRelationship { sender })
                    }
                    Payload::RequestNestedRelationship { vid } => {
                        let vid = std::str::from_utf8(vid)?;
                        self.add_nested_vid(vid)?;
                        self.set_parent_for_vid(vid, Some(&sender))?;

                        Ok(ReceivedTspMessage::RequestRelationship {
                            sender,
                            route: None,
                            thread_id: crate::crypto::sha256(raw_bytes),
                            nested_vid: Some(vid.to_string()),
                        })
                    }
                    Payload::AcceptNestedRelationship {
                        thread_id,
                        vid,
                        connect_to_vid,
                    } => {
                        let vid = std::str::from_utf8(vid)?;
                        let connect_to_vid = std::str::from_utf8(connect_to_vid)?;
                        self.add_nested_vid(vid)?;
                        self.set_parent_for_vid(vid, Some(&sender))?;
                        self.add_nested_relation(&sender, vid, thread_id)?;
                        self.set_relation_for_vid(connect_to_vid, Some(vid))?;
                        self.set_relation_for_vid(vid, Some(connect_to_vid))?;

                        Ok(ReceivedTspMessage::AcceptRelationship {
                            sender,
                            nested_vid: Some(vid.to_string()),
                        })
                    }
                }
            }
            EnvelopeType::SignedMessage {
                sender,
                receiver: intended_receiver,
            } => {
                if let Some(intended_receiver) = intended_receiver {
                    let intended_receiver = std::str::from_utf8(intended_receiver)?;

                    if !self.has_private_vid(intended_receiver)? {
                        return Err(CryptoError::UnexpectedRecipient.into());
                    }
                };

                let sender = String::from_utf8(sender.to_vec())?;

                let Ok(sender_vid) = self.get_verified_vid(&sender) else {
                    return Err(Error::UnverifiedVid(sender.to_string()));
                };

                let payload = crate::crypto::verify(&*sender_vid, message)?;

                Ok(ReceivedTspMessage::GenericMessage {
                    sender,
                    nonconfidential_data: None,
                    message: payload.to_owned(),
                    message_type: MessageType::Signed,
                })
            }
        }
    }

    pub fn make_relationship_request(
        &self,
        sender: &str,
        receiver: &str,
        route: Option<&[&str]>,
    ) -> Result<(Url, Vec<u8>), Error> {
        let sender = self.get_private_vid(sender)?;
        let receiver = self.get_verified_vid(receiver)?;

        let path = route;
        let route = route.map(|collection| collection.iter().map(|vid| vid.as_ref()).collect());

        let (tsp_message, thread_id) = crate::crypto::seal_and_hash(
            &*sender,
            &*receiver,
            None,
            Payload::RequestRelationship { route },
        )?;

        let (transport, tsp_message) = if let Some(hop_list) = path {
            self.set_route_for_vid(receiver.identifier(), hop_list)?;
            self.resolve_route_and_send(hop_list, &tsp_message)?
        } else {
            (receiver.endpoint().clone(), tsp_message)
        };

        self.set_relation_status_for_vid(
            receiver.identifier(),
            RelationshipStatus::Unidirectional { thread_id },
        )?;

        Ok((transport, tsp_message.to_owned()))
    }

    /// Accept a direct relationship between the resolved VIDs identifier by `sender` and `receiver`.
    /// `thread_id` must be the same as the one that was present in the relationship request.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub fn make_relationship_accept(
        &self,
        sender: &str,
        receiver: &str,
        thread_id: Digest,
        route: Option<&[&str]>,
    ) -> Result<(Url, Vec<u8>), Error> {
        let (transport, tsp_message) = self.seal_message_payload(
            sender,
            receiver,
            None,
            Payload::AcceptRelationship { thread_id },
        )?;

        let (transport, tsp_message) = if let Some(hop_list) = route {
            self.set_route_for_vid(receiver, hop_list)?;
            self.resolve_route_and_send(hop_list, &tsp_message)?
        } else {
            (transport.to_owned(), tsp_message)
        };

        self.set_relation_status_for_vid(
            receiver,
            RelationshipStatus::Bidirectional {
                thread_id,
                outstanding_nested_thread_ids: Default::default(),
            },
        )?;

        Ok((transport, tsp_message))
    }

    /// Cancels a direct relationship between the resolved `sender` and `receiver` VIDs.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub fn make_relationship_cancel(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.set_relation_status_for_vid(receiver, RelationshipStatus::Unrelated)?;

        let thread_id = Default::default(); // FNORD

        let (transport, message) = self.seal_message_payload(
            sender,
            receiver,
            None,
            Payload::CancelRelationship { thread_id },
        )?;

        Ok((transport, message))
    }

    /// Send a nested relationship request to `receiver`, creating a new nested vid with `outer_sender` as a parent.
    pub fn make_nested_relationship_request(
        &self,
        parent_sender: &str,
        receiver: &str,
    ) -> Result<((Url, Vec<u8>), OwnedVid), Error> {
        let sender = self.get_private_vid(parent_sender)?;
        let receiver = self.get_verified_vid(receiver)?;

        let nested_vid = self.make_propositioning_vid(sender.identifier())?;

        let (tsp_message, thread_id) = crate::crypto::seal_and_hash(
            &*sender,
            &*receiver,
            None,
            Payload::RequestNestedRelationship {
                vid: nested_vid.vid().as_ref(),
            },
        )?;

        self.add_nested_thread_id(receiver.identifier(), thread_id)?;

        Ok(((receiver.endpoint().clone(), tsp_message), nested_vid))
    }

    /// Accept a nested relationship with the (nested) VID identified by `nested_receiver`.
    /// Generate a new nested VID that will have `parent_sender` as its parent.
    /// `thread_id` must be the same as the one that was present in the relationship request.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub fn make_nested_relationship_accept(
        &self,
        parent_sender: &str,
        nested_receiver: &str,
        thread_id: Digest,
    ) -> Result<((Url, Vec<u8>), OwnedVid), Error> {
        let nested_vid = self.make_propositioning_vid(parent_sender)?;
        self.set_relation_for_vid(nested_vid.identifier(), Some(nested_receiver))?;
        self.set_relation_for_vid(nested_receiver, Some(nested_vid.identifier()))?;

        let receiver_vid = self.get_vid(nested_receiver)?;
        let parent_receiver = receiver_vid
            .get_parent_vid()
            .ok_or(Error::Relationship(format!(
                "missing parent for {nested_receiver}"
            )))?;

        let (transport, tsp_message) = self.seal_message_payload(
            parent_sender,
            parent_receiver,
            None,
            Payload::AcceptNestedRelationship {
                thread_id,
                vid: nested_vid.vid().as_ref(),
                connect_to_vid: nested_receiver.as_ref(),
            },
        )?;

        self.set_relation_status_for_vid(
            nested_receiver,
            RelationshipStatus::Bidirectional {
                thread_id,
                outstanding_nested_thread_ids: Default::default(),
            },
        )?;

        Ok(((transport, tsp_message), nested_vid))
    }

    fn make_propositioning_vid(&self, parent_vid: &str) -> Result<OwnedVid, Error> {
        let transport = Url::parse("https://example.net").expect("error generating a URL");

        let vid = OwnedVid::new_did_peer(transport);
        self.add_private_vid(vid.clone())?;
        self.set_parent_for_vid(vid.identifier(), Some(parent_vid))?;

        Ok(vid)
    }

    /// Send a message given a route, extracting the next hop and verifying it in the process
    fn resolve_route_and_send(
        &self,
        hop_list: &[&str],
        opaque_message: &[u8],
    ) -> Result<(Url, Vec<u8>), Error> {
        let (next_hop, path) = self.resolve_route(hop_list)?;

        self.forward_routed_message(&next_hop, path, opaque_message)
    }

    fn add_nested_vid(&self, vid: &str) -> Result<(), Error> {
        //TODO: a non-async resolve function should probably be added to the `vid` module instead of here
        use crate::vid::did::{self, peer};
        let parts = vid.split(':').collect::<Vec<&str>>();
        let Some([did::SCHEME, did::peer::SCHEME]) = parts.get(0..2) else {
            return Err(Error::Relationship(
                "nested relationships must use did:peer".into(),
            ));
        };
        let nested_vid = peer::verify_did_peer(&parts)?;

        self.add_verified_vid(nested_vid)
    }

    fn upgrade_relation(&self, vid: &str, thread_id: Digest) -> Result<(), Error> {
        let mut vids = self.vids.write()?;
        let Some(context) = vids.get_mut(vid) else {
            return Err(Error::Relationship(vid.into()));
        };

        let RelationshipStatus::Unidirectional { thread_id: digest } = context.relation_status
        else {
            return Err(Error::Relationship(vid.into()));
        };

        if thread_id != digest {
            return Err(Error::Relationship(vid.into()));
        }

        context.relation_status = RelationshipStatus::Bidirectional {
            thread_id: digest,
            outstanding_nested_thread_ids: Default::default(),
        };

        Ok(())
    }

    fn add_nested_thread_id(&self, vid: &str, thread_id: Digest) -> Result<(), Error> {
        let mut vids = self.vids.write()?;
        let Some(context) = vids.get_mut(vid) else {
            return Err(Error::MissingVid(vid.into()));
        };

        let RelationshipStatus::Bidirectional {
            ref mut outstanding_nested_thread_ids,
            ..
        } = context.relation_status
        else {
            return Err(Error::Relationship(vid.into()));
        };

        outstanding_nested_thread_ids.push(thread_id);

        Ok(())
    }

    fn add_nested_relation(
        &self,
        parent_vid: &str,
        nested_vid: &str,
        thread_id: Digest,
    ) -> Result<(), Error> {
        let mut vids = self.vids.write()?;
        let Some(context) = vids.get_mut(parent_vid) else {
            return Err(Error::Relationship(parent_vid.into()));
        };

        let RelationshipStatus::Bidirectional {
            ref mut outstanding_nested_thread_ids,
            ..
        } = context.relation_status
        else {
            return Err(Error::Relationship(parent_vid.into()));
        };

        // find the thread_id in the list of outstanding thread id's of the parent and remove it
        let Some(index) = outstanding_nested_thread_ids
            .iter()
            .position(|&x| x == thread_id)
        else {
            return Err(Error::Relationship(nested_vid.into()));
        };
        outstanding_nested_thread_ids.remove(index);

        let Some(context) = vids.get_mut(nested_vid) else {
            return Err(Error::Relationship(nested_vid.into()));
        };

        context.relation_status = RelationshipStatus::Bidirectional {
            thread_id,
            outstanding_nested_thread_ids: Default::default(),
        };

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{definitions::MessageType, OwnedVid, ReceivedTspMessage, Store, VerifiedVid};

    fn new_vid() -> OwnedVid {
        OwnedVid::new_did_peer("tcp://127.0.0.1:1337".parse().unwrap())
    }

    #[test]
    fn test_add_private_vid() {
        let store = Store::new();
        let vid = new_vid();

        store.add_private_vid(vid.clone()).unwrap();

        assert!(store.has_private_vid(vid.identifier()).unwrap());
    }

    #[test]
    fn test_add_verified_vid() {
        let store = Store::new();
        let owned_vid = new_vid();

        store.add_verified_vid(owned_vid.vid().clone()).unwrap();

        assert!(store.get_verified_vid(owned_vid.identifier()).is_ok());
    }

    #[test]
    fn test_remove() {
        let store = Store::new();
        let vid = new_vid();

        store.add_private_vid(vid.clone()).unwrap();

        assert!(store.has_private_vid(vid.identifier()).unwrap());

        store.forget_vid(vid.identifier()).unwrap();

        assert!(!store.has_private_vid(vid.identifier()).unwrap());
    }

    #[test]
    fn test_open_seal() {
        let store = Store::new();
        let alice = new_vid();
        let bob = new_vid();

        store.add_private_vid(alice.clone()).unwrap();
        store.add_private_vid(bob.clone()).unwrap();

        let message = b"hello world";

        let (url, sealed) = store
            .seal_message(alice.identifier(), bob.identifier(), None, message)
            .unwrap();

        assert_eq!(url.as_str(), "tcp://127.0.0.1:1337");

        let received = store.open_message(&mut sealed.clone()).unwrap();

        if let ReceivedTspMessage::GenericMessage {
            sender,
            message: received_message,
            message_type,
            ..
        } = received
        {
            assert_eq!(sender, alice.identifier());
            assert_eq!(received_message, message);
            assert_eq!(message_type, MessageType::SignedAndEncrypted);
        } else {
            panic!("unexpected message type");
        }
    }
}
