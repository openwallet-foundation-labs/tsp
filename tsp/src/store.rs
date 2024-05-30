use crate::{
    cesr::EnvelopeType,
    crypto::CryptoError,
    definitions::{Digest, MessageType, Payload, PrivateVid, ReceivedTspMessage, VerifiedVid},
    error::Error,
    vid::VidError,
    OwnedVid, Vid,
};
#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, RwLock},
};
use url::Url;

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug)]
pub enum RelationshipStatus {
    _Controlled,
    Bidirectional(Digest),
    Unidirectional(Digest),
    Unrelated,
}

/// VID and its key material, intended for serialization
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct ExportVid {
    vid: crate::Vid,
    private: Option<crate::OwnedVid>,
    relation_status: RelationshipStatus,
    relation_vid: Option<String>,
    parent_vid: Option<String>,
    tunnel: Option<Box<[String]>>,
}

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
                    vid: Vid::from_verified_vid(context.vid.clone()),
                    private: context.private.clone().map(OwnedVid::from_private_vid),
                    relation_status: context.relation_status,
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
                vid.vid.identifier().to_string(),
                VidContext {
                    vid: Arc::new(vid.vid),
                    private: match vid.private {
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

                (next_hop, hops[1..].to_vec(), inner_message)
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
            let sender = self.get_private_vid(next_hop)?;

            //TODO: we cannot user 'sender.relation_vid()', since the relationship status of this cannot be set
            let recipient = match self.get_vid(sender.identifier())?.get_relation_vid() {
                Some(destination) => self.get_verified_vid(destination)?,
                None => return Err(Error::MissingDropOff(sender.identifier().to_string())),
            };

            let tsp_message = crate::crypto::seal(
                &*sender,
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
                        // TODO: do not allocate
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
                        })
                    }
                    Payload::AcceptRelationship { thread_id } => {
                        let mut vids = self.vids.write()?;
                        let Some(context) = vids.get_mut(&sender) else {
                            //TODO: should we inform the user of who sent this?
                            return Err(Error::Relationship(
                                "received confirmation of a relation with an unknown entity".into(),
                            ));
                        };

                        let RelationshipStatus::Unidirectional(digest) = context.relation_status
                        else {
                            return Err(Error::Relationship(
                                "received confirmation of a relation that we did not want".into(),
                            ));
                        };

                        if thread_id != digest {
                            return Err(Error::Relationship(
                                "attempt to change the terms of the relationship".into(),
                            ));
                        }

                        context.relation_status = RelationshipStatus::Bidirectional(digest);

                        Ok(ReceivedTspMessage::AcceptRelationship { sender })
                    }
                    Payload::CancelRelationship { thread_id } => {
                        if let Some(context) = self.vids.write()?.get_mut(&sender) {
                            match context.relation_status {
                                RelationshipStatus::Bidirectional(digest)
                                | RelationshipStatus::Unidirectional(digest) => {
                                    if thread_id != digest {
                                        return Err(Error::Relationship(
                                            "invalid attempt to end the relationship".into(),
                                        ));
                                    }
                                    context.relation_status = RelationshipStatus::Unrelated;
                                }
                                _ => todo!(),
                            }
                        }

                        Ok(ReceivedTspMessage::CancelRelationship { sender })
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
