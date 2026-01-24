use crate::{
    ExportVid, OwnedVid,
    cesr::EnvelopeType,
    crypto::CryptoError,
    definitions::{
        Digest, MessageType, Payload, PrivateVid, ReceivedTspMessage, RelationshipStatus,
        VerifiedVid,
    },
    error::Error,
    vid::{VidError, resolve::verify_vid_offline},
};
#[cfg(feature = "async")]
use bytes::Bytes;
use bytes::BytesMut;
use std::{
    collections::HashMap,
    fmt::Display,
    sync::{Arc, RwLock},
};
use url::Url;

#[derive(Clone)]
pub(crate) struct VidContext {
    vid: Arc<dyn VerifiedVid>,
    private: Option<Arc<dyn PrivateVid>>,
    relation_status: RelationshipStatus,
    relation_vid: Option<String>,
    parent_vid: Option<String>,
    tunnel: Option<Box<[String]>>,
    metadata: Option<serde_json::Value>,
}

impl VidContext {
    /// Set the parent VID for this VID. Used to create a nested TSP message
    fn set_parent_vid(&mut self, parent_vid: Option<&str>) {
        self.parent_vid = parent_vid.map(|r| r.to_string());
    }

    /// Set the relation VID for this VID. The relation VID will be used as
    /// sender VID when sending messages to this VID
    fn set_relation_vid(&mut self, relation_vid: Option<&str>) {
        self.relation_vid = relation_vid.map(|r| r.to_string());
    }

    /// Replace the relation status for this VID.
    #[must_use]
    fn replace_relation_status(
        &mut self,
        relation_status: RelationshipStatus,
    ) -> RelationshipStatus {
        std::mem::replace(&mut self.relation_status, relation_status)
    }

    /// Set the route for this VID. The route will be used to send routed messages to this VID
    fn set_route(&mut self, route: Vec<String>) {
        if route.is_empty() {
            self.tunnel = None;
        } else {
            self.tunnel = Some(route.into_boxed_slice());
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

pub type Aliases = HashMap<String, String>;
pub type WebvhUpdateKeys = HashMap<String, Vec<u8>>;

/// Holds private and verified VIDs
///
/// A Store contains verified VIDs, our relationship status to them,
/// as well as the private VIDs that this application has control over.
///
/// The struct is the primary interface to the VID wallet, in a synchronous
/// context (when no async runtime is available).
#[derive(Default, Clone)]
pub struct SecureStore {
    pub(crate) vids: Arc<RwLock<HashMap<String, VidContext>>>,
    pub(crate) aliases: Arc<RwLock<Aliases>>,
    pub(crate) keys: Arc<RwLock<WebvhUpdateKeys>>,
}

/// This wallet is used to store and resolve VIDs
impl SecureStore {
    /// Create a new, empty VID wallet
    pub fn new() -> Self {
        Default::default()
    }

    /// Export the wallet to serializable default types
    pub fn export(&self) -> Result<(Vec<ExportVid>, Aliases, WebvhUpdateKeys), Error> {
        let vids = self
            .vids
            .read()?
            .values()
            .map(|context| ExportVid {
                id: context.vid.identifier().to_string(),
                transport: context.vid.endpoint().clone(),
                public_sigkey: context.vid.verifying_key().clone(),
                sig_key_type: context.vid.signature_key_type(),
                public_enckey: context.vid.encryption_key().clone(),
                enc_key_type: context.vid.encryption_key_type(),
                sigkey: context.private.as_ref().map(|x| x.signing_key().clone()),
                enckey: context.private.as_ref().map(|x| x.decryption_key().clone()),
                relation_status: context.relation_status.clone(),
                relation_vid: context.relation_vid.clone(),
                parent_vid: context.parent_vid.clone(),
                tunnel: context.tunnel.clone(),
                metadata: context.metadata.clone(),
            })
            .collect::<Vec<_>>();

        Ok((
            vids,
            self.aliases.read()?.clone(),
            self.keys.read()?.clone(),
        ))
    }

    /// Import the wallet from serializable default types
    pub fn import(
        &self,
        vids: Vec<ExportVid>,
        aliases: Aliases,
        keys: WebvhUpdateKeys,
    ) -> Result<(), Error> {
        vids.into_iter().try_for_each(|vid| {
            self.vids.write()?.insert(
                vid.id.to_string(),
                VidContext {
                    vid: Arc::new(vid.verified_vid()),
                    private: vid
                        .private_vid()
                        .map(|private| -> Arc<dyn PrivateVid> { Arc::new(private) }),
                    relation_status: vid.relation_status,
                    relation_vid: vid.relation_vid,
                    parent_vid: vid.parent_vid,
                    tunnel: vid.tunnel,
                    metadata: vid.metadata,
                },
            );

            Ok::<(), Error>(())
        })?;

        keys.into_iter().try_for_each(|(k, v)| {
            self.add_secret_key(k, v)?;
            Ok::<(), Error>(())
        })?;

        aliases.into_iter().try_for_each(|(k, v)| {
            self.set_alias(k, v)?;
            Ok(())
        })
    }

    pub fn add_secret_key(&self, kid: String, secret_key: Vec<u8>) -> Result<(), Error> {
        self.keys.write()?.insert(kid, secret_key);
        Ok(())
    }

    pub fn get_secret_key(&self, kid: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.keys.read()?.get(kid).cloned())
    }

    /// Add the already resolved `verified_vid` to the wallet as a relationship
    pub fn add_verified_vid(
        &self,
        verified_vid: impl VerifiedVid + 'static,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        let did = verified_vid.identifier().to_string();
        let verified_vid = Arc::new(verified_vid);

        self.vids
            .write()?
            .entry(did.clone())
            .and_modify(|context| {
                context.vid = verified_vid.clone();
                context.metadata = metadata.clone();
            })
            .or_insert(VidContext {
                vid: verified_vid,
                private: None,
                relation_status: RelationshipStatus::Unrelated,
                relation_vid: None,
                parent_vid: None,
                tunnel: None,
                metadata,
            });

        Ok(())
    }

    /// Adds `private_vid` to the wallet
    pub fn add_private_vid(
        &self,
        private_vid: impl PrivateVid + 'static,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        let vid = Arc::new(private_vid);

        self.vids
            .write()?
            .entry(vid.identifier().to_string())
            .and_modify(|context| {
                context.vid = vid.clone();
                context.private = Some(vid.clone());
                context.metadata = metadata.clone();
            })
            .or_insert(VidContext {
                vid: vid.clone(),
                private: Some(vid),
                relation_status: RelationshipStatus::Unrelated,
                relation_vid: None,
                parent_vid: None,
                tunnel: None,
                metadata: metadata
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(|_| Error::Internal)?,
            });

        Ok(())
    }

    /// Remove a VID from the [`SecureStore`]
    pub fn forget_vid(&self, vid: &str) -> Result<(), Error> {
        self.vids.write()?.remove(vid);

        Ok(())
    }

    /// Sets the parent for a VID, thus making it a nested VID
    pub fn set_parent_for_vid(&self, vid: &str, parent_vid: Option<&str>) -> Result<(), Error> {
        let parent_vid = if let Some(parent_vid) = parent_vid {
            Some(self.try_resolve_alias(parent_vid)?)
        } else {
            None
        };

        self.modify_vid(vid, |resolved| {
            resolved.set_parent_vid(parent_vid.as_deref());

            Ok(())
        })
    }

    pub fn relation_status_for_vid_pair(
        &self,
        local_vid: &str,
        remote_vid: &str,
    ) -> Result<RelationshipStatus, Error> {
        let local_vid = self.try_resolve_alias(local_vid)?;
        let remote_vid = self.try_resolve_alias(remote_vid)?;

        if let Some((_, context)) = self.vids.read()?.iter().find(|(r_vid, context)| {
            (**r_vid == remote_vid) && (context.relation_vid.as_deref() == Some(&local_vid))
        }) {
            Ok(context.relation_status.clone())
        } else {
            Ok(RelationshipStatus::Unrelated)
        }
    }

    /// List all VIDs in the wallet
    pub fn list_vids(&self) -> Result<Vec<String>, Error> {
        Ok(self.vids.read()?.keys().cloned().collect())
    }

    /// Sets the relationship status and relation for a VID.
    pub fn set_relation_and_status_for_vid(
        &self,
        vid: &str,
        relation_status: RelationshipStatus,
        relation_vid: &str,
    ) -> Result<(), Error> {
        let relation_vid = self.try_resolve_alias(relation_vid)?;
        self.modify_vid(vid, |resolved| {
            resolved.set_relation_vid(Some(&relation_vid));
            let _ = resolved.replace_relation_status(relation_status);

            Ok(())
        })
    }

    /// Sets the relationship status for a VID
    pub fn set_relation_status_for_vid(
        &self,
        vid: &str,
        relation_status: RelationshipStatus,
    ) -> Result<(), Error> {
        let _ = self.replace_relation_status_for_vid(vid, relation_status)?;

        Ok(())
    }

    /// Sets the relationship status for a VID
    pub fn replace_relation_status_for_vid(
        &self,
        vid: &str,
        relation_status: RelationshipStatus,
    ) -> Result<RelationshipStatus, Error> {
        self.modify_vid(vid, |resolved| {
            Ok(resolved.replace_relation_status(relation_status))
        })
    }

    /// Adds a route to an already existing VID, making it a nested VID
    pub fn set_route_for_vid(
        &self,
        vid: &str,
        route: impl IntoIterator<Item: ToString, IntoIter: ExactSizeIterator<Item = impl Display>>,
    ) -> Result<(), Error> {
        let route = route.into_iter();
        if route.len() == 1 {
            return Err(Error::InvalidRoute(
                "A route must have at least two VIDs".into(),
            ));
        }

        self.modify_vid(vid, |resolved| {
            resolved.set_route(route.map(|x| x.to_string()).collect());

            Ok(())
        })
    }

    /// Modify a verified-vid by applying an operation to it (internal use only)
    pub(crate) fn modify_vid<T>(
        &self,
        vid: &str,
        change: impl FnOnce(&mut VidContext) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let vid = self.try_resolve_alias(vid)?;

        match self.vids.write()?.get_mut(&vid) {
            Some(resolved) => change(resolved),
            None => Err(Error::UnverifiedVid(vid.to_string())),
        }
    }

    /// Check whether the [PrivateVid] identified by `vid` exists in the wallet
    pub fn has_private_vid(&self, vid: &str) -> Result<bool, Error> {
        match self.get_private_vid(vid) {
            Ok(_) => Ok(true),
            Err(Error::UnverifiedVid(_)) | Err(Error::MissingPrivateVid(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Retrieve the [PrivateVid] identified by `vid` from the wallet, if it exists.
    pub(crate) fn get_private_vid(&self, vid: &str) -> Result<Arc<dyn PrivateVid>, Error> {
        match self.get_vid(vid)?.private {
            Some(private) => Ok(private),
            None => Err(Error::MissingPrivateVid(vid.to_string())),
        }
    }

    /// Check whether the [VerifiedVid] identified by `vid` exists in the wallet
    pub fn has_verified_vid(&self, vid: &str) -> Result<bool, Error> {
        match self.get_verified_vid(vid) {
            Ok(_) => Ok(true),
            Err(Error::UnverifiedVid(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Retrieve the [VerifiedVid] identified by `vid` from the wallet if it exists.
    pub fn get_verified_vid(&self, vid: &str) -> Result<Arc<dyn VerifiedVid>, Error> {
        Ok(self.get_vid(vid)?.vid)
    }

    /// Retrieve the [VidContext] identified by `vid` from the wallet, if it exists.
    pub(super) fn get_vid(&self, vid: &str) -> Result<VidContext, Error> {
        let vid = self.try_resolve_alias(vid)?;

        match self.vids.read()?.get(&vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnverifiedVid(vid.to_string())),
        }
    }

    /// Resolve alias to its corresponding DID
    pub fn resolve_alias(&self, alias: &str) -> Result<Option<String>, Error> {
        let aliases = self.aliases.read()?;
        Ok(aliases.get(alias).cloned())
    }

    /// Resolve alias to its corresponding DID, or leave it as is
    pub fn try_resolve_alias(&self, alias: &str) -> Result<String, Error> {
        Ok(self
            .resolve_alias(alias)?
            .unwrap_or(alias.to_owned())
            .to_string())
    }

    /// Set alias for a DID
    pub fn set_alias(&self, alias: String, did: String) -> Result<(), Error> {
        self.aliases.write()?.insert(alias, did);
        Ok(())
    }

    // ANCHOR: seal_message-mbBook
    /// Seal a TSP message.
    /// The message is encrypted, encoded, and signed using the key material
    /// of the sender and receiver, specified by their VIDs.
    ///
    /// Note that the corresponding VIDs should first be added and configured
    /// using this store.
    pub fn seal_message(
        &self,
        sender: &str,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<(Url, Vec<u8>), Error> {
        // ANCHOR_END: seal_message-mbBook
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
        self.seal_message_payload_and_hash(sender, receiver, nonconfidential_data, payload, None)
    }

    /// Seal a TSP message and return the digest of the payload
    pub(crate) fn seal_message_payload_and_hash(
        &self,
        sender: &str,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        payload: Payload<&[u8]>,
        digest: Option<&mut Digest>,
    ) -> Result<(url::Url, Vec<u8>), Error> {
        let sender = self.get_private_vid(sender)?;
        let receiver_context = self.get_vid(receiver)?;

        // send routed mode
        if let Some(intermediaries) = receiver_context.get_route() {
            let first_hop = self.get_vid(&intermediaries[0])?;

            let (sender, inner_message) = match first_hop.get_relation_vid() {
                Some(first_sender) => {
                    let inner_sender = receiver_context
                        .get_relation_vid()
                        .unwrap_or(sender.identifier());
                    let inner_sender = self.get_private_vid(inner_sender)?;

                    let tsp_message: Vec<u8> = crate::crypto::seal_and_hash(
                        &*inner_sender,
                        &*receiver_context.vid,
                        nonconfidential_data,
                        payload,
                        digest,
                    )?;

                    let first_sender = self.get_private_vid(first_sender)?;

                    (first_sender, tsp_message)
                }
                None => return Err(VidError::ResolveVid("missing sender VID for first hop").into()),
            };

            let hops = intermediaries[1..]
                .iter()
                .map(|x| x.as_ref())
                .collect::<Vec<_>>();

            return self.seal_message_payload(
                sender.identifier(),
                first_hop.vid.identifier(),
                None,
                Payload::RoutedMessage(hops, &inner_message),
            );
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

            if parent_sender != sender.identifier() && inner_sender != sender.identifier() {
                return Err(VidError::ResolveVid("incorrect sender VID").into());
            }

            let inner_sender = self.get_private_vid(inner_sender)?;

            let inner_message = if let Payload::Content(_) = payload {
                crate::crypto::sign(
                    &*inner_sender,
                    Some(&*receiver_context.vid),
                    payload.as_bytes(),
                )?
            } else {
                crate::crypto::seal_and_hash(
                    &*inner_sender,
                    &*receiver_context.vid,
                    None,
                    payload,
                    digest,
                )?
            };

            let parent_sender = self.get_private_vid(parent_sender)?;
            let parent_receiver = self.get_verified_vid(parent_receiver)?;

            return self.seal_message_payload(
                parent_sender.identifier(),
                parent_receiver.identifier(),
                nonconfidential_data,
                Payload::NestedMessage(&inner_message),
            );
        }

        // send direct mode
        let tsp_message = crate::crypto::seal_and_hash(
            &*sender,
            &*receiver_context.vid,
            nonconfidential_data,
            payload,
            digest,
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

    /// Pass along an in-transit routed TSP `opaque_message` that is not meant for us, given earlier resolved VIDs.
    /// The message is routed through the route that has been established with `receiver`.
    pub fn forward_routed_message(
        &self,
        next_hop: &str,
        route: Vec<&[u8]>,
        opaque_payload: &[u8],
    ) -> Result<(Url, Vec<u8>), Error> {
        if route.is_empty() {
            // we are the final delivery point, we should be the 'next_hop'
            let sender = self.get_vid(next_hop)?;

            let Some(sender_private) = &sender.private else {
                return Err(Error::MissingPrivateVid(next_hop.to_string()));
            };

            let recipient = match sender.get_relation_vid() {
                Some(destination) => self.get_verified_vid(destination)?,
                None => return Err(Error::MissingDropOff(sender.vid.identifier().to_string())),
            };

            self.seal_message_payload(
                sender_private.identifier(),
                recipient.identifier(),
                None,
                Payload::NestedMessage(opaque_payload),
            )
        } else {
            // we are an intermediary, continue sending the message
            let next_hop_context = self
                .get_vid(next_hop)
                .map_err(|_| Error::UnresolvedNextHop(next_hop.to_string()))?;

            let sender = match next_hop_context.get_relation_vid() {
                Some(first_sender) => self.get_private_vid(first_sender)?,
                None => return Err(Error::InvalidNextHop(next_hop.to_string())),
            };

            self.seal_message_payload(
                sender.identifier(),
                next_hop_context.vid.identifier(),
                None,
                Payload::RoutedMessage(route, opaque_payload),
            )
        }
    }

    // ANCHOR: probe_sender-mbBook
    /// Get the sender from a CESR message
    fn probe_sender(message: &mut [u8]) -> Result<&str, Error> {
        // ANCHOR_END: probe_sender-mbBook
        Ok(match crate::cesr::probe(message)? {
            EnvelopeType::EncryptedMessage { sender, .. } => std::str::from_utf8(sender)?,
            EnvelopeType::SignedMessage { sender, .. } => std::str::from_utf8(sender)?,
        })
    }

    // ANCHOR: open_message-mbBook
    /// Decode an encrypted `message`, which has to be addressed to one of the VIDs in `receivers`, and has to have
    /// `verified_vids` as one of the senders.
    pub fn open_message<'a>(
        &self,
        message: &'a mut [u8],
    ) -> Result<ReceivedTspMessage<&'a [u8]>, Error> {
        // ANCHOR_END: open_message-mbBook
        let probed_message = crate::cesr::probe(message)?;

        match probed_message {
            EnvelopeType::EncryptedMessage {
                sender,
                receiver: intended_receiver,
                ..
            } => {
                let intended_receiver = std::str::from_utf8(intended_receiver)?.to_string();

                let Ok(receiver_pid) = self.get_private_vid(&intended_receiver) else {
                    return Err(CryptoError::UnexpectedRecipient.into());
                };

                let sender = std::str::from_utf8(sender)?.to_string();

                let Ok(sender_vid) = self.get_verified_vid(&sender) else {
                    #[cfg(feature = "async")]
                    return Err(Error::UnverifiedSource(sender, None));
                    #[cfg(not(feature = "async"))]
                    return Err(Error::UnverifiedSource(sender));
                };

                let (nonconfidential_data, payload, crypto_type, signature_type) =
                    crate::crypto::open(&*receiver_pid, &*sender_vid, message)?;

                match payload {
                    Payload::Content(message) => Ok(ReceivedTspMessage::GenericMessage {
                        sender,
                        receiver: Some(intended_receiver),
                        nonconfidential_data,
                        message,
                        message_type: MessageType {
                            crypto_type,
                            signature_type,
                        },
                    }),
                    Payload::NestedMessage(inner) => {
                        // in case the inner vid isn't recognized (which can realistically happen in Routed mode),
                        // in async mode we might want to ask if they still want to open the message; but for that
                        // we must communicate the payload to them so they can process it further.
                        // we cannot do this after 'open_message' since 'inner' will be borrowed
                        let inner_vid = Self::probe_sender(inner)?;
                        if self.get_verified_vid(inner_vid).is_err() {
                            return Err(Error::UnverifiedSource(
                                inner_vid.to_owned(),
                                #[cfg(feature = "async")]
                                Some(Bytes::from(inner.to_vec()).into()),
                            ));
                        }

                        let mut received_message = self.open_message(inner)?;

                        // if inner message was not encrypted, but outer message was encrypted by the same sender,
                        // then inner message was also sufficiently encrypted
                        if let ReceivedTspMessage::GenericMessage {
                            message_type:
                                ref mut message_type @ MessageType {
                                    crypto_type: crate::cesr::CryptoType::Plaintext,
                                    signature_type: _,
                                },
                            sender: ref inner_sender,
                            ..
                        } = received_message
                            && self.get_vid(inner_sender)?.get_parent_vid() == Some(&sender)
                        {
                            message_type.crypto_type = crypto_type;
                        }

                        Ok(received_message)
                    }
                    Payload::RoutedMessage(hops, message) => {
                        let next_hop = std::str::from_utf8(hops[0])?;

                        Ok(ReceivedTspMessage::ForwardRequest {
                            sender,
                            receiver: intended_receiver,
                            next_hop: next_hop.to_string(),
                            route: hops[1..]
                                .iter()
                                .map(|x| BytesMut::from_iter(x.iter()))
                                .collect(),
                            opaque_payload: BytesMut::from_iter(message.iter()),
                        })
                    }
                    Payload::RequestRelationship { route, thread_id } => {
                        Ok(ReceivedTspMessage::RequestRelationship {
                            sender,
                            receiver: intended_receiver,
                            route: route.map(|vec| vec.iter().map(|vid| vid.to_vec()).collect()),
                            thread_id,
                            nested_vid: None,
                        })
                    }
                    Payload::AcceptRelationship { thread_id } => {
                        self.upgrade_relation(receiver_pid.identifier(), &sender, thread_id)?;

                        Ok(ReceivedTspMessage::AcceptRelationship {
                            sender,
                            receiver: intended_receiver,
                            nested_vid: None,
                        })
                    }
                    Payload::CancelRelationship { thread_id } => {
                        if let Some(context) = self.vids.write()?.get_mut(&sender) {
                            match context.relation_status {
                                RelationshipStatus::Bidirectional {
                                    thread_id: digest, ..
                                }
                                | RelationshipStatus::Unidirectional { thread_id: digest }
                                | RelationshipStatus::ReverseUnidirectional { thread_id: digest } =>
                                {
                                    if thread_id != digest {
                                        return Err(Error::Relationship(
                                            "invalid attempt to end the relationship, wrong thread_id".into(),
                                        ));
                                    }
                                    context.relation_status = RelationshipStatus::Unrelated;
                                    context.relation_vid = None;
                                }
                                RelationshipStatus::_Controlled => {
                                    return Err(Error::Relationship(
                                        "you cannot cancel a relationship with yourself".into(),
                                    ));
                                }
                                RelationshipStatus::Unrelated => {}
                            }
                        }

                        Ok(ReceivedTspMessage::CancelRelationship {
                            sender,
                            receiver: intended_receiver,
                        })
                    }
                    Payload::RequestNestedRelationship { inner, thread_id } => {
                        let EnvelopeType::SignedMessage {
                            sender: inner_vid,
                            receiver: None,
                            ..
                        } = crate::cesr::probe(inner)?
                        else {
                            return Err(Error::Relationship(
                                "invalid nested request, not a signed message".into(),
                            ));
                        };

                        let inner_vid = std::str::from_utf8(inner_vid)?.to_string();

                        self.add_nested_vid(&inner_vid)?;

                        // the act of opening this message is simply verifying the signature, because this SDK doesn't yet
                        // support sending data as part of control messages. This can easily change.
                        let _ = self.open_message(inner)?;

                        self.set_parent_for_vid(&inner_vid, Some(&sender))?;

                        Ok(ReceivedTspMessage::RequestRelationship {
                            sender,
                            receiver: intended_receiver,
                            route: None,
                            thread_id,
                            nested_vid: Some(inner_vid),
                        })
                    }
                    Payload::AcceptNestedRelationship { thread_id, inner } => {
                        let EnvelopeType::SignedMessage {
                            sender: vid,
                            receiver: Some(connect_to_vid),
                            ..
                        } = crate::cesr::probe(inner)?
                        else {
                            return Err(Error::Relationship(
                                "invalid nested accept reply, not a signed message".into(),
                            ));
                        };

                        let vid = std::str::from_utf8(vid)?.to_string();
                        let connect_to_vid = std::str::from_utf8(connect_to_vid)?.to_string();
                        self.add_nested_vid(&vid)?;

                        let _ = self.open_message(inner)?;

                        self.set_parent_for_vid(&vid, Some(&sender))?;
                        self.add_nested_relation(&sender, &vid, thread_id)?;
                        self.set_relation_and_status_for_vid(
                            &connect_to_vid,
                            RelationshipStatus::bi_default(),
                            &vid,
                        )?;
                        self.set_relation_and_status_for_vid(
                            &vid,
                            RelationshipStatus::bi_default(),
                            &connect_to_vid,
                        )?;

                        Ok(ReceivedTspMessage::AcceptRelationship {
                            sender,
                            receiver: intended_receiver,
                            nested_vid: Some(vid),
                        })
                    }
                    Payload::NewIdentifier { thread_id, new_vid } => {
                        let vid = std::str::from_utf8(new_vid)?.to_string();
                        match self.get_vid(&sender)?.relation_status {
                            RelationshipStatus::Bidirectional {
                                thread_id: check_id,
                                ..
                            } => {
                                if check_id == thread_id {
                                    Ok(ReceivedTspMessage::NewIdentifier {
                                        sender,
                                        receiver: intended_receiver,
                                        new_vid: vid,
                                    })
                                } else {
                                    Err(Error::Relationship(
                                        "thread_id does not match, not accepting new identifier"
                                            .into(),
                                    ))
                                }
                            }
                            _ => Err(Error::Relationship(format!(
                                "no bidirectional relationship with {sender}, not accepting new identifier"
                            ))),
                        }
                    }
                    Payload::Referral { referred_vid } => {
                        //NOTE: we could also check the relationship status here, but since a 3rd party introduction
                        //might be of interest to a user anyway regardless of existing status, we are less strict about it
                        let vid = std::str::from_utf8(referred_vid)?;
                        Ok(ReceivedTspMessage::Referral {
                            sender,
                            receiver: intended_receiver,
                            referred_vid: vid.to_string(),
                        })
                    }
                }
            }
            EnvelopeType::SignedMessage {
                sender,
                receiver: intended_receiver,
                ..
            } => {
                let intended_receiver = intended_receiver
                    .map(|intended_receiver| {
                        let intended_receiver = std::str::from_utf8(intended_receiver)?;

                        if !self.has_private_vid(intended_receiver)? {
                            return Err::<_, Error>(CryptoError::UnexpectedRecipient.into());
                        }

                        Ok(intended_receiver.to_string())
                    })
                    .transpose()?;

                let sender = std::str::from_utf8(sender)?.to_string();

                let Ok(sender_vid) = self.get_verified_vid(&sender) else {
                    return Err(Error::UnverifiedVid(sender.to_string()));
                };

                let (message, message_type) = crate::crypto::verify(&*sender_vid, message)?;

                Ok(ReceivedTspMessage::GenericMessage {
                    sender,
                    receiver: intended_receiver,
                    nonconfidential_data: None,
                    message,
                    message_type,
                })
            }
        }
    }

    /// Make relationship request messages. The receiver vid has to be a publicly discoverable Vid.
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

        let mut thread_id = Default::default();
        let tsp_message = crate::crypto::seal_and_hash(
            &*sender,
            &*receiver,
            None,
            Payload::RequestRelationship {
                route,
                thread_id: Default::default(),
            },
            Some(&mut thread_id),
        )?;

        let (transport, tsp_message) = if let Some(hop_list) = path {
            self.set_route_for_vid(receiver.identifier(), hop_list)?;
            self.resolve_route_and_send(hop_list, &tsp_message)?
        } else {
            (receiver.endpoint().clone(), tsp_message)
        };

        self.set_relation_and_status_for_vid(
            receiver.identifier(),
            RelationshipStatus::Unidirectional { thread_id },
            sender.identifier(),
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

        self.set_relation_and_status_for_vid(
            receiver,
            RelationshipStatus::Bidirectional {
                thread_id,
                outstanding_nested_thread_ids: Default::default(),
            },
            sender,
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
        let old_relationship =
            self.replace_relation_status_for_vid(receiver, RelationshipStatus::Unrelated)?;

        let thread_id = match old_relationship {
            RelationshipStatus::Bidirectional { thread_id, .. } => thread_id,
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            RelationshipStatus::ReverseUnidirectional { thread_id } => thread_id,
            RelationshipStatus::_Controlled | RelationshipStatus::Unrelated => {
                return Err(Error::Relationship("no relationship to cancel".into()));
            }
        };

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

        let inner_message = crate::crypto::sign(&nested_vid, None, &[])?;

        let mut thread_id = Default::default();
        let (endpoint, tsp_message) = self.seal_message_payload_and_hash(
            sender.identifier(),
            receiver.identifier(),
            None,
            Payload::RequestNestedRelationship {
                inner: &inner_message,
                thread_id: Default::default(),
            },
            Some(&mut thread_id),
        )?;

        self.add_nested_thread_id(receiver.identifier(), thread_id)?;

        Ok(((endpoint, tsp_message), nested_vid))
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
        self.set_relation_and_status_for_vid(
            nested_vid.identifier(),
            RelationshipStatus::bi(thread_id),
            nested_receiver,
        )?;
        self.set_relation_and_status_for_vid(
            nested_receiver,
            RelationshipStatus::bi(thread_id),
            nested_vid.identifier(),
        )?;

        let receiver_vid = self.get_vid(nested_receiver)?;
        let parent_receiver = receiver_vid
            .get_parent_vid()
            .ok_or(Error::Relationship(format!(
                "missing parent for {nested_receiver}"
            )))?;

        let inner_message = crate::crypto::sign(&nested_vid, Some(&*receiver_vid.vid), &[])?;

        let (transport, tsp_message) = self.seal_message_payload(
            parent_sender,
            parent_receiver,
            None,
            Payload::AcceptNestedRelationship {
                thread_id,
                inner: &inner_message,
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

    pub fn make_new_identifier_notice(
        &self,
        sender: &str,
        receiver: &str,
        new_vid: &str,
    ) -> Result<(Url, Vec<u8>), Error> {
        // check that the new vid is actually one of ours
        let new_vid = self.get_private_vid(new_vid)?;

        let RelationshipStatus::Bidirectional { thread_id, .. } =
            self.get_vid(receiver)?.relation_status
        else {
            return Err(Error::Relationship(format!(
                "no relationship with {receiver}"
            )));
        };

        let (transport, tsp_message) = self.seal_message_payload(
            sender,
            receiver,
            None,
            Payload::NewIdentifier {
                thread_id,
                new_vid: new_vid.identifier().as_ref(),
            },
        )?;

        Ok((transport, tsp_message))
    }

    pub fn make_relationship_referral(
        &self,
        sender: &str,
        receiver: &str,
        referred_vid: &str,
    ) -> Result<(Url, Vec<u8>), Error> {
        // check that we actually know the referred vid
        let referred_vid = self.get_vid(referred_vid)?;

        let (transport, tsp_message) = self.seal_message_payload(
            sender,
            receiver,
            None,
            Payload::Referral {
                referred_vid: referred_vid.vid.identifier().as_ref(),
            },
        )?;

        Ok((transport, tsp_message))
    }

    fn make_propositioning_vid(&self, parent_vid: &str) -> Result<OwnedVid, Error> {
        let transport = Url::parse("tsp://").expect("error generating a URL");

        let vid = OwnedVid::new_did_peer(transport);
        self.add_private_vid(vid.clone(), None::<serde_json::Value>)?;
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
        let nested_vid = verify_vid_offline(vid)?;

        self.add_verified_vid(nested_vid, None)
    }

    fn upgrade_relation(
        &self,
        my_vid: &str,
        other_vid: &str,
        thread_id: Digest,
    ) -> Result<(), Error> {
        let mut vids = self.vids.write()?;
        let Some(context) = vids.get_mut(other_vid) else {
            return Err(Error::Relationship(format!(
                "unknown other vid {other_vid}"
            )));
        };

        let RelationshipStatus::Unidirectional { thread_id: digest } = context.relation_status
        else {
            return Err(Error::Relationship(format!(
                "no unidirectional relationship with {other_vid}, cannot upgrade"
            )));
        };

        if thread_id != digest {
            return Err(Error::Relationship(
                "thread_id does not match digest".to_string(),
            ));
        }

        context.relation_vid = Some(my_vid.to_string());

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
            return Err(Error::Relationship(format!("no relationship with {vid}")));
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
            return Err(Error::Relationship(format!(
                "unknown parent vid {parent_vid}"
            )));
        };

        let RelationshipStatus::Bidirectional {
            ref mut outstanding_nested_thread_ids,
            ..
        } = context.relation_status
        else {
            return Err(Error::Relationship(format!(
                "no relationship set for parent vid {parent_vid}"
            )));
        };

        // find the thread_id in the list of outstanding thread id's of the parent and remove it
        let Some(index) = outstanding_nested_thread_ids
            .iter()
            .position(|&x| x == thread_id)
        else {
            return Err(Error::Relationship(format!(
                "cannot find thread_id for nested vid {nested_vid}"
            )));
        };
        outstanding_nested_thread_ids.remove(index);

        let Some(context) = vids.get_mut(nested_vid) else {
            return Err(Error::Relationship(format!(
                "unknown nested vid {nested_vid}"
            )));
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
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{OwnedVid, ReceivedTspMessage, RelationshipStatus, SecureStore, VerifiedVid};

    fn new_vid() -> OwnedVid {
        OwnedVid::new_did_peer("tcp://127.0.0.1:1337".parse().unwrap())
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_add_private_vid() {
        let store = SecureStore::new();
        let vid = new_vid();

        store.add_private_vid(vid.clone(), None).unwrap();

        assert!(store.has_private_vid(vid.identifier()).unwrap());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_add_verified_vid() {
        let store = SecureStore::new();
        let owned_vid = new_vid();

        store
            .add_verified_vid(owned_vid.vid().clone(), None)
            .unwrap();

        assert!(store.get_verified_vid(owned_vid.identifier()).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_remove() {
        let store = SecureStore::new();
        let vid = new_vid();

        store.add_private_vid(vid.clone(), None).unwrap();

        assert!(store.has_private_vid(vid.identifier()).unwrap());

        store.forget_vid(vid.identifier()).unwrap();

        assert!(!store.has_private_vid(vid.identifier()).unwrap());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_open_seal() {
        let store = SecureStore::new();
        let alice = new_vid();
        let bob = new_vid();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();

        let message = b"hello world";

        let (url, mut sealed) = store
            .seal_message(alice.identifier(), bob.identifier(), None, message)
            .unwrap();

        assert_eq!(url.as_str(), "tcp://127.0.0.1:1337");

        let received = store.open_message(&mut sealed).unwrap();

        if let ReceivedTspMessage::GenericMessage {
            sender,
            message: received_message,
            message_type,
            ..
        } = received
        {
            assert_eq!(sender, alice.identifier());
            assert_eq!(received_message, message);
            assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
            assert_ne!(
                message_type.signature_type,
                crate::cesr::SignatureType::NoSignature
            );
        } else {
            panic!("unexpected message type");
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_make_relationship_request() {
        let store = SecureStore::new();
        let alice = new_vid();
        let bob = new_vid();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();

        let (url, mut sealed) = store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();

        assert_eq!(url.as_str(), "tcp://127.0.0.1:1337");

        let received = store.open_message(&mut sealed).unwrap();

        if let ReceivedTspMessage::RequestRelationship { sender, .. } = received {
            assert_eq!(sender, alice.identifier());
        } else {
            panic!("unexpected message type");
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_make_relationship_accept() {
        let store = SecureStore::new();
        let alice = new_vid();
        let bob = new_vid();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();

        // alice wants to establish a relation
        let (url, mut sealed) = store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();

        assert_eq!(url.as_str(), "tcp://127.0.0.1:1337");
        let received = store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::RequestRelationship {
            sender, thread_id, ..
        } = received
        else {
            panic!("unexpected message type");
        };

        assert_eq!(sender, alice.identifier());

        // bob accepts the relation
        let (url, mut sealed) = store
            .make_relationship_accept(bob.identifier(), alice.identifier(), thread_id, None)
            .unwrap();

        assert_eq!(url.as_str(), "tcp://127.0.0.1:1337");
        let received = store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::AcceptRelationship { sender, .. } = received else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, bob.identifier());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_relationship_accept_resolves_aliases() {
        let store = SecureStore::new();
        let alice = new_vid();
        let bob = new_vid();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();
        store
            .set_alias("alice".to_string(), alice.identifier().to_string())
            .unwrap();
        store
            .set_alias("bob".to_string(), bob.identifier().to_string())
            .unwrap();

        let (_, mut sealed) = store
            .make_relationship_request("alice", "bob", None)
            .unwrap();
        let ReceivedTspMessage::RequestRelationship { thread_id, .. } =
            store.open_message(&mut sealed).unwrap()
        else {
            panic!("unexpected message type");
        };

        store
            .make_relationship_accept("bob", "alice", thread_id, None)
            .unwrap();

        let (vids, _aliases, _keys) = store.export().unwrap();
        let alice_entry = vids
            .iter()
            .find(|vid| vid.id == alice.identifier())
            .expect("missing alice entry");
        assert_eq!(alice_entry.relation_vid.as_deref(), Some(bob.identifier()));
        assert!(matches!(
            alice_entry.relation_status,
            RelationshipStatus::Bidirectional { .. }
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_make_relationship_cancel() {
        let store = SecureStore::new();
        let alice = new_vid();
        let bob = new_vid();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();

        // alice wants to establish a relation
        let (url, mut sealed) = store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();

        assert_eq!(url.as_str(), "tcp://127.0.0.1:1337");
        let received = store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::RequestRelationship {
            sender, thread_id, ..
        } = received
        else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, alice.identifier());

        // bob accepts the relation
        let (url, mut sealed) = store
            .make_relationship_accept(bob.identifier(), alice.identifier(), thread_id, None)
            .unwrap();

        assert_eq!(url.as_str(), "tcp://127.0.0.1:1337");
        let received = store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::AcceptRelationship { sender, .. } = received else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, bob.identifier());

        // now bob cancels the relation
        let (url, mut sealed) = store
            .make_relationship_cancel(bob.identifier(), alice.identifier())
            .unwrap();

        assert_eq!(url.as_str(), "tcp://127.0.0.1:1337");
        let received = store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::CancelRelationship { sender, .. } = received else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, bob.identifier());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_make_new_identity() {
        let a_store = SecureStore::new();
        let b_store = SecureStore::new();
        let alice = new_vid();
        let bob = new_vid();
        let charles = new_vid();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        a_store.add_private_vid(charles.clone(), None).unwrap();

        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();

        let status = super::RelationshipStatus::bi_default();

        a_store
            .replace_relation_status_for_vid(bob.identifier(), status.clone())
            .unwrap();
        b_store
            .replace_relation_status_for_vid(alice.identifier(), status)
            .unwrap();

        // alice introduces her new identity to bob
        let (url, mut sealed) = a_store
            .make_new_identifier_notice(alice.identifier(), bob.identifier(), charles.identifier())
            .unwrap();

        assert_eq!(url.as_str(), "tcp://127.0.0.1:1337");
        let received = b_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::NewIdentifier {
            sender,
            receiver,
            new_vid,
        } = received
        else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, alice.identifier());
        assert_eq!(receiver, bob.identifier());
        assert_eq!(new_vid, charles.identifier());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_make_referral() {
        let store = SecureStore::new();
        let alice = new_vid();
        let bob = new_vid();
        let charles = new_vid();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();
        store.add_verified_vid(charles.clone(), None).unwrap();

        // alice vouches for charlies to bob
        let (url, mut sealed) = store
            .make_relationship_referral(alice.identifier(), bob.identifier(), charles.identifier())
            .unwrap();

        assert_eq!(url.as_str(), "tcp://127.0.0.1:1337");
        let received = store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::Referral {
            sender,
            receiver,
            referred_vid,
        } = received
        else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, alice.identifier());
        assert_eq!(receiver, bob.identifier());
        assert_eq!(referred_vid, charles.identifier());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_routed() {
        let a_store = SecureStore::new();
        let b_store = SecureStore::new();
        let c_store = SecureStore::new();
        let d_store = SecureStore::new();

        let nette_a = new_vid();
        let sneaky_a = new_vid();

        let b = new_vid();

        let mailbox_c = new_vid();
        let c = new_vid();

        let sneaky_d = new_vid();
        let nette_d = new_vid();

        a_store.add_private_vid(nette_a.clone(), None).unwrap();
        a_store.add_private_vid(sneaky_a.clone(), None).unwrap();
        b_store.add_private_vid(b.clone(), None).unwrap();
        c_store.add_private_vid(mailbox_c.clone(), None).unwrap();
        c_store.add_private_vid(c.clone(), None).unwrap();
        d_store.add_private_vid(sneaky_d.clone(), None).unwrap();
        d_store.add_private_vid(nette_d.clone(), None).unwrap();

        a_store.add_verified_vid(b.clone(), None).unwrap();
        a_store.add_verified_vid(sneaky_d.clone(), None).unwrap();

        b_store.add_verified_vid(nette_a.clone(), None).unwrap();
        b_store.add_verified_vid(c.clone(), None).unwrap();

        c_store.add_verified_vid(b.clone(), None).unwrap();
        c_store.add_verified_vid(nette_d.clone(), None).unwrap();

        d_store.add_verified_vid(sneaky_a.clone(), None).unwrap();
        d_store.add_verified_vid(mailbox_c.clone(), None).unwrap();

        a_store
            .set_relation_and_status_for_vid(
                b.identifier(),
                RelationshipStatus::Unidirectional {
                    thread_id: Default::default(),
                },
                nette_a.identifier(),
            )
            .unwrap();

        a_store
            .set_relation_and_status_for_vid(
                sneaky_d.identifier(),
                RelationshipStatus::Unidirectional {
                    thread_id: Default::default(),
                },
                sneaky_a.identifier(),
            )
            .unwrap();

        a_store
            .set_route_for_vid(
                sneaky_d.identifier(),
                &[b.identifier(), c.identifier(), mailbox_c.identifier()],
            )
            .unwrap();

        b_store
            .set_relation_and_status_for_vid(
                c.identifier(),
                RelationshipStatus::Unidirectional {
                    thread_id: Default::default(),
                },
                b.identifier(),
            )
            .unwrap();

        c_store
            .set_relation_and_status_for_vid(
                mailbox_c.identifier(),
                RelationshipStatus::Unidirectional {
                    thread_id: Default::default(),
                },
                nette_d.identifier(),
            )
            .unwrap();

        let hello_world = b"hello world";

        let (_url, mut sealed) = a_store
            .seal_message(
                sneaky_a.identifier(),
                sneaky_d.identifier(),
                None,
                hello_world,
            )
            .unwrap();

        let received = b_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::ForwardRequest {
            sender,
            receiver,
            next_hop,
            route,
            opaque_payload,
        } = received
        else {
            panic!()
        };
        assert_eq!(sender, nette_a.identifier());
        assert_eq!(receiver, b.identifier());

        let (_url, mut sealed) = b_store
            .forward_routed_message(
                &next_hop,
                route.iter().map(|s| s.iter().as_slice()).collect(),
                &opaque_payload,
            )
            .unwrap();

        let received = c_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::ForwardRequest {
            sender,
            receiver,
            next_hop,
            route,
            opaque_payload,
        } = received
        else {
            panic!()
        };
        assert_eq!(sender, b.identifier());
        assert_eq!(receiver, c.identifier());

        let (_url, mut sealed) = c_store
            .forward_routed_message(
                &next_hop,
                route.iter().map(|s| s.iter().as_slice()).collect(),
                &opaque_payload,
            )
            .unwrap();

        let received = d_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::GenericMessage {
            sender,
            receiver,
            nonconfidential_data,
            message,
            message_type,
        } = received
        else {
            panic!()
        };

        assert_eq!(sender, sneaky_a.identifier());
        assert_eq!(receiver.unwrap(), sneaky_d.identifier());
        assert!(nonconfidential_data.is_none());
        assert_eq!(message, hello_world);
        assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
        assert_ne!(
            message_type.signature_type,
            crate::cesr::SignatureType::NoSignature
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_nested_manual() {
        let a_store = SecureStore::new();
        let b_store = SecureStore::new();

        let a = new_vid();
        let b = new_vid();

        let nested_a = new_vid();
        let nested_b = new_vid();

        a_store.add_private_vid(a.clone(), None).unwrap();
        a_store.add_private_vid(nested_a.clone(), None).unwrap();

        b_store.add_private_vid(b.clone(), None).unwrap();
        b_store.add_private_vid(nested_b.clone(), None).unwrap();

        a_store.add_verified_vid(b.clone(), None).unwrap();
        a_store.add_verified_vid(nested_b.clone(), None).unwrap();

        b_store.add_verified_vid(a.clone(), None).unwrap();
        b_store.add_verified_vid(nested_a.clone(), None).unwrap();

        a_store
            .set_parent_for_vid(nested_b.identifier(), Some(b.identifier()))
            .unwrap();

        a_store
            .set_relation_and_status_for_vid(
                nested_b.identifier(),
                RelationshipStatus::Unidirectional {
                    thread_id: Default::default(),
                },
                nested_a.identifier(),
            )
            .unwrap();

        a_store
            .set_parent_for_vid(nested_a.identifier(), Some(a.identifier()))
            .unwrap();

        b_store
            .set_parent_for_vid(nested_a.identifier(), Some(a.identifier()))
            .unwrap();

        let hello_world = b"hello world";

        let (_url, mut sealed) = a_store
            .seal_message(
                nested_a.identifier(),
                nested_b.identifier(),
                None,
                hello_world,
            )
            .unwrap();

        let received = b_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::GenericMessage {
            sender,
            receiver,
            nonconfidential_data,
            message,
            message_type,
        } = received
        else {
            panic!()
        };

        assert_eq!(sender, nested_a.identifier());
        assert_eq!(receiver.unwrap(), nested_b.identifier());
        assert!(nonconfidential_data.is_none());
        assert_eq!(message, hello_world);
        assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
        assert_ne!(
            message_type.signature_type,
            crate::cesr::SignatureType::NoSignature
        );
    }

    #[cfg(not(feature = "pq"))]
    #[test]
    #[wasm_bindgen_test]
    fn test_nested_automatic_setup() {
        let a_store = SecureStore::new();
        let b_store = SecureStore::new();

        let a = new_vid();
        let b = new_vid();

        a_store.add_private_vid(a.clone(), None).unwrap();
        b_store.add_private_vid(b.clone(), None).unwrap();

        a_store.add_verified_vid(b.clone(), None).unwrap();
        b_store.add_verified_vid(a.clone(), None).unwrap();

        let (_url, mut sealed) = a_store
            .make_relationship_request(a.identifier(), b.identifier(), None)
            .unwrap();

        let received = b_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::RequestRelationship {
            nested_vid: None,
            thread_id,
            ..
        } = received
        else {
            panic!()
        };

        let (_url, mut sealed) = b_store
            .make_relationship_accept(b.identifier(), a.identifier(), thread_id, None)
            .unwrap();

        let received = a_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::AcceptRelationship { .. } = received else {
            panic!()
        };

        let ((_url, mut sealed), nested_a) = a_store
            .make_nested_relationship_request(a.identifier(), b.identifier())
            .unwrap();

        let received = b_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::RequestRelationship {
            nested_vid: Some(ref nested_vid_1),
            thread_id,
            ..
        } = received
        else {
            panic!()
        };

        let ((_url, mut sealed), nested_b) = b_store
            .make_nested_relationship_accept(b.identifier(), nested_vid_1, thread_id)
            .unwrap();

        let received = a_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::AcceptRelationship {
            nested_vid: Some(ref nested_vid_2),
            ..
        } = received
        else {
            panic!()
        };

        assert_eq!(nested_a.identifier(), nested_vid_1);
        assert_eq!(nested_b.identifier(), nested_vid_2);

        assert_eq!(
            a_store
                .get_vid(nested_a.identifier())
                .unwrap()
                .get_parent_vid(),
            Some(a.identifier())
        );

        assert_eq!(
            b_store
                .get_vid(nested_b.identifier())
                .unwrap()
                .get_parent_vid(),
            Some(b.identifier())
        );

        assert_eq!(
            b_store.get_vid(nested_vid_1).unwrap().get_parent_vid(),
            Some(a.identifier())
        );

        assert_eq!(
            a_store.get_vid(nested_vid_2).unwrap().get_parent_vid(),
            Some(b.identifier())
        );

        let hello_world = b"hello world";

        let (_url, mut sealed) = a_store
            .seal_message(
                nested_a.identifier(),
                nested_b.identifier(),
                None,
                hello_world,
            )
            .unwrap();

        let received = b_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::GenericMessage {
            sender,
            receiver,
            nonconfidential_data,
            message,
            message_type,
        } = received
        else {
            panic!()
        };

        assert_eq!(sender, nested_a.identifier());
        assert_eq!(receiver.unwrap(), nested_b.identifier());
        assert!(nonconfidential_data.is_none());
        assert_eq!(message, hello_world);
        assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
        assert_ne!(
            message_type.signature_type,
            crate::cesr::SignatureType::NoSignature
        );
    }
}
