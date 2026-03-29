use crate::{
    ExportVid, OwnedVid,
    cesr::EnvelopeType,
    crypto::CryptoError,
    definitions::{
        Digest, MessageType, Payload, PendingNestedRelationship, PrivateVid,
        ReceivedRelationshipDelivery, ReceivedRelationshipForm, ReceivedTspMessage,
        RelationshipForm, RelationshipStatus, VerifiedVid,
    },
    error::Error,
    vid::{VidError, resolve::verify_vid_offline},
};
#[cfg(feature = "async")]
use bytes::Bytes;
use bytes::BytesMut;
use rand::{RngCore, SeedableRng, rngs::StdRng};
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

fn nested_digest(bytes: &[u8]) -> Digest {
    #[cfg(feature = "nacl")]
    {
        crate::crypto::blake2b256(bytes)
    }

    #[cfg(not(feature = "nacl"))]
    {
        crate::crypto::sha256(bytes)
    }
}

fn relationship_digest_algorithm() -> crate::crypto::RelationshipDigestAlgorithm {
    #[cfg(feature = "nacl")]
    {
        crate::crypto::RelationshipDigestAlgorithm::Blake2b256
    }

    #[cfg(not(feature = "nacl"))]
    {
        crate::crypto::RelationshipDigestAlgorithm::Sha2_256
    }
}

fn nested_digest_field<'a>(digest: &'a Digest) -> crate::cesr::Digest<'a> {
    #[cfg(feature = "nacl")]
    {
        crate::cesr::Digest::Blake2b256(digest)
    }

    #[cfg(not(feature = "nacl"))]
    {
        crate::cesr::Digest::Sha2_256(digest)
    }
}

enum NestedRelationshipEvent {
    Request {
        nested_vid: String,
        thread_id: Digest,
    },
    Accept {
        nested_vid: String,
        thread_id: Digest,
        reply_thread_id: Digest,
    },
}

fn received_relationship_form<'a>(
    form: RelationshipForm<'a, &'a [u8]>,
) -> Result<ReceivedRelationshipForm<&'a [u8]>, Error> {
    match form {
        RelationshipForm::Direct => Ok(ReceivedRelationshipForm::Direct),
        RelationshipForm::Parallel {
            new_vid,
            sig_new_vid,
        } => Ok(ReceivedRelationshipForm::Parallel {
            new_vid: std::str::from_utf8(new_vid)?.to_string(),
            sig_new_vid,
        }),
    }
}

fn unverified_parallel_vid_error(vid: &str, error: VidError) -> Error {
    match error {
        VidError::InvalidVid(_) => Error::UnverifiedVid(vid.to_string()),
        other => other.into(),
    }
}

fn unverified_source_error(vid: &str) -> Error {
    #[cfg(feature = "async")]
    {
        Error::UnverifiedSource(vid.to_string(), None)
    }

    #[cfg(not(feature = "async"))]
    {
        Error::UnverifiedSource(vid.to_string())
    }
}

fn requires_existing_parallel_relationship_error() -> Error {
    Error::Relationship(
        "parallel relationship-forming requires an existing bidirectional relationship".into(),
    )
}

enum DeferredVerifiedVid {
    Known(Arc<dyn VerifiedVid>),
    Deferred(crate::Vid),
}

impl DeferredVerifiedVid {
    fn as_verified(&self) -> &dyn VerifiedVid {
        match self {
            DeferredVerifiedVid::Known(vid) => &**vid,
            DeferredVerifiedVid::Deferred(vid) => vid,
        }
    }

    fn persist(self, store: &SecureStore) -> Result<(), Error> {
        if let DeferredVerifiedVid::Deferred(vid) = self {
            store.add_verified_vid(vid, None)?;
        }

        Ok(())
    }
}

struct ParallelSignatureMaterial {
    digest: Digest,
    sig_new_vid: Vec<u8>,
    request_nonce: Option<[u8; 32]>,
}

enum ParallelSignatureContext<'a> {
    Request {
        sender_identity: &'a str,
        nonce: [u8; 32],
    },
    Accept {
        sender_identity: &'a str,
        thread_id: Digest,
    },
}

fn random_nonce_bytes() -> [u8; 32] {
    let mut nonce_bytes = [0_u8; 32];
    StdRng::from_entropy().fill_bytes(&mut nonce_bytes);
    nonce_bytes
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

    fn get_verified_vid_or_resolve_offline(
        &self,
        vid: &str,
        map_offline_error: impl FnOnce(VidError) -> Error,
    ) -> Result<DeferredVerifiedVid, Error> {
        match self.get_verified_vid(vid) {
            Ok(verified_vid) => Ok(DeferredVerifiedVid::Known(verified_vid)),
            Err(Error::UnverifiedVid(_)) => Ok(DeferredVerifiedVid::Deferred(
                verify_vid_offline(vid).map_err(map_offline_error)?,
            )),
            Err(error) => Err(error),
        }
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

    fn make_signed_nested_request_message(
        &self,
        sender: &dyn PrivateVid,
    ) -> Result<(Vec<u8>, Digest), Error> {
        let mut csprng = StdRng::from_entropy();
        let mut nonce_bytes = [0_u8; 32];
        csprng.fill_bytes(&mut nonce_bytes);

        let sender_identity = Some(sender.identifier().as_bytes());
        let mut request_digest = [0_u8; 32];

        let placeholder_payload: crate::cesr::Payload<'_, &[u8], &[u8]> =
            crate::cesr::Payload::DirectRelationProposal {
                nonce: crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes),
                request_digest: nested_digest_field(&request_digest),
            };

        let mut encoded_payload =
            Vec::with_capacity(placeholder_payload.calculate_size(sender_identity));
        crate::cesr::encode_payload(&placeholder_payload, sender_identity, &mut encoded_payload)?;

        request_digest = nested_digest(&encoded_payload);

        encoded_payload.clear();
        let payload: crate::cesr::Payload<'_, &[u8], &[u8]> =
            crate::cesr::Payload::DirectRelationProposal {
                nonce: crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes),
                request_digest: nested_digest_field(&request_digest),
            };
        crate::cesr::encode_payload(&payload, sender_identity, &mut encoded_payload)?;

        let message = crate::crypto::sign(sender, None, &encoded_payload)?;

        Ok((message, request_digest))
    }

    fn make_signed_nested_accept_message(
        &self,
        sender: &dyn PrivateVid,
        receiver: &dyn VerifiedVid,
        thread_id: Digest,
    ) -> Result<(Vec<u8>, Digest), Error> {
        let sender_identity = Some(sender.identifier().as_bytes());
        let mut reply_thread_id = [0_u8; 32];

        let placeholder_payload: crate::cesr::Payload<'_, &[u8], &[u8]> =
            crate::cesr::Payload::DirectRelationAffirm {
                request_digest: nested_digest_field(&thread_id),
                reply_digest: nested_digest_field(&reply_thread_id),
            };

        let mut encoded_payload =
            Vec::with_capacity(placeholder_payload.calculate_size(sender_identity));
        crate::cesr::encode_payload(&placeholder_payload, sender_identity, &mut encoded_payload)?;

        reply_thread_id = nested_digest(&encoded_payload);

        encoded_payload.clear();
        let payload: crate::cesr::Payload<'_, &[u8], &[u8]> =
            crate::cesr::Payload::DirectRelationAffirm {
                request_digest: nested_digest_field(&thread_id),
                reply_digest: nested_digest_field(&reply_thread_id),
            };
        crate::cesr::encode_payload(&payload, sender_identity, &mut encoded_payload)?;

        let message = crate::crypto::sign(sender, Some(receiver), &encoded_payload)?;

        Ok((message, reply_thread_id))
    }

    fn try_open_nested_relationship_message(
        &self,
        outer_sender: &str,
        inner: &mut [u8],
    ) -> Result<Option<NestedRelationshipEvent>, Error> {
        let EnvelopeType::SignedMessage {
            sender: inner_sender,
            receiver: inner_receiver,
            ..
        } = crate::cesr::probe(inner)?
        else {
            return Ok(None);
        };

        let inner_sender = std::str::from_utf8(inner_sender)?.to_string();
        let inner_receiver = inner_receiver
            .map(std::str::from_utf8)
            .transpose()?
            .map(str::to_owned);

        let (inner_message, _) = match self.get_verified_vid(&inner_sender) {
            Ok(sender_vid) => crate::crypto::verify(&*sender_vid, inner)?,
            Err(_) => {
                let Ok(sender_vid) = verify_vid_offline(&inner_sender) else {
                    return Ok(None);
                };
                crate::crypto::verify(&sender_vid, inner)?
            }
        };

        let mut payload_bytes = inner_message.to_vec();
        let crate::cesr::DecodedPayload {
            payload,
            sender_identity,
        } = match crate::cesr::decode_payload(&mut payload_bytes) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(None),
        };

        if sender_identity != Some(inner_sender.as_bytes()) {
            return Err(Error::Relationship(
                "nested relationship control payload sender mismatch".into(),
            ));
        }

        match payload {
            crate::cesr::Payload::DirectRelationProposal { request_digest, .. } => {
                if inner_receiver.is_some() {
                    return Err(Error::Relationship(
                        "invalid nested relationship request receiver".into(),
                    ));
                }

                if self.get_verified_vid(&inner_sender).is_err() {
                    self.add_nested_vid(&inner_sender)?;
                }
                self.set_parent_for_vid(&inner_sender, Some(outer_sender))?;

                Ok(Some(NestedRelationshipEvent::Request {
                    nested_vid: inner_sender,
                    thread_id: *request_digest.as_bytes(),
                }))
            }
            crate::cesr::Payload::DirectRelationAffirm {
                request_digest,
                reply_digest,
            } => {
                let Some(connect_to_vid) = inner_receiver else {
                    return Err(Error::Relationship(
                        "invalid nested relationship accept receiver".into(),
                    ));
                };

                if self.get_verified_vid(&inner_sender).is_err() {
                    self.add_nested_vid(&inner_sender)?;
                }
                self.set_parent_for_vid(&inner_sender, Some(outer_sender))?;
                self.consume_pending_nested_request(
                    outer_sender,
                    *request_digest.as_bytes(),
                    &connect_to_vid,
                )?;

                let relation_status =
                    RelationshipStatus::bi(*request_digest.as_bytes(), *reply_digest.as_bytes());
                self.set_relation_and_status_for_vid(
                    &connect_to_vid,
                    relation_status.clone(),
                    &inner_sender,
                )?;
                self.set_relation_and_status_for_vid(
                    &inner_sender,
                    relation_status,
                    &connect_to_vid,
                )?;

                Ok(Some(NestedRelationshipEvent::Accept {
                    nested_vid: inner_sender,
                    thread_id: *request_digest.as_bytes(),
                    reply_thread_id: *reply_digest.as_bytes(),
                }))
            }
            _ => Ok(None),
        }
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
                let sender_vid = self.get_verified_vid_or_resolve_offline(&sender, |_| {
                    unverified_source_error(&sender)
                })?;

                let (
                    (nonconfidential_data, payload, crypto_type, signature_type),
                    parallel_signature_info,
                ) = crate::crypto::open_with_signature_info(
                    &*receiver_pid,
                    sender_vid.as_verified(),
                    message,
                )?;

                if let Some(parallel_signature_info) = parallel_signature_info {
                    self.verify_parallel_relationship_signature(parallel_signature_info)?;
                }
                sender_vid.persist(self)?;

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
                        if let Some(received_message) =
                            self.try_open_nested_relationship_message(&sender, inner)?
                        {
                            return Ok(match received_message {
                                NestedRelationshipEvent::Request {
                                    nested_vid,
                                    thread_id,
                                } => ReceivedTspMessage::RequestRelationship {
                                    sender,
                                    receiver: intended_receiver,
                                    thread_id,
                                    form: ReceivedRelationshipForm::Direct,
                                    delivery: ReceivedRelationshipDelivery::Nested { nested_vid },
                                },
                                NestedRelationshipEvent::Accept {
                                    nested_vid,
                                    thread_id,
                                    reply_thread_id,
                                } => ReceivedTspMessage::AcceptRelationship {
                                    sender,
                                    receiver: intended_receiver,
                                    thread_id,
                                    reply_thread_id,
                                    form: ReceivedRelationshipForm::Direct,
                                    delivery: ReceivedRelationshipDelivery::Nested { nested_vid },
                                },
                            });
                        }

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
                    Payload::RequestRelationship { thread_id, form } => {
                        let form = received_relationship_form(form)?;

                        Ok(ReceivedTspMessage::RequestRelationship {
                            sender,
                            receiver: intended_receiver,
                            thread_id,
                            form,
                            delivery: ReceivedRelationshipDelivery::Direct,
                        })
                    }
                    Payload::AcceptRelationship {
                        thread_id,
                        reply_thread_id,
                        form,
                    } => {
                        let is_direct = matches!(&form, RelationshipForm::Direct);
                        let form = received_relationship_form(form)?;

                        if is_direct {
                            self.upgrade_relation(
                                receiver_pid.identifier(),
                                &sender,
                                thread_id,
                                reply_thread_id,
                            )?;
                        }

                        Ok(ReceivedTspMessage::AcceptRelationship {
                            sender,
                            receiver: intended_receiver,
                            thread_id,
                            reply_thread_id,
                            form,
                            delivery: ReceivedRelationshipDelivery::Direct,
                        })
                    }
                    Payload::CancelRelationship { thread_id } => {
                        if let Some(context) = self.vids.write()?.get_mut(&sender) {
                            match context.relation_status {
                                RelationshipStatus::Bidirectional {
                                    remote_thread_id: digest,
                                    ..
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
        if route.is_some() {
            return Err(Error::Relationship(
                "routed relationship-forming requires Reply_Path; not implemented".into(),
            ));
        }

        let sender = self.get_private_vid(sender)?;
        let receiver = self.get_verified_vid(receiver)?;
        let mut thread_id = Default::default();
        let tsp_message = crate::crypto::seal_and_hash(
            &*sender,
            &*receiver,
            None,
            Payload::RequestRelationship {
                thread_id: Default::default(),
                form: RelationshipForm::Direct,
            },
            Some(&mut thread_id),
        )?;

        self.set_relation_and_status_for_vid(
            receiver.identifier(),
            RelationshipStatus::Unidirectional { thread_id },
            sender.identifier(),
        )?;

        Ok((receiver.endpoint().clone(), tsp_message.to_owned()))
    }

    fn build_parallel_signature_material(
        &self,
        sender_new_vid: &dyn PrivateVid,
        context: ParallelSignatureContext<'_>,
    ) -> Result<ParallelSignatureMaterial, Error> {
        let digest_algorithm = relationship_digest_algorithm();
        let mut digest = [0_u8; 32];

        let (signed_data, request_nonce) = match context {
            ParallelSignatureContext::Request {
                sender_identity,
                nonce,
            } => (
                crate::crypto::build_parallel_request_signed_data(
                    Some(sender_identity.as_bytes()),
                    digest_algorithm,
                    nonce,
                    &mut digest,
                    sender_new_vid.identifier().as_bytes(),
                )?,
                Some(nonce),
            ),
            ParallelSignatureContext::Accept {
                sender_identity,
                thread_id,
            } => (
                crate::crypto::build_parallel_accept_signed_data(
                    &thread_id,
                    Some(sender_identity.as_bytes()),
                    digest_algorithm,
                    &mut digest,
                    sender_new_vid.identifier().as_bytes(),
                )?,
                None,
            ),
        };

        let sig_new_vid = crate::crypto::sign_detached(sender_new_vid, &signed_data)?;

        Ok(ParallelSignatureMaterial {
            digest,
            sig_new_vid,
            request_nonce,
        })
    }

    /// Make a parallel relationship request using an existing relationship as a referral.
    pub fn make_parallel_relationship_request(
        &self,
        sender: &str,
        receiver: &str,
        sender_new_vid: &str,
    ) -> Result<(Url, Vec<u8>), Error> {
        let sender = self.get_private_vid(sender)?;
        let receiver = self.get_verified_vid(receiver)?;
        let sender_new_vid = self.get_private_vid(sender_new_vid)?;

        match self.relation_status_for_vid_pair(sender.identifier(), receiver.identifier())? {
            RelationshipStatus::Bidirectional { .. } => {}
            RelationshipStatus::_Controlled
            | RelationshipStatus::Unidirectional { .. }
            | RelationshipStatus::ReverseUnidirectional { .. }
            | RelationshipStatus::Unrelated => {
                return Err(requires_existing_parallel_relationship_error());
            }
        }

        let signature_material = self.build_parallel_signature_material(
            &*sender_new_vid,
            ParallelSignatureContext::Request {
                sender_identity: sender.identifier(),
                nonce: random_nonce_bytes(),
            },
        )?;
        let mut thread_id = signature_material.digest;

        let tsp_message = crate::crypto::seal_and_hash_with_relationship_nonce(
            &*sender,
            &*receiver,
            None,
            Payload::RequestRelationship {
                thread_id: Default::default(),
                form: RelationshipForm::Parallel {
                    new_vid: sender_new_vid.identifier().as_bytes(),
                    sig_new_vid: signature_material.sig_new_vid.as_slice(),
                },
            },
            Some(&mut thread_id),
            signature_material.request_nonce,
        )?;

        Ok((receiver.endpoint().clone(), tsp_message.to_owned()))
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
        if route.is_some() {
            return Err(Error::Relationship(
                "routed relationship-forming requires Reply_Path; not implemented".into(),
            ));
        }

        let mut reply_thread_id = Default::default();
        let (transport, tsp_message) = self.seal_message_payload_and_hash(
            sender,
            receiver,
            None,
            Payload::AcceptRelationship {
                thread_id,
                reply_thread_id: Default::default(),
                form: RelationshipForm::Direct,
            },
            Some(&mut reply_thread_id),
        )?;

        self.set_relation_and_status_for_vid(
            receiver,
            RelationshipStatus::Bidirectional {
                thread_id: reply_thread_id,
                remote_thread_id: thread_id,
                outstanding_nested_requests: Default::default(),
            },
            sender,
        )?;

        Ok((transport, tsp_message))
    }

    /// Make a parallel relationship accept message over the new relationship.
    pub fn make_parallel_relationship_accept(
        &self,
        sender_new_vid: &str,
        receiver_new_vid: &str,
        thread_id: Digest,
    ) -> Result<(Url, Vec<u8>), Error> {
        let sender_new_vid = self.get_private_vid(sender_new_vid)?;
        let receiver_new_vid = self.get_verified_vid(receiver_new_vid)?;
        let signature_material = self.build_parallel_signature_material(
            &*sender_new_vid,
            ParallelSignatureContext::Accept {
                sender_identity: sender_new_vid.identifier(),
                thread_id,
            },
        )?;
        let mut reply_thread_id = signature_material.digest;

        let tsp_message = crate::crypto::seal_and_hash(
            &*sender_new_vid,
            &*receiver_new_vid,
            None,
            Payload::AcceptRelationship {
                thread_id,
                reply_thread_id: Default::default(),
                form: RelationshipForm::Parallel {
                    new_vid: sender_new_vid.identifier().as_bytes(),
                    sig_new_vid: signature_material.sig_new_vid.as_slice(),
                },
            },
            Some(&mut reply_thread_id),
        )?;

        Ok((receiver_new_vid.endpoint().clone(), tsp_message.to_owned()))
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
        let (inner_message, thread_id) = self.make_signed_nested_request_message(&nested_vid)?;

        let (endpoint, tsp_message) = self.seal_message_payload(
            sender.identifier(),
            receiver.identifier(),
            None,
            Payload::NestedMessage(&inner_message),
        )?;

        self.add_pending_nested_request(receiver.identifier(), thread_id, nested_vid.identifier())?;

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
        let receiver_vid = self.get_vid(nested_receiver)?;
        let parent_receiver = receiver_vid
            .get_parent_vid()
            .ok_or(Error::Relationship(format!(
                "missing parent for {nested_receiver}"
            )))?;

        let (inner_message, reply_thread_id) =
            self.make_signed_nested_accept_message(&nested_vid, &*receiver_vid.vid, thread_id)?;

        let (transport, tsp_message) = self.seal_message_payload(
            parent_sender,
            parent_receiver,
            None,
            Payload::NestedMessage(&inner_message),
        )?;

        let relation_status = RelationshipStatus::bi(reply_thread_id, thread_id);
        self.set_relation_and_status_for_vid(
            nested_vid.identifier(),
            relation_status.clone(),
            nested_receiver,
        )?;
        self.set_relation_and_status_for_vid(
            nested_receiver,
            relation_status,
            nested_vid.identifier(),
        )?;

        Ok(((transport, tsp_message), nested_vid))
    }

    fn make_propositioning_vid(&self, parent_vid: &str) -> Result<OwnedVid, Error> {
        let transport = Url::parse("tsp://").expect("error generating a URL");

        let vid = OwnedVid::new_did_peer(transport);
        self.add_private_vid(vid.clone(), None::<serde_json::Value>)?;
        self.set_parent_for_vid(vid.identifier(), Some(parent_vid))?;

        Ok(vid)
    }

    // Keep the routed relationship-forming scaffolding in place for a future
    // Reply_Path/routed-accept implementation, even though the public entry
    // points currently reject routed relationship-forming.
    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
        remote_thread_id: Digest,
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
            remote_thread_id,
            outstanding_nested_requests: Default::default(),
        };

        Ok(())
    }

    fn verify_parallel_relationship_signature(
        &self,
        parallel_signature_info: crate::crypto::ParallelSignatureInfo<'_>,
    ) -> Result<(), Error> {
        let new_vid = std::str::from_utf8(parallel_signature_info.new_vid)?;
        let verified_vid = self.get_verified_vid_or_resolve_offline(new_vid, |error| {
            unverified_parallel_vid_error(new_vid, error)
        })?;

        crate::crypto::verify_detached(
            verified_vid.as_verified(),
            &parallel_signature_info.signed_data,
            parallel_signature_info.sig_new_vid,
        )?;
        verified_vid.persist(self)?;

        Ok(())
    }

    fn add_pending_nested_request(
        &self,
        vid: &str,
        thread_id: Digest,
        local_nested_vid: &str,
    ) -> Result<(), Error> {
        let mut vids = self.vids.write()?;
        let Some(context) = vids.get_mut(vid) else {
            return Err(Error::MissingVid(vid.into()));
        };

        let RelationshipStatus::Bidirectional {
            ref mut outstanding_nested_requests,
            ..
        } = context.relation_status
        else {
            return Err(Error::Relationship(format!("no relationship with {vid}")));
        };

        outstanding_nested_requests.push(PendingNestedRelationship {
            thread_id,
            local_nested_vid: local_nested_vid.to_string(),
        });

        Ok(())
    }

    fn consume_pending_nested_request(
        &self,
        parent_vid: &str,
        thread_id: Digest,
        expected_local_nested_vid: &str,
    ) -> Result<(), Error> {
        let mut vids = self.vids.write()?;
        let Some(context) = vids.get_mut(parent_vid) else {
            return Err(Error::Relationship(format!(
                "unknown parent vid {parent_vid}"
            )));
        };

        let RelationshipStatus::Bidirectional {
            ref mut outstanding_nested_requests,
            ..
        } = context.relation_status
        else {
            return Err(Error::Relationship(format!(
                "no relationship set for parent vid {parent_vid}"
            )));
        };

        let Some(index) = outstanding_nested_requests
            .iter()
            .position(|request| request.thread_id == thread_id)
        else {
            return Err(Error::Relationship(format!(
                "cannot find thread_id for parent vid {parent_vid}"
            )));
        };
        if outstanding_nested_requests[index].local_nested_vid != expected_local_nested_vid {
            return Err(Error::Relationship(format!(
                "nested relationship accept receiver mismatch for parent vid {parent_vid}"
            )));
        }
        outstanding_nested_requests.remove(index);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::store::relationship_digest_algorithm;
    use crate::test_utils::*;
    use crate::{
        Error, Payload, ReceivedRelationshipDelivery, ReceivedRelationshipForm, ReceivedTspMessage,
        RelationshipForm, RelationshipStatus, SecureStore, VerifiedVid, crypto::CryptoError,
    };

    fn assert_url_matches(url: &url::Url, expected_receiver: &dyn VerifiedVid) {
        assert_eq!(url.as_str(), expected_receiver.endpoint().as_str());
    }

    fn establish_existing_relationship(
        a_store: &SecureStore,
        a_vid: &dyn VerifiedVid,
        b_store: &SecureStore,
        b_vid: &dyn VerifiedVid,
    ) {
        a_store
            .set_relation_and_status_for_vid(
                b_vid.identifier(),
                RelationshipStatus::Bidirectional {
                    thread_id: [1; 32],
                    remote_thread_id: [2; 32],
                    outstanding_nested_requests: vec![],
                },
                a_vid.identifier(),
            )
            .unwrap();
        b_store
            .set_relation_and_status_for_vid(
                a_vid.identifier(),
                RelationshipStatus::Bidirectional {
                    thread_id: [2; 32],
                    remote_thread_id: [1; 32],
                    outstanding_nested_requests: vec![],
                },
                b_vid.identifier(),
            )
            .unwrap();
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_add_private_vid() {
        let store = create_test_store();
        let vid = create_test_vid();

        store.add_private_vid(vid.clone(), None).unwrap();

        assert!(store.has_private_vid(vid.identifier()).unwrap());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_add_verified_vid() {
        let store = create_test_store();
        let owned_vid = create_test_vid();

        store
            .add_verified_vid(owned_vid.vid().clone(), None)
            .unwrap();

        assert!(store.get_verified_vid(owned_vid.identifier()).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_remove() {
        let store = create_test_store();
        let vid = create_test_vid();

        store.add_private_vid(vid.clone(), None).unwrap();

        assert!(store.has_private_vid(vid.identifier()).unwrap());

        store.forget_vid(vid.identifier()).unwrap();

        assert!(!store.has_private_vid(vid.identifier()).unwrap());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_open_seal() {
        let store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();

        let message = b"hello world";

        let (url, mut sealed) = store
            .seal_message(alice.identifier(), bob.identifier(), None, message)
            .unwrap();

        assert_url_matches(&url, &bob);

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
        let store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();

        let (url, mut sealed) = store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();

        assert_url_matches(&url, &bob);

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
        let store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();

        // alice wants to establish a relation
        let (url, mut sealed) = store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();

        assert_url_matches(&url, &bob);
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

        assert_url_matches(&url, &alice);
        let received = store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::AcceptRelationship { sender, .. } = received else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, bob.identifier());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_relationship_accept_resolves_aliases() {
        let store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

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
        let store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();

        // alice wants to establish a relation
        let (url, mut sealed) = store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();

        assert_url_matches(&url, &bob);
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

        assert_url_matches(&url, &alice);
        let received = store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::AcceptRelationship { sender, .. } = received else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, bob.identifier());

        // now bob cancels the relation
        let (url, mut sealed) = store
            .make_relationship_cancel(bob.identifier(), alice.identifier())
            .unwrap();

        assert_url_matches(&url, &alice);
        let received = store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::CancelRelationship { sender, .. } = received else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, bob.identifier());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_open_parallel_relationship_request() {
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();
        let alice_parallel = create_test_vid();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        a_store
            .add_private_vid(alice_parallel.clone(), None)
            .unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();
        establish_existing_relationship(&a_store, &alice, &b_store, &bob);
        let (url, mut sealed) = a_store
            .make_parallel_relationship_request(
                alice.identifier(),
                bob.identifier(),
                alice_parallel.identifier(),
            )
            .unwrap();

        assert_url_matches(&url, &bob);
        let received = b_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::RequestRelationship {
            sender,
            receiver,
            thread_id: received_request_digest,
            form:
                ReceivedRelationshipForm::Parallel {
                    new_vid,
                    sig_new_vid,
                },
            delivery: ReceivedRelationshipDelivery::Direct,
        } = received
        else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, alice.identifier());
        assert_eq!(receiver, bob.identifier());
        assert_eq!(new_vid, alice_parallel.identifier());
        assert_eq!(
            b_store
                .get_verified_vid(alice_parallel.identifier())
                .unwrap()
                .identifier(),
            alice_parallel.identifier()
        );
        assert!(received_request_digest.iter().any(|byte| *byte != 0));
        assert_eq!(sig_new_vid.len(), 64);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_open_parallel_relationship_accept() {
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();
        let alice_parallel = create_test_vid();
        let bob_parallel = create_test_vid();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        a_store
            .add_private_vid(alice_parallel.clone(), None)
            .unwrap();
        b_store.add_private_vid(bob_parallel.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();
        establish_existing_relationship(&a_store, &alice, &b_store, &bob);

        let (_url, mut request) = a_store
            .make_parallel_relationship_request(
                alice.identifier(),
                bob.identifier(),
                alice_parallel.identifier(),
            )
            .unwrap();
        let ReceivedTspMessage::RequestRelationship { thread_id, .. } =
            b_store.open_message(&mut request).unwrap()
        else {
            panic!("unexpected message type");
        };

        let (url, mut sealed) = b_store
            .make_parallel_relationship_accept(
                bob_parallel.identifier(),
                alice_parallel.identifier(),
                thread_id,
            )
            .unwrap();

        assert_url_matches(&url, &alice_parallel);
        let received = a_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::AcceptRelationship {
            sender,
            receiver,
            thread_id: request_digest,
            reply_thread_id: received_reply_digest,
            form:
                ReceivedRelationshipForm::Parallel {
                    new_vid,
                    sig_new_vid,
                },
            delivery: ReceivedRelationshipDelivery::Direct,
        } = received
        else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, bob_parallel.identifier());
        assert_eq!(receiver, alice_parallel.identifier());
        assert_eq!(new_vid, bob_parallel.identifier());
        assert_eq!(
            a_store
                .get_verified_vid(bob_parallel.identifier())
                .unwrap()
                .identifier(),
            bob_parallel.identifier()
        );
        assert_eq!(request_digest, thread_id);
        assert!(received_reply_digest.iter().any(|byte| *byte != 0));
        assert_eq!(sig_new_vid.len(), 64);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_parallel_relationship_request_rejects_invalid_signature_new() {
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();
        let alice_parallel = create_test_vid();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        a_store
            .add_private_vid(alice_parallel.clone(), None)
            .unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();

        let mut nonce_bytes = [0_u8; 32];
        StdRng::from_entropy().fill_bytes(&mut nonce_bytes);
        let mut thread_id = [0_u8; 32];
        let signed_data = crate::crypto::build_parallel_request_signed_data(
            Some(alice.identifier().as_bytes()),
            relationship_digest_algorithm(),
            nonce_bytes,
            &mut thread_id,
            alice_parallel.identifier().as_bytes(),
        )
        .unwrap();
        let mut sig_new_vid = crate::crypto::sign_detached(&alice_parallel, &signed_data).unwrap();
        sig_new_vid[0] ^= 0x01;

        let sender_vid = a_store.get_private_vid(alice.identifier()).unwrap();
        let receiver_vid = a_store.get_verified_vid(bob.identifier()).unwrap();
        let mut request_digest = Default::default();
        let mut sealed = crate::crypto::seal_and_hash_with_relationship_nonce(
            &*sender_vid,
            &*receiver_vid,
            None,
            Payload::RequestRelationship {
                thread_id: Default::default(),
                form: RelationshipForm::Parallel {
                    new_vid: alice_parallel.identifier().as_ref(),
                    sig_new_vid: sig_new_vid.as_slice(),
                },
            },
            Some(&mut request_digest),
            Some(nonce_bytes),
        )
        .unwrap();

        let Err(Error::Crypto(CryptoError::Verify(vid, _))) = b_store.open_message(&mut sealed)
        else {
            panic!("unexpected message result");
        };

        assert_eq!(vid, alice_parallel.identifier());
        assert!(matches!(
            b_store.get_verified_vid(alice_parallel.identifier()),
            Err(Error::UnverifiedVid(_))
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_invalid_outer_signature_does_not_persist_unknown_sender() {
        let receiver_store = create_test_store();
        let sender_store = create_test_store();
        let sender = create_test_vid();
        let receiver = create_test_vid();

        receiver_store
            .add_private_vid(receiver.clone(), None)
            .unwrap();
        sender_store.add_private_vid(sender.clone(), None).unwrap();
        sender_store
            .add_verified_vid(receiver.clone(), None)
            .unwrap();

        let (_url, mut sealed) = sender_store
            .seal_message(sender.identifier(), receiver.identifier(), None, b"hello")
            .unwrap();
        let last = sealed
            .last_mut()
            .expect("sealed message should not be empty");
        *last ^= 0x01;

        let Err(Error::Crypto(CryptoError::Verify(vid, _))) =
            receiver_store.open_message(&mut sealed)
        else {
            panic!("unexpected message result");
        };

        assert_eq!(vid, sender.identifier());
        assert!(matches!(
            receiver_store.get_verified_vid(sender.identifier()),
            Err(Error::UnverifiedVid(_))
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_parallel_relationship_request_requires_existing_relationship() {
        let store = create_test_store();
        let (alice, bob) = create_test_vid_pair();
        let alice_parallel = create_test_vid();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(alice_parallel.clone(), None).unwrap();
        store.add_verified_vid(bob.clone(), None).unwrap();

        let err = store
            .make_parallel_relationship_request(
                alice.identifier(),
                bob.identifier(),
                alice_parallel.identifier(),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            Error::Relationship(message) if message.contains("existing bidirectional relationship")
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_direct_relationship_tracks_local_and_remote_thread_ids() {
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();

        let (_url, mut request) = a_store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();

        let request_digest = match a_store
            .relation_status_for_vid_pair(alice.identifier(), bob.identifier())
            .unwrap()
        {
            RelationshipStatus::Unidirectional { thread_id } => thread_id,
            status => panic!("unexpected requester status after request: {status}"),
        };

        let ReceivedTspMessage::RequestRelationship { thread_id, .. } =
            b_store.open_message(&mut request).unwrap()
        else {
            panic!("unexpected message type");
        };
        assert_eq!(thread_id, request_digest);

        b_store
            .set_relation_and_status_for_vid(
                alice.identifier(),
                RelationshipStatus::Unidirectional { thread_id },
                bob.identifier(),
            )
            .unwrap();

        let (_url, mut accept) = b_store
            .make_relationship_accept(bob.identifier(), alice.identifier(), thread_id, None)
            .unwrap();

        let reply_digest = match b_store
            .relation_status_for_vid_pair(bob.identifier(), alice.identifier())
            .unwrap()
        {
            RelationshipStatus::Bidirectional {
                thread_id,
                remote_thread_id,
                ..
            } => {
                assert_eq!(remote_thread_id, request_digest);
                thread_id
            }
            status => panic!("unexpected replier status after accept: {status}"),
        };

        let ReceivedTspMessage::AcceptRelationship { .. } =
            a_store.open_message(&mut accept).unwrap()
        else {
            panic!("unexpected message type");
        };

        match a_store
            .relation_status_for_vid_pair(alice.identifier(), bob.identifier())
            .unwrap()
        {
            RelationshipStatus::Bidirectional {
                thread_id,
                remote_thread_id,
                ..
            } => {
                assert_eq!(thread_id, request_digest);
                assert_eq!(remote_thread_id, reply_digest);
            }
            status => panic!("unexpected requester status after accept: {status}"),
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_relationship_forming_requires_reply_path_for_routes() {
        let store = create_test_store();
        let (alice, bob) = create_test_vid_pair();
        let hop = create_test_vid();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_verified_vid(bob.clone(), None).unwrap();
        store.add_verified_vid(hop.clone(), None).unwrap();

        let err = store
            .make_relationship_request(
                alice.identifier(),
                bob.identifier(),
                Some(&[hop.identifier()]),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            crate::Error::Relationship(message) if message.contains("Reply_Path")
        ));

        let err = store
            .make_relationship_accept(
                alice.identifier(),
                bob.identifier(),
                [3; 32],
                Some(&[hop.identifier()]),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            crate::Error::Relationship(message) if message.contains("Reply_Path")
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_routed() {
        let a_store = create_test_store();
        let b_store = create_test_store();
        let c_store = create_test_store();
        let d_store = create_test_store();

        let nette_a = create_test_vid();
        let sneaky_a = create_test_vid();

        let b = create_test_vid();

        let mailbox_c = create_test_vid();
        let c = create_test_vid();

        let sneaky_d = create_test_vid();
        let nette_d = create_test_vid();

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
        let a_store = create_test_store();
        let b_store = create_test_store();

        let a = create_test_vid();
        let b = create_test_vid();

        let nested_a = create_test_vid();
        let nested_b = create_test_vid();

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
        let a_store = create_test_store();
        let b_store = create_test_store();

        let a = create_test_vid();
        let b = create_test_vid();

        a_store.add_private_vid(a.clone(), None).unwrap();
        b_store.add_private_vid(b.clone(), None).unwrap();

        a_store.add_verified_vid(b.clone(), None).unwrap();
        b_store.add_verified_vid(a.clone(), None).unwrap();

        let (_url, mut sealed) = a_store
            .make_relationship_request(a.identifier(), b.identifier(), None)
            .unwrap();

        let received = b_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::RequestRelationship {
            thread_id,
            form,
            delivery,
            ..
        } = received
        else {
            panic!()
        };
        assert!(matches!(form, ReceivedRelationshipForm::Direct));
        assert!(matches!(delivery, ReceivedRelationshipDelivery::Direct));

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
            thread_id,
            form,
            delivery,
            ..
        } = received
        else {
            panic!()
        };
        let ReceivedRelationshipDelivery::Nested {
            nested_vid: nested_vid_1,
        } = delivery
        else {
            panic!()
        };
        assert!(matches!(form, ReceivedRelationshipForm::Direct));

        let ((_url, mut sealed), nested_b) = b_store
            .make_nested_relationship_accept(b.identifier(), &nested_vid_1, thread_id)
            .unwrap();

        let received = a_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::AcceptRelationship { form, delivery, .. } = received else {
            panic!()
        };
        let ReceivedRelationshipDelivery::Nested {
            nested_vid: nested_vid_2,
        } = delivery
        else {
            panic!()
        };
        assert!(matches!(form, ReceivedRelationshipForm::Direct));

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
            b_store.get_vid(&nested_vid_1).unwrap().get_parent_vid(),
            Some(a.identifier())
        );

        assert_eq!(
            a_store.get_vid(&nested_vid_2).unwrap().get_parent_vid(),
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
