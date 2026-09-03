use crate::{
    ExportVid, OwnedVid,
    cesr::EnvelopeType,
    crypto::{
        CryptoError, OutboundCryptoSelection, PayloadConfidentiality, RelationshipDigestAlgorithm,
    },
    definitions::{
        Digest, MessageType, Payload, PendingIncomingParallelRelationship,
        PendingNestedRelationship, PendingParallelRelationship, PrivateVid,
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

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub(crate) struct VidContext {
    vid: Arc<dyn VerifiedVid>,
    private: Option<Arc<dyn PrivateVid>>,
    relation_status: RelationshipStatus,
    relation_vid: Option<String>,
    parent_vid: Option<String>,
    tunnel: Option<Box<[String]>>,
    pending_parallel_requests: Vec<PendingParallelRelationship>,
    pending_incoming_parallel_requests: Vec<PendingIncomingParallelRelationship>,
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

fn nested_digest_field<'a>(
    digest: &'a Digest,
    algorithm: RelationshipDigestAlgorithm,
) -> crate::cesr::Digest<'a> {
    algorithm.field(digest)
}

/// How an outbound message is formed, beyond what it says.
///
/// Every field has a default that is the right answer unless a caller has a
/// reason otherwise: the cipher suite the recipient's keys call for, an
/// encrypted payload, and no padding.
#[derive(Clone, Copy, Debug, Default)]
pub struct SendOptions<'a> {
    /// The cipher suite. `None` is HPKE-Base, or its post-quantum KEM where the
    /// recipient's encryption key type asks for one.
    pub crypto_type: Option<crate::cesr::CryptoType>,
    /// Whether the payload is encrypted or only signed. Meaningful under
    /// nesting; see [`PayloadConfidentiality`].
    pub confidentiality: PayloadConfidentiality,
    /// Bytes for the payload's padding field, which hides the length of what
    /// the message actually carries. `None` encodes the empty field `4BAA`.
    /// The field is excluded from the SAID digest, so padding does not change
    /// a message's thread id (spec 7.2.1).
    pub padding: Option<&'a [u8]>,
}

fn selected_outbound_crypto<'a>(
    sender: &dyn VerifiedVid,
    receiver: &dyn VerifiedVid,
    selection: Option<OutboundCryptoSelection<'a>>,
) -> OutboundCryptoSelection<'a> {
    selection.unwrap_or_else(|| crate::crypto::default_outbound_crypto_selection(sender, receiver))
}

fn digest_algorithm_for_selection(
    selection: OutboundCryptoSelection,
) -> Result<RelationshipDigestAlgorithm, Error> {
    Ok(RelationshipDigestAlgorithm::for_crypto_type(
        selection.crypto_type,
    )?)
}

/// A private VID presented under the identifier it is being introduced by.
///
/// A `did:peer` is used by its short form, which a peer cannot resolve until it
/// has seen the document, so the message that introduces it carries the long
/// form instead. Everything else about the VID — its keys, its endpoint — is
/// unchanged, so wrapping it here puts the right identifier in the envelope,
/// in the AAD derived from it, and in the ESSR sender field, without the
/// sealing code needing to know that any of this is going on.
struct IntroducedVid<'a> {
    inner: &'a dyn PrivateVid,
    identifier: String,
}

impl<'a> IntroducedVid<'a> {
    fn new(inner: &'a dyn PrivateVid) -> Self {
        Self {
            identifier: crate::vid::did::peer::introduction_identifier(inner),
            inner,
        }
    }
}

impl VerifiedVid for IntroducedVid<'_> {
    fn identifier(&self) -> &str {
        &self.identifier
    }

    fn endpoint(&self) -> &Url {
        self.inner.endpoint()
    }

    fn verifying_key(&self) -> &crate::definitions::PublicVerificationKeyData {
        self.inner.verifying_key()
    }

    fn encryption_key(&self) -> &crate::definitions::PublicKeyData {
        self.inner.encryption_key()
    }

    fn encryption_key_type(&self) -> crate::definitions::VidEncryptionKeyType {
        self.inner.encryption_key_type()
    }

    fn signature_key_type(&self) -> crate::definitions::VidSignatureKeyType {
        self.inner.signature_key_type()
    }
}

impl PrivateVid for IntroducedVid<'_> {
    fn decryption_key(&self) -> &crate::definitions::PrivateKeyData {
        self.inner.decryption_key()
    }

    fn signing_key(&self) -> &crate::definitions::PrivateSigningKeyData {
        self.inner.signing_key()
    }
}

fn seal_envelope(
    sender: &dyn PrivateVid,
    receiver: &dyn VerifiedVid,
    payload: Payload<&[u8]>,
    digest: Option<&mut Digest>,
    request_nonce_override: Option<[u8; 16]>,
    selection: Option<OutboundCryptoSelection>,
) -> Result<Vec<u8>, Error> {
    Ok(crate::crypto::seal_with_selection(
        sender,
        receiver,
        payload,
        digest,
        request_nonce_override,
        selected_outbound_crypto(sender, receiver, selection),
    )?)
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
    request_nonce: Option<[u8; 16]>,
}

/// The fields an invite's `Signature_new` is made over. An accept carries no
/// such signature: its new VID is the sender of the message, so the message's
/// own signature proves control of it.
struct ParallelSignatureContext<'a> {
    sender_identity: &'a str,
    receiver_identity: &'a str,
    nonce: [u8; 16],
    /// The crypto this message will be sealed with, which decides what the
    /// payload's ESSR sender field holds — and that field is covered by the
    /// referral signature, so it has to be the same on both sides
    selection: OutboundCryptoSelection<'static>,
}

fn random_nonce_bytes() -> [u8; 16] {
    let mut nonce_bytes = [0_u8; 16];
    StdRng::from_entropy().fill_bytes(&mut nonce_bytes);
    nonce_bytes
}

pub type Aliases = HashMap<String, String>;
pub type MethodSecretKeys = HashMap<String, Vec<u8>>;
pub type ResolutionContexts = HashMap<String, crate::vid::ResolutionContext>;

#[cfg_attr(
    feature = "serialize",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
#[derive(Clone, Debug, Default)]
pub struct WalletMethodState {
    pub secret_keys: MethodSecretKeys,
    pub resolution_contexts: ResolutionContexts,
}

/// Whether application messages from a VID with no established relationship
/// are accepted (spec 7.2.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RelationshipPolicy {
    /// Drop an application message whose sender has no relationship with the
    /// receiving VID. A relationship must first be formed with `TSP_RFI`.
    /// This is the behavior the specification requires of an endpoint.
    #[default]
    Gated,
    /// Accept application messages from any verified sender. Intended for
    /// nodes that are not endpoints in the specification's sense — an
    /// intermediary accepting drop-off traffic, or a relay under upper-layer
    /// admission control — and for tests.
    Ungated,
}

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
    pub(crate) method_state: Arc<RwLock<WalletMethodState>>,
    pub(crate) relationship_policy: Arc<RwLock<RelationshipPolicy>>,
}

/// This wallet is used to store and resolve VIDs
/// The transport to use when sending to `vid`.
///
/// A transport may carry a placeholder where the identifier belongs. For identifier methods whose
/// identifier is derived from the document that holds the transport, the transport cannot name
/// that identifier without defining it circularly, so it is filled in at the point of use. The
/// identifier is inserted verbatim: it is one path segment, and a receiver keying anything by it
/// has to see exactly the text the identifier is written with.
fn sending_endpoint(vid: &dyn VerifiedVid) -> url::Url {
    let mut endpoint = vid.endpoint().clone();

    if endpoint.path().contains("[vid_placeholder]") {
        let path = endpoint
            .path()
            .replace("[vid_placeholder]", vid.identifier());
        endpoint.set_path(&path);
    }

    endpoint
}

impl SecureStore {
    /// Create a new, empty VID wallet
    pub fn new() -> Self {
        Default::default()
    }

    /// Set whether application messages from senders without an established
    /// relationship are accepted; see [RelationshipPolicy]
    pub fn set_relationship_policy(&self, policy: RelationshipPolicy) -> Result<(), Error> {
        *self.relationship_policy.write()? = policy;

        Ok(())
    }

    /// The current relationship policy; see [RelationshipPolicy]
    pub fn relationship_policy(&self) -> Result<RelationshipPolicy, Error> {
        Ok(*self.relationship_policy.read()?)
    }

    /// Export the wallet to serializable default types
    pub fn export(&self) -> Result<(Vec<ExportVid>, Aliases, WalletMethodState), Error> {
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
                pending_parallel_requests: context.pending_parallel_requests.clone(),
                pending_incoming_parallel_requests: context
                    .pending_incoming_parallel_requests
                    .clone(),
                metadata: context.metadata.clone(),
            })
            .collect::<Vec<_>>();

        Ok((
            vids,
            self.aliases.read()?.clone(),
            self.method_state.read()?.clone(),
        ))
    }

    /// Import the wallet from serializable default types
    pub fn import(
        &self,
        vids: Vec<ExportVid>,
        aliases: Aliases,
        method_state: WalletMethodState,
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
                    pending_parallel_requests: vid.pending_parallel_requests,
                    pending_incoming_parallel_requests: vid.pending_incoming_parallel_requests,
                    metadata: vid.metadata,
                },
            );

            Ok::<(), Error>(())
        })?;

        *self.method_state.write()? = method_state;

        aliases.into_iter().try_for_each(|(k, v)| {
            self.set_alias(k, v)?;
            Ok(())
        })
    }

    pub fn add_secret_key(&self, kid: String, secret_key: Vec<u8>) -> Result<(), Error> {
        self.method_state
            .write()?
            .secret_keys
            .insert(kid, secret_key);
        Ok(())
    }

    pub fn get_secret_key(&self, kid: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.method_state.read()?.secret_keys.get(kid).cloned())
    }

    pub fn register_resolution_context(
        &self,
        did: String,
        context: crate::vid::ResolutionContext,
    ) -> Result<(), Error> {
        self.method_state
            .write()?
            .resolution_contexts
            .insert(did, context);
        Ok(())
    }

    pub fn get_resolution_context(
        &self,
        did: &str,
    ) -> Result<Option<crate::vid::ResolutionContext>, Error> {
        Ok(self
            .method_state
            .read()?
            .resolution_contexts
            .get(did)
            .cloned())
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
                pending_parallel_requests: vec![],
                pending_incoming_parallel_requests: vec![],
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
                pending_parallel_requests: vec![],
                pending_incoming_parallel_requests: vec![],
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

    /// The metadata stored alongside a VID when it was last resolved, which is
    /// what a later resolution is compared against (spec 3.7)
    pub fn metadata_for_vid(&self, vid: &str) -> Result<Option<serde_json::Value>, Error> {
        let vid = self.try_resolve_alias(vid)?;

        Ok(self
            .vids
            .read()?
            .get(&vid)
            .and_then(|context| context.metadata.clone()))
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
        if route.len() < 2 {
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

    pub fn get_owned_private_vid(&self, vid: &str) -> Result<OwnedVid, Error> {
        let context = self.get_vid(vid)?;
        let Some(private) = context.private else {
            return Err(Error::MissingPrivateVid(vid.to_string()));
        };

        Ok(OwnedVid::from_parts(
            crate::vid::Vid::from_verified(context.vid.as_ref()),
            private.signing_key().clone(),
            private.decryption_key().clone(),
        ))
    }

    /// Check whether the [VerifiedVid] identified by `vid` exists in the wallet
    /// Whether any relationship exists in which this VID takes part
    pub fn has_relationship_with(&self, vid: &str) -> Result<bool, Error> {
        let vid = self.try_resolve_alias(vid)?;

        Ok(self.vids.read()?.get(&vid).is_some_and(|context| {
            !matches!(context.relation_status, RelationshipStatus::Unrelated)
        }))
    }

    /// Whether a route is configured for this VID
    /// The route configured for this VID, if any
    pub fn get_route_for_vid(&self, vid: &str) -> Result<Option<Vec<String>>, Error> {
        let vid = self.try_resolve_alias(vid)?;

        Ok(self
            .vids
            .read()?
            .get(&vid)
            .and_then(|context| context.get_route().map(<[String]>::to_vec)))
    }

    pub fn has_route_for_vid(&self, vid: &str) -> Result<bool, Error> {
        let vid = self.try_resolve_alias(vid)?;

        Ok(self
            .vids
            .read()?
            .get(&vid)
            .is_some_and(|context| context.get_route().is_some()))
    }

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
        let resolved = self
            .resolve_alias(alias)?
            .unwrap_or(alias.to_owned())
            .to_string();

        // a did:peer is introduced by its long form and known by its short
        // form, so a caller naming it by the form it was handed still means
        // the VID the wallet holds
        if !self.vids.read()?.contains_key(&resolved)
            && let Some(short_form) = crate::vid::did::peer::short_form(&resolved)
            && self.vids.read()?.contains_key(&short_form)
        {
            return Ok(short_form);
        }

        Ok(resolved)
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
        message: &[u8],
    ) -> Result<(Url, Vec<u8>), Error> {
        #[cfg(feature = "bench-network-timings")]
        let signature_before = crate::bench::signature_before();
        #[cfg(feature = "bench-network-timings")]
        let started = std::time::Instant::now();

        let result = self.seal_message_payload(sender, receiver, Payload::Content(message));

        #[cfg(feature = "bench-network-timings")]
        crate::bench::record_seal_core(started, signature_before);

        result
    }

    pub fn seal_message_with_crypto_type(
        &self,
        sender: &str,
        receiver: &str,
        message: &[u8],
        crypto_type: crate::cesr::CryptoType,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.seal_message_payload_and_hash_with_selection(
            sender,
            receiver,
            Payload::Content(message),
            None,
            Some(OutboundCryptoSelection {
                crypto_type,
                essr_sender: Default::default(),
                confidentiality: Default::default(),
                padding: None,
            }),
        )
    }

    /// Seal a TSP message, choosing how the payload itself is protected.
    ///
    /// [`PayloadConfidentiality::Confidential`] is what [`Self::seal_message`]
    /// does. [`PayloadConfidentiality::SignedOnly`] signs the payload without
    /// encrypting it, which is only meaningful under nesting: the outer
    /// envelope is confidential either way, so the payload is never in the
    /// clear on the wire, but its confidentiality then rests on the outer
    /// relationship's keys rather than the inner relationship's (spec 4).
    ///
    /// Without nesting this makes no difference — a direct message has no
    /// outer envelope to hide behind, so it is always encrypted.
    pub fn seal_message_with_confidentiality(
        &self,
        sender: &str,
        receiver: &str,
        message: &[u8],
        confidentiality: PayloadConfidentiality,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.seal_message_with(
            sender,
            receiver,
            message,
            SendOptions {
                confidentiality,
                ..Default::default()
            },
        )
    }

    /// Seal a TSP message, choosing both the cipher suite and how the payload
    /// itself is protected. The two are independent: see
    /// [`Self::seal_message_with_crypto_type`] and
    /// [`Self::seal_message_with_confidentiality`], each of which is this with
    /// the other left at its default.
    pub fn seal_message_with(
        &self,
        sender: &str,
        receiver: &str,
        message: &[u8],
        options: SendOptions<'_>,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.seal_payload_with(sender, receiver, Payload::Content(message), options)
    }

    /// Seal an upper layer's own control payload (`XCTL`).
    ///
    /// TSP carries it opaquely, exactly as it carries an application message.
    /// The separate payload type exists so that an upper layer can tell its
    /// control plane from its data plane without reserving part of its own
    /// format to say which is which (spec 9.3). It arrives as
    /// [`crate::ReceivedTspMessage::ControlMessage`].
    pub fn seal_control_message(
        &self,
        sender: &str,
        receiver: &str,
        message: &[u8],
        options: SendOptions<'_>,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.seal_payload_with(sender, receiver, Payload::ControlMessage(message), options)
    }

    /// Seal a padding message (`XPAD`), which carries nothing.
    ///
    /// It exists so that an observer counting or timing messages sees ones that
    /// mean nothing (spec 7.5). Give it `options.padding` to choose its size;
    /// with none it is as small as a TSP message gets, which is its own kind of
    /// signal, so a caller hiding a traffic pattern should pass some.
    pub fn seal_padding_message(
        &self,
        sender: &str,
        receiver: &str,
        options: SendOptions<'_>,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.seal_payload_with(sender, receiver, Payload::Padding, options)
    }

    fn seal_payload_with(
        &self,
        sender: &str,
        receiver: &str,
        payload: Payload<&[u8]>,
        options: SendOptions<'_>,
    ) -> Result<(Url, Vec<u8>), Error> {
        let sender_vid = self.get_private_vid(sender)?;
        let receiver_vid = self.get_verified_vid(receiver)?;
        let selection = crate::crypto::default_outbound_crypto_selection(
            &*sender_vid as &dyn crate::definitions::VerifiedVid,
            &*receiver_vid,
        );

        self.seal_message_payload_and_hash_with_selection(
            sender,
            receiver,
            payload,
            None,
            Some(OutboundCryptoSelection {
                crypto_type: options.crypto_type.unwrap_or(selection.crypto_type),
                confidentiality: options.confidentiality,
                padding: options.padding,
                ..selection
            }),
        )
    }

    // ANCHOR_END: seal_message-mbBook

    /// Seal a TSP message.
    pub(crate) fn seal_message_payload(
        &self,
        sender: &str,
        receiver: &str,
        payload: Payload<&[u8]>,
    ) -> Result<(url::Url, Vec<u8>), Error> {
        self.seal_message_payload_and_hash(sender, receiver, payload, None)
    }

    /// Seal a TSP message and return the digest of the payload
    pub(crate) fn seal_message_payload_and_hash(
        &self,
        sender: &str,
        receiver: &str,
        payload: Payload<&[u8]>,
        digest: Option<&mut Digest>,
    ) -> Result<(url::Url, Vec<u8>), Error> {
        self.seal_message_payload_and_hash_with_selection(sender, receiver, payload, digest, None)
    }

    pub(crate) fn seal_message_payload_and_hash_with_selection(
        &self,
        sender: &str,
        receiver: &str,
        payload: Payload<&[u8]>,
        digest: Option<&mut Digest>,
        selection: Option<OutboundCryptoSelection>,
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

                    let tsp_message = seal_envelope(
                        &*inner_sender,
                        &*receiver_context.vid,
                        payload,
                        digest,
                        None,
                        selection,
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

            return self.seal_message_payload_and_hash_with_selection(
                sender.identifier(),
                first_hop.vid.identifier(),
                Payload::RoutedMessage(hops, &inner_message),
                None,
                None,
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

            // Only an upper layer's own payload may be signed-only, and only
            // when the caller asks: TSP's control messages are always
            // encrypted. Section 4 permits a signed-only inner message, since
            // the outer envelope conceals it in transit, but its confidentiality
            // then rests on the outer relationship's keys rather than the inner
            // relationship's — so encrypting is the default.
            let content_payload = matches!(&payload, Payload::Content(_));
            let signed_only = content_payload
                && matches!(
                    selection.map(|s| s.confidentiality).unwrap_or_default(),
                    PayloadConfidentiality::SignedOnly
                );

            let inner_message = if signed_only {
                crate::crypto::sign(
                    &*inner_sender,
                    Some(&*receiver_context.vid),
                    payload.as_bytes(),
                )?
            } else {
                seal_envelope(
                    &*inner_sender,
                    &*receiver_context.vid,
                    payload,
                    digest,
                    None,
                    selection,
                )?
            };

            let parent_sender = self.get_private_vid(parent_sender)?;
            let parent_receiver = self.get_verified_vid(parent_receiver)?;

            return self.seal_message_payload_and_hash_with_selection(
                parent_sender.identifier(),
                parent_receiver.identifier(),
                Payload::NestedMessage(&inner_message),
                None,
                if content_payload { selection } else { None },
            );
        }

        // send direct mode
        let tsp_message = seal_envelope(
            &*sender,
            &*receiver_context.vid,
            payload,
            digest,
            None,
            selection,
        )?;

        Ok((sending_endpoint(&*receiver_context.vid), tsp_message))
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
        digest_algorithm: RelationshipDigestAlgorithm,
    ) -> Result<(Vec<u8>, Digest), Error> {
        let mut csprng = StdRng::from_entropy();
        let mut nonce_bytes = [0_u8; 16];
        csprng.fill_bytes(&mut nonce_bytes);

        // the invite introduces the new VID, so it carries the form the peer
        // can verify without having seen it before (spec 2.1, did:peer:4 long
        // form); the peer resolves it to the short form used thereafter
        let wire_sender = crate::vid::did::peer::introduction_identifier(sender);
        let sender_identity = Some(wire_sender.as_bytes());
        let mut request_digest = [0_u8; 32];

        // the inner message is an ordinary TSP message whose sender is the new
        // VID and whose receiver is NULL, and the digest is that message's own
        // SAID (spec 7.2.1: the innermost message that carries it)
        let mut envelope_prefix = Vec::with_capacity(64);
        crate::cesr::encode_envelope_prefix(wire_sender.as_bytes(), None, &mut envelope_prefix)
            .map_err(crate::crypto::CryptoError::from)?;

        fn proposal<'a>(
            request_digest: &'a Digest,
            nonce_bytes: [u8; 16],
            digest_algorithm: RelationshipDigestAlgorithm,
        ) -> crate::cesr::Payload<'a, &'a [u8], &'a [u8]> {
            crate::cesr::Payload::RelationProposal {
                request_digest: nested_digest_field(request_digest, digest_algorithm),
                nonce: crate::cesr::Nonce::generate(|dst| *dst = nonce_bytes),
                reply_path: vec![],
                referral: None,
            }
        }

        let mut digest_input = Vec::with_capacity(128);
        crate::cesr::encode_digest_input(
            &proposal(&request_digest, nonce_bytes, digest_algorithm),
            sender_identity,
            &envelope_prefix,
            &mut digest_input,
        )?;
        request_digest = digest_algorithm.hash(&digest_input);

        let final_payload = proposal(&request_digest, nonce_bytes, digest_algorithm);

        // the inner message's payload IS the TSP_RFI (spec 9.4.13), so it is
        // signed as it stands rather than wrapped in an application payload
        let message = crate::crypto::sign_payload_as(
            sender,
            &wire_sender,
            None,
            &final_payload,
            sender_identity,
        )?;

        Ok((message, request_digest))
    }

    fn make_signed_nested_accept_message(
        &self,
        sender: &dyn PrivateVid,
        receiver: &dyn VerifiedVid,
        thread_id: Digest,
        digest_algorithm: RelationshipDigestAlgorithm,
    ) -> Result<(Vec<u8>, Digest), Error> {
        // as with the invite, the accept introduces this endpoint's new VID
        let wire_sender = crate::vid::did::peer::introduction_identifier(sender);
        let sender_identity = Some(wire_sender.as_bytes());
        let mut reply_thread_id = [0_u8; 32];

        let mut envelope_prefix = Vec::with_capacity(64);
        crate::cesr::encode_envelope_prefix(
            wire_sender.as_bytes(),
            Some(receiver.identifier().as_bytes()),
            &mut envelope_prefix,
        )
        .map_err(crate::crypto::CryptoError::from)?;

        fn affirm<'a>(
            thread_id: &'a Digest,
            reply_thread_id: &'a Digest,
            digest_algorithm: RelationshipDigestAlgorithm,
        ) -> crate::cesr::Payload<'a, &'a [u8], &'a [u8]> {
            crate::cesr::Payload::RelationAffirm {
                request_digest: nested_digest_field(thread_id, digest_algorithm),
                reply_digest: nested_digest_field(reply_thread_id, digest_algorithm),
            }
        }

        let mut digest_input = Vec::with_capacity(128);
        crate::cesr::encode_digest_input(
            &affirm(&thread_id, &reply_thread_id, digest_algorithm),
            sender_identity,
            &envelope_prefix,
            &mut digest_input,
        )?;
        reply_thread_id = digest_algorithm.hash(&digest_input);

        let final_payload = affirm(&thread_id, &reply_thread_id, digest_algorithm);

        // likewise the TSP_RFA is the inner message's payload (spec 9.4.14)
        let message = crate::crypto::sign_payload_as(
            sender,
            &wire_sender,
            Some(receiver),
            &final_payload,
            sender_identity,
        )?;

        Ok((message, reply_thread_id))
    }

    fn try_open_nested_relationship_message(
        &self,
        outer_sender: &str,
        outer_receiver: &str,
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

        // a VID being introduced arrives in a form that carries its own
        // verification material; resolving it yields the identifier the two
        // endpoints use from here on, which is what the wallet is keyed by
        let sender_vid: std::sync::Arc<dyn VerifiedVid> = match self.get_verified_vid(&inner_sender)
        {
            Ok(sender_vid) => sender_vid,
            Err(_) => match verify_vid_offline(&inner_sender) {
                Ok(sender_vid) => std::sync::Arc::new(sender_vid),
                Err(_) => return Ok(None),
            },
        };
        let nested_vid = sender_vid.identifier().to_string();

        let (
            crate::cesr::DecodedPayload {
                payload,
                sender_identity,
            },
            _,
        ) = crate::crypto::verify_payload(&*sender_vid, inner)?;

        // anything that is not a relationship control message belongs to the
        // caller of this function, which opens it as an ordinary message
        if !matches!(
            payload,
            crate::cesr::Payload::RelationProposal { .. }
                | crate::cesr::Payload::RelationAffirm { .. }
        ) {
            return Ok(None);
        }

        if sender_identity != Some(inner_sender.as_bytes()) {
            return Err(Error::Relationship(
                "nested relationship control payload sender mismatch".into(),
            ));
        }

        // the digest is the inner message's own SAID (spec 7.2.1), so recompute
        // it over that message and reject a mismatch
        let mut envelope_prefix = Vec::with_capacity(64);
        crate::cesr::encode_envelope_prefix(
            inner_sender.as_bytes(),
            inner_receiver.as_deref().map(str::as_bytes),
            &mut envelope_prefix,
        )
        .map_err(crate::crypto::CryptoError::from)?;
        crate::crypto::verify_relationship_digest(&payload, sender_identity, &envelope_prefix)?;

        match payload {
            crate::cesr::Payload::RelationProposal { request_digest, .. } => {
                // a nested relationship is formed on the referral of the outer
                // one, so there has to be an outer one (spec 7.2.5)
                self.check_relationship_gate(outer_receiver, outer_sender)?;

                if inner_receiver.is_some() {
                    return Err(Error::Relationship(
                        "invalid nested relationship request receiver".into(),
                    ));
                }

                if self.get_verified_vid(&nested_vid).is_err() {
                    self.add_nested_vid(&inner_sender)?;
                }
                self.set_parent_for_vid(&nested_vid, Some(outer_sender))?;

                Ok(Some(NestedRelationshipEvent::Request {
                    nested_vid,
                    thread_id: *request_digest.as_bytes(),
                }))
            }
            crate::cesr::Payload::RelationAffirm {
                request_digest,
                reply_digest,
            } => {
                self.check_relationship_gate(outer_receiver, outer_sender)?;

                let Some(connect_to_vid) = inner_receiver else {
                    return Err(Error::Relationship(
                        "invalid nested relationship accept receiver".into(),
                    ));
                };

                if self.get_verified_vid(&nested_vid).is_err() {
                    self.add_nested_vid(&inner_sender)?;
                }
                self.set_parent_for_vid(&nested_vid, Some(outer_sender))?;
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
                    &nested_vid,
                )?;
                self.set_relation_and_status_for_vid(
                    &nested_vid,
                    relation_status,
                    &connect_to_vid,
                )?;

                Ok(Some(NestedRelationshipEvent::Accept {
                    nested_vid,
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
            // We are the destination's intermediary. The exit entry of a hop
            // list is the destination's own VID at this intermediary (spec
            // 5.3.3), so deliver over the relationship this intermediary holds
            // with it; if there is none, the specification calls it an error.
            let destination = self.get_vid(next_hop)?;

            let Some(local_vid) = destination.get_relation_vid() else {
                return Err(Error::MissingDropOff(next_hop.to_string()));
            };
            let sender_private = self.get_private_vid(local_vid)?;

            self.seal_message_payload(
                sender_private.identifier(),
                destination.vid.identifier(),
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

                let ((payload, crypto_type, signature_type), parallel_signature_info) =
                    crate::crypto::open_with_signature_info(
                        &*receiver_pid,
                        sender_vid.as_verified(),
                        message,
                    )?;

                // a VID being introduced names itself in the envelope by the
                // form that carries its verification material; from here on it
                // is the identifier that resolves to
                let sender = sender_vid.as_verified().identifier().to_string();

                let parallel_sender_vid = parallel_signature_info
                    .map(|parallel_signature_info| {
                        self.verify_parallel_relationship_signature(parallel_signature_info)
                    })
                    .transpose()?;
                sender_vid.persist(self)?;

                match payload {
                    Payload::Content(message) => {
                        // an application message is only accepted within an
                        // established relationship (spec 7.2.2)
                        self.check_relationship_gate(&intended_receiver, &sender)?;

                        Ok(ReceivedTspMessage::GenericMessage {
                            sender,
                            receiver: Some(intended_receiver),
                            message,
                            message_type: MessageType {
                                crypto_type,
                                signature_type,
                                enclosing_crypto_type: None,
                            },
                        })
                    }
                    Payload::ControlMessage(message) => {
                        // an upper layer's control payload is addressed to a VID
                        // and carries its data, so spec 7.2.2 applies to it as it
                        // does to an application message
                        self.check_relationship_gate(&intended_receiver, &sender)?;

                        Ok(ReceivedTspMessage::ControlMessage {
                            sender,
                            receiver: Some(intended_receiver),
                            message,
                            message_type: MessageType {
                                crypto_type,
                                signature_type,
                                enclosing_crypto_type: None,
                            },
                        })
                    }
                    // not gated: there is nothing in a padding message to accept
                    // or refuse, and the receiver discards it either way
                    Payload::Padding => Ok(ReceivedTspMessage::PaddingMessage {
                        sender,
                        receiver: Some(intended_receiver),
                    }),
                    Payload::NestedMessage(inner) => {
                        if let Some(received_message) = self.try_open_nested_relationship_message(
                            &sender,
                            &intended_receiver,
                            inner,
                        )? {
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

                        // Record how the enclosing message was encrypted, so an
                        // application can tell a signed-only inner message from
                        // an encrypted one and still know it was confidential on
                        // the wire. Reporting the enclosing type *as* the inner
                        // one would hide exactly the distinction section 4 asks
                        // applications to notice.
                        //
                        // This is a fact about how the message arrived — it came
                        // out of an envelope just decrypted here — so it does not
                        // depend on what the wallet records about the sender. Who
                        // sent that envelope is a separate question, and the
                        // caller has the sender to answer it with.
                        if let ReceivedTspMessage::GenericMessage {
                            ref mut message_type,
                            ..
                        } = received_message
                        {
                            message_type.enclosing_crypto_type = Some(crypto_type);
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
                    Payload::RequestRelationship {
                        thread_id,
                        form,
                        reply_path,
                    } => {
                        let form = received_relationship_form(form)?;

                        // the sender told us how to reach it (spec 7.2.4), so
                        // record that as the route for its VID; the accept and
                        // everything after it then travel that path
                        if !reply_path.is_empty() {
                            let hops = reply_path
                                .iter()
                                .map(|hop| std::str::from_utf8(hop))
                                .collect::<Result<Vec<_>, _>>()?;
                            self.set_route_for_vid(&sender, &hops)?;
                        }

                        if matches!(form, ReceivedRelationshipForm::Direct) {
                            self.record_incoming_relationship_request(
                                &intended_receiver,
                                &sender,
                                thread_id,
                            )?;
                        }

                        let mut form = form;
                        if let ReceivedRelationshipForm::Parallel { new_vid, .. } = &mut form {
                            match self.relation_status_for_vid_pair(&intended_receiver, &sender)? {
                                RelationshipStatus::Bidirectional { .. } => {}
                                RelationshipStatus::Unidirectional { .. }
                                | RelationshipStatus::ReverseUnidirectional { .. }
                                | RelationshipStatus::Unrelated => {
                                    return Err(requires_existing_parallel_relationship_error());
                                }
                            }

                            let parallel_sender_vid = parallel_sender_vid.ok_or_else(|| {
                                Error::Relationship(
                                    "missing verified parallel VID for request message".into(),
                                )
                            })?;
                            // the referral introduced the VID in the form that
                            // carries its verification material; from here it is
                            // known by the identifier that resolves to
                            *new_vid = parallel_sender_vid.as_verified().identifier().to_string();
                            let new_vid = new_vid.clone();
                            parallel_sender_vid.persist(self)?;
                            self.add_pending_incoming_parallel_request(
                                &new_vid,
                                thread_id,
                                &intended_receiver,
                            )?;
                        }

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
                        let form = received_relationship_form(form)?;

                        // an accept answering an outstanding parallel invite
                        // completes it, and arrives from the peer's new VID
                        // over the new relationship (spec 7.2.5); any other
                        // accept upgrades the relationship it names
                        if self.consume_pending_parallel_request(
                            receiver_pid.identifier(),
                            thread_id,
                        )? {
                            self.establish_bidirectional_relation(
                                receiver_pid.identifier(),
                                &sender,
                                thread_id,
                                reply_thread_id,
                            )?;
                        } else {
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
                        let reply_expected =
                            self.cancel_relationship(&intended_receiver, &sender, thread_id)?;

                        Ok(ReceivedTspMessage::CancelRelationship {
                            sender,
                            receiver: intended_receiver,
                            thread_id,
                            reply_expected,
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

                // an addressed application message is only accepted within an
                // established relationship (spec 7.2.2). The rule is about a
                // message "destined to one of its legitimate VIDs" and says
                // nothing about confidentiality, so it applies to a signed-only
                // message as much as to an encrypted one. An anycast broadcast
                // names no receiver, so there is no destination VID for the rule
                // to be about, and it is not gated.
                if let Some(intended_receiver) = &intended_receiver {
                    self.check_relationship_gate(intended_receiver, &sender)?;
                }

                let (message, message_type) = crate::crypto::verify(&*sender_vid, message)?;

                Ok(ReceivedTspMessage::GenericMessage {
                    sender,
                    receiver: intended_receiver,
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
        self.make_relationship_request_with_selection(sender, receiver, route, None)
    }

    pub fn make_relationship_request_with_crypto_type(
        &self,
        sender: &str,
        receiver: &str,
        route: Option<&[&str]>,
        crypto_type: crate::cesr::CryptoType,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.make_relationship_request_with_selection(
            sender,
            receiver,
            route,
            Some(OutboundCryptoSelection {
                crypto_type,
                essr_sender: Default::default(),
                confidentiality: Default::default(),
                padding: None,
            }),
        )
    }

    fn make_relationship_request_with_selection(
        &self,
        sender: &str,
        receiver: &str,
        reply_path: Option<&[&str]>,
        selection: Option<OutboundCryptoSelection>,
    ) -> Result<(Url, Vec<u8>), Error> {
        let sender_vid = self.get_private_vid(sender)?;
        let receiver_vid = self.get_verified_vid(receiver)?;

        let reply_path = self.resolve_reply_path(reply_path)?;
        let reply_path_bytes = reply_path
            .iter()
            .map(|hop| hop.as_bytes())
            .collect::<Vec<_>>();

        let mut thread_id = Default::default();
        // the invite itself travels whatever route is set for the receiver,
        // so relationship forming over a routed path uses the same machinery
        // as any other message (spec 7.2.4)
        let (endpoint, tsp_message) = self.seal_message_payload_and_hash_with_selection(
            sender_vid.identifier(),
            receiver_vid.identifier(),
            Payload::RequestRelationship {
                thread_id: Default::default(),
                form: RelationshipForm::Direct,
                reply_path: reply_path_bytes,
            },
            Some(&mut thread_id),
            selection,
        )?;

        self.set_relation_and_status_for_vid(
            receiver_vid.identifier(),
            RelationshipStatus::Unidirectional { thread_id },
            sender_vid.identifier(),
        )?;

        Ok((endpoint, tsp_message))
    }

    /// Resolve the aliases of a caller-supplied reply path
    fn resolve_reply_path(&self, reply_path: Option<&[&str]>) -> Result<Vec<String>, Error> {
        reply_path
            .unwrap_or_default()
            .iter()
            .map(|hop| self.try_resolve_alias(hop))
            .collect()
    }

    fn build_parallel_signature_material(
        &self,
        sender_new_vid: &dyn PrivateVid,
        context: ParallelSignatureContext<'_>,
        digest_algorithm: RelationshipDigestAlgorithm,
    ) -> Result<ParallelSignatureMaterial, Error> {
        let mut digest = [0_u8; 32];

        let ParallelSignatureContext {
            sender_identity,
            receiver_identity,
            nonce,
            selection,
        } = context;

        let mut envelope_prefix = Vec::with_capacity(64);
        crate::cesr::encode_envelope_prefix(
            sender_identity.as_bytes(),
            Some(receiver_identity.as_bytes()),
            &mut envelope_prefix,
        )
        .map_err(crate::crypto::CryptoError::from)?;

        let sender_vid = self.get_verified_vid(sender_identity)?;
        let signed_data = crate::crypto::build_parallel_request_signed_data(
            selection.essr_sender_in_payload(&*sender_vid),
            digest_algorithm,
            nonce,
            &[],
            &envelope_prefix,
            &mut digest,
            crate::vid::did::peer::introduction_identifier(sender_new_vid).as_bytes(),
        )?;
        let request_nonce = Some(nonce);

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
            RelationshipStatus::Unidirectional { .. }
            | RelationshipStatus::ReverseUnidirectional { .. }
            | RelationshipStatus::Unrelated => {
                return Err(requires_existing_parallel_relationship_error());
            }
        }

        let selection = selected_outbound_crypto(&*sender, &*receiver, None);
        let digest_algorithm = digest_algorithm_for_selection(selection)?;
        // the referral introduces the new VID, so it names the form the peer
        // can verify without having seen it (did:peer:4 long form)
        let new_vid_long_form = crate::vid::did::peer::introduction_identifier(&*sender_new_vid);
        let signature_material = self.build_parallel_signature_material(
            &*sender_new_vid,
            ParallelSignatureContext {
                sender_identity: sender.identifier(),
                receiver_identity: receiver.identifier(),
                nonce: random_nonce_bytes(),
                selection,
            },
            digest_algorithm,
        )?;
        let mut thread_id = signature_material.digest;

        let tsp_message = seal_envelope(
            &*sender,
            &*receiver,
            Payload::RequestRelationship {
                thread_id: Default::default(),
                reply_path: vec![],
                form: RelationshipForm::Parallel {
                    new_vid: new_vid_long_form.as_bytes(),
                    sig_new_vid: signature_material.sig_new_vid.as_slice(),
                },
            },
            Some(&mut thread_id),
            signature_material.request_nonce,
            Some(selection),
        )?;

        self.add_pending_parallel_request(
            receiver.identifier(),
            thread_id,
            sender_new_vid.identifier(),
        )?;

        Ok((sending_endpoint(&*receiver), tsp_message.to_owned()))
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
        // the accept travels the reply path the invite carried, which was
        // recorded as the route for the inviting VID when the invite arrived.
        // A caller may add hops of its own in front of it (spec 7.2.4).
        if let Some(route) = route {
            let route = self.resolve_reply_path(Some(route))?;
            self.set_route_for_vid(
                receiver,
                &route.iter().map(String::as_str).collect::<Vec<_>>(),
            )?;
        }

        let mut reply_thread_id = Default::default();
        let (transport, tsp_message) = self.seal_message_payload_and_hash(
            sender,
            receiver,
            Payload::AcceptRelationship {
                thread_id,
                reply_thread_id: Default::default(),
                form: RelationshipForm::Direct,
            },
            Some(&mut reply_thread_id),
        )?;

        self.establish_bidirectional_relation(sender, receiver, reply_thread_id, thread_id)?;

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
        // the invite must be outstanding; it recorded which relationship referred it
        self.find_pending_incoming_parallel_request(receiver_new_vid.identifier(), thread_id)?;
        let selection = selected_outbound_crypto(&*sender_new_vid, &*receiver_new_vid, None);

        // the accept travels the new relationship, from this endpoint's new VID
        // to the peer's, so its own signature proves control of that VID and it
        // carries no referral field (spec 7.2.5)
        let mut reply_thread_id = Default::default();
        let tsp_message = seal_envelope(
            &IntroducedVid::new(&*sender_new_vid),
            &*receiver_new_vid,
            Payload::AcceptRelationship {
                thread_id,
                reply_thread_id: Default::default(),
                form: RelationshipForm::Direct,
            },
            Some(&mut reply_thread_id),
            None,
            Some(selection),
        )?;

        self.establish_bidirectional_relation(
            sender_new_vid.identifier(),
            receiver_new_vid.identifier(),
            reply_thread_id,
            thread_id,
        )?;
        self.remove_pending_incoming_parallel_request(receiver_new_vid.identifier(), thread_id)?;

        Ok((sending_endpoint(&*receiver_new_vid), tsp_message.to_owned()))
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
            RelationshipStatus::Unrelated => {
                return Err(Error::Relationship("no relationship to cancel".into()));
            }
        };

        let (transport, message) =
            self.seal_message_payload(sender, receiver, Payload::CancelRelationship { thread_id })?;

        Ok((transport, message))
    }

    /// Reply to a `TSP_RFD` that cancelled a bidirectional relationship, with a
    /// `TSP_RFD` of our own (spec 7.3).
    ///
    /// `thread_id` is the digest the incoming cancellation named, carried on
    /// [`ReceivedTspMessage::CancelRelationship`]. Receiving the cancellation
    /// already removed the relationship, which is why this does not look one
    /// up: the reply closes the other direction for the peer, and echoing the
    /// digest is what identifies the relationship being closed.
    pub fn make_relationship_cancel_reply(
        &self,
        sender: &str,
        receiver: &str,
        thread_id: Digest,
    ) -> Result<(Url, Vec<u8>), Error> {
        self.seal_message_payload(sender, receiver, Payload::CancelRelationship { thread_id })
    }

    /// Send a nested relationship request to `receiver`, creating a new nested vid with `outer_sender` as a parent.
    pub fn make_nested_relationship_request(
        &self,
        parent_sender: &str,
        receiver: &str,
    ) -> Result<((Url, Vec<u8>), OwnedVid), Error> {
        let sender = self.get_private_vid(parent_sender)?;
        let receiver = self.get_verified_vid(receiver)?;
        // the new relationship is nested inside an existing one, which refers
        // it; without that outer relationship there is nothing to nest in and
        // the peer would drop the invite (spec 7.2.5)
        self.check_relationship_gate(sender.identifier(), receiver.identifier())?;

        let nested_vid = self.make_propositioning_vid(sender.identifier())?;
        let selection = selected_outbound_crypto(&*sender, &*receiver, None);
        let digest_algorithm = digest_algorithm_for_selection(selection)?;
        let (inner_message, thread_id) =
            self.make_signed_nested_request_message(&nested_vid, digest_algorithm)?;

        let (endpoint, tsp_message) = self.seal_message_payload_and_hash_with_selection(
            sender.identifier(),
            receiver.identifier(),
            Payload::NestedMessage(&inner_message),
            None,
            Some(selection),
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

        let parent_sender_vid = self.get_private_vid(parent_sender)?;
        let parent_receiver_vid = self.get_verified_vid(parent_receiver)?;
        let selection = selected_outbound_crypto(&*parent_sender_vid, &*parent_receiver_vid, None);
        let digest_algorithm = digest_algorithm_for_selection(selection)?;
        let (inner_message, reply_thread_id) = self.make_signed_nested_accept_message(
            &nested_vid,
            &*receiver_vid.vid,
            thread_id,
            digest_algorithm,
        )?;

        let (transport, tsp_message) = self.seal_message_payload_and_hash_with_selection(
            parent_sender,
            parent_receiver,
            Payload::NestedMessage(&inner_message),
            None,
            Some(selection),
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

    fn establish_bidirectional_relation(
        &self,
        my_vid: &str,
        other_vid: &str,
        thread_id: Digest,
        remote_thread_id: Digest,
    ) -> Result<(), Error> {
        self.set_relation_and_status_for_vid(
            other_vid,
            RelationshipStatus::Bidirectional {
                thread_id,
                remote_thread_id,
                outstanding_nested_requests: Default::default(),
            },
            my_vid,
        )
    }

    /// Refuse an application message from a sender with which the receiving VID
    /// has no relationship (spec 7.2.2: a relationship must be formed with a
    /// `TSP_RFI` first, and an application message that arrives outside one
    /// SHOULD be dropped). Callers treat the error as a silent discard.
    fn check_relationship_gate(&self, local_vid: &str, remote_vid: &str) -> Result<(), Error> {
        if self.relationship_policy()? == RelationshipPolicy::Ungated {
            return Ok(());
        }

        match self.relation_status_for_vid_pair(local_vid, remote_vid)? {
            RelationshipStatus::Unrelated => Err(Error::UnestablishedRelationship(
                remote_vid.to_string(),
                local_vid.to_string(),
            )),
            _ => Ok(()),
        }
    }

    /// Record the relationship an incoming `TSP_RFI` establishes, and resolve
    /// the race in which both endpoints sent one for the same VID pair.
    ///
    /// The receiving endpoint records `<VID_local, VID_remote>` so that
    /// application messages in this direction are accepted (spec 3.5). When an
    /// invite of our own is still outstanding for the same pair, both endpoints
    /// keep the invite whose digest is lexicographically lower and discard the
    /// other (spec 7.2.3); if ours wins, the incoming invite is dropped.
    fn record_incoming_relationship_request(
        &self,
        local_vid: &str,
        remote_vid: &str,
        thread_id: Digest,
    ) -> Result<(), Error> {
        match self.relation_status_for_vid_pair(local_vid, remote_vid)? {
            RelationshipStatus::Unrelated => self.set_relation_and_status_for_vid(
                remote_vid,
                RelationshipStatus::ReverseUnidirectional { thread_id },
                local_vid,
            ),
            // our own invite is still outstanding: the lower digest wins
            RelationshipStatus::Unidirectional {
                thread_id: our_thread_id,
            } => {
                if thread_id < our_thread_id {
                    self.set_relation_and_status_for_vid(
                        remote_vid,
                        RelationshipStatus::ReverseUnidirectional { thread_id },
                        local_vid,
                    )
                } else {
                    Err(Error::Relationship(format!(
                        "concurrent relationship request from {remote_vid} discarded: \
                         our own outstanding request has the lower digest"
                    )))
                }
            }
            // a repeated or renewed invite in an existing relationship: the
            // status already permits this direction, so leave it untouched
            RelationshipStatus::ReverseUnidirectional { .. }
            | RelationshipStatus::Bidirectional { .. } => Ok(()),
        }
    }

    /// Apply an incoming `TSP_RFD` (spec 7.3). A bidirectional relationship is
    /// removed and a reply is expected; a one-way relationship is removed with
    /// no reply; a relationship that does not exist or is not recognized is
    /// ignored, which the caller sees as a discard. Returns whether a reply is
    /// expected.
    ///
    /// The digest identifies the relationship being cancelled. Every party to a
    /// relationship holds at least the invite's digest, since a relationship
    /// cannot be formed without one, so a cancellation always names it.
    fn cancel_relationship(
        &self,
        local_vid: &str,
        remote_vid: &str,
        thread_id: Digest,
    ) -> Result<bool, Error> {
        let ignore = || {
            Err(Error::Relationship(format!(
                "unrecognized relationship cancellation from {remote_vid}; ignored"
            )))
        };
        let reply_expected = match self.relation_status_for_vid_pair(local_vid, remote_vid)? {
            RelationshipStatus::Bidirectional {
                thread_id: local,
                remote_thread_id: remote,
                ..
            } => {
                // either direction's digest identifies the relationship
                if thread_id != local && thread_id != remote {
                    return ignore();
                }

                true
            }
            RelationshipStatus::Unidirectional { thread_id: digest }
            | RelationshipStatus::ReverseUnidirectional { thread_id: digest } => {
                if thread_id != digest {
                    return ignore();
                }

                false
            }
            RelationshipStatus::Unrelated => return ignore(),
        };

        // only the status goes: the relation VID says which of our VIDs
        // corresponds to this peer, which is what addresses the reply the
        // specification asks for (spec 7.3), and cancelling from this side
        // leaves it in place too
        self.replace_relation_status_for_vid(remote_vid, RelationshipStatus::Unrelated)?;

        Ok(reply_expected)
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
    ) -> Result<DeferredVerifiedVid, Error> {
        let new_vid = std::str::from_utf8(parallel_signature_info.new_vid)?;
        let verified_vid = self.get_verified_vid_or_resolve_offline(new_vid, |error| {
            unverified_parallel_vid_error(new_vid, error)
        })?;

        crate::crypto::verify_detached(
            verified_vid.as_verified(),
            &parallel_signature_info.signed_data,
            parallel_signature_info.sig_new_vid,
        )?;

        Ok(verified_vid)
    }

    fn add_pending_parallel_request(
        &self,
        outer_receiver: &str,
        thread_id: Digest,
        local_parallel_vid: &str,
    ) -> Result<(), Error> {
        let mut vids = self.vids.write()?;
        let Some(outer_context) = vids.get(outer_receiver) else {
            return Err(Error::MissingVid(outer_receiver.into()));
        };

        if !matches!(
            outer_context.relation_status,
            RelationshipStatus::Bidirectional { .. }
        ) {
            return Err(Error::Relationship(format!(
                "no bidirectional relationship with {outer_receiver}"
            )));
        }

        let Some(local_context) = vids.get_mut(local_parallel_vid) else {
            return Err(Error::MissingVid(local_parallel_vid.into()));
        };

        local_context
            .pending_parallel_requests
            .push(PendingParallelRelationship {
                thread_id,
                local_parallel_vid: local_parallel_vid.to_string(),
                outer_receiver: outer_receiver.to_string(),
            });

        Ok(())
    }

    fn add_pending_incoming_parallel_request(
        &self,
        remote_parallel_vid: &str,
        thread_id: Digest,
        local_outer_vid: &str,
    ) -> Result<(), Error> {
        let mut vids = self.vids.write()?;
        let Some(remote_context) = vids.get_mut(remote_parallel_vid) else {
            return Err(Error::MissingVid(remote_parallel_vid.into()));
        };

        remote_context.pending_incoming_parallel_requests.push(
            PendingIncomingParallelRelationship {
                thread_id,
                local_outer_vid: local_outer_vid.to_string(),
            },
        );

        Ok(())
    }

    fn find_pending_incoming_parallel_request(
        &self,
        remote_parallel_vid: &str,
        thread_id: Digest,
    ) -> Result<PendingIncomingParallelRelationship, Error> {
        let vids = self.vids.read()?;
        let Some(remote_context) = vids.get(remote_parallel_vid) else {
            return Err(Error::MissingVid(remote_parallel_vid.into()));
        };

        remote_context
            .pending_incoming_parallel_requests
            .iter()
            .find(|request| request.thread_id == thread_id)
            .cloned()
            .ok_or_else(|| {
                Error::Relationship(format!(
                    "cannot find pending incoming parallel request for {remote_parallel_vid}"
                ))
            })
    }

    fn remove_pending_incoming_parallel_request(
        &self,
        remote_parallel_vid: &str,
        thread_id: Digest,
    ) -> Result<(), Error> {
        let mut vids = self.vids.write()?;
        let Some(remote_context) = vids.get_mut(remote_parallel_vid) else {
            return Err(Error::MissingVid(remote_parallel_vid.into()));
        };

        let Some(index) = remote_context
            .pending_incoming_parallel_requests
            .iter()
            .position(|request| request.thread_id == thread_id)
        else {
            return Err(Error::Relationship(format!(
                "cannot find pending incoming parallel request for {remote_parallel_vid}"
            )));
        };
        remote_context
            .pending_incoming_parallel_requests
            .remove(index);

        Ok(())
    }

    /// Complete an outstanding parallel invite, if this accept answers one.
    /// The accept arrives from the peer's new VID over the new relationship
    /// (spec 7.2.5), so the thread id is what identifies it.
    fn consume_pending_parallel_request(
        &self,
        local_parallel_vid: &str,
        thread_id: Digest,
    ) -> Result<bool, Error> {
        let mut vids = self.vids.write()?;

        let Some(local_context) = vids.get_mut(local_parallel_vid) else {
            return Ok(false);
        };

        let Some(index) = local_context
            .pending_parallel_requests
            .iter()
            .position(|request| {
                request.thread_id == thread_id && request.local_parallel_vid == local_parallel_vid
            })
        else {
            return Ok(false);
        };

        local_context.pending_parallel_requests.remove(index);

        Ok(true)
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
        let local_nested_vid = &outstanding_nested_requests[index].local_nested_vid;
        if !local_nested_vid.is_empty() && local_nested_vid != expected_local_nested_vid {
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

    use crate::test_utils::*;
    use crate::{
        Error, Payload, PendingParallelRelationship, ReceivedRelationshipDelivery,
        ReceivedRelationshipForm, ReceivedTspMessage, RelationshipForm, RelationshipStatus,
        SecureStore, SendOptions, VerifiedVid,
        crypto::{CryptoError, PayloadConfidentiality},
        store::RelationshipPolicy,
    };

    fn assert_url_matches(url: &url::Url, expected_receiver: &dyn VerifiedVid) {
        assert_eq!(url.as_str(), expected_receiver.endpoint().as_str());
    }

    fn test_envelope_prefix(
        sender: &(impl VerifiedVid + ?Sized),
        receiver: &(impl VerifiedVid + ?Sized),
    ) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(64);
        crate::cesr::encode_envelope_prefix(
            sender.identifier().as_bytes(),
            Some(receiver.identifier().as_bytes()),
            &mut prefix,
        )
        .unwrap();
        prefix
    }

    /// What the payload's ESSR sender field will hold for this pair, decided
    /// the same way the seal path decides it — the referral signature covers
    /// that field, so a test that builds the challenge by hand has to agree.
    fn test_essr_sender<'a>(
        sender: &'a dyn VerifiedVid,
        receiver: &dyn VerifiedVid,
    ) -> Option<&'a [u8]> {
        super::selected_outbound_crypto(sender, receiver, None).essr_sender_in_payload(sender)
    }

    fn relationship_digest_algorithm(
        sender: &dyn VerifiedVid,
        receiver: &dyn VerifiedVid,
    ) -> crate::crypto::RelationshipDigestAlgorithm {
        super::digest_algorithm_for_selection(super::selected_outbound_crypto(
            sender, receiver, None,
        ))
        .unwrap()
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

    fn reopen_store(store: &SecureStore) -> SecureStore {
        let reopened = SecureStore::new();
        let (vids, aliases, keys) = store.export().unwrap();
        reopened.import(vids, aliases, keys).unwrap();
        reopened
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
    fn test_application_message_without_relationship_is_dropped() {
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();

        let (_url, mut sealed) = a_store
            .seal_message(alice.identifier(), bob.identifier(), b"hello world")
            .unwrap();
        // open_message decrypts in place, so the second attempt needs its own copy
        let (_url, mut sealed_again) = a_store
            .seal_message(alice.identifier(), bob.identifier(), b"hello world")
            .unwrap();

        // bob has verified alice, but no relationship was ever formed
        let Err(Error::UnestablishedRelationship(sender, receiver)) =
            b_store.open_message(&mut sealed)
        else {
            panic!("an application message without a relationship must be dropped");
        };
        assert_eq!(sender, alice.identifier());
        assert_eq!(receiver, bob.identifier());

        // the same message is accepted once the receiver opts out of gating
        b_store
            .set_relationship_policy(RelationshipPolicy::Ungated)
            .unwrap();
        let received = b_store.open_message(&mut sealed_again).unwrap();
        assert!(matches!(
            received,
            ReceivedTspMessage::GenericMessage { .. }
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_relationship_request_admits_following_application_message() {
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();

        let (_url, mut request) = a_store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();
        let (_url, mut sealed) = a_store
            .seal_message(alice.identifier(), bob.identifier(), b"hello world")
            .unwrap();

        // receiving the invite records <bob, alice>, so the message that
        // follows is inside an established relationship
        assert!(matches!(
            b_store.open_message(&mut request).unwrap(),
            ReceivedTspMessage::RequestRelationship { .. }
        ));
        assert!(matches!(
            b_store
                .relation_status_for_vid_pair(bob.identifier(), alice.identifier())
                .unwrap(),
            RelationshipStatus::ReverseUnidirectional { .. }
        ));
        assert!(matches!(
            b_store.open_message(&mut sealed).unwrap(),
            ReceivedTspMessage::GenericMessage { .. }
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_concurrent_relationship_requests_keep_the_lower_digest() {
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();

        // both endpoints invite each other for the same VID pair
        let (_url, mut a_request) = a_store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();
        let (_url, mut b_request) = b_store
            .make_relationship_request(bob.identifier(), alice.identifier(), None)
            .unwrap();

        let RelationshipStatus::Unidirectional {
            thread_id: a_digest,
        } = a_store
            .relation_status_for_vid_pair(alice.identifier(), bob.identifier())
            .unwrap()
        else {
            panic!("alice should have an outstanding request");
        };
        let RelationshipStatus::Unidirectional {
            thread_id: b_digest,
        } = b_store
            .relation_status_for_vid_pair(bob.identifier(), alice.identifier())
            .unwrap()
        else {
            panic!("bob should have an outstanding request");
        };
        assert_ne!(a_digest, b_digest);

        let a_result = a_store.open_message(&mut b_request);
        let b_result = b_store.open_message(&mut a_request);

        // exactly one invite survives on both sides: the one with the lower digest
        if a_digest < b_digest {
            assert!(a_result.is_err(), "alice keeps her own lower-digest invite");
            assert!(b_result.is_ok(), "bob adopts alice's lower-digest invite");
            assert!(matches!(
                b_store
                    .relation_status_for_vid_pair(bob.identifier(), alice.identifier())
                    .unwrap(),
                RelationshipStatus::ReverseUnidirectional { thread_id } if thread_id == a_digest
            ));
        } else {
            assert!(b_result.is_err(), "bob keeps his own lower-digest invite");
            assert!(a_result.is_ok(), "alice adopts bob's lower-digest invite");
            assert!(matches!(
                a_store
                    .relation_status_for_vid_pair(alice.identifier(), bob.identifier())
                    .unwrap(),
                RelationshipStatus::ReverseUnidirectional { thread_id } if thread_id == b_digest
            ));
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_cancel_relationship_follows_the_relationship_direction() {
        // bidirectional: the relationship is removed and a reply is expected
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();
        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();
        establish_existing_relationship(&a_store, &alice, &b_store, &bob);

        let (_url, mut cancel) = a_store
            .make_relationship_cancel(alice.identifier(), bob.identifier())
            .unwrap();
        let ReceivedTspMessage::CancelRelationship {
            thread_id,
            reply_expected,
            ..
        } = b_store.open_message(&mut cancel).unwrap()
        else {
            panic!("unexpected message type");
        };
        assert!(
            reply_expected,
            "a bidirectional cancellation is echoed back"
        );
        assert!(matches!(
            b_store
                .relation_status_for_vid_pair(bob.identifier(), alice.identifier())
                .unwrap(),
            RelationshipStatus::Unrelated
        ));
        // and bob can still build that reply, though he has already dropped
        // the relationship it names (spec 7.3)
        b_store
            .make_relationship_cancel_reply(bob.identifier(), alice.identifier(), thread_id)
            .unwrap();

        // one-way: the relationship is removed, but no reply is expected
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();
        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();

        let (_url, mut request) = a_store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();
        b_store.open_message(&mut request).unwrap();
        let (_url, mut cancel) = a_store
            .make_relationship_cancel(alice.identifier(), bob.identifier())
            .unwrap();
        let ReceivedTspMessage::CancelRelationship { reply_expected, .. } =
            b_store.open_message(&mut cancel).unwrap()
        else {
            panic!("unexpected message type");
        };
        assert!(!reply_expected, "a one-way cancellation is not echoed back");
        assert!(matches!(
            b_store
                .relation_status_for_vid_pair(bob.identifier(), alice.identifier())
                .unwrap(),
            RelationshipStatus::Unrelated
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_cancel_of_unknown_relationship_is_ignored() {
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();
        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();

        // alice believes there is a relationship; bob has none
        a_store
            .set_relation_and_status_for_vid(
                bob.identifier(),
                RelationshipStatus::Unidirectional { thread_id: [9; 32] },
                alice.identifier(),
            )
            .unwrap();

        let (_url, mut cancel) = a_store
            .make_relationship_cancel(alice.identifier(), bob.identifier())
            .unwrap();

        assert!(
            b_store.open_message(&mut cancel).is_err(),
            "a cancellation for a relationship bob does not have is ignored"
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_nested_message_from_unknown_inner_sender_opens_after_verification() {
        // A nested message whose inner sender is unknown is reported as
        // UnverifiedSource so the caller can resolve that VID and try again.
        // The retry must succeed on a fresh copy of the same bytes -- this is
        // the shape of a routed invite arriving from an endpoint the receiver
        // has never seen.
        let a_store = create_test_store();
        let q_store = create_test_store();
        let b_store = create_test_store();

        let alice = create_test_vid();
        let bob = create_test_vid();
        let intermediary = create_test_vid();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        q_store.add_private_vid(intermediary.clone(), None).unwrap();
        q_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store
            .add_verified_vid(intermediary.clone(), None)
            .unwrap();
        // bob knows the intermediary, but has never seen alice
        b_store
            .set_relation_and_status_for_vid(
                intermediary.identifier(),
                RelationshipStatus::Unidirectional { thread_id: [7; 32] },
                bob.identifier(),
            )
            .unwrap();

        let (_url, inner) = a_store
            .make_relationship_request(alice.identifier(), bob.identifier(), None)
            .unwrap();
        let (_url, nested) = q_store
            .seal_message_payload(
                intermediary.identifier(),
                bob.identifier(),
                Payload::NestedMessage(&inner),
            )
            .unwrap();

        let mut first = nested.clone();
        // the variant carries the payload only when the async feature is on
        let Err(Error::UnverifiedSource(unknown, ..)) = b_store.open_message(&mut first) else {
            panic!("an unknown inner sender should be reported");
        };
        assert_eq!(unknown, alice.identifier());

        b_store.add_verified_vid(alice.clone(), None).unwrap();

        let mut retry = nested.clone();
        let received = b_store
            .open_message(&mut retry)
            .expect("the retry must open the message");
        assert!(matches!(
            received,
            ReceivedTspMessage::RequestRelationship { .. }
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_open_seal() {
        let store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        store.add_private_vid(alice.clone(), None).unwrap();
        store.add_private_vid(bob.clone(), None).unwrap();
        establish_existing_relationship(&store, &alice, &store, &bob);

        let message = b"hello world";

        let (url, mut sealed) = store
            .seal_message(alice.identifier(), bob.identifier(), message)
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
        assert_eq!(
            sig_new_vid.len(),
            match alice_parallel.signature_key_type() {
                crate::definitions::VidSignatureKeyType::Ed25519 => 64,
                crate::definitions::VidSignatureKeyType::MlDsa65 => 3309,
            }
        );
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
        let RelationshipStatus::Bidirectional {
            thread_id: sender_thread_id,
            remote_thread_id: sender_remote_thread_id,
            outstanding_nested_requests,
        } = b_store
            .relation_status_for_vid_pair(bob_parallel.identifier(), alice_parallel.identifier())
            .unwrap()
        else {
            panic!("parallel accept did not establish sender-side relationship");
        };
        assert_eq!(sender_remote_thread_id, thread_id);
        assert!(sender_thread_id.iter().any(|byte| *byte != 0));
        assert!(outstanding_nested_requests.is_empty());

        let received = a_store.open_message(&mut sealed).unwrap();

        // the accept arrives from bob's new VID over the new relationship, so
        // the new VID is the sender rather than a payload field (spec 7.2.5)
        let ReceivedTspMessage::AcceptRelationship {
            sender,
            receiver,
            thread_id: request_digest,
            reply_thread_id: received_reply_digest,
            form: ReceivedRelationshipForm::Direct,
            delivery: ReceivedRelationshipDelivery::Direct,
        } = received
        else {
            panic!("unexpected message type");
        };
        assert_eq!(sender, bob_parallel.identifier());
        assert_eq!(receiver, alice_parallel.identifier());
        assert_eq!(request_digest, thread_id);
        assert!(received_reply_digest.iter().any(|byte| *byte != 0));

        let RelationshipStatus::Bidirectional {
            thread_id: receiver_thread_id,
            remote_thread_id: receiver_remote_thread_id,
            outstanding_nested_requests,
        } = a_store
            .relation_status_for_vid_pair(alice_parallel.identifier(), bob_parallel.identifier())
            .unwrap()
        else {
            panic!("parallel accept did not establish receiver-side relationship");
        };
        assert_eq!(receiver_thread_id, thread_id);
        assert_eq!(receiver_remote_thread_id, received_reply_digest);
        assert!(outstanding_nested_requests.is_empty());
        assert_eq!(sender_thread_id, received_reply_digest);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_parallel_relationship_accept_requires_pending_request() {
        let b_store = create_test_store();
        let alice_parallel = create_test_vid();
        let bob_parallel = create_test_vid();

        b_store.add_private_vid(bob_parallel.clone(), None).unwrap();
        b_store
            .add_verified_vid(alice_parallel.clone(), None)
            .unwrap();

        let random_thread_id = [7; 32];
        let Err(Error::Relationship(message)) = b_store.make_parallel_relationship_accept(
            bob_parallel.identifier(),
            alice_parallel.identifier(),
            random_thread_id,
        ) else {
            panic!("unexpected accept construction result");
        };

        assert!(message.contains("pending incoming parallel request"));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_parallel_relationship_accept_after_reopen() {
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
        let reopened_a_store = reopen_store(&a_store);

        let ReceivedTspMessage::RequestRelationship { thread_id, .. } =
            b_store.open_message(&mut request).unwrap()
        else {
            panic!("unexpected message type");
        };

        let (_url, mut accept) = b_store
            .make_parallel_relationship_accept(
                bob_parallel.identifier(),
                alice_parallel.identifier(),
                thread_id,
            )
            .unwrap();

        let ReceivedTspMessage::AcceptRelationship {
            reply_thread_id, ..
        } = reopened_a_store.open_message(&mut accept).unwrap()
        else {
            panic!("unexpected message type");
        };

        match reopened_a_store
            .relation_status_for_vid_pair(alice_parallel.identifier(), bob_parallel.identifier())
            .unwrap()
        {
            RelationshipStatus::Bidirectional {
                thread_id: reopened_thread_id,
                remote_thread_id,
                ..
            } => {
                assert_eq!(reopened_thread_id, thread_id);
                assert_eq!(remote_thread_id, reply_thread_id);
            }
            status => panic!("unexpected requester status after reopen: {status}"),
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_parallel_relationship_accept_can_be_sent_after_receiver_reopen() {
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

        let reopened_b_store = reopen_store(&b_store);
        let (_url, mut accept) = reopened_b_store
            .make_parallel_relationship_accept(
                bob_parallel.identifier(),
                alice_parallel.identifier(),
                thread_id,
            )
            .unwrap();

        let ReceivedTspMessage::AcceptRelationship {
            sender,
            form: ReceivedRelationshipForm::Direct,
            ..
        } = a_store.open_message(&mut accept).unwrap()
        else {
            panic!("unexpected message type");
        };

        // the accept comes from bob's new VID over the new relationship
        assert_eq!(sender, bob_parallel.identifier());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_parallel_relationship_accept_requires_the_invite_thread_id() {
        // The accept now travels the new relationship, from the peer's new VID,
        // so what ties it to the invite is the thread id -- which is the
        // invite's digest, carried inside a ciphertext only the invited
        // endpoint could open. An accept naming any other thread id does not
        // complete the invite.
        let a_store = create_test_store();
        let b_store = create_test_store();
        let c_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();
        let alice_parallel = create_test_vid();
        let charlie_parallel = create_test_vid();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        a_store
            .add_private_vid(alice_parallel.clone(), None)
            .unwrap();
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
        assert!(matches!(
            b_store.open_message(&mut request).unwrap(),
            ReceivedTspMessage::RequestRelationship { .. }
        ));

        c_store
            .add_private_vid(charlie_parallel.clone(), None)
            .unwrap();
        c_store
            .add_verified_vid(alice_parallel.clone(), None)
            .unwrap();
        a_store
            .add_verified_vid(charlie_parallel.clone(), None)
            .unwrap();

        // an accept for a thread id that is not the outstanding invite's
        let forged_receiver = c_store
            .get_verified_vid(alice_parallel.identifier())
            .unwrap();
        let forged_sender = c_store
            .get_private_vid(charlie_parallel.identifier())
            .unwrap();
        let mut forged_accept = crate::crypto::seal_and_hash(
            &*forged_sender,
            &*forged_receiver,
            Payload::AcceptRelationship {
                thread_id: [0xAB; 32],
                reply_thread_id: Default::default(),
                form: RelationshipForm::Direct,
            },
            None,
        )
        .unwrap();

        assert!(
            a_store.open_message(&mut forged_accept).is_err(),
            "an accept that names no outstanding invite must not establish one"
        );
        assert!(matches!(
            a_store
                .relation_status_for_vid_pair(
                    alice_parallel.identifier(),
                    charlie_parallel.identifier()
                )
                .unwrap(),
            RelationshipStatus::Unrelated
        ));

        // the invite is still outstanding
        let (vids, _, _) = a_store.export().unwrap();
        let Some(alice_parallel_export) = vids
            .iter()
            .find(|vid| vid.id == alice_parallel.identifier())
        else {
            panic!("missing exported local parallel vid");
        };
        assert_eq!(alice_parallel_export.pending_parallel_requests.len(), 1);
        assert_eq!(
            alice_parallel_export.pending_parallel_requests[0].outer_receiver,
            bob.identifier()
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_parallel_relationship_request_is_tracked_on_local_parallel_vid() {
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

        let (vids, _, _) = a_store.export().unwrap();
        let Some(alice_parallel_export) = vids
            .iter()
            .find(|vid| vid.id == alice_parallel.identifier())
        else {
            panic!("missing exported local parallel vid");
        };
        assert_eq!(
            alice_parallel_export.pending_parallel_requests,
            vec![PendingParallelRelationship {
                thread_id,
                local_parallel_vid: alice_parallel.identifier().to_string(),
                outer_receiver: bob.identifier().to_string(),
            }]
        );

        let Some(bob_export) = vids.iter().find(|vid| vid.id == bob.identifier()) else {
            panic!("missing exported outer receiver vid");
        };
        assert!(bob_export.pending_parallel_requests.is_empty());
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

        let mut nonce_bytes = [0_u8; 16];
        StdRng::from_entropy().fill_bytes(&mut nonce_bytes);
        let mut thread_id = [0_u8; 32];
        let signed_data = crate::crypto::build_parallel_request_signed_data(
            test_essr_sender(&alice, &bob),
            relationship_digest_algorithm(&alice, &bob),
            nonce_bytes,
            &[],
            &test_envelope_prefix(&alice, &bob),
            &mut thread_id,
            crate::vid::did::peer::introduction_identifier(&alice_parallel).as_bytes(),
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
            Payload::RequestRelationship {
                thread_id: Default::default(),
                reply_path: vec![],
                form: RelationshipForm::Parallel {
                    new_vid: crate::vid::did::peer::introduction_identifier(&alice_parallel)
                        .as_ref(),
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
    fn test_parallel_relationship_request_requires_existing_outer_relationship() {
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

        let mut nonce_bytes = [0_u8; 16];
        StdRng::from_entropy().fill_bytes(&mut nonce_bytes);
        let mut thread_id = [0_u8; 32];
        let signed_data = crate::crypto::build_parallel_request_signed_data(
            test_essr_sender(&alice, &bob),
            relationship_digest_algorithm(&alice, &bob),
            nonce_bytes,
            &[],
            &test_envelope_prefix(&alice, &bob),
            &mut thread_id,
            crate::vid::did::peer::introduction_identifier(&alice_parallel).as_bytes(),
        )
        .unwrap();
        let sig_new_vid = crate::crypto::sign_detached(&alice_parallel, &signed_data).unwrap();

        let sender_vid = a_store.get_private_vid(alice.identifier()).unwrap();
        let receiver_vid = a_store.get_verified_vid(bob.identifier()).unwrap();
        let mut request_digest = Default::default();
        let mut sealed = crate::crypto::seal_and_hash_with_relationship_nonce(
            &*sender_vid,
            &*receiver_vid,
            Payload::RequestRelationship {
                thread_id: Default::default(),
                reply_path: vec![],
                form: RelationshipForm::Parallel {
                    new_vid: crate::vid::did::peer::introduction_identifier(&alice_parallel)
                        .as_ref(),
                    sig_new_vid: sig_new_vid.as_slice(),
                },
            },
            Some(&mut request_digest),
            Some(nonce_bytes),
        )
        .unwrap();

        let Err(Error::Relationship(message)) = b_store.open_message(&mut sealed) else {
            panic!("unexpected message result");
        };

        assert_eq!(
            message,
            "parallel relationship-forming requires an existing bidirectional relationship"
        );
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
            .seal_message(sender.identifier(), receiver.identifier(), b"hello")
            .unwrap();
        let last = sealed
            .last_mut()
            .expect("sealed message should not be empty");
        *last ^= 0x01;

        // the sender is a did:peer, whose short form the receiver cannot
        // resolve without having been introduced to it, so an unknown sender
        // is rejected before its signature is ever considered
        let Err(Error::UnverifiedSource(vid, ..)) = receiver_store.open_message(&mut sealed) else {
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
    fn test_relationship_forming_carries_a_reply_path() {
        // A invites B over a route, telling B how to reach it; B records that
        // as the route for A, so its accept travels back the same way
        // (spec 7.2.4).
        let a_store = create_test_store();
        let b_store = create_test_store();

        let alice = create_test_vid();
        let bob = create_test_vid();
        let alice_intermediary = create_test_vid();
        let bob_intermediary = create_test_vid();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        a_store
            .add_verified_vid(bob_intermediary.clone(), None)
            .unwrap();
        a_store
            .add_verified_vid(alice_intermediary.clone(), None)
            .unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();
        b_store
            .add_verified_vid(alice_intermediary.clone(), None)
            .unwrap();
        // bob reaches alice's intermediary over his own relationship with it
        b_store
            .set_relation_and_status_for_vid(
                alice_intermediary.identifier(),
                RelationshipStatus::Unidirectional { thread_id: [6; 32] },
                bob.identifier(),
            )
            .unwrap();

        // alice reaches bob through his intermediary, and asks for the reply
        // to come back through hers
        a_store
            .set_relation_and_status_for_vid(
                bob_intermediary.identifier(),
                RelationshipStatus::Unidirectional { thread_id: [5; 32] },
                alice.identifier(),
            )
            .unwrap();
        a_store
            .set_route_for_vid(
                bob.identifier(),
                &[bob_intermediary.identifier(), bob.identifier()],
            )
            .unwrap();

        let (_url, mut request) = a_store
            .make_relationship_request(
                alice.identifier(),
                bob.identifier(),
                Some(&[alice_intermediary.identifier(), alice.identifier()]),
            )
            .unwrap();

        // the invite reached bob's intermediary as a routed message; it hands
        // the inner message to bob
        let i_store = create_test_store();
        i_store
            .add_private_vid(bob_intermediary.clone(), None)
            .unwrap();
        i_store.add_verified_vid(alice.clone(), None).unwrap();
        let forwarded = i_store.open_message(&mut request).unwrap().into_owned();

        let ReceivedTspMessage::ForwardRequest { opaque_payload, .. } = forwarded else {
            panic!("the invite did not travel the route");
        };

        let mut inner = opaque_payload.to_vec();
        let ReceivedTspMessage::RequestRelationship { thread_id, .. } =
            b_store.open_message(&mut inner).unwrap()
        else {
            panic!("bob did not receive a relationship request");
        };

        // bob now knows how to reach alice
        assert_eq!(
            b_store.get_route_for_vid(alice.identifier()).unwrap(),
            Some(vec![
                alice_intermediary.identifier().to_string(),
                alice.identifier().to_string(),
            ]),
        );

        // so his accept goes to alice's intermediary rather than to alice
        let (url, _accept) = b_store
            .make_relationship_accept(bob.identifier(), alice.identifier(), thread_id, None)
            .unwrap();
        assert_url_matches(&url, &alice_intermediary);
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

        // the destination endpoint has an endpoint-to-endpoint relationship
        // with the source; without it the arriving message is gated (spec 7.2.2)
        d_store
            .set_relation_and_status_for_vid(
                sneaky_a.identifier(),
                RelationshipStatus::ReverseUnidirectional {
                    thread_id: Default::default(),
                },
                sneaky_d.identifier(),
            )
            .unwrap();

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
                &[b.identifier(), c.identifier(), nette_d.identifier()],
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
                nette_d.identifier(),
                RelationshipStatus::Unidirectional {
                    thread_id: Default::default(),
                },
                mailbox_c.identifier(),
            )
            .unwrap();

        let hello_world = b"hello world";

        let (_url, mut sealed) = a_store
            .seal_message(sneaky_a.identifier(), sneaky_d.identifier(), hello_world)
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
            message,
            message_type,
        } = received
        else {
            panic!()
        };

        assert_eq!(sender, sneaky_a.identifier());
        assert_eq!(receiver.unwrap(), sneaky_d.identifier());
        assert_eq!(message, hello_world);
        assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
        assert_ne!(
            message_type.signature_type,
            crate::cesr::SignatureType::NoSignature
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_nested_relationship_cancel_travels_the_outer_relationship() {
        // A nested relationship is cancelled with the same TSP_RFD as any
        // other, carried as an inner message of the outer relationship, and it
        // references the digest that formed it (spec 9.4).
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();
        establish_existing_relationship(&a_store, &alice, &b_store, &bob);

        let ((_url, mut invite), nested_a) = a_store
            .make_nested_relationship_request(alice.identifier(), bob.identifier())
            .unwrap();
        let ReceivedTspMessage::RequestRelationship {
            thread_id,
            delivery: ReceivedRelationshipDelivery::Nested { nested_vid },
            ..
        } = b_store.open_message(&mut invite).unwrap()
        else {
            panic!("bob did not receive a nested relationship request");
        };

        let ((_url, mut accept), nested_b) = b_store
            .make_nested_relationship_accept(bob.identifier(), &nested_vid, thread_id)
            .unwrap();
        let ReceivedTspMessage::AcceptRelationship { .. } =
            a_store.open_message(&mut accept).unwrap()
        else {
            panic!("alice did not receive a nested relationship accept");
        };

        // alice ends the nested relationship
        let (_url, mut cancel) = a_store
            .make_relationship_cancel(nested_a.identifier(), nested_b.identifier())
            .unwrap();

        let ReceivedTspMessage::CancelRelationship {
            sender,
            receiver,
            thread_id: cancelled,
            reply_expected,
        } = b_store.open_message(&mut cancel).unwrap()
        else {
            panic!("bob did not receive a cancellation");
        };
        assert_eq!(sender, nested_a.identifier());
        assert_eq!(receiver, nested_b.identifier());
        // the relationship was bidirectional, so bob replies in kind, echoing
        // the digest even though he has already dropped the relationship
        assert!(reply_expected);
        let (_url, mut reply) = b_store
            .make_relationship_cancel_reply(nested_b.identifier(), nested_a.identifier(), cancelled)
            .unwrap();
        // alice dropped it when she sent hers, so she ignores the reply
        assert!(matches!(
            a_store.open_message(&mut reply),
            Err(Error::Relationship(_))
        ));

        // bob accepted it, which means it named one of the two digests that
        // formed the relationship, and both sides have now dropped it
        assert!(matches!(
            a_store
                .relation_status_for_vid_pair(nested_a.identifier(), nested_b.identifier())
                .unwrap(),
            RelationshipStatus::Unrelated
        ));
        assert!(matches!(
            b_store
                .relation_status_for_vid_pair(nested_b.identifier(), nested_a.identifier())
                .unwrap(),
            RelationshipStatus::Unrelated
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_nested_relationship_needs_an_outer_relationship() {
        // A nested relationship is referred by the outer one it sits inside, so
        // neither endpoint takes part without that outer relationship (spec
        // 7.2.5).
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();

        // alice knows bob's VID but has formed no relationship with him
        assert!(matches!(
            a_store.make_nested_relationship_request(alice.identifier(), bob.identifier()),
            Err(Error::UnestablishedRelationship(..))
        ));

        // and if alice believes there is one but bob has no record of it, bob
        // does not act on the invite either
        a_store
            .set_relation_and_status_for_vid(
                bob.identifier(),
                RelationshipStatus::Bidirectional {
                    thread_id: [1; 32],
                    remote_thread_id: [2; 32],
                    outstanding_nested_requests: vec![],
                },
                alice.identifier(),
            )
            .unwrap();
        let ((_url, mut invite), _nested_a) = a_store
            .make_nested_relationship_request(alice.identifier(), bob.identifier())
            .unwrap();
        assert!(matches!(
            b_store.open_message(&mut invite),
            Err(Error::UnestablishedRelationship(..))
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_nested_control_message_payload_is_the_control_payload() {
        // The inner message of a nested TSP_RFI/TSP_RFA carries that control
        // payload itself (spec 9.4.13/9.4.14), not an XSCS application payload
        // wrapping one. A round trip cannot catch the difference, because the
        // receiver peels whatever the sender wrapped, so decode the payload of
        // the inner message directly and look at its type.
        fn payload_type_of(message: &[u8]) -> &'static str {
            let mut buf = message.to_vec();
            let crate::cesr::DecodedEnvelope {
                payload_position: Some(payload),
                ..
            } = crate::cesr::decode_envelope(&mut buf)
                .unwrap()
                .into_opened::<&[u8]>()
                .unwrap()
            else {
                panic!("the inner message carries a payload");
            };
            match crate::cesr::decode_payload(payload).unwrap().payload {
                crate::cesr::Payload::RelationProposal { .. } => "XRFI",
                crate::cesr::Payload::RelationAffirm { .. } => "XRFA",
                crate::cesr::Payload::GenericMessage(_) => "XSCS",
                _ => "other",
            }
        }

        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();
        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();
        establish_existing_relationship(&a_store, &alice, &b_store, &bob);

        let ((_url, mut invite), nested_a) = a_store
            .make_nested_relationship_request(alice.identifier(), bob.identifier())
            .unwrap();
        let ReceivedTspMessage::RequestRelationship {
            thread_id,
            delivery: ReceivedRelationshipDelivery::Nested { nested_vid },
            ..
        } = b_store.open_message(&mut invite).unwrap()
        else {
            panic!("bob did not receive a nested relationship request");
        };

        let (rfi, _) = a_store
            .make_signed_nested_request_message(
                &*a_store.get_private_vid(nested_a.identifier()).unwrap(),
                crate::crypto::RelationshipDigestAlgorithm::Sha2_256,
            )
            .unwrap();
        assert_eq!(payload_type_of(&rfi), "XRFI");

        let (_accept, nested_b) = b_store
            .make_nested_relationship_accept(bob.identifier(), &nested_vid, thread_id)
            .unwrap();
        let (rfa, _) = b_store
            .make_signed_nested_accept_message(
                &*b_store.get_private_vid(nested_b.identifier()).unwrap(),
                &*b_store.get_verified_vid(&nested_vid).unwrap(),
                thread_id,
                crate::crypto::RelationshipDigestAlgorithm::Sha2_256,
            )
            .unwrap();
        assert_eq!(payload_type_of(&rfa), "XRFA");
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_nested_relationship_digest_is_self_referencing() {
        // The digests of a nested exchange are the inner messages' own SAIDs
        // (spec 7.2.1). The receiver recomputes each one, so a legitimate
        // exchange only completes if both sides derive it identically, and an
        // altered message stops matching.
        let a_store = create_test_store();
        let b_store = create_test_store();
        let (alice, bob) = create_test_vid_pair();

        a_store.add_private_vid(alice.clone(), None).unwrap();
        a_store.add_verified_vid(bob.clone(), None).unwrap();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();
        establish_existing_relationship(&a_store, &alice, &b_store, &bob);

        let ((_url, mut invite), _nested_a) = a_store
            .make_nested_relationship_request(alice.identifier(), bob.identifier())
            .unwrap();
        let pristine = invite.clone();

        let ReceivedTspMessage::RequestRelationship {
            thread_id,
            delivery: ReceivedRelationshipDelivery::Nested { nested_vid },
            ..
        } = b_store.open_message(&mut invite).unwrap()
        else {
            panic!("bob did not receive a nested relationship request");
        };
        // deriving it from the message means it cannot be a fixed value
        assert!(thread_id.iter().any(|byte| *byte != 0));

        // the accept echoes that digest and derives its own
        let ((_url, mut accept), _nested_b) = b_store
            .make_nested_relationship_accept(bob.identifier(), &nested_vid, thread_id)
            .unwrap();

        let ReceivedTspMessage::AcceptRelationship {
            thread_id: echoed,
            reply_thread_id,
            ..
        } = a_store.open_message(&mut accept).unwrap()
        else {
            panic!("alice did not receive a nested relationship accept");
        };
        assert_eq!(echoed, thread_id, "the invite's digest is echoed verbatim");
        assert!(reply_thread_id.iter().any(|byte| *byte != 0));
        assert_ne!(reply_thread_id, thread_id);

        // an invite whose bytes were altered no longer matches its own digest
        let b_store = create_test_store();
        b_store.add_private_vid(bob.clone(), None).unwrap();
        b_store.add_verified_vid(alice.clone(), None).unwrap();
        establish_existing_relationship(&a_store, &alice, &b_store, &bob);

        let mut tampered = pristine.clone();
        let position = tampered.len() / 2;
        tampered[position] ^= 0x01;
        assert!(
            b_store.open_message(&mut tampered).is_err(),
            "a nested invite whose bytes were altered must not be accepted"
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

        // the nested relationship exists on both sides, as the control-message
        // handshake leaves it. The inner message is encrypted, so it passes
        // through the relationship gate of spec 7.2.2 like any other
        // application message.
        b_store
            .set_relation_and_status_for_vid(
                nested_a.identifier(),
                RelationshipStatus::Unidirectional {
                    thread_id: Default::default(),
                },
                nested_b.identifier(),
            )
            .unwrap();

        let hello_world = b"hello world";

        let (_url, mut sealed) = a_store
            .seal_message(nested_a.identifier(), nested_b.identifier(), hello_world)
            .unwrap();

        let received = b_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::GenericMessage {
            sender,
            receiver,
            message,
            message_type,
        } = received
        else {
            panic!()
        };

        assert_eq!(sender, nested_a.identifier());
        assert_eq!(receiver.unwrap(), nested_b.identifier());
        assert_eq!(message, hello_world);
        assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
        assert_ne!(
            message_type.signature_type,
            crate::cesr::SignatureType::NoSignature
        );
        assert!(
            message_type.enclosing_crypto_type.is_some(),
            "a nested message must report how its enclosing message was encrypted"
        );

        // the same exchange with a signed-only inner message: the receiver must
        // be told that the inner message was not itself encrypted, and that it
        // nonetheless arrived inside a confidential envelope (spec 4)
        let (_url, mut sealed) = a_store
            .seal_message_with_confidentiality(
                nested_a.identifier(),
                nested_b.identifier(),
                hello_world,
                PayloadConfidentiality::SignedOnly,
            )
            .unwrap();

        let ReceivedTspMessage::GenericMessage {
            message,
            message_type,
            ..
        } = b_store.open_message(&mut sealed).unwrap()
        else {
            panic!()
        };

        assert_eq!(message, hello_world);
        assert_eq!(
            message_type.crypto_type,
            crate::cesr::CryptoType::Plaintext,
            "a signed-only inner message must be reported as such, not as the enclosing type"
        );
        assert_ne!(
            message_type.enclosing_crypto_type,
            Some(crate::cesr::CryptoType::Plaintext),
            "and the enclosing message it arrived in was encrypted"
        );
    }

    /// `XCTL`, `XPAD` and a caller's padding all reach the wire and come back.
    ///
    /// Before this they existed only at the CESR layer: the crypto layer
    /// answered `UnsupportedPayload` for the two payload types, and the padding
    /// field was hard-coded empty at every seal site.
    #[test]
    #[wasm_bindgen_test]
    fn control_padding_and_a_padded_payload_round_trip() {
        let a_store = create_test_store();
        let b_store = create_test_store();
        let a = create_test_vid();
        let b = create_test_vid();

        for (store, own, other) in [(&a_store, &a, &b), (&b_store, &b, &a)] {
            store.add_private_vid(own.clone(), None).unwrap();
            store.add_verified_vid(other.clone(), None).unwrap();
            store
                .set_relation_and_status_for_vid(
                    other.identifier(),
                    RelationshipStatus::Unidirectional {
                        thread_id: Default::default(),
                    },
                    own.identifier(),
                )
                .unwrap();
        }

        // an upper layer's control payload arrives as its own kind, not as a
        // generic message — that distinction is the whole point of XCTL
        let (_, mut sealed) = a_store
            .seal_control_message(
                a.identifier(),
                b.identifier(),
                b"turn left",
                Default::default(),
            )
            .unwrap();
        let ReceivedTspMessage::ControlMessage { message, .. } =
            b_store.open_message(&mut sealed).unwrap()
        else {
            panic!("a control payload must not arrive as anything else")
        };
        assert_eq!(message, b"turn left");

        // a padding message carries nothing and says so
        let (_, mut sealed) = a_store
            .seal_padding_message(
                a.identifier(),
                b.identifier(),
                SendOptions {
                    padding: Some(&[0_u8; 64]),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(matches!(
            b_store.open_message(&mut sealed).unwrap(),
            ReceivedTspMessage::PaddingMessage { .. }
        ));

        // padding rides in any payload, lengthening the message without
        // changing what it says
        let plain = a_store
            .seal_message(a.identifier(), b.identifier(), b"hello world")
            .unwrap()
            .1;
        let (_, mut padded) = a_store
            .seal_message_with(
                a.identifier(),
                b.identifier(),
                b"hello world",
                SendOptions {
                    padding: Some(&[0_u8; 128]),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            padded.len() > plain.len() + 100,
            "padding must actually reach the wire: {} vs {}",
            padded.len(),
            plain.len()
        );
        let ReceivedTspMessage::GenericMessage { message, .. } =
            b_store.open_message(&mut padded).unwrap()
        else {
            panic!("a padded message is still a generic message")
        };
        assert_eq!(message, b"hello world");
    }

    /// An addressed application message is dropped outside a relationship
    /// (spec 7.2.2), whether or not it was encrypted. An anycast broadcast
    /// names no receiver, so the rule does not reach it.
    #[test]
    #[wasm_bindgen_test]
    fn signed_only_messages_are_gated_on_a_relationship_but_anycast_is_not() {
        let a_store = create_test_store();
        let b_store = create_test_store();

        let a = create_test_vid();
        let b = create_test_vid();

        a_store.add_private_vid(a.clone(), None).unwrap();
        a_store.add_verified_vid(b.clone(), None).unwrap();
        b_store.add_private_vid(b.clone(), None).unwrap();
        b_store.add_verified_vid(a.clone(), None).unwrap();

        // addressed, signed only, with no relationship: dropped
        let mut addressed = crate::crypto::sign(&a, Some(b.vid()), b"hello world").unwrap();
        assert!(
            matches!(
                b_store.open_message(&mut addressed),
                Err(Error::UnestablishedRelationship(..))
            ),
            "an addressed signed-only message outside a relationship must be dropped"
        );

        // the same message once the relationship exists: accepted
        b_store
            .set_relation_and_status_for_vid(
                a.identifier(),
                RelationshipStatus::Unidirectional {
                    thread_id: Default::default(),
                },
                b.identifier(),
            )
            .unwrap();
        let mut addressed = crate::crypto::sign(&a, Some(b.vid()), b"hello world").unwrap();
        assert!(b_store.open_message(&mut addressed).is_ok());

        // a broadcast names no receiver, so there is no destination VID for the
        // rule to be about
        let c_store = create_test_store();
        c_store.add_verified_vid(a.clone(), None).unwrap();
        let mut broadcast = a_store
            .sign_anycast(a.identifier(), b"hello world")
            .unwrap();
        assert!(
            c_store.open_message(&mut broadcast).is_ok(),
            "an anycast broadcast is not gated on a relationship"
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
            .seal_message(nested_a.identifier(), nested_b.identifier(), hello_world)
            .unwrap();

        let received = b_store.open_message(&mut sealed).unwrap();

        let ReceivedTspMessage::GenericMessage {
            sender,
            receiver,
            message,
            message_type,
        } = received
        else {
            panic!()
        };

        assert_eq!(sender, nested_a.identifier());
        assert_eq!(receiver.unwrap(), nested_b.identifier());
        assert_eq!(message, hello_world);
        assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
        assert_ne!(
            message_type.signature_type,
            crate::cesr::SignatureType::NoSignature
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_set_route_for_vid_rejects_empty_route() {
        let store = create_test_store();
        let bob = create_test_vid();
        store
            .add_verified_vid(bob.vid().clone(), None)
            .expect("should add verified vid");

        let result = store.set_route_for_vid(bob.identifier(), &[] as &[&str]);
        assert!(
            matches!(result, Err(Error::InvalidRoute(_))),
            "empty route must be rejected, got: {result:?}"
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_set_route_for_vid_rejects_single_hop() {
        let store = create_test_store();
        let bob = create_test_vid();
        let intermediary = create_test_vid();
        store
            .add_verified_vid(bob.vid().clone(), None)
            .expect("should add verified vid");

        let result = store.set_route_for_vid(bob.identifier(), &[intermediary.identifier()]);
        assert!(
            matches!(result, Err(Error::InvalidRoute(_))),
            "single-hop route must be rejected, got: {result:?}"
        );
    }
}
