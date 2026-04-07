use clap::ValueEnum;
use tsp_sdk::{AsyncSecureStore, Error, OwnedVid, RelationshipStatus, VerifiedVid};

const LOCAL_TCP_SERVER_VID: &str = "bob";
const LOCAL_TCP_CLIENT_SENDER: &str = "alice";
const LOCAL_TCP_CLIENT_RECEIVER: &str = "bob";
const HOSTED_HTTP_SERVER_VID: &str = "b";
const HOSTED_HTTP_CLIENT_SENDER: &str = "a";
const HOSTED_HTTP_CLIENT_RECEIVER: &str = "b";
const BUILTIN_ALICE_PIV: &str = include_str!("../test/alice/piv.json");
const BUILTIN_BOB_PIV: &str = include_str!("../test/bob/piv.json");
const BUILTIN_A_PIV: &str = include_str!("../test/a/piv.json");
const BUILTIN_B_PIV: &str = include_str!("../test/b/piv.json");
const LOCAL_QUIC_SERVER_VID: &str = "quic-bob";
const LOCAL_QUIC_CLIENT_SENDER: &str = "quic-alice";
const LOCAL_QUIC_CLIENT_RECEIVER: &str = "quic-bob";
const BUILTIN_QUIC_ALICE_PIV: &str = include_str!("../test/quic-alice/piv.json");
const BUILTIN_QUIC_BOB_PIV: &str = include_str!("../test/quic-bob/piv.json");
const LOCAL_TLS_SERVER_VID: &str = "tls-bob";
const LOCAL_TLS_CLIENT_SENDER: &str = "tls-alice";
const LOCAL_TLS_CLIENT_RECEIVER: &str = "tls-bob";
const BUILTIN_TLS_ALICE_PIV: &str = include_str!("../test/tls-alice/piv.json");
const BUILTIN_TLS_BOB_PIV: &str = include_str!("../test/tls-bob/piv.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum BenchProfile {
    LocalTcp,
    HostedHttp,
    LocalQuic,
    LocalTls,
}

impl BenchProfile {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::LocalTcp => "local-tcp",
            Self::HostedHttp => "hosted-http",
            Self::LocalQuic => "local-quic",
            Self::LocalTls => "local-tls",
        }
    }

    pub(crate) fn default_server_vid(self) -> &'static str {
        match self {
            Self::LocalTcp => LOCAL_TCP_SERVER_VID,
            Self::HostedHttp => HOSTED_HTTP_SERVER_VID,
            Self::LocalQuic => LOCAL_QUIC_SERVER_VID,
            Self::LocalTls => LOCAL_TLS_SERVER_VID,
        }
    }

    pub(crate) fn default_client_sender(self) -> &'static str {
        match self {
            Self::LocalTcp => LOCAL_TCP_CLIENT_SENDER,
            Self::HostedHttp => HOSTED_HTTP_CLIENT_SENDER,
            Self::LocalQuic => LOCAL_QUIC_CLIENT_SENDER,
            Self::LocalTls => LOCAL_TLS_CLIENT_SENDER,
        }
    }

    pub(crate) fn default_client_receiver(self) -> &'static str {
        match self {
            Self::LocalTcp => LOCAL_TCP_CLIENT_RECEIVER,
            Self::HostedHttp => HOSTED_HTTP_CLIENT_RECEIVER,
            Self::LocalQuic => LOCAL_QUIC_CLIENT_RECEIVER,
            Self::LocalTls => LOCAL_TLS_CLIENT_RECEIVER,
        }
    }

    pub(crate) fn default_sender_piv(self) -> &'static str {
        match self {
            Self::LocalTcp => BUILTIN_ALICE_PIV,
            Self::HostedHttp => BUILTIN_A_PIV,
            Self::LocalQuic => BUILTIN_QUIC_ALICE_PIV,
            Self::LocalTls => BUILTIN_TLS_ALICE_PIV,
        }
    }

    pub(crate) fn default_receiver_piv(self) -> &'static str {
        match self {
            Self::LocalTcp => BUILTIN_BOB_PIV,
            Self::HostedHttp => BUILTIN_B_PIV,
            Self::LocalQuic => BUILTIN_QUIC_BOB_PIV,
            Self::LocalTls => BUILTIN_TLS_BOB_PIV,
        }
    }
}

impl std::fmt::Display for BenchProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum BuiltinAliasKind {
    Private,
    Verified,
}

fn parse_builtin_owned_vid(alias: &str, piv_json: &str) -> Result<OwnedVid, Error> {
    serde_json::from_str(piv_json).map_err(|e| {
        Error::Relationship(format!("failed to load built-in identity '{alias}': {e}"))
    })
}

pub(crate) fn ensure_builtin_alias(
    store: &AsyncSecureStore,
    alias: &str,
    piv_json: &str,
    kind: BuiltinAliasKind,
) -> Result<String, Error> {
    let owned = parse_builtin_owned_vid(alias, piv_json)?;
    let vid = owned.identifier().to_string();

    if let Some(existing_vid) = store.resolve_alias(alias)? {
        if existing_vid != vid {
            return Err(Error::Relationship(format!(
                "alias '{alias}' already points to '{existing_vid}', expected built-in VID '{vid}'"
            )));
        }

        match kind {
            BuiltinAliasKind::Private => {
                if !store.has_private_vid(&vid)? {
                    store.add_private_vid(owned, None)?;
                }
            }
            BuiltinAliasKind::Verified => {
                if !store.has_verified_vid(&vid)? {
                    store.add_verified_vid(owned.vid().clone(), None)?;
                }
            }
        }

        return Ok(vid);
    }

    match kind {
        BuiltinAliasKind::Private => {
            if !store.has_private_vid(&vid)? {
                store.add_private_vid(owned, None)?;
            }
        }
        BuiltinAliasKind::Verified => {
            if !store.has_verified_vid(&vid)? {
                store.add_verified_vid(owned.vid().clone(), None)?;
            }
        }
    }

    store.set_alias(alias.to_string(), vid.clone())?;
    Ok(vid)
}

pub(crate) fn ensure_bidirectional_relation(
    store: &AsyncSecureStore,
    local_vid: &str,
    remote_vid: &str,
) -> Result<(), Error> {
    match store.get_relation_status_for_vid_pair(local_vid, remote_vid) {
        Ok(RelationshipStatus::Unrelated) | Err(Error::Relationship(_)) => {
            store.set_relation_and_status_for_vid(
                remote_vid,
                RelationshipStatus::Bidirectional {
                    thread_id: [0; 32],
                    remote_thread_id: [0; 32],
                    outstanding_nested_requests: vec![],
                },
                local_vid,
            )?;
        }
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    Ok(())
}

pub(crate) fn maybe_bootstrap_server_profile_defaults(
    store: &AsyncSecureStore,
    profile: BenchProfile,
    vid_alias_or_id: &str,
) -> Result<(), Error> {
    if vid_alias_or_id != profile.default_server_vid() {
        return Ok(());
    }

    let local = ensure_builtin_alias(
        store,
        profile.default_server_vid(),
        profile.default_receiver_piv(),
        BuiltinAliasKind::Private,
    )?;
    let peer = ensure_builtin_alias(
        store,
        profile.default_client_sender(),
        profile.default_sender_piv(),
        BuiltinAliasKind::Verified,
    )?;
    ensure_bidirectional_relation(store, &local, &peer)
}

pub(crate) fn maybe_bootstrap_client_profile_identities(
    store: &AsyncSecureStore,
    profile: BenchProfile,
    sender_alias_or_vid: &str,
    sender_kind: BuiltinAliasKind,
    receiver_alias_or_vid: &str,
    receiver_kind: BuiltinAliasKind,
) -> Result<(Option<String>, Option<String>), Error> {
    let mut sender_vid = None;
    let mut receiver_vid = None;

    if sender_alias_or_vid == profile.default_client_sender() {
        sender_vid = Some(ensure_builtin_alias(
            store,
            profile.default_client_sender(),
            profile.default_sender_piv(),
            sender_kind,
        )?);
    }

    if receiver_alias_or_vid == profile.default_client_receiver() {
        receiver_vid = Some(ensure_builtin_alias(
            store,
            profile.default_client_receiver(),
            profile.default_receiver_piv(),
            receiver_kind,
        )?);
    }

    Ok((sender_vid, receiver_vid))
}

pub(crate) fn maybe_bootstrap_client_profile_defaults(
    store: &AsyncSecureStore,
    profile: BenchProfile,
    sender_alias_or_vid: &str,
    receiver_alias_or_vid: &str,
) -> Result<(), Error> {
    let (sender_vid, receiver_vid) = maybe_bootstrap_client_profile_identities(
        store,
        profile,
        sender_alias_or_vid,
        BuiltinAliasKind::Private,
        receiver_alias_or_vid,
        BuiltinAliasKind::Verified,
    )?;

    if let (Some(sender), Some(receiver)) = (sender_vid.as_deref(), receiver_vid.as_deref()) {
        ensure_bidirectional_relation(store, sender, receiver)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_client_bootstrap_loads_both_private_vids_without_relation() {
        let store = AsyncSecureStore::new();

        let (sender, receiver) = maybe_bootstrap_client_profile_identities(
            &store,
            BenchProfile::LocalTcp,
            "alice",
            BuiltinAliasKind::Private,
            "bob",
            BuiltinAliasKind::Private,
        )
        .unwrap();

        let sender = sender.expect("missing sender");
        let receiver = receiver.expect("missing receiver");

        assert!(store.has_private_vid(&sender).unwrap());
        assert!(store.has_private_vid(&receiver).unwrap());
        assert!(matches!(
            store.get_relation_status_for_vid_pair(&sender, &receiver),
            Err(Error::Relationship(_)) | Ok(RelationshipStatus::Unrelated)
        ));
    }
}
