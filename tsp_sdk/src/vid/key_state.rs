//! Telling a key-state change from a substitution.
//!
//! Spec 3.7 requires an endpoint not to act on a message when it cannot
//! confirm the sending VID's key state, or when the state it obtains
//! "conflicts with the key state it holds rather than extending it". Whether
//! that distinction can be drawn at all depends on what the VID's resolution
//! returns, which is what [`KeyStateProvenance`] classifies.

use crate::definitions::VerifiedVid;

/// What an endpoint can learn about a VID's key state when it resolves it.
///
/// Spec 7.4.2 notes that whether an endpoint resolves key state for itself is
/// a property of the deployment rather than of the VID type. This is the other
/// half of the question, and is a property of the type: given that we did
/// resolve, can the result be checked against what we already held?
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyStateProvenance {
    /// The identifier is derived from the key state, so the key state cannot
    /// change: a different document is a different VID. `did:peer`.
    SelfCertifying,
    /// Resolution returns a verifiable history, so an obtained state can be
    /// checked to continue the held one. `did:webvh`, `did:scid`.
    Provenanced,
    /// Resolution returns current key state and no history, so a rotation and
    /// a substitution look the same. `did:web`.
    ///
    /// A VID of this kind cannot satisfy the requirement in spec 2 that a VID's
    /// key state be verifiable, which is why `did:web` is not among the types
    /// the specification lists as suitable (spec 2.2). It is retained for
    /// testing and demonstration.
    Unprovenanced,
}

/// Classify a VID by what its resolution can tell us; see [`KeyStateProvenance`].
pub fn key_state_provenance(vid: &str) -> KeyStateProvenance {
    if vid.starts_with("did:peer:") {
        KeyStateProvenance::SelfCertifying
    } else if vid.starts_with("did:webvh:") || vid.starts_with("did:scid:") {
        KeyStateProvenance::Provenanced
    } else {
        KeyStateProvenance::Unprovenanced
    }
}

/// The leading integer of a `did:webvh` version id, which is of the form
/// `<version number>-<entry hash>`.
fn version_number(metadata: Option<&serde_json::Value>) -> Option<u64> {
    metadata?["webvh_meta_data"]["versionId"]
        .as_str()?
        .split('-')
        .next()?
        .parse()
        .ok()
}

fn scid(metadata: Option<&serde_json::Value>) -> Option<&str> {
    metadata?["webvh_meta_data"]["scid"].as_str()
}

/// Whether newly resolved key state continues the state already held, rather
/// than replacing it (spec 3.7).
///
/// A `false` here is not "the peer rotated"; it is "this endpoint cannot tell
/// a rotation from a substitution", which spec 11.2 calls evidence of
/// compromise rather than an error to be resolved by choosing one.
pub fn extends_held_key_state(
    held: &dyn VerifiedVid,
    held_metadata: Option<&serde_json::Value>,
    obtained: &dyn VerifiedVid,
    obtained_metadata: Option<&serde_json::Value>,
) -> bool {
    match key_state_provenance(held.identifier()) {
        // the keys are what the identifier is derived from, so resolving the
        // same identifier cannot yield different keys
        KeyStateProvenance::SelfCertifying => true,

        // the history has to be the same history, and cannot go backwards
        KeyStateProvenance::Provenanced => {
            match (
                scid(held_metadata),
                scid(obtained_metadata),
                version_number(held_metadata),
                version_number(obtained_metadata),
            ) {
                (
                    Some(held_scid),
                    Some(obtained_scid),
                    Some(held_version),
                    Some(obtained_version),
                ) => held_scid == obtained_scid && obtained_version >= held_version,
                // without both histories there is nothing to compare, and an
                // unverifiable claim about key state is not a confirmation
                _ => false,
            }
        }

        // nothing distinguishes a rotation from a substitution, so only an
        // unchanged key state is a confirmation
        KeyStateProvenance::Unprovenanced => {
            held.verifying_key().as_ref() == obtained.verifying_key().as_ref()
                && held.encryption_key().as_ref() == obtained.encryption_key().as_ref()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    fn webvh_metadata(scid: &str, version: u64) -> serde_json::Value {
        json!({"webvh_meta_data": {"scid": scid, "versionId": format!("{version}-QmHash")}})
    }

    #[test]
    fn classifies_by_what_resolution_returns() {
        assert_eq!(
            key_state_provenance("did:peer:4zQmHash"),
            KeyStateProvenance::SelfCertifying
        );
        assert_eq!(
            key_state_provenance("did:webvh:QmScid:example.com"),
            KeyStateProvenance::Provenanced
        );
        assert_eq!(
            key_state_provenance("did:web:example.com:user"),
            KeyStateProvenance::Unprovenanced
        );
    }

    fn vid(id: &str, key: u8) -> crate::vid::Vid {
        crate::vid::Vid {
            id: id.to_string(),
            transport: url::Url::parse("tcp://127.0.0.1:1337").unwrap(),
            sig_key_type: crate::definitions::VidSignatureKeyType::Ed25519,
            public_sigkey: vec![key; 32].into(),
            enc_key_type: crate::definitions::VidEncryptionKeyType::X25519,
            public_enckey: vec![key; 32].into(),
        }
    }

    #[test]
    fn a_self_certifying_vid_cannot_change_its_key_state() {
        // the identifier is derived from the document, so resolving the same
        // identifier cannot produce different keys; nothing needs comparing
        let held = vid("did:peer:4zQmHash", 1);
        let obtained = vid("did:peer:4zQmHash", 1);

        assert!(extends_held_key_state(&held, None, &obtained, None));
    }

    #[test]
    fn a_history_must_continue_and_must_not_go_backwards() {
        let held = vid("did:webvh:QmScid:example.com", 1);
        let obtained = vid("did:webvh:QmScid:example.com", 2);
        let at = |scid, version| Some(webvh_metadata(scid, version));

        // the same history moving forward is a rotation
        assert!(extends_held_key_state(
            &held,
            at("QmScid", 3).as_ref(),
            &obtained,
            at("QmScid", 4).as_ref()
        ));
        // the same version is the state we already hold
        assert!(extends_held_key_state(
            &held,
            at("QmScid", 3).as_ref(),
            &obtained,
            at("QmScid", 3).as_ref()
        ));

        // a history that goes backwards is not an extension of this one
        assert!(!extends_held_key_state(
            &held,
            at("QmScid", 4).as_ref(),
            &obtained,
            at("QmScid", 3).as_ref()
        ));
        // nor is a different history, however current it claims to be
        assert!(!extends_held_key_state(
            &held,
            at("QmScid", 3).as_ref(),
            &obtained,
            at("QmOther", 9).as_ref()
        ));
        // and an absent history confirms nothing
        assert!(!extends_held_key_state(
            &held,
            at("QmScid", 3).as_ref(),
            &obtained,
            None
        ));
    }

    #[test]
    fn without_a_history_only_an_unchanged_key_state_is_confirmation() {
        // did:web resolution returns the current document and nothing else, so
        // a rotation and a substitution are the same observation
        let held = vid("did:web:example.com:user", 1);

        assert!(extends_held_key_state(
            &held,
            None,
            &vid("did:web:example.com:user", 1),
            None
        ));
        assert!(!extends_held_key_state(
            &held,
            None,
            &vid("did:web:example.com:user", 2),
            None
        ));
    }
}
