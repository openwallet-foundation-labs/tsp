//! Property-based tests for TSP SDK core components.
//!
//! Uses `proptest` to test invariant properties across generated inputs for:
//! - CESR payload serialization/deserialization (Generic, Control, Nested, Routed)
//! - DID Peer generation and deterministic invariants
//! - SecureStore message seal and open roundtrips

#![cfg(not(target_arch = "wasm32"))]

use proptest::prelude::*;
use tsp_sdk::cesr::{Payload, decode_payload, encode_payload};
use tsp_sdk::{OwnedVid, ReceivedTspMessage, RelationshipPolicy, SecureStore, VerifiedVid};

proptest! {
    /// Tests that arbitrary GenericMessage payloads with optional sender identities
    /// and optional padding correctly round-trip through CESR encoding and decoding.
    #[test]
    fn cesr_generic_payload_roundtrip(
        data in prop::collection::vec(any::<u8>(), 0..=4096),
        sender_id in prop::option::of(prop::collection::vec(any::<u8>(), 1..=64)),
        padding in prop::option::of(prop::collection::vec(any::<u8>(), 0..=32)),
    ) {
        let payload = Payload::<_, &[u8]>::GenericMessage(&data);
        let mut encoded = Vec::new();
        encode_payload(
            &payload,
            sender_id.as_deref(),
            padding.as_deref(),
            &mut encoded,
        )
        .expect("encode generic payload");

        let decoded = decode_payload(&mut encoded).expect("decode generic payload");
        prop_assert_eq!(decoded.sender_identity, sender_id.as_deref());

        match decoded.payload {
            Payload::GenericMessage(decoded_data) => {
                prop_assert_eq!(decoded_data, &data[..]);
            }
            other => {
                return Err(TestCaseError::fail(format!("unexpected payload variant: {other:?}")));
            }
        }
    }

    /// Tests that ControlMessage payloads round-trip correctly.
    #[test]
    fn cesr_control_payload_roundtrip(
        data in prop::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let payload = Payload::<_, &[u8]>::ControlMessage(&data);
        let mut encoded = Vec::new();
        encode_payload(&payload, None, None, &mut encoded).expect("encode control payload");

        let decoded = decode_payload(&mut encoded).expect("decode control payload");
        prop_assert_eq!(decoded.sender_identity, None);

        match decoded.payload {
            Payload::ControlMessage(decoded_data) => {
                prop_assert_eq!(decoded_data, &data[..]);
            }
            other => {
                return Err(TestCaseError::fail(format!("unexpected payload variant: {other:?}")));
            }
        }
    }

    /// Tests that 3-byte aligned NestedMessage payloads round-trip correctly.
    #[test]
    fn cesr_nested_payload_roundtrip(
        mut data in prop::collection::vec(any::<u8>(), 0..=4095),
    ) {
        // nested payloads must be 3-byte aligned
        data.resize(data.len().div_ceil(3) * 3, 0);
        let payload = Payload::<_, &[u8]>::NestedMessage(&data);
        let mut encoded = Vec::new();
        encode_payload(&payload, None, None, &mut encoded).expect("encode nested payload");

        let decoded = decode_payload(&mut encoded).expect("decode nested payload");
        match decoded.payload {
            Payload::NestedMessage(decoded_data) => {
                prop_assert_eq!(decoded_data, &data[..]);
            }
            other => {
                return Err(TestCaseError::fail(format!("unexpected payload variant: {other:?}")));
            }
        }
    }

    /// Tests that RoutedMessage payloads with arbitrary hops and aligned inner payloads round-trip.
    #[test]
    fn cesr_routed_payload_roundtrip(
        hops in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=32), 1..=4),
        mut inner_data in prop::collection::vec(any::<u8>(), 1..=300),
    ) {
        // the inner payload must be 3-byte aligned
        inner_data.resize(inner_data.len().div_ceil(3) * 3, 0);
        let hop_slices: Vec<&[u8]> = hops.iter().map(|h| h.as_slice()).collect();
        let payload = Payload::<_, &[u8]>::RoutedMessage(hop_slices.clone(), &inner_data);

        let mut encoded = Vec::new();
        encode_payload(&payload, None, None, &mut encoded).expect("encode routed payload");

        let decoded = decode_payload(&mut encoded).expect("decode routed payload");
        match decoded.payload {
            Payload::RoutedMessage(decoded_hops, decoded_inner) => {
                prop_assert_eq!(decoded_hops, hop_slices);
                prop_assert_eq!(decoded_inner, &inner_data[..]);
            }
            other => {
                return Err(TestCaseError::fail(format!("unexpected payload variant: {other:?}")));
            }
        }
    }

    /// Tests that deterministic seed derivation for `did:peer` VIDs preserves invariants:
    /// - Starts with `did:peer:4zQm`
    /// - Endpoint matches the specified URL
    /// - Calling derivation twice on the same seed produces identical identifiers
    #[test]
    fn did_peer_seed_derivation_invariants(seed: [u8; 32]) {
        let url: url::Url = "tsp://".parse().unwrap();
        let vid1 = OwnedVid::new_did_peer_from_seed(url.clone(), seed);
        let vid2 = OwnedVid::new_did_peer_from_seed(url, seed);

        prop_assert!(
            vid1.identifier().starts_with("did:peer:4zQm"),
            "did:peer identifier must start with did:peer:4zQm"
        );
        prop_assert_eq!(vid1.endpoint().as_str(), "tsp://");
        prop_assert_eq!(
            vid1.identifier(),
            vid2.identifier(),
            "identical seeds must produce identical identifiers"
        );
    }

    /// Tests that messages sealed and opened between two parties in `SecureStore`
    /// successfully round-trip for arbitrary seeds and payload messages.
    #[test]
    fn secure_store_seal_open_roundtrip(
        alice_seed: [u8; 32],
        bob_seed: [u8; 32],
        message in prop::collection::vec(any::<u8>(), 1..=1024),
    ) {
        // Alice wallet
        let alice_store = SecureStore::new();
        let alice_vid = OwnedVid::new_did_peer_from_seed("tsp://alice".parse().unwrap(), alice_seed);
        alice_store.add_private_vid(alice_vid.clone(), None).unwrap();

        // Bob wallet
        let bob_store = SecureStore::new();
        let bob_vid = OwnedVid::new_did_peer_from_seed("tsp://bob".parse().unwrap(), bob_seed);
        bob_store.add_private_vid(bob_vid.clone(), None).unwrap();
        bob_store.set_relationship_policy(RelationshipPolicy::Ungated).unwrap();

        // Alice adds Bob's verified VID
        alice_store.add_verified_vid(bob_vid.vid().clone(), None).unwrap();
        // Bob adds Alice's verified VID
        bob_store.add_verified_vid(alice_vid.vid().clone(), None).unwrap();

        // Alice seals a message for Bob
        let (_, mut sealed) = alice_store
            .seal_message(alice_vid.identifier(), bob_vid.identifier(), &message)
            .expect("seal message");

        // Bob opens the message
        let received = bob_store.open_message(&mut sealed).expect("open message");
        match received {
            ReceivedTspMessage::GenericMessage {
                sender,
                receiver,
                message: received_bytes,
                ..
            } => {
                prop_assert_eq!(sender, alice_vid.identifier());
                prop_assert_eq!(receiver.as_deref(), Some(bob_vid.identifier()));
                prop_assert_eq!(received_bytes, message);
            }
            other => {
                return Err(TestCaseError::fail(format!("unexpected message: {other:?}")));
            }
        }
    }
}
