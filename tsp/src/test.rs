use crate::{AsyncStore, OwnedVid, VerifiedVid};
use futures::StreamExt;

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_direct_mode() {
    // bob database
    let mut bob_db = AsyncStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone()).unwrap();
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // alice database
    let mut alice_db = AsyncStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone()).unwrap();
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // send a message
    alice_db
        .send(
            "did:web:did.tsp-test.org:user:alice",
            "did:web:did.tsp-test.org:user:bob",
            Some(b"extra non-confidential data"),
            b"hello world",
        )
        .await
        .unwrap();

    // receive a message
    let crate::definitions::ReceivedTspMessage::GenericMessage {
        message,
        message_type,
        ..
    } = bobs_messages.next().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a generic message")
    };

    assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
    assert_ne!(
        message_type.signature_type,
        crate::cesr::SignatureType::NoSignature
    );

    assert_eq!(message.iter().as_slice(), b"hello world");
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_large_messages() {
    // bob database
    let mut bob_db = AsyncStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone()).unwrap();
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // alice database
    let mut alice_db = AsyncStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone()).unwrap();
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    for i in 1..10 {
        let sent_message = "hello world ".repeat(i * 70);
        // send a message
        alice_db
            .send(
                "did:web:did.tsp-test.org:user:alice",
                "did:web:did.tsp-test.org:user:bob",
                None,
                sent_message.as_bytes(),
            )
            .await
            .unwrap();

        // receive a message
        let crate::definitions::ReceivedTspMessage::GenericMessage {
            message,
            message_type,
            ..
        } = bobs_messages.next().await.unwrap().unwrap()
        else {
            panic!("bob did not receive a generic message")
        };

        assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
        assert_ne!(
            message_type.signature_type,
            crate::cesr::SignatureType::NoSignature
        );

        assert_eq!(sent_message.as_bytes(), message);
    }
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_anycast() {
    // bob database
    let mut bob_db = AsyncStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone()).unwrap();
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // alice database
    let mut alice_db = AsyncStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone()).unwrap();
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // send a message
    alice_db
        .send_anycast(
            "did:web:did.tsp-test.org:user:alice",
            &["did:web:did.tsp-test.org:user:bob"],
            b"hello world",
        )
        .await
        .unwrap();

    // receive a message
    let crate::definitions::ReceivedTspMessage::GenericMessage {
        message,
        message_type,
        ..
    } = bobs_messages.next().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a broadcast message")
    };

    assert_eq!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
    assert_ne!(
        message_type.signature_type,
        crate::cesr::SignatureType::NoSignature
    );

    assert_eq!(message.iter().as_slice(), b"hello world");
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_nested_mode() {
    // bob database
    let mut bob_db = AsyncStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone()).unwrap();
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    // alice database
    let mut alice_db = AsyncStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone()).unwrap();
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // create nested id's
    let nested_bob_vid = OwnedVid::new_did_peer(bob_vid.endpoint().clone());
    bob_db.add_private_vid(nested_bob_vid.clone()).unwrap();
    bob_db
        .set_parent_for_vid(nested_bob_vid.identifier(), Some(bob_vid.identifier()))
        .unwrap();

    // receive a messages on inner vid
    let mut bobs_inner_messages = bob_db.receive(nested_bob_vid.identifier()).await.unwrap();

    let nested_alice_vid = OwnedVid::new_did_peer(alice_vid.endpoint().clone());
    alice_db.add_private_vid(nested_alice_vid.clone()).unwrap();
    alice_db
        .set_parent_for_vid(nested_alice_vid.identifier(), Some(alice_vid.identifier()))
        .unwrap();
    alice_db
        .verify_vid(nested_bob_vid.identifier())
        .await
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_bob_vid.identifier(), Some(bob_vid.identifier()))
        .unwrap();
    alice_db
        .set_relation_for_vid(
            nested_bob_vid.identifier(),
            Some(nested_alice_vid.identifier()),
        )
        .unwrap();

    bob_db
        .verify_vid(nested_alice_vid.identifier())
        .await
        .unwrap();
    bob_db
        .set_parent_for_vid(nested_alice_vid.identifier(), Some(alice_vid.identifier()))
        .unwrap();

    // send a message using inner vid
    alice_db
        .send(
            nested_alice_vid.identifier(),
            nested_bob_vid.identifier(),
            Some(b"extra non-confidential data"),
            b"hello nested world",
        )
        .await
        .unwrap();

    // receive message using inner vid
    let crate::definitions::ReceivedTspMessage::GenericMessage {
        message,
        message_type,
        ..
    } = bobs_inner_messages.next().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a generic message inner")
    };

    assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
    assert_ne!(
        message_type.signature_type,
        crate::cesr::SignatureType::NoSignature
    );

    assert_eq!(message.iter().as_slice(), b"hello nested world");
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_routed_mode() {
    let mut bob_db = AsyncStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone()).unwrap();

    let mut alice_db = AsyncStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone()).unwrap();

    // inform bob about alice
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    // let bob listen as an intermediary
    let mut bobs_messages = bob_db
        .receive("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // inform alice about the nodes
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();
    alice_db
        .set_route_for_vid(
            "did:web:did.tsp-test.org:user:alice",
            &[
                "did:web:did.tsp-test.org:user:bob",
                "did:web:did.tsp-test.org:user:alice",
                "did:web:hidden.web:user:realbob",
            ],
        )
        .unwrap();
    alice_db
        .set_relation_for_vid(
            "did:web:did.tsp-test.org:user:bob",
            Some("did:web:did.tsp-test.org:user:alice"),
        )
        .unwrap();
    alice_db
        .set_relation_for_vid(
            "did:web:did.tsp-test.org:user:alice",
            Some("did:web:did.tsp-test.org:user:alice"),
        )
        .unwrap();

    // let alice send a message via bob to herself
    alice_db
        .send(
            "did:web:did.tsp-test.org:user:alice",
            "did:web:did.tsp-test.org:user:alice",
            None,
            b"hello self (via bob)",
        )
        .await
        .unwrap();

    // let bob receive the message
    let crate::definitions::ReceivedTspMessage::ForwardRequest {
        opaque_payload,
        sender,
        next_hop,
        route,
    } = bobs_messages.next().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a forward request")
    };

    assert_eq!(sender, "did:web:did.tsp-test.org:user:alice");
    assert_eq!(next_hop, "did:web:did.tsp-test.org:user:alice");
    assert_eq!(
        route
            .iter()
            .map(|b| b.iter().as_slice())
            .collect::<Vec<_>>(),
        vec![b"did:web:hidden.web:user:realbob"]
    );

    // let alice listen
    let mut alice_messages = alice_db
        .receive("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    // bob is going to forward to alice three times; once using an incorrect intermediary, once with a correct, and once without
    bob_db
        .set_relation_for_vid(
            "did:web:did.tsp-test.org:user:alice",
            Some("did:web:did.tsp-test.org:user:bob"),
        )
        .unwrap();

    // test1: alice doens't know "realbob"
    bob_db
        .forward_routed_message(
            "did:web:did.tsp-test.org:user:alice",
            route,
            &opaque_payload,
        )
        .await
        .unwrap();

    let crate::ReceivedTspMessage::ForwardRequest {
        next_hop,
        route,
        opaque_payload,
        ..
    } = alice_messages.next().await.unwrap().unwrap()
    else {
        panic!("alice accepted a message which she cannot handle");
    };
    assert_eq!(next_hop, "did:web:hidden.web:user:realbob");
    let crate::Error::UnverifiedVid { .. } = alice_db
        .forward_routed_message(&next_hop, route, &opaque_payload)
        .await
        .unwrap_err()
    else {
        panic!("unexpected error");
    };
    let crate::Error::UnverifiedVid { .. } = alice_db
        .forward_routed_message(&next_hop, Vec::<&[u8]>::new(), &opaque_payload)
        .await
        .unwrap_err()
    else {
        panic!("unexpected error");
    };

    // test2: just use "bob"
    bob_db
        .forward_routed_message(
            "did:web:did.tsp-test.org:user:alice",
            vec![b"did:web:did.tsp-test.org:user:bob"],
            &opaque_payload,
        )
        .await
        .unwrap();
    let crate::definitions::ReceivedTspMessage::ForwardRequest {
        sender,
        next_hop,
        route,
        ..
    } = alice_messages.next().await.unwrap().unwrap()
    else {
        panic!("alice did not receive message");
    };
    assert_eq!(sender, "did:web:did.tsp-test.org:user:bob");
    assert_eq!(next_hop, "did:web:did.tsp-test.org:user:bob");
    assert!(route.is_empty());

    // test3: alice is the recipient (using "bob" as the 'final hop')
    bob_db
        .set_relation_for_vid(
            "did:web:did.tsp-test.org:user:bob",
            Some("did:web:did.tsp-test.org:user:alice"),
        )
        .unwrap();
    bob_db
        .forward_routed_message(
            "did:web:did.tsp-test.org:user:bob",
            Vec::<&[u8]>::new(),
            &opaque_payload,
        )
        .await
        .unwrap();
    let crate::definitions::ReceivedTspMessage::GenericMessage {
        sender,
        message,
        message_type,
        ..
    } = alice_messages.next().await.unwrap().unwrap()
    else {
        panic!("alice did not receive message");
    };

    assert_ne!(message_type.crypto_type, crate::cesr::CryptoType::Plaintext);
    assert_ne!(
        message_type.signature_type,
        crate::cesr::SignatureType::NoSignature
    );

    assert_eq!(sender, "did:web:did.tsp-test.org:user:alice");
    assert_eq!(message.iter().as_slice(), b"hello self (via bob)");
}

#[tokio::test]
async fn attack_failures() {
    // bob database
    let mut bob_db = AsyncStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone()).unwrap();

    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    let alice = crate::vid::OwnedVid::from_file("../examples/test/alice.json")
        .await
        .unwrap();

    let bob = crate::vid::verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    let payload = b"hello world";

    for i in 0.. {
        let mut faulty_message =
            crate::crypto::seal(&alice, &bob, None, super::Payload::Content(payload)).unwrap();

        if i >= faulty_message.len() {
            break;
        } else {
            faulty_message[i] ^= 0x10;
        }

        // corrupting a message might only corrupt the envelope, which is something we cannot
        // detect immediately without looking up cryptographic material
        if let Ok(msg) = bob_db.open_message(&mut faulty_message) {
            let crate::ReceivedTspMessage::PendingMessage {
                unknown_vid,
                payload,
            } = msg
            else {
                panic!("a corrupted message was decoded correctly! corrupt byte: {i}",);
            };

            // confirm that the sender vid has been corrupted
            assert_ne!(unknown_vid, "did:web:did.tsp-test.org:user:alice");

            // confirm that opening the pending message also fails
            // (We cannot test this exhaustively -- but because the cryptographic material for this
            // message does not belong to the corrupted vid, it should reliably always fail)
            assert!(bob_db
                .verify_and_open(&unknown_vid, payload.into())
                .await
                .is_err());
        };
    }
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_relation_forming() {
    // bob database
    let mut bob_db = AsyncStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone()).unwrap();
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // alice database
    let mut alice_db = AsyncStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone()).unwrap();
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // send a message
    alice_db
        .send_relationship_request(
            "did:web:did.tsp-test.org:user:alice",
            "did:web:did.tsp-test.org:user:bob",
            None,
        )
        .await
        .unwrap();

    // receive a message
    let crate::definitions::ReceivedTspMessage::RequestRelationship {
        sender, thread_id, ..
    } = bobs_messages.next().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a relation request")
    };

    // let alice listen
    let mut alice_messages = alice_db
        .receive("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    assert_eq!(sender, "did:web:did.tsp-test.org:user:alice");

    // send the reply
    bob_db
        .send_relationship_accept(
            "did:web:did.tsp-test.org:user:bob",
            "did:web:did.tsp-test.org:user:alice",
            thread_id,
            None,
        )
        .await
        .unwrap();

    let crate::definitions::ReceivedTspMessage::AcceptRelationship { sender, .. } =
        alice_messages.next().await.unwrap().unwrap()
    else {
        panic!("alice did not receive a relation accept")
    };

    assert_eq!(sender, "did:web:did.tsp-test.org:user:bob");
}
