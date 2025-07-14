use crate::{AsyncSecureStore, OwnedVid, RelationshipStatus, VerifiedVid};
use futures::StreamExt;

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_direct_mode() {
    // bob wallet
    let mut bob_db = AsyncSecureStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob/piv.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None)
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob")
        .await
        .unwrap();

    // alice wallet
    let mut alice_db = AsyncSecureStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob", None)
        .await
        .unwrap();

    // send a message
    alice_db
        .send(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
            Some(b"extra non-confidential data"),
            b"hello world",
        )
        .await
        .unwrap();

    // first, receive a Relationship request as this is the first contact
    let crate::definitions::ReceivedTspMessage::RequestRelationship { .. } =
        bobs_messages.next().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a relationship request message")
    };

    // second, receive a generic message
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
    // bob wallet
    let mut bob_db = AsyncSecureStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob/piv.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None)
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob")
        .await
        .unwrap();

    // alice wallet
    let mut alice_db = AsyncSecureStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob", None)
        .await
        .unwrap();

    for i in 1..10 {
        let sent_message = "hello world ".repeat(i * 70);
        // send a message
        alice_db
            .send(
                "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
                "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
                None,
                sent_message.as_bytes(),
            )
            .await
            .unwrap();

        // first, receive a Relationship request as this is the first contact
        if i == 1 {
            let crate::definitions::ReceivedTspMessage::RequestRelationship { .. } =
                bobs_messages.next().await.unwrap().unwrap()
            else {
                panic!("bob did not receive a relationship request message")
            };
        }

        // second, receive a message
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
    // bob wallet
    let mut bob_db = AsyncSecureStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob/piv.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None)
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob")
        .await
        .unwrap();

    // alice wallet
    let mut alice_db = AsyncSecureStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob", None)
        .await
        .unwrap();

    // send a message
    alice_db
        .send_anycast(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            &["did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob"],
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
    // bob wallet
    let mut bob_db = AsyncSecureStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob/piv.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None)
        .await
        .unwrap();

    // alice wallet
    let mut alice_db = AsyncSecureStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob", None)
        .await
        .unwrap();

    // create nested id's
    let nested_bob_vid = OwnedVid::new_did_peer(bob_vid.endpoint().clone());
    bob_db
        .add_private_vid(nested_bob_vid.clone(), None)
        .unwrap();
    bob_db
        .set_parent_for_vid(nested_bob_vid.identifier(), Some(bob_vid.identifier()))
        .unwrap();

    // receive a messages on inner vid
    let mut bobs_inner_messages = bob_db.receive(nested_bob_vid.identifier()).await.unwrap();

    let nested_alice_vid = OwnedVid::new_did_peer(alice_vid.endpoint().clone());
    alice_db
        .add_private_vid(nested_alice_vid.clone(), None)
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_alice_vid.identifier(), Some(alice_vid.identifier()))
        .unwrap();
    alice_db
        .verify_vid(nested_bob_vid.identifier(), None)
        .await
        .unwrap();
    alice_db
        .set_parent_for_vid(nested_bob_vid.identifier(), Some(bob_vid.identifier()))
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            nested_bob_vid.identifier(),
            RelationshipStatus::Unrelated,
            nested_alice_vid.identifier(),
        )
        .unwrap();

    bob_db
        .verify_vid(nested_alice_vid.identifier(), None)
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

    // first, receive a Relationship request as this is the first contact
    let crate::definitions::ReceivedTspMessage::RequestRelationship { .. } =
        bobs_inner_messages.next().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a relationship request message")
    };

    // second, receive a generic message using inner vid
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
    let mut bob_db = AsyncSecureStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob/piv.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    let mut alice_db = AsyncSecureStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    // inform bob about alice
    bob_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None)
        .await
        .unwrap();

    // let bob listen as an intermediary
    let mut bobs_messages = bob_db
        .receive("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob")
        .await
        .unwrap();

    // inform alice about the nodes
    alice_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob", None)
        .await
        .unwrap();
    alice_db
        .set_route_for_vid(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            &[
                "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
                "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
                "did:web:hidden.web:endpoint:realbob",
            ],
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
            RelationshipStatus::Bidirectional { thread_id: Default::default(), outstanding_nested_thread_ids: vec![] },
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            RelationshipStatus::Bidirectional { thread_id: Default::default(), outstanding_nested_thread_ids: vec![] },
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
        )
        .unwrap();

    // let alice send a message via bob to herself
    alice_db
        .send(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            None,
            b"hello self (via bob)",
        )
        .await
        .unwrap();

    // let bob receive the message
    let crate::definitions::ReceivedTspMessage::ForwardRequest {
        opaque_payload,
        sender,
        receiver,
        next_hop,
        route,
    } = bobs_messages.next().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a forward request")
    };

    assert_eq!(
        sender,
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice"
    );
    assert_eq!(
        receiver,
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob"
    );
    assert_eq!(
        next_hop,
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice"
    );
    assert_eq!(
        route
            .iter()
            .map(|b| b.iter().as_slice())
            .collect::<Vec<_>>(),
        vec![b"did:web:hidden.web:endpoint:realbob"]
    );

    // let alice listen
    let mut alice_messages = alice_db
        .receive("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice")
        .await
        .unwrap();

    // bob is going to forward to alice three times; once using an incorrect intermediary, once with a correct, and once without
    bob_db
        .set_relation_and_status_for_vid(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            RelationshipStatus::Unrelated,
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
        )
        .unwrap();

    // test1: alice doens't know "realbob"
    bob_db
        .forward_routed_message(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
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
    assert_eq!(next_hop, "did:web:hidden.web:endpoint:realbob");
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
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            vec![b"did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob"],
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
    assert_eq!(
        sender,
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob"
    );
    assert_eq!(
        next_hop,
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob"
    );
    assert!(route.is_empty());

    // test3: alice is the recipient (using "bob" as the 'final hop')
    bob_db
        .set_relation_and_status_for_vid(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
            RelationshipStatus::Unrelated,
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
        )
        .unwrap();
    bob_db
        .forward_routed_message(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
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

    assert_eq!(
        sender,
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice"
    );
    assert_eq!(message.iter().as_slice(), b"hello self (via bob)");
}

#[tokio::test]
async fn attack_failures() {
    // bob wallet
    let mut bob_db = AsyncSecureStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob/piv.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    bob_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None)
        .await
        .unwrap();

    let alice = crate::vid::OwnedVid::from_file("../examples/test/alice/piv.json")
        .await
        .unwrap();

    let (bob, _metadata) = crate::vid::verify_vid(
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
    )
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
            assert_ne!(
                unknown_vid,
                "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice"
            );

            // confirm that opening the pending message also fails
            // (We cannot test this exhaustively -- but because the cryptographic material for this
            // message does not belong to the corrupted vid, it should reliably always fail)
            assert!(bob_db.verify_and_open(&unknown_vid, payload).await.is_err());
        };
    }
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_relation_forming() {
    // bob wallet
    let mut bob_db = AsyncSecureStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob/piv.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None)
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob")
        .await
        .unwrap();

    // alice wallet
    let mut alice_db = AsyncSecureStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();
    alice_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob", None)
        .await
        .unwrap();

    // send a message
    alice_db
        .send_relationship_request(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
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
        .receive("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice")
        .await
        .unwrap();

    assert_eq!(
        sender,
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice"
    );

    // send the reply
    bob_db
        .send_relationship_accept(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
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

    assert_eq!(
        sender,
        "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob"
    );
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_unverified_receiver_in_direct_mode() {
    // bob wallet (unverified receiver)
    let mut bob_db = AsyncSecureStore::new();
    let bob_vid = OwnedVid::from_file("../examples/test/bob/piv.json")
        .await
        .unwrap();
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None)
        .await
        .unwrap();

    // bob listens
    let _ = bob_db
        .receive("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob")
        .await
        .unwrap();

    // alice wallet
    let alice_db = AsyncSecureStore::new();
    let alice_vid = OwnedVid::from_file("../examples/test/alice/piv.json")
        .await
        .unwrap();
    alice_db.add_private_vid(alice_vid.clone(), None).unwrap();

    // send a message
    let err= alice_db
        .send(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:bob",
            Some(b"extra non-confidential data"),
            b"hello world",
        )
        .await
        .unwrap_err();

    assert!(matches!(err, crate::Error::UnverifiedVid(_)));
}
