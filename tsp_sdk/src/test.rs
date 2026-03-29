use crate::{
    AskarSecureStorage, AsyncSecureStore, OwnedVid, ReceivedRelationshipDelivery,
    ReceivedRelationshipForm, RelationshipStatus, SecureStorage, VerifiedVid, test_utils::*,
};
use futures::StreamExt;
use std::collections::BTreeMap;

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_direct_mode() {
    // bob wallet
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
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
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
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
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
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
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
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
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
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
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
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
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();
    bob_db
        .verify_vid("did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice", None)
        .await
        .unwrap();

    // alice wallet
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
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
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
    bob_db.add_private_vid(bob_vid.clone(), None).unwrap();

    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
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
            RelationshipStatus::Bidirectional {
                thread_id: Default::default(),
                remote_thread_id: Default::default(),
                outstanding_nested_requests: vec![],
            },
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
        )
        .unwrap();
    alice_db
        .set_relation_and_status_for_vid(
            "did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:alice",
            RelationshipStatus::Bidirectional {
                thread_id: Default::default(),
                remote_thread_id: Default::default(),
                outstanding_nested_requests: vec![],
            },
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
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
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
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
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
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
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
    let bob_db = create_async_test_store();
    let bob_vid = create_vid_from_file("../examples/test/bob/piv.json").await;
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
    let alice_db = create_async_test_store();
    let alice_vid = create_vid_from_file("../examples/test/alice/piv.json").await;
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

#[tokio::test]
async fn test_prepopulated_store_import_preserves_dirty_state() {
    let dirty_store = create_prepopulated_store();
    let (vids, aliases, keys) = dirty_store.export().unwrap();
    let local_vid = aliases.get("local-owner").cloned().unwrap();

    let imported_store = create_async_test_store();
    imported_store.import(vids, aliases, keys).unwrap();

    assert_eq!(
        imported_store
            .resolve_alias("local-owner")
            .unwrap()
            .as_deref(),
        Some(local_vid.as_str())
    );
    assert_eq!(
        imported_store.get_secret_key("test-history-key-1").unwrap(),
        Some(vec![1, 2, 3, 4])
    );

    let mut found_unidirectional = 0_usize;
    let mut found_reverse_unidirectional = 0_usize;
    let mut found_bidirectional = 0_usize;

    for remote_vid in imported_store.list_vids().unwrap() {
        if remote_vid == local_vid {
            continue;
        }

        match imported_store
            .get_relation_status_for_vid_pair(&local_vid, &remote_vid)
            .unwrap()
        {
            RelationshipStatus::Unidirectional { .. } => found_unidirectional += 1,
            RelationshipStatus::ReverseUnidirectional { .. } => {
                found_reverse_unidirectional += 1;
            }
            RelationshipStatus::Bidirectional { .. } => found_bidirectional += 1,
            RelationshipStatus::_Controlled | RelationshipStatus::Unrelated => {}
        }
    }

    assert!(found_unidirectional > 0);
    assert!(found_reverse_unidirectional > 0);
    assert!(found_bidirectional > 0);
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_persisted_store_roundtrip_reopens_dirty_wallet() {
    let in_memory_store = create_async_test_store();
    let dirty_store = create_prepopulated_store();
    let (vids, aliases, keys) = dirty_store.export().unwrap();
    in_memory_store.import(vids, aliases, keys).unwrap();

    let fixture = create_persisted_store().await;
    fixture.persist_from(&in_memory_store).await;
    let reopened_store = fixture.reopen_into_store().await;

    let (before_vids, before_aliases, _before_keys) = in_memory_store.export().unwrap();
    let (after_vids, after_aliases, _after_keys) = reopened_store.export().unwrap();

    assert_eq!(before_vids.len(), after_vids.len());
    assert_eq!(
        before_aliases.get("local-owner"),
        after_aliases.get("local-owner")
    );
    assert_eq!(
        reopened_store.get_secret_key("test-history-key-2").unwrap(),
        Some(vec![5, 6, 7, 8])
    );

    let local_vid = reopened_store
        .resolve_alias("local-owner")
        .unwrap()
        .unwrap();

    let receiver_vid = after_vids
        .iter()
        .find(|exported| {
            if exported.id == local_vid {
                return false;
            }
            if exported.relation_vid.as_deref() != Some(local_vid.as_str()) {
                return false;
            }

            matches!(
                reopened_store
                    .get_relation_status_for_vid_pair(&local_vid, &exported.id)
                    .unwrap(),
                RelationshipStatus::Bidirectional { .. }
                    | RelationshipStatus::Unidirectional { .. }
                    | RelationshipStatus::ReverseUnidirectional { .. }
            )
        })
        .map(|exported| exported.id.clone())
        .unwrap();

    let (_endpoint, sealed_message) = reopened_store
        .seal_message(&local_vid, &receiver_vid, None, b"persisted-wallet-message")
        .unwrap();
    assert!(!sealed_message.is_empty());
}

fn relationship_status_signature(status: RelationshipStatus) -> String {
    match status {
        RelationshipStatus::_Controlled => "Controlled".to_string(),
        RelationshipStatus::Unrelated => "Unrelated".to_string(),
        RelationshipStatus::Unidirectional { thread_id } => format!("Uni:{thread_id:?}"),
        RelationshipStatus::ReverseUnidirectional { thread_id } => format!("RevUni:{thread_id:?}"),
        RelationshipStatus::Bidirectional {
            thread_id,
            remote_thread_id,
            outstanding_nested_requests,
        } => format!("Bi:{thread_id:?}:{remote_thread_id:?}:{outstanding_nested_requests:?}"),
    }
}

fn export_snapshot(
    store: &AsyncSecureStore,
) -> (
    BTreeMap<String, String>,
    Vec<String>,
    BTreeMap<String, String>,
) {
    let (vids, aliases, keys) = store.export().unwrap();
    let mut vid_rows = vids
        .into_iter()
        .map(|exported| {
            format!(
                "{}|{}|{}|{}|{}",
                exported.id,
                exported.is_private(),
                exported.relation_vid.unwrap_or_default(),
                exported.parent_vid.unwrap_or_default(),
                relationship_status_signature(exported.relation_status)
            )
        })
        .collect::<Vec<_>>();
    vid_rows.sort();

    let key_rows = keys
        .into_iter()
        .map(|(k, v)| (k, format!("{v:?}")))
        .collect::<BTreeMap<_, _>>();

    (
        aliases.into_iter().collect::<BTreeMap<_, _>>(),
        vid_rows,
        key_rows,
    )
}

fn setup_transition_pair() -> (AsyncSecureStore, String, AsyncSecureStore, String) {
    let a_store = create_async_test_store();
    let b_store = create_async_test_store();

    let a = create_test_vid();
    let b = create_test_vid();

    a_store.add_private_vid(a.clone(), None).unwrap();
    a_store.add_verified_vid(b.clone(), None).unwrap();

    b_store.add_private_vid(b.clone(), None).unwrap();
    b_store.add_verified_vid(a.clone(), None).unwrap();

    (
        a_store,
        a.identifier().to_string(),
        b_store,
        b.identifier().to_string(),
    )
}

async fn assert_storage_open_or_read_fails(url: &str, password: &[u8]) {
    let open_result = <AskarSecureStorage as SecureStorage>::open(url, password).await;
    match open_result {
        Err(_) => {}
        Ok(storage) => {
            let read_result = storage.read().await;
            assert!(
                read_result.is_err(),
                "storage opened and read unexpectedly succeeded"
            );
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_dirty_roundtrip_multi_reopen_idempotent() {
    let dirty_store = create_prepopulated_store();
    let (vids, aliases, keys) = dirty_store.export().unwrap();
    let initial_store = create_async_test_store();
    initial_store.import(vids, aliases, keys).unwrap();

    let fixture = create_persisted_store().await;
    let baseline = export_snapshot(&initial_store);
    let reopened = persist_reopen_cycle(&initial_store, &fixture, 3).await;

    assert_eq!(baseline, export_snapshot(&reopened));
    assert_eq!(
        reopened.get_secret_key("test-history-key-1").unwrap(),
        Some(vec![1, 2, 3, 4])
    );
    assert_eq!(
        reopened.get_secret_key("test-history-key-2").unwrap(),
        Some(vec![5, 6, 7, 8])
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_relationship_transition_request_accept_after_reopen() {
    let (a_store, a_vid, b_store, b_vid) = setup_transition_pair();
    let fixture_a = create_persisted_store().await;
    let fixture_b = create_persisted_store().await;

    let (_endpoint, mut request_message) = a_store
        .make_relationship_request(&a_vid, &b_vid, None)
        .unwrap();

    let request_thread_id = match a_store
        .get_relation_status_for_vid_pair(&a_vid, &b_vid)
        .unwrap()
    {
        RelationshipStatus::Unidirectional { thread_id } => thread_id,
        status => panic!("unexpected status after request: {status}"),
    };

    let a_store = persist_reopen_cycle(&a_store, &fixture_a, 1).await;
    let b_store = persist_reopen_cycle(&b_store, &fixture_b, 1).await;

    let crate::ReceivedTspMessage::RequestRelationship { thread_id, .. } =
        b_store.open_message(&mut request_message).unwrap()
    else {
        panic!("receiver did not decode relationship request");
    };
    assert_eq!(thread_id, request_thread_id);

    // Receiver explicitly marks the incoming request as pending relation before sending accept.
    b_store
        .set_relation_and_status_for_vid(
            &a_vid,
            RelationshipStatus::Unidirectional { thread_id },
            &b_vid,
        )
        .unwrap();
    let (_endpoint, mut accept_message) = b_store
        .make_relationship_accept(&b_vid, &a_vid, thread_id, None)
        .unwrap();

    let a_store = persist_reopen_cycle(&a_store, &fixture_a, 1).await;
    let _ = persist_reopen_cycle(&b_store, &fixture_b, 1).await;

    let crate::ReceivedTspMessage::AcceptRelationship { .. } =
        a_store.open_message(&mut accept_message).unwrap()
    else {
        panic!("sender did not decode relationship accept");
    };

    let RelationshipStatus::Bidirectional {
        thread_id: upgraded,
        ..
    } = a_store
        .get_relation_status_for_vid_pair(&a_vid, &b_vid)
        .unwrap()
    else {
        panic!("relationship was not upgraded to bidirectional");
    };
    assert_eq!(upgraded, thread_id);
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_relationship_transition_cancel_after_reopen() {
    let (store, seed) = create_dirty_store_with_transition_seed();
    let fixture = create_persisted_store().await;
    let store = persist_reopen_cycle(&store, &fixture, 1).await;

    let (_endpoint, cancel_message) = store
        .make_relationship_cancel(&seed.local_vid, &seed.remote_bidirectional_vid)
        .unwrap();
    assert!(!cancel_message.is_empty());

    let RelationshipStatus::Unrelated = store
        .get_relation_status_for_vid_pair(&seed.local_vid, &seed.remote_bidirectional_vid)
        .unwrap()
    else {
        panic!("relationship was not cancelled");
    };
    let RelationshipStatus::Unrelated = store
        .get_relation_status_for_vid_pair(&seed.local_vid, &seed.remote_unrelated_vid)
        .unwrap()
    else {
        panic!("unrelated relationship unexpectedly changed");
    };

    let store = persist_reopen_cycle(&store, &fixture, 1).await;
    let RelationshipStatus::Unrelated = store
        .get_relation_status_for_vid_pair(&seed.local_vid, &seed.remote_bidirectional_vid)
        .unwrap()
    else {
        panic!("cancelled relationship did not persist as unrelated");
    };

    let err = store
        .make_relationship_cancel(&seed.local_vid, &seed.remote_bidirectional_vid)
        .unwrap_err();
    assert!(matches!(err, crate::Error::Relationship(_)));
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_nested_relationship_transition_after_reopen() {
    let (a_store, a_vid, b_store, b_vid) = setup_transition_pair();
    let fixture_a = create_persisted_store().await;
    let fixture_b = create_persisted_store().await;

    let (_endpoint, mut request_message) = a_store
        .make_relationship_request(&a_vid, &b_vid, None)
        .unwrap();
    let thread_id = match a_store
        .get_relation_status_for_vid_pair(&a_vid, &b_vid)
        .unwrap()
    {
        RelationshipStatus::Unidirectional { thread_id } => thread_id,
        _ => panic!("missing unidirectional relation before accept"),
    };
    b_store
        .set_relation_and_status_for_vid(
            &a_vid,
            RelationshipStatus::Unidirectional { thread_id },
            &b_vid,
        )
        .unwrap();
    let (_endpoint, mut accept_message) = b_store
        .make_relationship_accept(&b_vid, &a_vid, thread_id, None)
        .unwrap();
    let _ = b_store.open_message(&mut request_message).unwrap();
    let _ = a_store.open_message(&mut accept_message).unwrap();

    let a_store = persist_reopen_cycle(&a_store, &fixture_a, 1).await;
    let b_store = persist_reopen_cycle(&b_store, &fixture_b, 1).await;

    let ((_endpoint, mut nested_request), nested_a_vid) = a_store
        .make_nested_relationship_request(&a_vid, &b_vid)
        .unwrap();

    let nested_thread = match a_store
        .get_relation_status_for_vid_pair(&a_vid, &b_vid)
        .unwrap()
    {
        RelationshipStatus::Bidirectional {
            outstanding_nested_requests,
            ..
        } => outstanding_nested_requests.last().unwrap().thread_id,
        _ => panic!("missing outstanding nested thread id"),
    };

    let a_store = persist_reopen_cycle(&a_store, &fixture_a, 1).await;
    let b_store = persist_reopen_cycle(&b_store, &fixture_b, 1).await;

    let crate::ReceivedTspMessage::RequestRelationship {
        thread_id,
        form,
        delivery,
        ..
    } = b_store.open_message(&mut nested_request).unwrap()
    else {
        panic!("nested relationship request was not decoded");
    };
    let ReceivedRelationshipDelivery::Nested { nested_vid } = delivery else {
        panic!("nested relationship request kind was not decoded");
    };
    assert!(matches!(form, ReceivedRelationshipForm::Direct));
    assert_eq!(nested_vid, nested_a_vid.identifier());
    assert_eq!(thread_id, nested_thread);

    let ((_endpoint, mut nested_accept), nested_b_vid) = b_store
        .make_nested_relationship_accept(&b_vid, &nested_vid, thread_id)
        .unwrap();
    let a_store = persist_reopen_cycle(&a_store, &fixture_a, 1).await;

    let crate::ReceivedTspMessage::AcceptRelationship { form, delivery, .. } =
        a_store.open_message(&mut nested_accept).unwrap()
    else {
        panic!("nested relationship accept was not decoded");
    };
    let ReceivedRelationshipDelivery::Nested {
        nested_vid: accepted_nested_vid,
    } = delivery
    else {
        panic!("nested relationship accept kind was not decoded");
    };
    assert!(matches!(form, ReceivedRelationshipForm::Direct));
    assert_eq!(accepted_nested_vid, nested_b_vid.identifier());

    let RelationshipStatus::Bidirectional {
        outstanding_nested_requests,
        ..
    } = a_store
        .get_relation_status_for_vid_pair(&a_vid, &b_vid)
        .unwrap()
    else {
        panic!("parent relation is not bidirectional after nested accept");
    };
    assert!(
        !outstanding_nested_requests
            .iter()
            .any(|pending| pending.thread_id == thread_id),
        "nested thread id was not consumed after nested accept"
    );

    let RelationshipStatus::Bidirectional { .. } = a_store
        .get_relation_status_for_vid_pair(nested_a_vid.identifier(), nested_b_vid.identifier())
        .unwrap()
    else {
        panic!("nested vid relation was not persisted as bidirectional");
    };
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_persisted_store_open_with_wrong_password_fails() {
    let fixture = create_persisted_store().await;
    let store = create_async_test_store();
    store.add_private_vid(create_test_vid(), None).unwrap();
    fixture.persist_from(&store).await;

    assert_storage_open_or_read_fails(fixture.storage_url(), b"definitely-wrong-password").await;
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_persisted_store_open_with_corrupted_file_fails() {
    let fixture = create_persisted_store().await;
    let store = create_async_test_store();
    store.add_private_vid(create_test_vid(), None).unwrap();
    fixture.persist_from(&store).await;

    corrupt_sqlite_file(fixture.sqlite_path());

    assert_storage_open_or_read_fails(fixture.storage_url(), fixture.password()).await;
}
