use crate::{
    AsyncSecureStore, ReceivedRelationshipDelivery, ReceivedRelationshipForm, RelationshipStatus,
    VerifiedVid, test_utils::*,
};
use futures::StreamExt;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
use tokio::time::timeout;

fn can_use_loopback_transport() -> bool {
    let Ok(listener) = TcpListener::bind(("127.0.0.1", 0)) else {
        return false;
    };
    let Ok(addr) = listener.local_addr() else {
        return false;
    };

    TcpStream::connect(addr).is_ok()
}

fn establish_existing_relationship(
    a_store: &AsyncSecureStore,
    a_vid: &dyn VerifiedVid,
    b_store: &AsyncSecureStore,
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

fn assert_bidirectional_relationship(store: &AsyncSecureStore, local_vid: &str, remote_vid: &str) {
    assert!(matches!(
        store
            .get_relation_status_for_vid_pair(local_vid, remote_vid)
            .unwrap(),
        RelationshipStatus::Bidirectional { .. }
    ));
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_parallel_relationship_accept_bootstraps_unknown_sender_async() {
    if !can_use_loopback_transport() {
        eprintln!("skipping async bootstrap test: local TCP transport is unavailable");
        return;
    }

    let alice_db = create_async_test_store();
    let bob_db = create_async_test_store();
    let (alice, bob) = create_test_vid_pair();
    let alice_parallel = create_test_vid();
    let bob_parallel = create_test_vid();

    alice_db.add_private_vid(alice.clone(), None).unwrap();
    bob_db.add_private_vid(bob.clone(), None).unwrap();
    alice_db
        .add_private_vid(alice_parallel.clone(), None)
        .unwrap();
    bob_db.add_private_vid(bob_parallel.clone(), None).unwrap();
    alice_db.add_verified_vid(bob.clone(), None).unwrap();
    bob_db.add_verified_vid(alice.clone(), None).unwrap();
    bob_db
        .add_verified_vid(alice_parallel.clone(), None)
        .unwrap();
    establish_existing_relationship(&alice_db, &alice, &bob_db, &bob);

    assert!(
        !alice_db
            .has_verified_vid(bob_parallel.identifier())
            .unwrap()
    );

    let mut bob_messages = bob_db.receive(bob.identifier()).await.unwrap();
    let mut alice_parallel_messages = alice_db.receive(alice_parallel.identifier()).await.unwrap();

    alice_db
        .send_parallel_relationship_request(
            alice.identifier(),
            bob.identifier(),
            alice_parallel.identifier(),
        )
        .await
        .unwrap();

    let request = timeout(Duration::from_secs(5), bob_messages.next())
        .await
        .expect("timed out waiting for parallel request")
        .expect("parallel request stream ended")
        .expect("failed to receive parallel request");

    let crate::definitions::ReceivedTspMessage::RequestRelationship {
        sender,
        receiver,
        thread_id,
        form:
            ReceivedRelationshipForm::Parallel {
                new_vid,
                sig_new_vid: _,
            },
        delivery: ReceivedRelationshipDelivery::Direct,
    } = request
    else {
        panic!("bob did not receive a parallel relationship request");
    };

    assert_eq!(sender, alice.identifier());
    assert_eq!(receiver, bob.identifier());
    assert_eq!(new_vid, alice_parallel.identifier());

    bob_db
        .send_parallel_relationship_accept(
            bob_parallel.identifier(),
            alice_parallel.identifier(),
            thread_id,
        )
        .await
        .unwrap();

    let accept = timeout(Duration::from_secs(5), alice_parallel_messages.next())
        .await
        .expect("timed out waiting for parallel accept")
        .expect("parallel accept stream ended")
        .expect("failed to receive parallel accept");

    let crate::definitions::ReceivedTspMessage::AcceptRelationship {
        sender,
        receiver,
        thread_id: received_thread_id,
        reply_thread_id: _,
        form:
            ReceivedRelationshipForm::Parallel {
                new_vid,
                sig_new_vid: _,
            },
        delivery: ReceivedRelationshipDelivery::Direct,
    } = accept
    else {
        panic!("alice did not receive a parallel relationship accept");
    };

    assert_eq!(sender, bob.identifier());
    assert_eq!(receiver, alice_parallel.identifier());
    assert_eq!(received_thread_id, thread_id);
    assert_eq!(new_vid, bob_parallel.identifier());
    assert!(
        alice_db
            .has_verified_vid(bob_parallel.identifier())
            .unwrap()
    );
    assert_bidirectional_relationship(
        &alice_db,
        alice_parallel.identifier(),
        bob_parallel.identifier(),
    );
    assert_bidirectional_relationship(&alice_db, alice.identifier(), bob.identifier());
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_parallel_relationship_state_persists_after_import_and_reopen() {
    let alice_db = create_async_test_store();
    let bob_db = create_async_test_store();
    let (alice, bob) = create_test_vid_pair();
    let alice_parallel = create_test_vid();
    let bob_parallel = create_test_vid();

    alice_db.add_private_vid(alice.clone(), None).unwrap();
    bob_db.add_private_vid(bob.clone(), None).unwrap();
    alice_db
        .add_private_vid(alice_parallel.clone(), None)
        .unwrap();
    bob_db.add_private_vid(bob_parallel.clone(), None).unwrap();
    alice_db.add_verified_vid(bob.clone(), None).unwrap();
    bob_db.add_verified_vid(alice.clone(), None).unwrap();
    alice_db
        .add_verified_vid(bob_parallel.clone(), None)
        .unwrap();
    bob_db
        .add_verified_vid(alice_parallel.clone(), None)
        .unwrap();
    establish_existing_relationship(&alice_db, &alice, &bob_db, &bob);

    let (_endpoint, mut request) = alice_db
        .make_parallel_relationship_request(
            alice.identifier(),
            bob.identifier(),
            alice_parallel.identifier(),
        )
        .unwrap();

    let crate::definitions::ReceivedTspMessage::RequestRelationship { thread_id, .. } =
        bob_db.as_store().open_message(&mut request).unwrap()
    else {
        panic!("bob did not open a parallel relationship request");
    };

    let (_endpoint, mut accept) = bob_db
        .make_parallel_relationship_accept(
            bob_parallel.identifier(),
            alice_parallel.identifier(),
            thread_id,
        )
        .unwrap();

    let crate::definitions::ReceivedTspMessage::AcceptRelationship { .. } =
        alice_db.as_store().open_message(&mut accept).unwrap()
    else {
        panic!("alice did not open a parallel relationship accept");
    };

    assert_bidirectional_relationship(&alice_db, alice.identifier(), bob.identifier());
    assert_bidirectional_relationship(
        &alice_db,
        alice_parallel.identifier(),
        bob_parallel.identifier(),
    );
    assert_bidirectional_relationship(&bob_db, bob.identifier(), alice.identifier());
    assert_bidirectional_relationship(
        &bob_db,
        bob_parallel.identifier(),
        alice_parallel.identifier(),
    );

    let imported_alice = create_async_test_store();
    let (vids, aliases, keys) = alice_db.export().unwrap();
    imported_alice.import(vids, aliases, keys).unwrap();

    assert_bidirectional_relationship(&imported_alice, alice.identifier(), bob.identifier());
    assert_bidirectional_relationship(
        &imported_alice,
        alice_parallel.identifier(),
        bob_parallel.identifier(),
    );

    let fixture = create_persisted_store().await;
    fixture.persist_from(&bob_db).await;
    let reopened_bob = fixture.reopen_into_store().await;

    assert_bidirectional_relationship(&reopened_bob, bob.identifier(), alice.identifier());
    assert_bidirectional_relationship(
        &reopened_bob,
        bob_parallel.identifier(),
        alice_parallel.identifier(),
    );
}
