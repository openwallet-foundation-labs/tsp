//! # Smart Home Lock Example
//!
//! This example demonstrates the usage of the TSP SDK's advanced features in a
//! realistic scenario: a Smart Home Controller (App) interacting with a Smart Lock.
//!
//! It covers three key features:
//! 1. **Relationship State Machine**: Establishing a secure relationship between
//!    the Controller and the Lock using the `RelationshipMachine`.
//! 2. **Retry Mechanism**: Handling network instability by automatically retrying
//!    failed relationship requests using `check_timeouts`.
//! 3. **Offline Message Queue**: Queueing commands when the device is offline and
//!    sending them later using `queue_message` and `retrieve_pending_messages`.
//!
//! ## Scenarios
//!
//! - **Scenario 1**: Successful relationship establishment.
//! - **Scenario 2**: Network flakiness causing a request to drop, followed by a successful retry.
//! - **Scenario 3**: Controller sending a command while offline, which is queued and sent upon reconnection.

use std::time::Duration;
use tokio::time::sleep;
use tsp_sdk::{AsyncSecureStore, OwnedVid, ReceivedTspMessage, RelationshipStatus, VerifiedVid};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    println!("--- TSP Smart Home Lock Scenario ---");

    // 1. Setup Identities
    println!("\n[Setup] Creating identities for Controller (App) and Lock (Device)...");
    let controller_store = AsyncSecureStore::new();
    let lock_store = AsyncSecureStore::new();

    let controller_vid = OwnedVid::new_did_peer(Url::parse("tcp://127.0.0.1:1337")?);
    let lock_vid = OwnedVid::new_did_peer(Url::parse("tcp://127.0.0.1:1338")?);

    controller_store.add_private_vid(controller_vid.clone(), None)?;
    lock_store.add_private_vid(lock_vid.clone(), None)?;

    // Add each other's verified VIDs (initial discovery)
    controller_store.add_verified_vid(lock_vid.vid().clone(), None)?;
    lock_store.add_verified_vid(controller_vid.vid().clone(), None)?;

    println!("Identities created.");
    println!("Controller: {}", controller_vid.identifier());
    println!("Lock:       {}", lock_vid.identifier());

    // 2. Relationship State Machine
    println!("\n[Scenario 1] Relationship Establishment (State Machine)");

    // Step A: Controller sends request
    println!("-> Controller sends Relationship Request...");
    let (_url, request_msg) = controller_store.make_relationship_request(
        controller_vid.identifier(),
        lock_vid.identifier(),
        None,
    )?;

    // Step B: Lock receives request
    println!("<- Lock receives request...");
    let mut received_msg = request_msg.clone();
    let message = lock_store.open_message(&mut received_msg)?;

    let thread_id = if let ReceivedTspMessage::RequestRelationship { thread_id, .. } = message {
        println!(
            "   Lock: Received RequestRelationship. State transitions to ReverseUnidirectional."
        );
        thread_id
    } else {
        panic!("Unexpected message type");
    };

    // Step C: Lock accepts
    println!("-> Lock accepts relationship...");
    let (_url, accept_msg) = lock_store.make_relationship_accept(
        lock_vid.identifier(),
        controller_vid.identifier(),
        thread_id,
        None,
    )?;

    // Step D: Controller receives accept
    println!("<- Controller receives accept...");
    let mut received_accept = accept_msg.clone();
    let _ = controller_store.open_message(&mut received_accept)?;
    println!("   Controller: Received AcceptRelationship. State transitions to Bidirectional.");

    // Verify status
    let status = controller_store
        .get_relation_status_for_vid_pair(controller_vid.identifier(), lock_vid.identifier())?;
    println!("   Final Controller Status with Lock: {:?}", status);
    assert!(matches!(status, RelationshipStatus::Bidirectional { .. }));

    // 3. Retry Mechanism
    println!("\n[Scenario 2] Network Flakiness & Auto-Retry");

    // Create new VIDs for this scenario to start from a clean state
    println!("   Creating fresh VIDs for retry scenario...");
    let controller_vid_2 = OwnedVid::new_did_peer(Url::parse("tcp://127.0.0.1:1339")?);
    let lock_vid_2 = OwnedVid::new_did_peer(Url::parse("tcp://127.0.0.1:1340")?);

    controller_store.add_private_vid(controller_vid_2.clone(), None)?;
    // We don't strictly need to add lock_vid_2 private to lock_store since we won't deliver the message
    controller_store.add_verified_vid(lock_vid_2.vid().clone(), None)?;

    println!("-> Controller 2 sends Relationship Request to Lock 2...");

    // This will succeed in creating the message and updating state to Unidirectional
    let (_url, _msg) = controller_store.make_relationship_request(
        controller_vid_2.identifier(),
        lock_vid_2.identifier(),
        None,
    )?;

    println!("   (Simulating network drop - message is NOT delivered to Lock)");
    // We simply do nothing with _msg.

    // Wait a bit to simulate time passing > initial_delay
    println!("   ... Waiting for timeout (600ms) ...");
    sleep(Duration::from_millis(600)).await;

    println!("-> Controller checks for timeouts...");
    let resend_list = controller_store.as_store().check_timeouts()?;

    if !resend_list.is_empty() {
        println!(
            "   SUCCESS: Retry mechanism detected timeout. {} message(s) queued for resend.",
            resend_list.len()
        );
        // Verify it's for the right VID
        // In a real app, we would resend here.
    } else {
        println!("   WARNING: No timeouts detected (maybe delay was too short?)");
    }

    // 4. Offline Message Queue
    println!("\n[Scenario 3] Offline Message Queue");

    println!("-> Controller wants to send 'Grant Access' but is offline...");
    let cmd_payload = b"Grant Access: Guest";
    let (url, sealed_msg) = controller_store.seal_message(
        controller_vid.identifier(),
        lock_vid.identifier(),
        None,
        cmd_payload,
    )?;

    // Queue it
    controller_store.as_store().queue_message(url, sealed_msg)?;
    println!("   Message queued successfully.");

    // Simulate coming online
    println!("-> Controller comes online. Retrieving pending messages...");
    let pending = controller_store.as_store().retrieve_pending_messages()?;
    println!("   Retrieved {} message(s) from queue.", pending.len());

    assert_eq!(pending.len(), 1);
    println!("   Sending queued message to Lock...");

    // Lock receives it
    let mut queued_msg_data = pending[0].1.clone();
    let received_queued = lock_store.open_message(&mut queued_msg_data)?;

    if let ReceivedTspMessage::GenericMessage { message, .. } = received_queued {
        println!("   Lock received: {}", String::from_utf8_lossy(&message));
        assert_eq!(message, cmd_payload);
    }

    println!("\n--- Scenario Completed Successfully ---");
    Ok(())
}
