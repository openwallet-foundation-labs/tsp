use assert_cmd::{Command, cargo_bin};
use predicates::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use std::process::Command as StdCommand;
use std::thread;
use std::time::Duration;
fn random_string(n: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(n)
        .map(char::from) // From link above, this is needed in later versions
        .collect()
}

fn create_wallet(alias: &str, did_type: &str) -> String {
    let mut cmd: Command = Command::new(cargo_bin!("tsp"));
    let random_name = format!("test_wallet_{}", random_string(8));
    cmd.args([
        "--wallet",
        random_name.as_str(),
        "create",
        "--type",
        did_type,
        "--alias",
        alias,
        random_name.as_str(),
    ])
    .assert()
    .success();

    random_name
}

fn print_did(wallet_name: &str, alias: &str) -> String {
    let mut cmd: Command = Command::new(cargo_bin!("tsp"));
    let output = cmd
        .args(["--wallet", wallet_name, "print", alias])
        .output()
        .expect("failed to execute print command");
    std::str::from_utf8(&output.stdout)
        .expect("invalid utf-8")
        .trim()
        .to_string()
}

fn verify_did(wallet_name: &str, alias: &str, did: &str) {
    let mut cmd: Command = Command::new(cargo_bin!("tsp"));
    cmd.args(["--wallet", wallet_name, "verify", "--alias", alias, did])
        .assert()
        .success();
}

fn rotate_keys(wallet_name: &str, alias: &str) {
    let mut cmd: Command = Command::new(cargo_bin!("tsp"));
    cmd.args(["--wallet", wallet_name, "update", alias])
        .assert()
        .success();
}

fn clean_wallet() {
    StdCommand::new("sh")
        .arg("-c")
        .arg("rm -f test_wallet_*.sqlite*")
        .status()
        .expect("Failed to clean wallet files");
}

#[test]
#[serial_test::serial(clean_wallet)]
fn test_send_command_unverified_receiver_default() {
    clean_wallet();

    // create a new sender identity
    let random_sender_name = create_wallet("marlon", "web");

    // create a new receiver identity
    let random_receiver_name = create_wallet("marc", "web");

    // print the sender's DID
    let marlon_did = print_did(&random_sender_name, "marlon");

    // print the receiver's DID
    let marc_did = print_did(&random_receiver_name, "marc");

    // receiver verifies the address of the sender
    verify_did(&random_receiver_name, "marlon", &marlon_did);

    thread::scope(|s| {
        s.spawn(|| {
            // send a message from sender to receiver
            let input = "Oh hello Marc";
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                random_sender_name.as_str(),
                "send",
                "-s",
                "marlon",
                "-r",
                &marc_did,
            ])
            .write_stdin(input)
            .assert()
            .success();
        });
        s.spawn(|| {
            // receive the message
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                random_receiver_name.as_str(),
                "receive",
                &marc_did,
            ])
            .timeout(Duration::from_secs(2))
            .assert()
            .stderr(predicate::str::contains("received relationship request"))
            .stdout(predicate::str::contains("Oh hello Marc"))
            .failure();
        });
    });

    clean_wallet();
}

#[test]
#[serial_test::serial(clean_wallet)]
fn test_send_command_unverified_receiver_ask_flag() {
    clean_wallet();

    // create a new sender identity
    let random_sender_name = create_wallet("marlon", "web");

    // create a new receiver identity
    let random_receiver_name = create_wallet("marc", "web");

    // print the sender's DID
    let marlon_did = print_did(&random_sender_name, "marlon");

    // print the receiver's DID
    let marc_did = print_did(&random_receiver_name, "marc");

    // receiver verifies the address of the sender
    verify_did(&random_receiver_name, "marlon", &marlon_did);

    // Send a message from Marlon to Marc with --ask flag, answer no
    let input = "n\nOh hello Marc";
    let mut cmd: Command = Command::new(cargo_bin!("tsp"));
    cmd.args([
        "--wallet",
        random_sender_name.as_str(),
        "send",
        "-s",
        "marlon",
        "-r",
        &marc_did,
        "--ask",
    ])
    .write_stdin(input)
    .timeout(Duration::from_secs(2))
    .assert()
    .stderr(predicate::str::contains(
        "Message cannot be sent without verifying the receiver's DID",
    ))
    .failure();

    // Send a message from Marlon to Marc with --ask flag, answer yes
    thread::scope(|s| {
        s.spawn(|| {
            // send a message from sender to receiver
            let input = "y\nOh hello Marc";
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                random_sender_name.as_str(),
                "send",
                "-s",
                "marlon",
                "-r",
                &marc_did,
                "--ask",
            ])
            .write_stdin(input)
            .timeout(Duration::from_secs(2))
            .assert()
            .stdout(predicate::str::contains(
                "Do you want to verify receiver DID",
            ))
            .success();
        });
        s.spawn(|| {
            // receive the message
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                random_receiver_name.as_str(),
                "receive",
                "--one",
                &marc_did,
            ])
            .timeout(Duration::from_secs(2))
            .assert()
            .stderr(predicate::str::contains("received relationship request"))
            .success();
        });
    });

    clean_wallet();
}

#[test]
#[serial_test::serial(clean_wallet)]
fn test_webvh_creation_key_rotation() {
    clean_wallet();

    // create a new sender identity
    let random_sender_name = create_wallet("foo", "webvh");

    // create a new receiver identity
    let random_receiver_name = create_wallet("bar", "web");

    // print the sender's DID
    let foo_did = print_did(&random_sender_name, "foo");

    // print the receiver's DID
    let bar_did = print_did(&random_receiver_name, "bar");

    // receiver verifies the address of the sender
    verify_did(&random_receiver_name, "foo", &foo_did);

    thread::scope(|s| {
        s.spawn(|| {
            // send a message from sender to receiver
            let input = "Oh hello Marc";
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                random_sender_name.as_str(),
                "send",
                "-s",
                "foo",
                "-r",
                &bar_did,
            ])
            .write_stdin(input)
            .assert()
            .success();
        });
        s.spawn(|| {
            // receive the message
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                random_receiver_name.as_str(),
                "receive",
                &bar_did,
            ])
            .timeout(Duration::from_secs(2))
            .assert()
            .stderr(predicate::str::contains("received relationship request"))
            .stdout(predicate::str::contains("Oh hello Marc"))
            .failure();
        });
    });

    rotate_keys(&random_sender_name, "foo");

    thread::scope(|s| {
        s.spawn(|| {
            // send a message from sender to receiver
            let input = "Oh hello Marc";
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                random_sender_name.as_str(),
                "send",
                "-s",
                "foo",
                "-r",
                &bar_did,
            ])
            .write_stdin(input)
            .assert()
            .success();
        });
        s.spawn(|| {
            // receive the message
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                random_receiver_name.as_str(),
                "receive",
                &bar_did,
            ])
            .timeout(Duration::from_secs(2))
            .assert()
            .stdout(predicate::str::contains("Oh hello Marc"))
            .failure();
        });
    });

    clean_wallet();
}

/// Stress test: Create DID, send message, rotate 100 times, send message again
/// This tests the precommit chain integrity over many rotations
#[test]
#[serial_test::serial(clean_wallet)]
#[ignore] // Run with: cargo test --package examples test_100_rotations -- --ignored --nocapture
fn test_100_rotations_stress() {
    clean_wallet();

    const NUM_ROTATIONS: usize = 100;

    println!("Creating sender (webvh) and receiver (web) wallets...");

    // Create sender with did:webvh (supports rotation with precommit)
    let sender_wallet = create_wallet("sender", "webvh");
    // Create receiver with did:web
    let receiver_wallet = create_wallet("receiver", "web");

    let sender_did = print_did(&sender_wallet, "sender");
    let receiver_did = print_did(&receiver_wallet, "receiver");

    println!("Sender DID: {}", sender_did);
    println!("Receiver DID: {}", receiver_did);

    // Receiver verifies sender
    verify_did(&receiver_wallet, "sender", &sender_did);

    // --- Test 1: Send message BEFORE any rotation ---
    println!("\n=== Test 1: Sending message BEFORE any rotations ===");
    thread::scope(|s| {
        s.spawn(|| {
            let input = "Hello before rotations";
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                sender_wallet.as_str(),
                "send",
                "-s",
                "sender",
                "-r",
                &receiver_did,
            ])
            .write_stdin(input)
            .assert()
            .success();
        });
        s.spawn(|| {
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                receiver_wallet.as_str(),
                "receive",
                &receiver_did,
            ])
            .timeout(Duration::from_secs(3))
            .assert()
            .stdout(predicate::str::contains("Hello before rotations"))
            .failure(); // timeout expected
        });
    });
    println!("Message sent and received successfully before rotations!");

    // --- Perform 100 rotations ---
    println!("\n=== Performing {} key rotations ===", NUM_ROTATIONS);
    for i in 1..=NUM_ROTATIONS {
        if i % 10 == 0 {
            println!("  Rotation {}/{}...", i, NUM_ROTATIONS);
        }
        rotate_keys(&sender_wallet, "sender");
    }
    println!("All {} rotations completed successfully!", NUM_ROTATIONS);

    // --- Test 2: Send message AFTER 100 rotations ---
    println!(
        "\n=== Test 2: Sending message AFTER {} rotations ===",
        NUM_ROTATIONS
    );

    // Give the server a moment to process
    thread::sleep(Duration::from_millis(500));

    thread::scope(|s| {
        s.spawn(|| {
            let input = "Hello after 100 rotations";
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                sender_wallet.as_str(),
                "send",
                "-s",
                "sender",
                "-r",
                &receiver_did,
            ])
            .write_stdin(input)
            .assert()
            .success();
        });
        s.spawn(|| {
            let mut cmd: Command = Command::new(cargo_bin!("tsp"));
            cmd.args([
                "--wallet",
                receiver_wallet.as_str(),
                "receive",
                &receiver_did,
            ])
            .timeout(Duration::from_secs(5))
            .assert()
            .stdout(predicate::str::contains("Hello after 100 rotations"))
            .failure(); // timeout expected
        });
    });
    println!(
        "Message sent and received successfully after {} rotations!",
        NUM_ROTATIONS
    );

    println!(
        "\n=== STRESS TEST PASSED: Precommit chain intact after {} rotations ===",
        NUM_ROTATIONS
    );

    clean_wallet();
}
