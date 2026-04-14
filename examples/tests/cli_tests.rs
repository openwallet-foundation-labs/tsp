use assert_cmd::{Command, cargo_bin};
use predicates::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use std::net::{TcpListener, TcpStream};
use std::process::Command as StdCommand;
use std::thread;
use std::time::Duration;
use tsp_sdk::{AskarSecureStorage, AsyncSecureStore, RelationshipStatus, SecureStorage};

struct WalletCleanupGuard;

impl Drop for WalletCleanupGuard {
    fn drop(&mut self) {
        clean_wallet();
    }
}

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

fn create_peer_wallet(alias: &str, tcp_addr: &str) -> String {
    let mut cmd: Command = Command::new(cargo_bin!("tsp"));
    let wallet_name = format!("test_wallet_{}", random_string(8));
    cmd.args([
        "--wallet",
        wallet_name.as_str(),
        "create",
        "--type",
        "peer",
        "--tcp",
        tcp_addr,
        alias,
    ])
    .assert()
    .success();

    wallet_name
}

fn create_peer_identity(wallet_name: &str, alias: &str, tcp_addr: &str) {
    let mut cmd: Command = Command::new(cargo_bin!("tsp"));
    cmd.args([
        "--wallet",
        wallet_name,
        "create",
        "--type",
        "peer",
        "--tcp",
        tcp_addr,
        alias,
    ])
    .assert()
    .success();
}

fn allocate_tcp_addr() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("failed to allocate test port");
    let addr = listener
        .local_addr()
        .expect("failed to read test listener address");
    drop(listener);
    format!("127.0.0.1:{}", addr.port())
}

fn can_use_loopback_transport() -> bool {
    let Ok(listener) = TcpListener::bind(("127.0.0.1", 0)) else {
        return false;
    };
    let Ok(addr) = listener.local_addr() else {
        return false;
    };

    TcpStream::connect(addr).is_ok()
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

fn parse_relationship_stdout(stdout: &[u8]) -> (String, String) {
    let stdout = std::str::from_utf8(stdout).expect("invalid utf-8");
    let line = stdout
        .lines()
        .find(|line| line.contains('\t'))
        .expect("expected tab-separated relationship output");
    let (left, right) = line
        .split_once('\t')
        .expect("relationship output should contain a tab");
    (left.trim().to_string(), right.trim().to_string())
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

fn remove_next_update_alias(wallet_name: &str, did: &str) {
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    runtime.block_on(async {
        let url = format!("sqlite://{wallet_name}.sqlite");
        let vault = AskarSecureStorage::open(&url, b"unsecure")
            .await
            .expect("Failed to open wallet storage");
        let (vids, mut aliases, keys) = vault.read().await.expect("Failed to read wallet");

        let next_kid_alias = format!("__next_update_kid:{did}");
        let removed = aliases.remove(&next_kid_alias);
        assert!(
            removed.is_some(),
            "Expected wallet to contain precommit alias {next_kid_alias}"
        );

        let db = AsyncSecureStore::new();
        db.import(vids, aliases, keys)
            .expect("Failed to import wallet state");
        vault
            .persist(db.export().expect("Failed to export wallet state"))
            .await
            .expect("Failed to persist modified wallet state");
        vault.close().await.expect("Failed to close wallet storage");
    });
}

fn load_wallet(wallet_name: &str) -> AsyncSecureStore {
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    runtime.block_on(async {
        let url = format!("sqlite://{wallet_name}.sqlite");
        let vault = AskarSecureStorage::open(&url, b"unsecure")
            .await
            .expect("Failed to open wallet storage");
        let (vids, aliases, keys) = vault.read().await.expect("Failed to read wallet");

        let db = AsyncSecureStore::new();
        db.import(vids, aliases, keys)
            .expect("Failed to import wallet state");
        vault.close().await.expect("Failed to close wallet storage");
        db
    })
}

fn clean_wallet() {
    StdCommand::new("sh")
        .arg("-c")
        .arg("rm -f test_wallet_*.sqlite*")
        .status()
        .expect("Failed to clean wallet files");
}

fn wallet_cleanup_guard() -> WalletCleanupGuard {
    clean_wallet();
    WalletCleanupGuard
}

#[test]
#[serial_test::serial(clean_wallet)]
fn test_send_command_unverified_receiver_default() {
    let _cleanup = wallet_cleanup_guard();

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
}

#[test]
#[serial_test::serial(clean_wallet)]
fn test_send_command_unverified_receiver_ask_flag() {
    let _cleanup = wallet_cleanup_guard();

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
}

#[test]
#[serial_test::serial(clean_wallet)]
fn test_webvh_creation_key_rotation() {
    let _cleanup = wallet_cleanup_guard();

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
}

#[test]
#[serial_test::serial(clean_wallet)]
fn test_webvh_update_reports_out_of_sync_when_precommit_alias_is_missing() {
    let _cleanup = wallet_cleanup_guard();

    let wallet_name = create_wallet("foo", "webvh");
    let did = print_did(&wallet_name, "foo");

    remove_next_update_alias(&wallet_name, &did);

    let mut cmd: Command = Command::new(cargo_bin!("tsp"));
    cmd.args(["--wallet", wallet_name.as_str(), "update", "foo"])
        .assert()
        .stderr(predicate::str::contains(
            "Server has precommit active but wallet has no matching key. Wallet may be out of sync.",
        ))
        .failure();
}

#[test]
#[serial_test::serial(clean_wallet)]
fn test_request_help_lists_parallel_options() {
    let _cleanup = wallet_cleanup_guard();

    let mut cmd: Command = Command::new(cargo_bin!("tsp"));
    cmd.args(["request", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--parallel"))
        .stdout(predicate::str::contains("--new-vid"));
}

#[test]
#[serial_test::serial(clean_wallet)]
fn test_parallel_request_requires_new_vid() {
    let _cleanup = wallet_cleanup_guard();

    let mut cmd: Command = Command::new(cargo_bin!("tsp"));
    cmd.args(["request", "--parallel", "-s", "alice", "-r", "bob"])
        .assert()
        .stderr(predicate::str::contains("--new-vid"))
        .failure();
}

#[test]
#[serial_test::serial(clean_wallet)]
fn test_parallel_request_and_accept_roundtrip_over_cli() {
    let _cleanup = wallet_cleanup_guard();

    if !can_use_loopback_transport() {
        eprintln!("skipping loopback CLI test: local TCP transport is unavailable");
        return;
    }

    let alice_wallet = create_peer_wallet("alice", &allocate_tcp_addr());
    let bob_wallet = create_peer_wallet("bob", &allocate_tcp_addr());
    create_peer_identity(&alice_wallet, "alice-alt", &allocate_tcp_addr());
    create_peer_identity(&bob_wallet, "bob-alt", &allocate_tcp_addr());

    let alice_did = print_did(&alice_wallet, "alice");
    let bob_did = print_did(&bob_wallet, "bob");
    let alice_alt_did = print_did(&alice_wallet, "alice-alt");
    let bob_alt_did = print_did(&bob_wallet, "bob-alt");

    verify_did(&alice_wallet, "bob", &bob_did);
    verify_did(&bob_wallet, "alice", &alice_did);

    let tsp_bin = cargo_bin!("tsp");

    let outer_receive = {
        let tsp_bin = tsp_bin.to_path_buf();
        let bob_wallet = bob_wallet.clone();
        thread::spawn(move || {
            StdCommand::new(tsp_bin)
                .args(["--wallet", bob_wallet.as_str(), "receive", "--one", "bob"])
                .output()
                .expect("failed to receive outer relationship request")
        })
    };

    thread::sleep(Duration::from_millis(300));

    let outer_request = StdCommand::new(tsp_bin)
        .args([
            "--wallet",
            alice_wallet.as_str(),
            "request",
            "-s",
            "alice",
            "-r",
            "bob",
        ])
        .output()
        .expect("failed to send outer relationship request");
    assert!(
        outer_request.status.success(),
        "outer request failed: {}",
        String::from_utf8_lossy(&outer_request.stderr)
    );

    let outer_receive = outer_receive.join().expect("outer receive thread panicked");
    assert!(
        outer_receive.status.success(),
        "outer receive failed: {}",
        String::from_utf8_lossy(&outer_receive.stderr)
    );
    let (outer_sender, outer_thread_id) = parse_relationship_stdout(&outer_receive.stdout);
    assert_eq!(outer_sender, alice_did);

    let outer_accept_receive = {
        let tsp_bin = tsp_bin.to_path_buf();
        let alice_wallet = alice_wallet.clone();
        thread::spawn(move || {
            StdCommand::new(tsp_bin)
                .args([
                    "--wallet",
                    alice_wallet.as_str(),
                    "receive",
                    "--one",
                    "alice",
                ])
                .output()
                .expect("failed to receive outer relationship accept")
        })
    };

    thread::sleep(Duration::from_millis(300));

    let outer_accept = StdCommand::new(tsp_bin)
        .args([
            "--wallet",
            bob_wallet.as_str(),
            "accept",
            "-s",
            "bob",
            "-r",
            &alice_did,
            "--thread-id",
            outer_thread_id.as_str(),
        ])
        .output()
        .expect("failed to send outer relationship accept");
    assert!(
        outer_accept.status.success(),
        "outer accept failed: {}",
        String::from_utf8_lossy(&outer_accept.stderr)
    );

    let outer_accept_receive = outer_accept_receive
        .join()
        .expect("outer accept receive thread panicked");
    assert!(
        outer_accept_receive.status.success(),
        "outer accept receive failed: {}",
        String::from_utf8_lossy(&outer_accept_receive.stderr)
    );

    verify_did(&alice_wallet, "alice-alt", &alice_alt_did);

    let parallel_receive = {
        let tsp_bin = tsp_bin.to_path_buf();
        let bob_wallet = bob_wallet.clone();
        thread::spawn(move || {
            StdCommand::new(tsp_bin)
                .args(["--wallet", bob_wallet.as_str(), "receive", "--one", "bob"])
                .output()
                .expect("failed to receive parallel relationship request")
        })
    };

    thread::sleep(Duration::from_millis(300));

    let parallel_request = {
        let tsp_bin = tsp_bin.to_path_buf();
        let alice_wallet = alice_wallet.clone();
        thread::spawn(move || {
            StdCommand::new(tsp_bin)
                .args([
                    "--wallet",
                    alice_wallet.as_str(),
                    "request",
                    "--parallel",
                    "-s",
                    "alice",
                    "-r",
                    "bob",
                    "--new-vid",
                    "alice-alt",
                    "--wait",
                ])
                .output()
                .expect("failed to send parallel relationship request")
        })
    };

    let parallel_receive = parallel_receive
        .join()
        .expect("parallel receive thread panicked");
    assert!(
        parallel_receive.status.success(),
        "parallel receive failed: {}",
        String::from_utf8_lossy(&parallel_receive.stderr)
    );
    let (received_new_vid, parallel_thread_id) =
        parse_relationship_stdout(&parallel_receive.stdout);
    assert_eq!(received_new_vid, alice_alt_did);

    let parallel_accept = StdCommand::new(tsp_bin)
        .args([
            "--wallet",
            bob_wallet.as_str(),
            "accept",
            "--parallel",
            "-s",
            "bob-alt",
            "-r",
            &alice_alt_did,
            "--thread-id",
            parallel_thread_id.as_str(),
        ])
        .output()
        .expect("failed to send parallel relationship accept");
    assert!(
        parallel_accept.status.success(),
        "parallel accept failed: {}",
        String::from_utf8_lossy(&parallel_accept.stderr)
    );

    let parallel_request = parallel_request
        .join()
        .expect("parallel request thread panicked");
    assert!(
        parallel_request.status.success(),
        "parallel request failed: {}",
        String::from_utf8_lossy(&parallel_request.stderr)
    );
    assert!(
        String::from_utf8_lossy(&parallel_request.stdout).contains(&bob_alt_did),
        "parallel request output did not include bob-alt did: stdout={}, stderr={}",
        String::from_utf8_lossy(&parallel_request.stdout),
        String::from_utf8_lossy(&parallel_request.stderr)
    );

    let alice_store = load_wallet(&alice_wallet);
    assert!(matches!(
        alice_store
            .get_relation_status_for_vid_pair("alice-alt", &bob_alt_did)
            .unwrap(),
        RelationshipStatus::Bidirectional { .. }
    ));

    let bob_store = load_wallet(&bob_wallet);
    assert!(matches!(
        bob_store
            .get_relation_status_for_vid_pair("bob-alt", &alice_alt_did)
            .unwrap(),
        RelationshipStatus::Bidirectional { .. }
    ));
}

/// Stress test: Create DID, send message, rotate 100 times, send message again
/// This tests the precommit chain integrity over many rotations
#[test]
#[serial_test::serial(clean_wallet)]
#[ignore] // Run with: cargo test --package examples test_100_rotations -- --ignored --nocapture
fn test_100_rotations_stress() {
    let _cleanup = wallet_cleanup_guard();

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
}
