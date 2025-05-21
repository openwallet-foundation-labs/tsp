use assert_cmd::Command;
use predicates::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use std::process::Command as StdCommand;
use std::thread;

fn random_string(n: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(n)
        .map(char::from) // From link above, this is needed in later versions
        .collect()
}

fn create_wallet(alias: &str) -> String {
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    let random_name = format!("test_wallet_{}", random_string(8));
    cmd.args(&[
        "--wallet",
        random_name.as_str(),
        "create",
        "--alias",
        alias,
        random_name.as_str(),
    ])
    .assert()
    .success();

    random_name
}

fn clean_wallet() {
    StdCommand::new("sh")
        .arg("-c")
        .arg("rm -f test_wallet_*.sqlite*")
        .status()
        .expect("Failed to clean wallet files");
}

#[test]
fn test_send_command_unverified_receiver_default() {
    clean_wallet();

    // create a new sender identity
    let random_sender_name = create_wallet("marlon");

    // create a new receiver identity
    let random_receiver_name = create_wallet("marc");

    // print the sender's DID
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    let output = cmd
        .args(&["--wallet", random_sender_name.as_str(), "print", "marlon"])
        .output()
        .expect("failed to execute print command");
    let marlon_did: &str = std::str::from_utf8(&output.stdout)
        .expect("invalid utf-8")
        .trim();

    // print the receiver's DID
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    let output = cmd
        .args(&["--wallet", random_receiver_name.as_str(), "print", "marc"])
        .output()
        .expect("failed to execute print command");
    let marc_did: &str = std::str::from_utf8(&output.stdout)
        .expect("invalid utf-8")
        .trim();

    // receiver verifies the address of the sender
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    cmd.args(&[
        "--wallet",
        random_receiver_name.as_str(),
        "verify",
        "--alias",
        "marlon",
        &marlon_did,
    ])
    .assert()
    .success();

    thread::scope(|s| {
        s.spawn(|| {
            // send a message from sender to receiver
            let input = "Oh hello Marc";
            let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
            cmd.args(&[
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
            let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
            cmd.args(&[
                "--wallet",
                random_receiver_name.as_str(),
                "receive",
                "--one",
                &marc_did,
            ])
            .assert()
            .stdout(predicate::str::contains("Oh hello Marc"))
            .success();
        });
    });

    clean_wallet();
}

#[test]
fn test_send_command_unverified_receiver_ask_flag() {
    clean_wallet();

    // create a new sender identity
    let random_sender_name = create_wallet("marlon");

    // create a new receiver identity
    let random_receiver_name = create_wallet("marc");

    // print the sender's DID
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    let output = cmd
        .args(&["--wallet", random_sender_name.as_str(), "print", "marlon"])
        .output()
        .expect("failed to execute print command");
    let marlon_did: &str = std::str::from_utf8(&output.stdout)
        .expect("invalid utf-8")
        .trim();

    // print the receiver's DID
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    let output = cmd
        .args(&["--wallet", random_receiver_name.as_str(), "print", "marc"])
        .output()
        .expect("failed to execute print command");
    let marc_did: &str = std::str::from_utf8(&output.stdout)
        .expect("invalid utf-8")
        .trim();

    // receiver verifies the address of the sender
    // receiver verifies the address of the sender
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    cmd.args(&[
        "--wallet",
        random_receiver_name.as_str(),
        "verify",
        "--alias",
        "marlon",
        &marlon_did,
    ])
    .assert()
    .success();

    // send a message from sender to receiver
    let input = "n\nOh hello Marc";
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    cmd.args(&[
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
    .assert()
    .stderr(predicate::str::contains(
        "Message cannot be sent without verifying the receiver's DID",
    ))
    .success();

    // Send a message from Marlon to Marc with --ask flag, answer yes
    thread::scope(|s| {
        s.spawn(|| {
            // send a message from sender to receiver
            let input = "y\nOh hello Marc";
            let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
            cmd.args(&[
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
            .assert()
            .stdout(predicate::str::contains(
                "Do you want to verify receiver DID",
            ))
            .success();
        });
        s.spawn(|| {
            // receive the message
            let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
            cmd.args(&[
                "--wallet",
                random_receiver_name.as_str(),
                "receive",
                "--one",
                &marc_did,
            ])
            .assert()
            .stdout(predicate::str::contains("Oh hello Marc"))
            .success();
        });
    });

    clean_wallet();
}
