use assert_cmd::Command;
use predicates::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use std::process::Command as StdCommand;

fn random_string(n: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(n)
        .map(char::from) // From link above, this is needed in later versions
        .collect()
}
#[test]
fn test_send_command_ask_flag() {
    // clean the wallet
    StdCommand::new("rm")
        .args(&["-f", "marlon.sqlite", "marc.sqlite"])
        .status()
        .expect("Failed to clean wallet files");

    // create a new sender identity
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    let random_sender_name = format!("test_wallet_{}", random_string(8));
    cmd.args(&[
        "--wallet",
        random_sender_name.as_str(),
        "create",
        "--alias",
        "marlon",
        random_sender_name.as_str(),
    ])
    .assert()
    .success();

    // create a new receiver identity
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    let random_receiver_name = format!("test_wallet_{}", random_string(8));
    cmd.args(&[
        "--wallet",
        random_receiver_name.as_str(),
        "create",
        "--alias",
        "marc",
        random_receiver_name.as_str(),
    ])
    .assert()
    .success();

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

    // clean the wallet
    StdCommand::new("rm")
        .args(&["-f", "marlon.sqlite", "marc.sqlite"])
        .status()
        .expect("Failed to clean wallet files");
}
