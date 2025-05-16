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

    // Create a new sender identity
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    let random_wallet_name = random_string(8);
    cmd.args(&[
        "--wallet",
        "marlon",
        "create",
        "--alias",
        "marlon",
        random_wallet_name.as_str(),
    ])
    .assert()
    .success();

    // Create a new receiver identity
    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    let random_wallet_name = random_string(8);
    cmd.args(&[
        "--wallet",
        "marc",
        "create",
        "--alias",
        "marc",
        random_wallet_name.as_str(),
    ])
    .assert()
    .success();

    let mut cmd: Command = Command::cargo_bin("tsp").expect("tsp binary exists");
    let output = cmd
        .args(&["--wallet", "marc", "print", "marc"])
        .output()
        .expect("failed to execute print command");
    let marc_did: &str = std::str::from_utf8(&output.stdout)
        .expect("invalid utf-8")
        .trim();

    // Send a message from Marlon to Marc with --ask flag, anwer no
    let input = "n\nOh hello Marc";
    let mut cmd = Command::cargo_bin("tsp").expect("tsp binary exists");
    cmd.args(&[
        "--wallet", "marlon", "send", "-s", "marlon", "-r", &marc_did, "--ask",
    ])
    .write_stdin(input)
    .assert()
    .stderr(predicate::str::contains(
        "Message cannot be sent without verifying the receiver's DID",
    ))
    .success();

    // Send a message from Marlon to Marc with --ask flag, answer yes
    let input = "y\nOh hello Marc";
    let mut cmd = Command::cargo_bin("tsp").expect("tsp binary exists");
    cmd.args(&[
        "--wallet", "marlon", "send", "-s", "marlon", "-r", &marc_did, "--ask",
    ])
    .write_stdin(input)
    .assert()
    .stdout(predicate::str::contains(
        "Do you want to verify receiver DID",
    ))
    .success();

    // clean the wallet
    StdCommand::new("rm")
        .args(&["-f", "marlon.sqlite", "marc.sqlite"])
        .status()
        .expect("Failed to clean wallet files");
}
