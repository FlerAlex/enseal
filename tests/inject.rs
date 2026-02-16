use assert_cmd::Command;
use predicates::prelude::*;

fn enseal() -> Command {
    Command::cargo_bin("enseal").unwrap()
}

#[test]
fn inject_help_shows_usage() {
    enseal()
        .args(["inject", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Receive secrets and inject into a child process"));
}

#[test]
fn inject_requires_command() {
    // inject without -- <cmd> should fail
    enseal()
        .args(["inject", "some-code"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}
