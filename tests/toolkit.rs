use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn enseal() -> Command {
    Command::cargo_bin("enseal").unwrap()
}

// --- redact ---

#[test]
fn redact_replaces_values() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    fs::write(&env_path, "SECRET=hunter2\nPORT=3000\n").unwrap();

    enseal()
        .args(["redact", env_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("SECRET=<REDACTED>"))
        .stdout(predicate::str::contains("PORT=<REDACTED>"))
        .stdout(predicate::str::contains("hunter2").not())
        .stdout(predicate::str::contains("3000").not());
}

#[test]
fn redact_to_output_file() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    let out_path = dir.path().join("redacted.env");
    fs::write(&env_path, "KEY=value\n").unwrap();

    enseal()
        .args([
            "redact",
            env_path.to_str().unwrap(),
            "--output",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("<REDACTED>"));
    assert!(!content.contains("value"));
}

#[test]
fn redact_missing_file() {
    enseal()
        .args(["redact", "/nonexistent/.env"])
        .assert()
        .failure();
}

// --- check ---

#[test]
fn check_all_present() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    let example_path = dir.path().join(".env.example");
    fs::write(&env_path, "A=1\nB=2\n").unwrap();
    fs::write(&example_path, "A=\nB=\n").unwrap();

    enseal()
        .args([
            "check",
            env_path.to_str().unwrap(),
            "--example",
            example_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("ok:"));
}

#[test]
fn check_missing_vars() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    let example_path = dir.path().join(".env.example");
    fs::write(&env_path, "A=1\n").unwrap();
    fs::write(&example_path, "A=\nB=\nC=\n").unwrap();

    enseal()
        .args([
            "check",
            env_path.to_str().unwrap(),
            "--example",
            example_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("B"))
        .stderr(predicate::str::contains("C"));
}

// --- diff ---

#[test]
fn diff_identical() {
    let dir = TempDir::new().unwrap();
    let f1 = dir.path().join("a.env");
    let f2 = dir.path().join("b.env");
    fs::write(&f1, "A=1\nB=2\n").unwrap();
    fs::write(&f2, "A=x\nB=y\n").unwrap();

    enseal()
        .args(["diff", f1.to_str().unwrap(), f2.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("no differences"));
}

#[test]
fn diff_shows_missing_and_extra() {
    let dir = TempDir::new().unwrap();
    let f1 = dir.path().join("a.env");
    let f2 = dir.path().join("b.env");
    fs::write(&f1, "A=1\nB=2\n").unwrap();
    fs::write(&f2, "B=2\nC=3\n").unwrap();

    enseal()
        .args(["diff", f1.to_str().unwrap(), f2.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("A"))
        .stdout(predicate::str::contains("C"));
}

#[test]
fn diff_never_shows_values() {
    let dir = TempDir::new().unwrap();
    let f1 = dir.path().join("a.env");
    let f2 = dir.path().join("b.env");
    fs::write(&f1, "SECRET=super_secret_value\n").unwrap();
    fs::write(&f2, "OTHER=another_secret\n").unwrap();

    let output = enseal()
        .args(["diff", f1.to_str().unwrap(), f2.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("super_secret_value"));
    assert!(!stderr.contains("super_secret_value"));
    assert!(!stdout.contains("another_secret"));
    assert!(!stderr.contains("another_secret"));
}
