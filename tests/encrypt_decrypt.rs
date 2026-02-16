use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn enseal() -> Command {
    Command::cargo_bin("enseal").unwrap()
}

// ---------------------------------------------------------------------------
// encrypt command tests
// ---------------------------------------------------------------------------

#[test]
fn encrypt_help_shows_usage() {
    enseal()
        .args(["encrypt", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("per-var"))
        .stdout(predicate::str::contains("output"));
}

#[test]
fn encrypt_missing_file() {
    enseal()
        .args(["encrypt", "/nonexistent/.env"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read"));
}

// ---------------------------------------------------------------------------
// decrypt command tests
// ---------------------------------------------------------------------------

#[test]
fn decrypt_help_shows_usage() {
    enseal()
        .args(["decrypt", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("output"));
}

#[test]
fn decrypt_missing_file() {
    enseal()
        .args(["decrypt", "/nonexistent/.env.encrypted"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read"));
}

#[test]
fn decrypt_plaintext_file_rejected() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("plain.env");
    fs::write(&file, "KEY=value\nOTHER=stuff\n").unwrap();

    enseal()
        .args(["decrypt", file.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("doesn't appear to be encrypted"));
}

// ---------------------------------------------------------------------------
// Crypto round-trip tests (unit-level, no key store needed)
// ---------------------------------------------------------------------------

#[test]
fn whole_file_encrypt_decrypt_round_trip() {
    // Test the crypto layer directly via the library
    use enseal::crypto::at_rest;
    use enseal::keys::identity::EnsealIdentity;

    let id = EnsealIdentity::generate();
    let plaintext = b"SECRET=hunter2\nAPI_KEY=abc123\nDATABASE_URL=postgres://localhost/db\n";

    let ciphertext = at_rest::encrypt_whole_file(plaintext, &[&id.age_recipient]).unwrap();
    assert!(at_rest::is_age_encrypted(&ciphertext));
    assert!(!String::from_utf8_lossy(&ciphertext).contains("hunter2"));

    let decrypted = at_rest::decrypt_whole_file(&ciphertext, &id.age_identity).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn per_var_encrypt_decrypt_round_trip() {
    use enseal::crypto::at_rest;
    use enseal::env::parser;
    use enseal::keys::identity::EnsealIdentity;

    let id = EnsealIdentity::generate();
    let env = parser::parse("SECRET=hunter2\nAPI_KEY=abc123\n").unwrap();

    let encrypted = at_rest::encrypt_per_var(&env, &[&id.age_recipient]).unwrap();
    let encrypted_str = encrypted.to_string();

    // Keys visible, values encrypted
    assert!(encrypted_str.contains("SECRET="));
    assert!(encrypted_str.contains("API_KEY="));
    assert!(!encrypted_str.contains("hunter2"));
    assert!(!encrypted_str.contains("abc123"));

    // Per-var encrypted values detected
    assert!(at_rest::is_per_var_encrypted(&encrypted_str));

    // Valid .env syntax — reparseable
    let reparsed = parser::parse(&encrypted_str).unwrap();
    assert_eq!(reparsed.var_count(), 2);

    // Decrypt
    let decrypted = at_rest::decrypt_per_var(&encrypted, &id.age_identity).unwrap();
    assert_eq!(decrypted.vars(), env.vars());
}

#[test]
fn multi_recipient_any_can_decrypt() {
    use enseal::crypto::at_rest;
    use enseal::keys::identity::EnsealIdentity;

    let id1 = EnsealIdentity::generate();
    let id2 = EnsealIdentity::generate();
    let plaintext = b"SHARED_SECRET=value123\n";

    let ciphertext =
        at_rest::encrypt_whole_file(plaintext, &[&id1.age_recipient, &id2.age_recipient]).unwrap();

    // Both can decrypt
    let d1 = at_rest::decrypt_whole_file(&ciphertext, &id1.age_identity).unwrap();
    assert_eq!(d1, plaintext);

    let d2 = at_rest::decrypt_whole_file(&ciphertext, &id2.age_identity).unwrap();
    assert_eq!(d2, plaintext);

    // Wrong key cannot
    let wrong = EnsealIdentity::generate();
    assert!(at_rest::decrypt_whole_file(&ciphertext, &wrong.age_identity).is_err());
}

#[test]
fn no_plaintext_in_encrypted_output() {
    use enseal::crypto::at_rest;
    use enseal::env::parser;
    use enseal::keys::identity::EnsealIdentity;

    let id = EnsealIdentity::generate();

    // Whole-file
    let plaintext = b"VERY_SECRET_TOKEN=sk_live_should_not_appear";
    let ciphertext = at_rest::encrypt_whole_file(plaintext, &[&id.age_recipient]).unwrap();
    let ciphertext_str = String::from_utf8_lossy(&ciphertext);
    assert!(!ciphertext_str.contains("sk_live_should_not_appear"));
    assert!(!ciphertext_str.contains("VERY_SECRET_TOKEN"));

    // Per-variable
    let env = parser::parse("VERY_SECRET_TOKEN=sk_live_should_not_appear\n").unwrap();
    let encrypted = at_rest::encrypt_per_var(&env, &[&id.age_recipient]).unwrap();
    let encrypted_str = encrypted.to_string();
    assert!(encrypted_str.contains("VERY_SECRET_TOKEN=")); // key IS visible
    assert!(!encrypted_str.contains("sk_live_should_not_appear")); // value NOT visible
}
