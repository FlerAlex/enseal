use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn enseal() -> Command {
    Command::cargo_bin("enseal").unwrap()
}

// --- validate ---

#[test]
fn validate_all_pass() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    let config_path = dir.path().join(".enseal.toml");

    fs::write(
        &env_path,
        "DATABASE_URL=postgres://localhost/mydb\nPORT=3000\nDEBUG=true\n",
    )
    .unwrap();

    fs::write(
        &config_path,
        r#"
[schema]
required = ["DATABASE_URL", "PORT"]

[schema.rules.PORT]
type = "integer"
range = [1024, 65535]

[schema.rules.DATABASE_URL]
pattern = "^postgres://"

[schema.rules.DEBUG]
type = "boolean"
"#,
    )
    .unwrap();

    enseal()
        .args([
            "validate",
            env_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("ok:"));
}

#[test]
fn validate_missing_required() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    let config_path = dir.path().join(".enseal.toml");

    fs::write(&env_path, "PORT=3000\n").unwrap();

    fs::write(
        &config_path,
        r#"
[schema]
required = ["DATABASE_URL", "PORT"]
"#,
    )
    .unwrap();

    enseal()
        .args([
            "validate",
            env_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("DATABASE_URL"));
}

#[test]
fn validate_type_error() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    let config_path = dir.path().join(".enseal.toml");

    fs::write(&env_path, "PORT=abc\n").unwrap();

    fs::write(
        &config_path,
        r#"
[schema.rules.PORT]
type = "integer"
"#,
    )
    .unwrap();

    enseal()
        .args([
            "validate",
            env_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not an integer"));
}

// --- template ---

#[test]
fn template_generates_example() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    let out_path = dir.path().join(".env.example");

    fs::write(
        &env_path,
        "# Database config\nDATABASE_URL=postgres://localhost/mydb\nPORT=3000\nDEBUG=true\nAPI_KEY=test_key_abcdefghijklmnopqrstuvwxyz1234\n",
    )
    .unwrap();

    enseal()
        .args([
            "template",
            env_path.to_str().unwrap(),
            "--output",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = fs::read_to_string(&out_path).unwrap();

    // Should have keys but not real values
    assert!(content.contains("DATABASE_URL=<"));
    assert!(content.contains("PORT=<"));
    assert!(content.contains("DEBUG=<"));
    assert!(content.contains("API_KEY=<"));
    // Should NOT contain actual values
    assert!(!content.contains("postgres://localhost/mydb"));
    assert!(!content.contains("sk_live_"));
    // Should preserve comments
    assert!(content.contains("# Database config"));
}

#[test]
fn template_with_schema_descriptions() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    let config_path = dir.path().join(".enseal.toml");

    fs::write(&env_path, "DATABASE_URL=postgres://localhost/mydb\n").unwrap();

    fs::write(
        &config_path,
        r#"
[schema.rules.DATABASE_URL]
description = "PostgreSQL connection string"
"#,
    )
    .unwrap();

    let output = enseal()
        .args([
            "template",
            env_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PostgreSQL connection string"));
}

// --- template infers types ---

#[test]
fn template_type_inference() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");

    fs::write(
        &env_path,
        "PORT=3000\nDEBUG=true\nURL=https://api.example.com\nEMAIL=user@example.com\n",
    )
    .unwrap();

    let output = enseal()
        .args(["template", env_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("integer"));
    assert!(stdout.contains("boolean"));
    assert!(stdout.contains("https"));
    assert!(stdout.contains("email"));
}
