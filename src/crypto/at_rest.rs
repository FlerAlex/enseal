use std::io::{Read, Write};

use anyhow::{bail, Context, Result};
use base64::Engine;

use crate::env::{Entry, EnvFile};

const PER_VAR_PREFIX: &str = "ENC[age:";
const PER_VAR_SUFFIX: &str = "]";

// ---------------------------------------------------------------------------
// Whole-file encryption
// ---------------------------------------------------------------------------

/// Encrypt an entire .env file to one or more age recipients.
/// Returns the raw age ciphertext bytes.
pub fn encrypt_whole_file(
    plaintext: &[u8],
    recipients: &[&age::x25519::Recipient],
) -> Result<Vec<u8>> {
    age_encrypt_multi(plaintext, recipients)
}

/// Decrypt a whole-file age ciphertext with the given identity.
pub fn decrypt_whole_file(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    age_decrypt(ciphertext, identity)
}

// ---------------------------------------------------------------------------
// Per-variable encryption
// ---------------------------------------------------------------------------

/// Encrypt an EnvFile per-variable: keys stay visible, values become `ENC[age:...]`.
/// Returns a new EnvFile where each value is individually encrypted.
pub fn encrypt_per_var(env: &EnvFile, recipients: &[&age::x25519::Recipient]) -> Result<EnvFile> {
    let mut result = EnvFile::new();

    for entry in &env.entries {
        match entry {
            Entry::KeyValue { key, value } => {
                let ciphertext = age_encrypt_multi(value.as_bytes(), recipients)?;
                let encoded = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
                result.entries.push(Entry::KeyValue {
                    key: key.clone(),
                    value: format!("{}{}{}", PER_VAR_PREFIX, encoded, PER_VAR_SUFFIX),
                });
            }
            other => {
                result.entries.push(other.clone());
            }
        }
    }

    Ok(result)
}

/// Decrypt an EnvFile where values are `ENC[age:...]`.
/// Returns a new EnvFile with decrypted plaintext values.
pub fn decrypt_per_var(env: &EnvFile, identity: &age::x25519::Identity) -> Result<EnvFile> {
    let mut result = EnvFile::new();

    for entry in &env.entries {
        match entry {
            Entry::KeyValue { key, value } => {
                let decrypted_value = if is_encrypted_value(value) {
                    let encoded = &value[PER_VAR_PREFIX.len()..value.len() - PER_VAR_SUFFIX.len()];
                    let ciphertext = base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .with_context(|| {
                            format!("invalid base64 in encrypted value for '{}'", key)
                        })?;
                    let plaintext = age_decrypt(&ciphertext, identity)
                        .with_context(|| format!("failed to decrypt value for '{}'", key))?;
                    String::from_utf8(plaintext).with_context(|| {
                        format!("decrypted value for '{}' is not valid UTF-8", key)
                    })?
                } else {
                    value.clone()
                };

                result.entries.push(Entry::KeyValue {
                    key: key.clone(),
                    value: decrypted_value,
                });
            }
            other => {
                result.entries.push(other.clone());
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Check if a value is an `ENC[age:...]` encrypted value.
pub fn is_encrypted_value(value: &str) -> bool {
    value.starts_with(PER_VAR_PREFIX) && value.ends_with(PER_VAR_SUFFIX)
}

/// Detect whether a file is per-variable encrypted (contains `ENC[age:...]` values).
pub fn is_per_var_encrypted(content: &str) -> bool {
    content.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        if let Some(eq_pos) = line.find('=') {
            let value = line[eq_pos + 1..].trim();
            is_encrypted_value(value)
        } else {
            false
        }
    })
}

/// Detect whether content is an age-encrypted file (binary header check).
pub fn is_age_encrypted(content: &[u8]) -> bool {
    content.starts_with(b"age-encryption.org/v1")
}

// ---------------------------------------------------------------------------
// Age helpers (multi-recipient)
// ---------------------------------------------------------------------------

fn age_encrypt_multi(data: &[u8], recipients: &[&age::x25519::Recipient]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        bail!("at least one recipient is required for encryption");
    }

    let recipients_iter = recipients.iter().map(|r| *r as &dyn age::Recipient);

    let encryptor =
        age::Encryptor::with_recipients(recipients_iter).expect("recipients should not be empty");

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("failed to create age encryptor")?;

    writer
        .write_all(data)
        .context("failed to write age ciphertext")?;
    writer
        .finish()
        .context("failed to finalize age encryption")?;

    Ok(encrypted)
}

fn age_decrypt(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    let decryptor = age::Decryptor::new(ciphertext).context("failed to read age header")?;

    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("age decryption failed: {}", e))?;

    let mut plaintext = vec![];
    reader
        .read_to_end(&mut plaintext)
        .context("failed to read decrypted data")?;

    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::parser;
    use crate::keys::identity::EnsealIdentity;

    #[test]
    fn whole_file_round_trip() {
        let id = EnsealIdentity::generate();
        let plaintext = b"SECRET=hunter2\nAPI_KEY=abc123\n";

        let ciphertext = encrypt_whole_file(plaintext, &[&id.age_recipient]).unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = decrypt_whole_file(&ciphertext, &id.age_identity).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn whole_file_is_age_format() {
        let id = EnsealIdentity::generate();
        let ciphertext = encrypt_whole_file(b"data", &[&id.age_recipient]).unwrap();
        assert!(is_age_encrypted(&ciphertext));
    }

    #[test]
    fn per_var_round_trip() {
        let id = EnsealIdentity::generate();
        let env = parser::parse("SECRET=hunter2\nAPI_KEY=abc123\n").unwrap();

        let encrypted = encrypt_per_var(&env, &[&id.age_recipient]).unwrap();

        // Keys should be visible
        let encrypted_str = encrypted.to_string();
        assert!(encrypted_str.contains("SECRET="));
        assert!(encrypted_str.contains("API_KEY="));

        // Values should be encrypted
        for (_, value) in encrypted.vars() {
            assert!(
                is_encrypted_value(value),
                "value should be encrypted: {}",
                value
            );
        }

        // No plaintext values
        assert!(!encrypted_str.contains("hunter2"));
        assert!(!encrypted_str.contains("abc123"));

        // Decrypt
        let decrypted = decrypt_per_var(&encrypted, &id.age_identity).unwrap();
        assert_eq!(decrypted.vars(), env.vars());
    }

    #[test]
    fn per_var_preserves_structure() {
        let id = EnsealIdentity::generate();
        let env = parser::parse("# comment\nKEY=value\n\nOTHER=stuff\n").unwrap();

        let encrypted = encrypt_per_var(&env, &[&id.age_recipient]).unwrap();
        assert_eq!(encrypted.entries.len(), 4); // comment, kv, blank, kv
        assert!(matches!(encrypted.entries[0], Entry::Comment(_)));
        assert!(matches!(encrypted.entries[2], Entry::Blank));
    }

    #[test]
    fn per_var_is_valid_env_syntax() {
        let id = EnsealIdentity::generate();
        let env = parser::parse("KEY=value\nSECRET=hunter2\n").unwrap();

        let encrypted = encrypt_per_var(&env, &[&id.age_recipient]).unwrap();
        let encrypted_str = encrypted.to_string();

        // Should be parseable as a .env file
        let reparsed = parser::parse(&encrypted_str).unwrap();
        assert_eq!(reparsed.var_count(), 2);
    }

    #[test]
    fn multi_recipient_any_can_decrypt() {
        let id1 = EnsealIdentity::generate();
        let id2 = EnsealIdentity::generate();
        let plaintext = b"SHARED_SECRET=value123\n";

        let ciphertext =
            encrypt_whole_file(plaintext, &[&id1.age_recipient, &id2.age_recipient]).unwrap();

        // Both recipients can decrypt
        let d1 = decrypt_whole_file(&ciphertext, &id1.age_identity).unwrap();
        assert_eq!(d1, plaintext);

        let d2 = decrypt_whole_file(&ciphertext, &id2.age_identity).unwrap();
        assert_eq!(d2, plaintext);
    }

    #[test]
    fn multi_recipient_per_var() {
        let id1 = EnsealIdentity::generate();
        let id2 = EnsealIdentity::generate();
        let env = parser::parse("SECRET=value\n").unwrap();

        let encrypted = encrypt_per_var(&env, &[&id1.age_recipient, &id2.age_recipient]).unwrap();

        let d1 = decrypt_per_var(&encrypted, &id1.age_identity).unwrap();
        assert_eq!(d1.vars(), env.vars());

        let d2 = decrypt_per_var(&encrypted, &id2.age_identity).unwrap();
        assert_eq!(d2.vars(), env.vars());
    }

    #[test]
    fn wrong_key_cannot_decrypt_whole() {
        let id = EnsealIdentity::generate();
        let wrong = EnsealIdentity::generate();

        let ciphertext = encrypt_whole_file(b"secret", &[&id.age_recipient]).unwrap();
        assert!(decrypt_whole_file(&ciphertext, &wrong.age_identity).is_err());
    }

    #[test]
    fn wrong_key_cannot_decrypt_per_var() {
        let id = EnsealIdentity::generate();
        let wrong = EnsealIdentity::generate();
        let env = parser::parse("SECRET=value\n").unwrap();

        let encrypted = encrypt_per_var(&env, &[&id.age_recipient]).unwrap();
        assert!(decrypt_per_var(&encrypted, &wrong.age_identity).is_err());
    }

    #[test]
    fn no_plaintext_in_whole_file_output() {
        let id = EnsealIdentity::generate();
        let plaintext = b"VERY_SECRET_TOKEN=sk_live_should_not_appear";

        let ciphertext = encrypt_whole_file(plaintext, &[&id.age_recipient]).unwrap();
        let ciphertext_str = String::from_utf8_lossy(&ciphertext);
        assert!(!ciphertext_str.contains("sk_live_should_not_appear"));
        assert!(!ciphertext_str.contains("VERY_SECRET_TOKEN"));
    }

    #[test]
    fn detection_per_var() {
        assert!(is_per_var_encrypted("KEY=ENC[age:abc123]"));
        assert!(!is_per_var_encrypted("KEY=plainvalue"));
        assert!(!is_per_var_encrypted("# just a comment"));
    }

    #[test]
    fn detection_age_format() {
        assert!(is_age_encrypted(b"age-encryption.org/v1\nsomething"));
        assert!(!is_age_encrypted(b"KEY=value\n"));
    }
}
