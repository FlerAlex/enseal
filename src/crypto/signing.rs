use anyhow::{bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use crate::keys::identity::{EnsealIdentity, TrustedKey};

/// A signed and encrypted identity-mode payload.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedEnvelope {
    /// JSON-serialized inner Envelope, age-encrypted to recipient.
    pub ciphertext: Vec<u8>,
    /// Sender's ed25519 public key (base64).
    pub sender_sign_pubkey: String,
    /// Sender's age public key (for the recipient to verify identity).
    pub sender_age_pubkey: String,
    /// Ed25519 signature over the ciphertext bytes.
    pub signature: String,
}

impl SignedEnvelope {
    /// Encrypt an inner envelope to one or more recipients and sign with the sender's key.
    pub fn seal(
        inner_bytes: &[u8],
        recipients: &[&age::x25519::Recipient],
        sender: &EnsealIdentity,
    ) -> Result<Self> {
        // Encrypt with age to recipients' public keys
        let ciphertext = age_encrypt_multi(inner_bytes, recipients)?;

        // Sign the ciphertext
        let signature = sender.signing_key.sign(&ciphertext);

        let sender_sign_pubkey = base64::engine::general_purpose::STANDARD
            .encode(sender.signing_key.verifying_key().to_bytes());
        let sender_age_pubkey = sender.age_recipient.to_string();

        Ok(Self {
            ciphertext,
            sender_sign_pubkey,
            sender_age_pubkey,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        })
    }

    /// Verify the signature and decrypt the inner envelope.
    /// If `expected_sender` is Some, verify the sender matches a trusted key.
    pub fn open(
        &self,
        own_identity: &EnsealIdentity,
        expected_sender: Option<&TrustedKey>,
    ) -> Result<Vec<u8>> {
        // Decode and verify the sender's signing key
        let sign_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.sender_sign_pubkey)
            .context("invalid sender signing key encoding")?;
        let sign_array: [u8; 32] = sign_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid sender signing key length"))?;
        let verifying_key =
            VerifyingKey::from_bytes(&sign_array).context("invalid sender signing key")?;

        // If we have an expected sender, verify it matches
        if let Some(trusted) = expected_sender {
            if verifying_key != trusted.verifying_key {
                bail!(
                    "sender key mismatch: expected {}, got a different key",
                    trusted.identity
                );
            }
        }

        // Verify signature over ciphertext
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.signature)
            .context("invalid signature encoding")?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signature length"))?;
        let signature = Signature::from_bytes(&sig_array);

        verifying_key
            .verify(&self.ciphertext, &signature)
            .map_err(|_| {
                anyhow::anyhow!("signature verification failed: payload may be tampered")
            })?;

        // Decrypt with own age key
        let plaintext = age_decrypt(&self.ciphertext, &own_identity.age_identity)?;

        Ok(plaintext)
    }

    /// Serialize to JSON bytes for wire transfer.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("failed to serialize signed envelope")
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).context("failed to deserialize signed envelope")
    }
}

/// Encrypt data with age to one or more recipients.
fn age_encrypt_multi(data: &[u8], recipients: &[&age::x25519::Recipient]) -> Result<Vec<u8>> {
    let recipients_iter = recipients.iter().map(|r| *r as &dyn age::Recipient);

    let encryptor =
        age::Encryptor::with_recipients(recipients_iter).expect("recipients should not be empty");

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("failed to create age encryptor")?;

    use std::io::Write;
    writer
        .write_all(data)
        .context("failed to write age ciphertext")?;
    writer
        .finish()
        .context("failed to finalize age encryption")?;

    Ok(encrypted)
}

/// Decrypt age-encrypted data with own identity.
fn age_decrypt(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    let decryptor = age::Decryptor::new(ciphertext).context("failed to read age header")?;

    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("age decryption failed: {}", e))?;

    let mut plaintext = vec![];
    use std::io::Read;
    reader
        .read_to_end(&mut plaintext)
        .context("failed to read decrypted data")?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let sender = EnsealIdentity::generate();
        let receiver = EnsealIdentity::generate();

        let plaintext = b"SECRET=hunter2\nAPI_KEY=abc123\n";
        let signed = SignedEnvelope::seal(plaintext, &[&receiver.age_recipient], &sender).unwrap();

        let bytes = signed.to_bytes().unwrap();
        let restored = SignedEnvelope::from_bytes(&bytes).unwrap();

        let decrypted = restored.open(&receiver, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let sender = EnsealIdentity::generate();
        let receiver = EnsealIdentity::generate();

        let plaintext = b"SECRET=value";
        let mut signed =
            SignedEnvelope::seal(plaintext, &[&receiver.age_recipient], &sender).unwrap();

        // Tamper with ciphertext
        if let Some(byte) = signed.ciphertext.last_mut() {
            *byte ^= 0xff;
        }

        let result = signed.open(&receiver, None);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_recipient_cannot_decrypt() {
        let sender = EnsealIdentity::generate();
        let receiver = EnsealIdentity::generate();
        let wrong_receiver = EnsealIdentity::generate();

        let plaintext = b"SECRET=value";
        let signed = SignedEnvelope::seal(plaintext, &[&receiver.age_recipient], &sender).unwrap();

        let result = signed.open(&wrong_receiver, None);
        assert!(result.is_err());
    }

    #[test]
    fn sender_mismatch_rejected() {
        let sender = EnsealIdentity::generate();
        let receiver = EnsealIdentity::generate();
        let fake_trusted = EnsealIdentity::generate();

        let plaintext = b"SECRET=value";
        let signed = SignedEnvelope::seal(plaintext, &[&receiver.age_recipient], &sender).unwrap();

        // Construct a TrustedKey from the fake_trusted identity
        let trusted = TrustedKey {
            identity: "fake@example.com".to_string(),
            age_recipient: fake_trusted.age_recipient.clone(),
            verifying_key: fake_trusted.signing_key.verifying_key(),
        };

        let result = signed.open(&receiver, Some(&trusted));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("sender key mismatch"));
    }
}
