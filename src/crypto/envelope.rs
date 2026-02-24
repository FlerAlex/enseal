use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::input::PayloadFormat;

/// The wire format for an enseal transfer.
#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub version: u32,
    pub format: PayloadFormat,
    pub metadata: Metadata,
    pub payload: String,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("version", &self.version)
            .field("format", &self.format)
            .field("metadata", &self.metadata)
            .field("payload", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub var_count: Option<usize>,
    pub label: Option<String>,
    pub sha256: String,
    pub project: Option<String>,
    /// Unix epoch seconds when the envelope was created.
    #[serde(default)]
    pub created_at: u64,
}

impl Envelope {
    /// Create a new envelope from plaintext content.
    pub fn seal(content: &str, format: PayloadFormat, label: Option<String>) -> Result<Self> {
        let sha256 = hex_sha256(content);

        let var_count = match format {
            PayloadFormat::Env => {
                let env = crate::env::parser::parse(content)?;
                Some(env.var_count())
            }
            PayloadFormat::Kv => Some(content.lines().filter(|l| l.contains('=')).count()),
            PayloadFormat::Raw => None,
        };

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            version: 1,
            format,
            metadata: Metadata {
                var_count,
                label,
                sha256,
                project: None,
                created_at,
            },
            payload: content.to_string(),
        })
    }

    /// Check that the envelope is not older than `max_age_secs`.
    /// Returns an error if the envelope is too old (replay protection).
    pub fn check_age(&self, max_age_secs: u64) -> Result<()> {
        if self.metadata.created_at == 0 {
            bail!("envelope has no timestamp (created_at is 0). This may indicate tampering or a replay attempt");
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Reject future timestamps (clock skew tolerance: 60 seconds)
        if self.metadata.created_at > now + 60 {
            bail!("envelope timestamp is in the future. Clock skew or tampering suspected");
        }
        let age = now.saturating_sub(self.metadata.created_at);
        if age > max_age_secs {
            bail!(
                "envelope expired: created {} seconds ago (max {})",
                age,
                max_age_secs
            );
        }
        Ok(())
    }

    /// Serialize the envelope to JSON bytes for transfer.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("failed to serialize envelope")
    }

    /// Deserialize an envelope from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() > 16 * 1024 * 1024 {
            bail!("envelope data exceeds maximum size (16 MiB)");
        }

        let envelope: Self =
            serde_json::from_slice(data).context("failed to deserialize envelope")?;

        // Validate version
        if envelope.version != 1 {
            bail!("unsupported envelope version: {}", envelope.version);
        }

        // Verify integrity
        let expected_hash = hex_sha256(&envelope.payload);
        if envelope.metadata.sha256 != expected_hash {
            bail!("integrity check failed: payload hash mismatch");
        }

        Ok(envelope)
    }
}

fn hex_sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_env() {
        let content = "KEY=value\nSECRET=hunter2\n";
        let envelope = Envelope::seal(content, PayloadFormat::Env, None).unwrap();
        assert_eq!(envelope.version, 1);
        assert_eq!(envelope.metadata.var_count, Some(2));

        let bytes = envelope.to_bytes().unwrap();
        let restored = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(restored.payload, content);
        assert_eq!(restored.format, PayloadFormat::Env);
    }

    #[test]
    fn round_trip_raw() {
        let content = "sk_live_abc123";
        let envelope =
            Envelope::seal(content, PayloadFormat::Raw, Some("Stripe key".to_string())).unwrap();
        assert_eq!(envelope.metadata.var_count, None);
        assert_eq!(envelope.metadata.label.as_deref(), Some("Stripe key"));

        let bytes = envelope.to_bytes().unwrap();
        let restored = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(restored.payload, content);
    }

    #[test]
    fn tampered_payload_rejected() {
        let content = "SECRET=value";
        let mut envelope = Envelope::seal(content, PayloadFormat::Kv, None).unwrap();
        envelope.payload = "SECRET=tampered".to_string();

        let bytes = envelope.to_bytes().unwrap();
        assert!(Envelope::from_bytes(&bytes).is_err());
    }
}
