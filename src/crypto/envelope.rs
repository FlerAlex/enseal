use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::input::PayloadFormat;

/// The wire format for an enseal transfer.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u32,
    pub format: PayloadFormat,
    pub metadata: Metadata,
    pub payload: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub var_count: Option<usize>,
    pub label: Option<String>,
    pub sha256: String,
    pub project: Option<String>,
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

        Ok(Self {
            version: 1,
            format,
            metadata: Metadata {
                var_count,
                label,
                sha256,
                project: None,
            },
            payload: content.to_string(),
        })
    }

    /// Serialize the envelope to JSON bytes for transfer.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("failed to serialize envelope")
    }

    /// Deserialize an envelope from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let envelope: Self =
            serde_json::from_slice(data).context("failed to deserialize envelope")?;

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
