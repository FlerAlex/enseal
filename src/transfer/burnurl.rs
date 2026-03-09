use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const BURNURL_DEFAULT_BASE: &str = "https://burnurl.dev";
const BURNURL_ENV_VAR: &str = "BURNURL_URL";
/// API key env var — requires Pro or Team plan on burnurl.dev; free tier is unauthenticated.
const BURNURL_API_KEY_VAR: &str = "BURNURL_API_KEY";
/// Standard plan payload cap (10 KB); Pro/Team plans allow up to 100 KB.
const MAX_PAYLOAD_BYTES: usize = 10 * 1024;
const UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct UploadConfig {
    pub base_url: String,
    pub ttl_hours: u32,
    /// Client-side age/scrypt passphrase encryption. The passphrase is never transmitted.
    pub passphrase: Option<String>,
    /// Optional API key (Bearer token). Falls back to `BURNURL_API_KEY` env var.
    pub api_key: Option<String>,
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            base_url: BURNURL_DEFAULT_BASE.to_string(),
            ttl_hours: 24,
            passphrase: None,
            api_key: None,
        }
    }
}

pub struct UploadResult {
    pub url: String,
    pub expires_at: String,
}

#[derive(Error, Debug)]
pub enum UploadError {
    #[error("rate limited by burnurl.dev — try again in a few minutes")]
    RateLimited,
    #[error("payload too large (10KB max on standard plans)")]
    PayloadTooLarge,
    #[error("authentication failed — check BURNURL_API_KEY")]
    Unauthorized,
    #[error("burnurl.dev unavailable — fall back to: enseal share")]
    ServerError,
    #[error("upload timed out — check connection or use relay instead")]
    Timeout,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Serialize)]
struct SecretRequest {
    payload: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_hours: Option<u32>,
}

#[derive(Deserialize)]
struct SecretResponse {
    url: String,
    expires_at: String,
}

/// Upload `payload` bytes to burnurl.dev and return the secret URL.
/// If `config.passphrase` is set, the payload is age-encrypted with a scrypt
/// passphrase recipient before upload. The passphrase is never transmitted.
pub async fn upload_secret(
    payload: &[u8],
    config: &UploadConfig,
) -> Result<UploadResult, UploadError> {
    let encoded_payload = if let Some(ref passphrase) = config.passphrase {
        // Client-side age encryption: binary output, must be base64 for JSON transport.
        // The passphrase is never transmitted.
        let ciphertext =
            encrypt_with_passphrase(payload, passphrase).map_err(UploadError::Other)?;
        if ciphertext.len() > MAX_PAYLOAD_BYTES {
            return Err(UploadError::PayloadTooLarge);
        }
        STANDARD.encode(&ciphertext)
    } else {
        // Envelope JSON is valid UTF-8; send as-is (still check size).
        let s = std::str::from_utf8(payload)
            .context("envelope is not valid UTF-8")
            .map_err(UploadError::Other)?;
        if s.len() > MAX_PAYLOAD_BYTES {
            return Err(UploadError::PayloadTooLarge);
        }
        s.to_string()
    };

    let request = SecretRequest {
        payload: encoded_payload,
        ttl_hours: Some(config.ttl_hours),
    };

    let base_url = std::env::var(BURNURL_ENV_VAR).unwrap_or_else(|_| config.base_url.clone());
    let api_url = format!("{}/api/secret", base_url.trim_end_matches('/'));

    // API key: explicit config value takes precedence over env var.
    let api_key = config
        .api_key
        .clone()
        .or_else(|| std::env::var(BURNURL_API_KEY_VAR).ok());

    let client = reqwest::Client::new();
    let mut req = client.post(&api_url).json(&request);
    if let Some(ref key) = api_key {
        req = req.bearer_auth(key);
    }

    let response = tokio::time::timeout(UPLOAD_TIMEOUT, req.send())
        .await
        .map_err(|_| UploadError::Timeout)?
        .context("failed to connect to burnurl.dev")
        .map_err(UploadError::Other)?;

    match response.status().as_u16() {
        201 => {
            let result: SecretResponse = response
                .json()
                .await
                .context("failed to parse burnurl.dev response")
                .map_err(UploadError::Other)?;
            Ok(UploadResult {
                url: result.url,
                expires_at: result.expires_at,
            })
        }
        401 => Err(UploadError::Unauthorized),
        413 => Err(UploadError::PayloadTooLarge),
        429 => Err(UploadError::RateLimited),
        _ => Err(UploadError::ServerError),
    }
}

/// Encrypt `plaintext` with age using a scrypt passphrase recipient.
/// Produces age-format ciphertext; the passphrase is required to decrypt.
fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    use std::io::Write;

    let passphrase_secret = age::secrecy::SecretString::new(Box::from(passphrase));
    let recipient = age::scrypt::Recipient::new(passphrase_secret);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| anyhow::anyhow!("failed to create age encryptor: {}", e))?;

    let mut output = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut output)
        .context("failed to initialize age encryption")?;
    writer
        .write_all(plaintext)
        .context("failed to write plaintext")?;
    writer.finish().context("failed to finalize encryption")?;

    Ok(output)
}
