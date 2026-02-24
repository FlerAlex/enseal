use std::io::Read;

use anyhow::{bail, Result};
use is_terminal::IsTerminal;

use crate::ui::display;

/// The format of the payload to be sent.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadFormat {
    /// Full .env file content.
    Env,
    /// Raw string (single secret, token, password).
    Raw,
    /// One or more KEY=VALUE pairs.
    Kv,
}

/// Resolved input ready for transfer.
#[derive(Debug)]
pub struct PayloadInput {
    pub content: String,
    pub format: PayloadFormat,
    pub label: Option<String>,
}

/// Determine what to send and its format.
/// Priority: --secret flag > stdin pipe > file argument > default .env
pub fn select_input(
    secret: Option<&str>,
    as_key: Option<&str>,
    label: Option<&str>,
    file: Option<&str>,
    quiet: bool,
) -> Result<PayloadInput> {
    // Validate label early if provided
    if let Some(label) = label {
        if label.len() > 256 {
            bail!("label is too long (max 256 characters)");
        }
        if label.contains('\n') || label.contains('\r') || label.contains('\0') {
            bail!("label contains invalid characters (newlines or null bytes)");
        }
    }

    // Reject incompatible flag combinations early
    if secret.is_some() && as_key.is_some() {
        bail!("--as cannot be used with --secret. Use --secret KEY=VALUE instead");
    }
    if as_key.is_some() && secret.is_none() && std::io::stdin().is_terminal() {
        bail!(
            "--as can only be used with piped stdin input. Usage: cat file | enseal share --as KEY"
        );
    }

    // 1. Inline secret (--secret flag)
    if let Some(secret) = secret {
        if !quiet {
            display::warning(
                "--secret puts the value in shell history. \
                 Consider piping instead: echo \"...\" | enseal share",
            );
        }

        if let Some(eq_pos) = secret.find('=') {
            let key_part = &secret[..eq_pos];
            // Only classify as KV if the part before = looks like a valid env var name
            if !key_part.is_empty()
                && key_part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Ok(PayloadInput {
                    content: secret.to_string(),
                    format: PayloadFormat::Kv,
                    label: label.map(|s| s.to_string()),
                });
            }
        }

        return Ok(PayloadInput {
            content: secret.to_string(),
            format: PayloadFormat::Raw,
            label: label.map(|s| s.to_string()),
        });
    }

    // 2. Stdin pipe (non-TTY stdin)
    if !std::io::stdin().is_terminal() {
        const MAX_STDIN_SIZE: u64 = 10 * 1024 * 1024; // 10 MB
        let mut buf = String::new();
        std::io::stdin()
            .take(MAX_STDIN_SIZE + 1)
            .read_to_string(&mut buf)?;
        if buf.len() as u64 > MAX_STDIN_SIZE {
            bail!("stdin input exceeds maximum size (10 MB)");
        }
        let buf = buf.trim_end_matches('\n').to_string();
        if buf.is_empty() {
            bail!("empty input from stdin");
        }

        // --as flag wraps raw input as KEY=VALUE
        if let Some(key) = as_key {
            if key.is_empty()
                || key.starts_with(|c: char| c.is_ascii_digit())
                || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                bail!(
                    "--as value '{}' is not a valid env var name (use A-Z, 0-9, _)",
                    key
                );
            }
            if buf.contains('\n') {
                bail!("--as cannot wrap multi-line input as a single KEY=VALUE pair");
            }
            return Ok(PayloadInput {
                content: format!("{key}={buf}"),
                format: PayloadFormat::Kv,
                label: label.map(|s| s.to_string()),
            });
        }

        // Auto-detect format: try dotenvy parsing first, fall back to raw.
        let format = if try_parse_dotenv(&buf) {
            PayloadFormat::Env
        } else if buf.contains('=') && buf.lines().count() == 1 {
            PayloadFormat::Kv
        } else {
            PayloadFormat::Raw
        };

        return Ok(PayloadInput {
            content: buf,
            format,
            label: label.map(|s| s.to_string()),
        });
    }

    // 3. File argument or default .env
    let path = file.unwrap_or(".env");
    if !std::path::Path::new(path).exists() {
        bail!("{} not found", path);
    }
    let content = std::fs::read_to_string(path)?;
    if content.trim().is_empty() {
        bail!("{} is empty", path);
    }
    Ok(PayloadInput {
        content,
        format: PayloadFormat::Env,
        label: label.map(|s| s.to_string()),
    })
}

/// Attempt to parse a string as .env content using dotenvy.
/// Returns true if the string contains at least one valid KEY=VALUE pair.
fn try_parse_dotenv(s: &str) -> bool {
    let vars: Vec<_> = dotenvy::from_read_iter(s.as_bytes()).collect();
    if vars.is_empty() {
        return false;
    }
    // At least one must parse successfully
    vars.iter().any(|r| r.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_parse_dotenv_single_var() {
        assert!(try_parse_dotenv("API_KEY=abc123"));
    }

    #[test]
    fn try_parse_dotenv_multiple_vars() {
        assert!(try_parse_dotenv("A=1\nB=2\nC=3"));
    }

    #[test]
    fn try_parse_dotenv_raw_string() {
        assert!(!try_parse_dotenv("just a plain string"));
    }

    #[test]
    fn try_parse_dotenv_empty() {
        assert!(!try_parse_dotenv(""));
    }

    #[test]
    fn try_parse_dotenv_comments_only() {
        assert!(!try_parse_dotenv("# just a comment\n# another"));
    }
}
