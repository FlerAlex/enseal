use anyhow::{bail, Result};
use clap::Args;

use crate::crypto::at_rest;
use crate::env;
use crate::keys::identity::EnsealIdentity;
use crate::keys::store::KeyStore;
use crate::ui::display;

#[derive(Args)]
pub struct EncryptArgs {
    /// Path to .env file to encrypt
    #[arg(default_value = ".env")]
    pub file: String,

    /// Output path (default: <file>.encrypted for whole-file, in-place for per-var)
    #[arg(long, short)]
    pub output: Option<String>,

    /// Per-variable encryption (keys visible, values encrypted)
    #[arg(long)]
    pub per_var: bool,

    /// Encrypt to specific recipient(s) (can be repeated)
    #[arg(long)]
    pub to: Vec<String>,

    /// Overwrite existing files without prompting
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: EncryptArgs) -> Result<()> {
    let content = std::fs::read_to_string(&args.file)
        .map_err(|e| anyhow::anyhow!("failed to read '{}': {}", args.file, e))?;

    // Collect recipients: either from --to flags or use own key
    let recipients = resolve_recipients(&args.to)?;
    let recipient_refs: Vec<&age::x25519::Recipient> = recipients.iter().collect();

    if args.per_var {
        encrypt_per_var(&args, &content, &recipient_refs)
    } else {
        encrypt_whole_file(&args, &content, &recipient_refs)
    }
}

fn encrypt_whole_file(
    args: &EncryptArgs,
    content: &str,
    recipients: &[&age::x25519::Recipient],
) -> Result<()> {
    let ciphertext = at_rest::encrypt_whole_file(content.as_bytes(), recipients)?;

    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| format!("{}.encrypted", args.file));

    check_overwrite(&output_path, args.force)?;
    write_secret_file(&output_path, &ciphertext)
        .map_err(|e| anyhow::anyhow!("failed to write '{}': {}", output_path, e))?;

    let env_file = env::parser::parse(content).ok();
    let var_count = env_file.map(|e| e.var_count()).unwrap_or(0);

    if var_count > 0 {
        display::ok(&format!(
            "{} encrypted ({} variables, age key)",
            output_path, var_count
        ));
    } else {
        display::ok(&format!("{} encrypted (age key)", output_path));
    }

    Ok(())
}

fn encrypt_per_var(
    args: &EncryptArgs,
    content: &str,
    recipients: &[&age::x25519::Recipient],
) -> Result<()> {
    let env_file = env::parser::parse(content)?;

    // Check if already encrypted
    if at_rest::is_per_var_encrypted(content) {
        bail!("file already contains per-variable encrypted values");
    }

    let encrypted = at_rest::encrypt_per_var(&env_file, recipients)?;
    let output_str = encrypted.to_string();

    let output_path = args.output.clone().unwrap_or_else(|| args.file.clone());

    if output_path == args.file {
        display::warning("per-var encryption will replace the plaintext file in-place");
    }
    check_overwrite(&output_path, args.force)?;
    write_secret_file(&output_path, output_str.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to write '{}': {}", output_path, e))?;

    display::ok(&format!(
        "{} encrypted ({} variables, per-variable, age key)",
        output_path,
        env_file.var_count()
    ));

    Ok(())
}

/// Write a file with restrictive permissions (0600 on Unix).
fn write_secret_file(path: &str, content: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)?;
    }
    Ok(())
}

/// Check if the target file exists and handle overwrite confirmation.
fn check_overwrite(path: &str, force: bool) -> Result<()> {
    if !std::path::Path::new(path).exists() {
        return Ok(());
    }
    if force {
        return Ok(());
    }
    if !is_terminal::is_terminal(std::io::stdin()) {
        bail!(
            "'{}' already exists. Use --force to overwrite in non-interactive mode",
            path
        );
    }
    let confirm = dialoguer::Confirm::new()
        .with_prompt(format!("'{}' already exists. Overwrite?", path))
        .default(false)
        .interact()?;
    if !confirm {
        bail!("aborted: not overwriting '{}'", path);
    }
    Ok(())
}

/// Resolve recipients from --to flags or use own key.
fn resolve_recipients(to: &[String]) -> Result<Vec<age::x25519::Recipient>> {
    if to.is_empty() {
        // Use own key
        let store = KeyStore::open()?;
        let identity = EnsealIdentity::load(&store)?;
        return Ok(vec![identity.age_recipient]);
    }

    let store = KeyStore::open()?;
    let mut recipients = Vec::new();

    for name in to {
        let identities = crate::keys::resolve_to_identities(name)?;
        for id in &identities {
            let trusted = crate::keys::identity::TrustedKey::load(&store, id)?;
            recipients.push(trusted.age_recipient);
        }
    }

    // Also include own key so the sender can decrypt too
    if store.is_initialized() {
        let identity = EnsealIdentity::load(&store)?;
        recipients.push(identity.age_recipient);
    }

    Ok(recipients)
}
