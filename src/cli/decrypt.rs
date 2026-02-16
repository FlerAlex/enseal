use anyhow::Result;
use clap::Args;

use crate::crypto::at_rest;
use crate::env;
use crate::keys::identity::EnsealIdentity;
use crate::keys::store::KeyStore;
use crate::ui::display;

#[derive(Args)]
pub struct DecryptArgs {
    /// Path to encrypted .env file
    #[arg(default_value = ".env.encrypted")]
    pub file: String,

    /// Output path (default: strip .encrypted suffix, or <file>.decrypted)
    #[arg(long, short)]
    pub output: Option<String>,
}

pub fn run(args: DecryptArgs) -> Result<()> {
    let raw_content = std::fs::read(&args.file)
        .map_err(|e| anyhow::anyhow!("failed to read '{}': {}", args.file, e))?;

    // Auto-detect format before loading identity (fail fast on unencrypted files)
    let is_whole_file = at_rest::is_age_encrypted(&raw_content);

    let text = if !is_whole_file {
        let t = String::from_utf8(raw_content.clone())
            .map_err(|_| anyhow::anyhow!("file is not valid UTF-8 and not age-encrypted"))?;
        if !at_rest::is_per_var_encrypted(&t) {
            anyhow::bail!(
                "file '{}' doesn't appear to be encrypted (not age format, no ENC[age:...] values)",
                args.file
            );
        }
        Some(t)
    } else {
        None
    };

    let store = KeyStore::open()?;
    let identity = EnsealIdentity::load(&store)?;

    if is_whole_file {
        decrypt_whole_file(&args, &raw_content, &identity)
    } else {
        decrypt_per_var(&args, text.as_ref().unwrap(), &identity)
    }
}

fn decrypt_whole_file(
    args: &DecryptArgs,
    ciphertext: &[u8],
    identity: &EnsealIdentity,
) -> Result<()> {
    let plaintext = at_rest::decrypt_whole_file(ciphertext, &identity.age_identity)?;

    let output_path = args.output.clone().unwrap_or_else(|| {
        if args.file.ends_with(".encrypted") {
            args.file.trim_end_matches(".encrypted").to_string()
        } else {
            format!("{}.decrypted", args.file)
        }
    });

    std::fs::write(&output_path, &plaintext)
        .map_err(|e| anyhow::anyhow!("failed to write '{}': {}", output_path, e))?;

    let env_file = env::parser::parse(&String::from_utf8_lossy(&plaintext)).ok();
    let var_count = env_file.map(|e| e.var_count()).unwrap_or(0);

    if var_count > 0 {
        display::ok(&format!(
            "{} decrypted ({} variables)",
            output_path, var_count
        ));
    } else {
        display::ok(&format!("{} decrypted", output_path));
    }

    Ok(())
}

fn decrypt_per_var(args: &DecryptArgs, content: &str, identity: &EnsealIdentity) -> Result<()> {
    let env_file = env::parser::parse(content)?;
    let decrypted = at_rest::decrypt_per_var(&env_file, &identity.age_identity)?;
    let output_str = decrypted.to_string();

    let output_path = args.output.clone().unwrap_or_else(|| args.file.clone());

    std::fs::write(&output_path, &output_str)
        .map_err(|e| anyhow::anyhow!("failed to write '{}': {}", output_path, e))?;

    display::ok(&format!(
        "{} decrypted ({} variables)",
        output_path,
        decrypted.var_count()
    ));

    Ok(())
}
