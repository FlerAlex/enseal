pub mod check;
pub mod decrypt;
pub mod diff;
pub mod encrypt;
pub mod inject;
pub mod input;
pub mod keys;
pub mod receive;
pub mod redact;
#[cfg(feature = "server")]
pub mod serve;
pub mod share;
pub mod template;
pub mod validate;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "enseal", about = "Secure, ephemeral secret sharing for developers")]
#[command(version, propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Show debug output (never prints secret values)
    #[arg(long, short, global = true)]
    pub verbose: bool,

    /// Minimal output (for scripting)
    #[arg(long, short, global = true)]
    pub quiet: bool,

    /// Path to .enseal.toml manifest
    #[arg(long, global = true)]
    pub config: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Send a .env file, piped input, or inline secret
    Share(share::ShareArgs),

    /// Receive secrets via wormhole code or encrypted file
    Receive(receive::ReceiveArgs),

    /// Receive secrets and inject into a child process (no file on disk)
    Inject(inject::InjectArgs),

    /// Verify .env has all vars from .env.example
    Check(check::CheckArgs),

    /// Show missing/extra vars between two .env files (keys only)
    Diff(diff::DiffArgs),

    /// Output .env with values replaced by <REDACTED>
    Redact(redact::RedactArgs),

    /// Validate .env against schema rules in .enseal.toml
    Validate(validate::ValidateArgs),

    /// Generate .env.example from a real .env with type hints
    Template(template::TemplateArgs),

    /// Encrypt a .env file for safe storage (age-based)
    Encrypt(encrypt::EncryptArgs),

    /// Decrypt an at-rest encrypted .env file
    Decrypt(decrypt::DecryptArgs),

    /// Manage identity keys, aliases, and trusted keys
    Keys(keys::KeysArgs),

    /// Run the enseal relay server
    #[cfg(feature = "server")]
    Serve(serve::ServeArgs),
}
