pub mod check;
pub mod diff;
pub mod input;
pub mod keys;
pub mod receive;
pub mod redact;
pub mod share;

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

    /// Receive secrets via wormhole code
    Receive(receive::ReceiveArgs),

    /// Verify .env has all vars from .env.example
    Check(check::CheckArgs),

    /// Show missing/extra vars between two .env files (keys only)
    Diff(diff::DiffArgs),

    /// Output .env with values replaced by <REDACTED>
    Redact(redact::RedactArgs),

    /// Manage identity keys, aliases, and trusted keys
    Keys(keys::KeysArgs),
}
