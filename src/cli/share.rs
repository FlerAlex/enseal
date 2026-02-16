use anyhow::Result;
use clap::Args;

use crate::cli::input;
use crate::crypto::envelope::Envelope;
use crate::env::{self, filter};
use crate::keys;
use crate::transfer;
use crate::ui::display;

#[derive(Args)]
pub struct ShareArgs {
    /// Path to .env file to share
    pub file: Option<String>,

    /// Inline secret: raw string or KEY=VALUE pair
    #[arg(long)]
    pub secret: Option<String>,

    /// Human label for raw/piped secrets
    #[arg(long)]
    pub label: Option<String>,

    /// Wrap raw string as KEY=<value> for .env-compatible receive
    #[arg(long, value_name = "KEY")]
    pub r#as: Option<String>,

    /// Identity mode: encrypt to named recipient (alias or identity)
    #[arg(long)]
    pub to: Option<String>,

    /// File drop: write encrypted file instead of network transfer (identity mode)
    #[arg(long)]
    pub output: Option<String>,

    /// Number of words in wormhole code (2-5)
    #[arg(long, default_value = "2")]
    pub words: usize,

    /// Regex to exclude vars
    #[arg(long)]
    pub exclude: Option<String>,

    /// Regex to include only matching vars
    #[arg(long)]
    pub include: Option<String>,

    /// Send raw file, skip .env parsing
    #[arg(long)]
    pub no_filter: bool,

    /// Use specific relay server
    #[arg(long, env = "ENSEAL_RELAY")]
    pub relay: Option<String>,

    /// Channel expiry in seconds
    #[arg(long, default_value = "300")]
    pub timeout: u64,

    /// Minimal output
    #[arg(long, short)]
    pub quiet: bool,
}

pub async fn run(args: ShareArgs) -> Result<()> {
    // 1. Detect and read input
    let payload = input::select_input(
        args.secret.as_deref(),
        args.r#as.as_deref(),
        args.label.as_deref(),
        args.file.as_deref(),
        args.quiet,
    )?;

    // 2. For .env payloads, parse and filter
    let content = if payload.format == input::PayloadFormat::Env && !args.no_filter {
        let env_file = env::parser::parse(&payload.content)?;

        // Run validation warnings
        let issues = env::validator::validate(&env_file);
        for issue in &issues {
            display::warning(&issue.message);
        }

        // Apply filters
        let filtered =
            filter::filter(&env_file, args.include.as_deref(), args.exclude.as_deref())?;

        filtered.to_string()
    } else {
        payload.content.clone()
    };

    // 3. Create envelope
    let envelope = Envelope::seal(&content, payload.format.clone(), payload.label.clone())?;

    // 4. Display pre-send info
    if !args.quiet {
        if let Some(count) = envelope.metadata.var_count {
            display::info("Secrets:", &format!("{} variables", count));
        }
        if let Some(ref label) = envelope.metadata.label {
            display::info("Label:", label);
        }
    }

    // 5. Route based on mode: identity (--to) vs anonymous (wormhole)
    if let Some(ref recipient_name) = args.to {
        send_identity_mode(&args, &envelope, recipient_name).await
    } else {
        send_anonymous_mode(&args, &envelope).await
    }
}

async fn send_anonymous_mode(args: &ShareArgs, envelope: &Envelope) -> Result<()> {
    if !args.quiet {
        display::info(
            "Expires:",
            &format!("{} seconds or first receive", args.timeout),
        );
    }

    let code = transfer::wormhole::send(envelope, args.relay.as_deref(), args.words).await?;

    if !args.quiet {
        display::info("Share code:", &code);
    } else {
        println!("{}", code);
    }

    display::ok("sent");
    Ok(())
}

async fn send_identity_mode(
    args: &ShareArgs,
    envelope: &Envelope,
    recipient_name: &str,
) -> Result<()> {
    // Resolve recipient
    let identity_name = keys::resolve_recipient(recipient_name)?;

    let store = keys::store::KeyStore::open()?;
    let sender = keys::identity::EnsealIdentity::load(&store)?;
    let recipient = keys::identity::TrustedKey::load(&store, &identity_name)?;

    if !args.quiet {
        display::info("To:", &identity_name);
        display::info("Fingerprint:", &recipient.fingerprint());
    }

    if let Some(ref output_dir) = args.output {
        // File drop mode
        let dest = transfer::filedrop::write(
            envelope,
            &recipient,
            &sender,
            std::path::Path::new(output_dir),
        )?;
        display::ok(&format!(
            "encrypted to {}, written to {}",
            identity_name,
            dest.display()
        ));
    } else {
        // Identity relay mode
        let code = transfer::identity::send(
            envelope,
            &recipient,
            &sender,
            args.relay.as_deref(),
            args.words,
        )
        .await?;

        if !args.quiet {
            display::info("Share code:", &code);
        } else {
            println!("{}", code);
        }

        display::ok(&format!("encrypted to {}, signed by you", identity_name));
    }

    Ok(())
}
