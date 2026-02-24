use anyhow::Result;
use clap::Args;

use crate::cli::input;
use crate::crypto::envelope::Envelope;
use crate::crypto::signing::SignedEnvelope;
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
    #[arg(long, default_value = "2", value_parser = clap::value_parser!(u16).range(2..=5))]
    pub words: u16,

    /// Regex to exclude vars
    #[arg(long)]
    pub exclude: Option<String>,

    /// Regex to include only matching vars
    #[arg(long)]
    pub include: Option<String>,

    /// Don't resolve ${VAR} references before sending
    #[arg(long)]
    pub no_interpolate: bool,

    /// Environment profile (resolves to .env.<name>)
    #[arg(long, value_name = "NAME")]
    pub env: Option<String>,

    /// Send raw file, skip .env parsing
    #[arg(long)]
    pub no_filter: bool,

    /// Use specific relay server
    #[arg(long, env = "ENSEAL_RELAY")]
    pub relay: Option<String>,

    /// Minimal output
    #[arg(long, short)]
    pub quiet: bool,
}

pub async fn run(args: ShareArgs) -> Result<()> {
    // Reject conflicting --env and file argument
    if args.env.is_some() && args.file.is_some() {
        anyhow::bail!("--env and a file argument are mutually exclusive");
    }

    // --output requires --to (file drop is identity mode only)
    if args.output.is_some() && args.to.is_none() {
        anyhow::bail!("--output requires --to (file drop is only available in identity mode)");
    }

    // --no-filter skips all processing; reject contradictory filter flags
    if args.no_filter && (args.include.is_some() || args.exclude.is_some()) {
        anyhow::bail!("--no-filter cannot be used with --include or --exclude");
    }

    // 1. Resolve file via profile if --env is set
    let file_arg = if let Some(ref profile) = args.env {
        let resolved = env::profile::resolve(profile, std::path::Path::new("."))?;
        Some(resolved.to_string_lossy().into_owned())
    } else {
        args.file.clone()
    };

    // 2. Detect and read input
    let payload = input::select_input(
        args.secret.as_deref(),
        args.r#as.as_deref(),
        args.label.as_deref(),
        file_arg.as_deref(),
        args.quiet,
    )?;

    // 3. For .env payloads, parse, interpolate, and filter
    let content = if payload.format == input::PayloadFormat::Env && !args.no_filter {
        let env_file = env::parser::parse(&payload.content)?;

        // Run validation warnings
        if !args.quiet {
            let issues = env::validator::validate(&env_file);
            for issue in &issues {
                display::warning(&issue.message);
            }
        }

        // Interpolate ${VAR} references (unless --no-interpolate)
        let env_file = if args.no_interpolate {
            env_file
        } else {
            env::interpolation::interpolate(&env_file)?
        };

        // Apply filters
        let filtered = filter::filter(&env_file, args.include.as_deref(), args.exclude.as_deref())?;

        if filtered.var_count() == 0 {
            anyhow::bail!("all variables were filtered out (check --include/--exclude patterns)");
        }

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
    let (code, mailbox) =
        transfer::wormhole::create_mailbox(args.relay.as_deref(), args.words.into()).await?;

    if !args.quiet {
        display::info("Share code:", &code);
        display::info("Expires:", "on first receive (server-dependent TTL)");
    } else {
        println!("{}", code);
    }

    transfer::wormhole::send(envelope, mailbox).await?;

    if !args.quiet {
        display::ok("sent");
    }
    Ok(())
}

async fn send_identity_mode(
    args: &ShareArgs,
    envelope: &Envelope,
    recipient_name: &str,
) -> Result<()> {
    // Resolve recipient (may be alias, group, or literal identity)
    let identities = keys::resolve_to_identities(recipient_name)?;

    let store = keys::store::KeyStore::open()?;
    let sender = keys::identity::EnsealIdentity::load(&store)?;

    // Load all trusted keys and collect age recipients
    let trusted_keys: Vec<keys::identity::TrustedKey> = identities
        .iter()
        .map(|id| keys::identity::TrustedKey::load(&store, id))
        .collect::<Result<Vec<_>>>()?;
    let age_recipients: Vec<&age::x25519::Recipient> =
        trusted_keys.iter().map(|k| &k.age_recipient).collect();

    let display_name = if identities.len() == 1 {
        identities[0].clone()
    } else {
        format!("{} ({} recipients)", recipient_name, identities.len())
    };

    if !args.quiet {
        display::info("To:", &display_name);
        if identities.len() == 1 {
            display::info("Fingerprint:", &trusted_keys[0].fingerprint());
        }
    }

    if let Some(ref output_dir) = args.output {
        // File drop mode — use group name or identity for filename
        let filename = if identities.len() > 1 {
            recipient_name.to_string()
        } else {
            identities[0].clone()
        };
        let dest = transfer::filedrop::write(
            envelope,
            &age_recipients,
            &sender,
            std::path::Path::new(output_dir),
            &filename,
        )?;
        if !args.quiet {
            display::ok(&format!(
                "encrypted to {}, written to {}",
                display_name,
                dest.display()
            ));
        }
    } else if let Some(ref relay_url) = args.relay {
        // Enseal relay push mode — no code needed
        let inner_bytes = envelope.to_bytes()?;
        let signed = SignedEnvelope::seal(&inner_bytes, &age_recipients, &sender)?;
        let wire_bytes = signed.to_bytes()?;

        // Push to all recipients' channels (important for groups)
        for tk in &trusted_keys {
            let channel_id = tk.channel_id();
            transfer::relay::push(&wire_bytes, relay_url, &channel_id).await?;
        }

        if !args.quiet {
            display::ok(&format!("pushed to {}", display_name));
        }
    } else {
        // Wormhole mode (default) — display code before sending
        let (code, wire_bytes, mailbox) = transfer::identity::create_mailbox(
            envelope,
            &age_recipients,
            &sender,
            None,
            args.words.into(),
        )
        .await?;

        if !args.quiet {
            display::info("Share code:", &code);
            display::info("Expires:", "on first receive (server-dependent TTL)");
        } else {
            println!("{}", code);
        }

        transfer::identity::send(wire_bytes, mailbox).await?;

        if !args.quiet {
            display::ok(&format!("encrypted to {}, signed by you", display_name));
        }
    }

    Ok(())
}
