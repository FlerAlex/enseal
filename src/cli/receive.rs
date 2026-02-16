use anyhow::Result;
use clap::Args;

use crate::cli::input::PayloadFormat;
use crate::crypto::envelope::Envelope;
use crate::env;
use crate::keys;
use crate::transfer;
use crate::ui::display;

#[derive(Args)]
pub struct ReceiveArgs {
    /// Wormhole share code or path to .env.age file
    pub code: String,

    /// Write to specific file (overrides format-based default)
    #[arg(long)]
    pub output: Option<String>,

    /// Copy received value to clipboard instead of stdout/file
    #[arg(long)]
    pub clipboard: bool,

    /// Print to stdout even for .env payloads (don't write file)
    #[arg(long)]
    pub no_write: bool,

    /// Use specific relay server
    #[arg(long, env = "ENSEAL_RELAY")]
    pub relay: Option<String>,

    /// Minimal output
    #[arg(long, short)]
    pub quiet: bool,
}

pub async fn run(args: ReceiveArgs) -> Result<()> {
    // Detect mode: file drop (.env.age file) vs wormhole code
    let is_file = std::path::Path::new(&args.code).exists() && args.code.ends_with(".age");

    let envelope = if is_file {
        receive_filedrop(&args)?
    } else {
        receive_wormhole(&args).await?
    };

    output_envelope(&args, &envelope)
}

async fn receive_wormhole(args: &ReceiveArgs) -> Result<Envelope> {
    // Try identity mode first: if we have keys initialized, use identity receive
    // But wormhole codes work the same for both — the envelope content tells us
    // whether it's signed or not.
    // For now, try to receive as signed first, fall back to anonymous.
    let store = keys::store::KeyStore::open()?;

    if store.is_initialized() {
        // Try receiving as identity-mode (signed envelope)
        let own_identity = keys::identity::EnsealIdentity::load(&store)?;
        match transfer::identity::receive(
            &args.code,
            &own_identity,
            None, // Don't require specific sender
            args.relay.as_deref(),
        )
        .await
        {
            Ok((envelope, sender_pubkey)) => {
                if !args.quiet {
                    display::info("From:", &sender_pubkey);
                    display::ok("signature verified");
                }
                return Ok(envelope);
            }
            Err(_) => {
                // Not an identity-mode transfer, try anonymous
                tracing::debug!("not an identity-mode transfer, trying anonymous");
            }
        }
    }

    // Anonymous mode
    let envelope = transfer::wormhole::receive(&args.code, args.relay.as_deref()).await?;
    Ok(envelope)
}

fn receive_filedrop(args: &ReceiveArgs) -> Result<Envelope> {
    let store = keys::store::KeyStore::open()?;
    let own_identity = keys::identity::EnsealIdentity::load(&store)?;

    let path = std::path::Path::new(&args.code);
    let (envelope, sender_pubkey) = transfer::filedrop::read(path, &own_identity, None)?;

    if !args.quiet {
        display::info("From:", &sender_pubkey);
        display::ok("signature verified, file decrypted");
    }

    Ok(envelope)
}

fn output_envelope(args: &ReceiveArgs, envelope: &Envelope) -> Result<()> {
    let payload = &envelope.payload;

    // Show metadata
    if !args.quiet {
        if let Some(count) = envelope.metadata.var_count {
            display::info("Secrets:", &format!("{} variables", count));
        }
        if let Some(ref label) = envelope.metadata.label {
            display::info("Label:", label);
        }
    }

    // Handle clipboard
    if args.clipboard {
        let mut clipboard = arboard::Clipboard::new()?;
        clipboard.set_text(payload)?;
        if let Some(ref label) = envelope.metadata.label {
            display::ok(&format!("copied to clipboard (label: \"{}\")", label));
        } else {
            display::ok("copied to clipboard");
        }
        return Ok(());
    }

    // Schema validation on receive (non-blocking warnings)
    if matches!(envelope.format, PayloadFormat::Env) {
        validate_against_schema(payload, args.quiet);
    }

    // Route output based on format
    match envelope.format {
        PayloadFormat::Env => {
            if args.no_write {
                print!("{}", payload);
            } else {
                let path = args.output.as_deref().unwrap_or(".env");
                std::fs::write(path, payload)?;
                let count = envelope.metadata.var_count.unwrap_or(0);
                display::ok(&format!("{} secrets written to {}", count, path));
            }
        }
        PayloadFormat::Raw => {
            if let Some(ref path) = args.output {
                std::fs::write(path, payload)?;
                display::ok(&format!("written to {}", path));
            } else {
                print!("{}", payload);
            }
        }
        PayloadFormat::Kv => {
            if let Some(ref path) = args.output {
                std::fs::write(path, payload)?;
                display::ok(&format!("written to {}", path));
            } else {
                println!("{}", payload);
            }
        }
    }

    Ok(())
}

/// Run schema validation against received .env payload.
/// Emits warnings but never blocks the receive.
fn validate_against_schema(payload: &str, quiet: bool) {
    if quiet {
        return;
    }

    let schema = match env::schema::load_schema(None) {
        Ok(Some(s)) => s,
        _ => return, // No schema or error loading — skip silently
    };

    let env_file = match env::parser::parse(payload) {
        Ok(f) => f,
        Err(_) => return,
    };

    let errors = env::schema::validate(&env_file, &schema);
    if !errors.is_empty() {
        display::warning("received .env has schema validation issues:");
        for err in &errors {
            display::warning(&format!("  {}", err));
        }
    }
}
