use anyhow::Result;
use clap::Args;

use crate::cli::input::PayloadFormat;
use crate::transfer;
use crate::ui::display;

#[derive(Args)]
pub struct ReceiveArgs {
    /// Wormhole share code
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
    // 1. Receive via wormhole
    let envelope = transfer::wormhole::receive(&args.code, args.relay.as_deref()).await?;

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

    // 2. Handle clipboard
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

    // 3. Route output based on format
    match envelope.format {
        PayloadFormat::Env => {
            if args.no_write {
                // Force stdout
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
                // Raw goes to stdout, metadata to stderr
                print!("{}", payload);
            }
        }
        PayloadFormat::Kv => {
            if let Some(ref path) = args.output {
                std::fs::write(path, payload)?;
                display::ok(&format!("written to {}", path));
            } else {
                // KV goes to stdout
                println!("{}", payload);
            }
        }
    }

    Ok(())
}
