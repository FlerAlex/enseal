use std::collections::HashMap;
use std::process::{Command, Stdio};

use anyhow::{bail, Result};
use clap::Args;

use crate::cli::input::PayloadFormat;
use crate::crypto::envelope::Envelope;
use crate::crypto::signing::SignedEnvelope;
use crate::keys;
use crate::transfer;
use crate::ui::display;

#[derive(Args)]
pub struct InjectArgs {
    /// Wormhole share code or path to .env.age file
    pub code: Option<String>,

    /// Listen for incoming identity-mode transfer (requires --relay)
    #[arg(long)]
    pub listen: bool,

    /// Separator between inject args and the command to run
    #[arg(
        last = true,
        required = true,
        value_name = "CMD",
        num_args = 1..,
    )]
    pub command: Vec<String>,

    /// Use specific relay server
    #[arg(long, env = "ENSEAL_RELAY")]
    pub relay: Option<String>,

    /// Minimal output
    #[arg(long, short)]
    pub quiet: bool,
}

pub async fn run(args: InjectArgs) -> Result<()> {
    if args.command.is_empty() {
        bail!("no command specified. Usage: enseal inject <code> -- <command>");
    }

    if !args.listen && args.code.is_none() {
        bail!("provide a wormhole code or use --listen. Usage: enseal inject <code> -- <command>");
    }

    if args.listen && args.code.is_some() {
        bail!("--listen and a wormhole code are mutually exclusive");
    }

    // 1. Receive the envelope
    let envelope = if args.listen {
        listen_mode(&args).await?
    } else {
        receive_envelope(&args).await?
    };

    // 2. Extract secrets as env vars
    let secrets = extract_secrets(&envelope)?;

    if !args.quiet {
        display::info("Secrets:", &format!("{} variables", secrets.len()));
        display::ok("injecting into process environment");
    }

    // 3. Spawn child with secrets in env
    run_child(&args.command, &secrets)
}

async fn receive_envelope(args: &InjectArgs) -> Result<Envelope> {
    let code = args.code.as_deref().expect("code required in non-listen mode");

    // Detect mode: file drop (.env.age file) vs wormhole code
    let is_file = std::path::Path::new(code).exists() && code.ends_with(".age");

    if is_file {
        let store = keys::store::KeyStore::open()?;
        let own_identity = keys::identity::EnsealIdentity::load(&store)?;
        let path = std::path::Path::new(code);
        let (envelope, sender_pubkey) = transfer::filedrop::read(path, &own_identity, None)?;
        if !args.quiet {
            display::info("From:", &sender_pubkey);
            display::ok("signature verified, file decrypted");
        }
        Ok(envelope)
    } else {
        // Try identity mode first, then anonymous
        let store = keys::store::KeyStore::open()?;
        if store.is_initialized() {
            let own_identity = keys::identity::EnsealIdentity::load(&store)?;
            match transfer::identity::receive(
                code,
                &own_identity,
                None,
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
                    tracing::debug!("not an identity-mode transfer, trying anonymous");
                }
            }
        }

        let envelope = transfer::wormhole::receive(code, args.relay.as_deref()).await?;
        Ok(envelope)
    }
}

async fn listen_mode(args: &InjectArgs) -> Result<Envelope> {
    let relay_url = args.relay.as_deref()
        .ok_or_else(|| anyhow::anyhow!("--listen requires --relay or ENSEAL_RELAY"))?;

    let store = keys::store::KeyStore::open()?;
    let own_identity = keys::identity::EnsealIdentity::load(&store)?;
    let channel_id = own_identity.channel_id();

    if !args.quiet {
        display::info("Listening on:", relay_url);
        display::info("Channel:", &channel_id[..12]);
        display::ok("waiting for incoming transfer...");
    }

    let data = transfer::relay::listen(relay_url, &channel_id).await?;

    // Parse and verify signed envelope
    let signed = SignedEnvelope::from_bytes(&data)?;
    let sender_pubkey = signed.sender_age_pubkey.clone();
    let inner_bytes = signed.open(&own_identity, None)?;
    let envelope = Envelope::from_bytes(&inner_bytes)?;

    if !args.quiet {
        display::info("From:", &sender_pubkey);
        display::ok("signature verified");
    }

    Ok(envelope)
}

fn extract_secrets(envelope: &Envelope) -> Result<HashMap<String, String>> {
    let mut secrets = HashMap::new();

    match envelope.format {
        PayloadFormat::Env | PayloadFormat::Kv => {
            for line in envelope.payload.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(eq_pos) = line.find('=') {
                    let key = line[..eq_pos].trim().to_string();
                    let value = line[eq_pos + 1..].trim().to_string();
                    // Strip surrounding quotes if present
                    let value = strip_quotes(&value);
                    if !key.is_empty() {
                        secrets.insert(key, value);
                    }
                }
            }
        }
        PayloadFormat::Raw => {
            // For raw payloads, check if there's a label to use as key
            if let Some(ref label) = envelope.metadata.label {
                secrets.insert(label.clone(), envelope.payload.clone());
            } else {
                bail!(
                    "cannot inject raw payload without a key name. \
                     Sender should use --as KEY or --label KEY"
                );
            }
        }
    }

    if secrets.is_empty() {
        bail!("no secrets found in received payload");
    }

    Ok(secrets)
}

fn strip_quotes(s: &str) -> String {
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn run_child(command: &[String], secrets: &HashMap<String, String>) -> Result<()> {
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .envs(secrets)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start '{}': {}", command[0], e))?;

    // Set up signal forwarding on Unix
    #[cfg(unix)]
    {
        setup_signal_forwarding(child.id());
    }

    let status = child.wait()?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(unix)]
fn setup_signal_forwarding(child_pid: u32) {
    use std::sync::atomic::{AtomicU32, Ordering};

    static CHILD_PID: AtomicU32 = AtomicU32::new(0);
    CHILD_PID.store(child_pid, Ordering::SeqCst);

    unsafe {
        libc::signal(
            libc::SIGINT,
            forward_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            forward_signal as *const () as libc::sighandler_t,
        );
    }

    extern "C" fn forward_signal(sig: libc::c_int) {
        let pid = CHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
        if pid != 0 {
            unsafe {
                libc::kill(pid as i32, sig);
            }
        }
    }
}
