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
    let code = args
        .code
        .as_deref()
        .expect("code required in non-listen mode");

    // Detect mode: file drop (.env.age file) vs wormhole code
    let is_file = std::path::Path::new(code).exists() && code.ends_with(".age");

    if is_file {
        let store = keys::store::KeyStore::open()?;
        let own_identity = keys::identity::EnsealIdentity::load(&store)?;
        let path = std::path::Path::new(code);

        let metadata = std::fs::metadata(path)?;
        if metadata.len() > 16 * 1024 * 1024 {
            bail!(
                "file too large ({} bytes, max 16 MiB): {}",
                metadata.len(),
                path.display()
            );
        }
        let data = std::fs::read(path)?;
        let signed = SignedEnvelope::from_bytes(&data)?;
        let trusted_sender = keys::find_trusted_sender(&store, &signed);

        let (envelope, sender_pubkey) =
            transfer::filedrop::read_from_bytes(&data, &own_identity, trusted_sender.as_ref())?;
        if !args.quiet {
            if let Some(ref trusted) = trusted_sender {
                display::info("From:", &trusted.identity);
            } else {
                display::warning(&format!(
                    "received from unknown sender (signing key: {}...)",
                    &sender_pubkey[..20.min(sender_pubkey.len())]
                ));
            }
            display::ok("signature verified, file decrypted");
        }
        Ok(envelope)
    } else {
        // Receive raw bytes once, then determine mode by trying to parse
        let data = transfer::wormhole::receive_raw(code, args.relay.as_deref()).await?;
        let store = keys::store::KeyStore::open()?;

        // Try identity mode: parse as SignedEnvelope
        if store.is_initialized() {
            if let Ok(signed) = SignedEnvelope::from_bytes(&data) {
                let own_identity = keys::identity::EnsealIdentity::load(&store)?;
                let sender_pubkey = signed.sender_sign_pubkey.clone();
                let trusted_sender = keys::find_trusted_sender(&store, &signed);

                let inner_bytes = signed.open(&own_identity, trusted_sender.as_ref())?;
                let envelope = Envelope::from_bytes(&inner_bytes)?;
                envelope.check_age(300)?;

                if !args.quiet {
                    if let Some(ref trusted) = trusted_sender {
                        display::info("From:", &trusted.identity);
                    } else {
                        display::warning(&format!(
                            "received from unknown sender (signing key: {}...)",
                            &sender_pubkey[..20.min(sender_pubkey.len())]
                        ));
                    }
                    display::ok("signature verified");
                }
                return Ok(envelope);
            }
        }

        // Anonymous mode: parse as plain Envelope
        if !args.quiet {
            display::warning(
                "received unsigned (anonymous) payload -- sender identity not verified",
            );
        }
        let envelope = Envelope::from_bytes(&data)?;
        envelope.check_age(300)?;
        Ok(envelope)
    }
}

async fn listen_mode(args: &InjectArgs) -> Result<Envelope> {
    let relay_url = args
        .relay
        .as_deref()
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
    let sender_pubkey = signed.sender_sign_pubkey.clone();
    let trusted_sender = keys::find_trusted_sender(&store, &signed);

    let inner_bytes = signed.open(&own_identity, trusted_sender.as_ref())?;
    let envelope = Envelope::from_bytes(&inner_bytes)?;
    envelope.check_age(300)?;

    if !args.quiet {
        if let Some(ref trusted) = trusted_sender {
            display::info("From:", &trusted.identity);
        } else {
            display::warning(&format!(
                "received from unknown sender (signing key: {}...)",
                &sender_pubkey[..20.min(sender_pubkey.len())]
            ));
        }
        display::ok("signature verified");
    }

    Ok(envelope)
}

fn extract_secrets(envelope: &Envelope) -> Result<HashMap<String, String>> {
    let mut secrets = HashMap::new();

    match envelope.format {
        PayloadFormat::Env | PayloadFormat::Kv => {
            let env_file = crate::env::parser::parse(&envelope.payload)?;
            for (key, value) in env_file.vars() {
                secrets.insert(key.to_string(), value.to_string());
            }
        }
        PayloadFormat::Raw => {
            // For raw payloads, check if there's a label to use as key
            if let Some(ref label) = envelope.metadata.label {
                // Validate label is a valid env var name
                if label.is_empty()
                    || label.starts_with(|c: char| c.is_ascii_digit())
                    || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    bail!(
                        "label '{}' is not a valid env var name (use A-Z, 0-9, _). \
                         Sender should use --as KEY instead",
                        label
                    );
                }
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

    // On Unix, if the child was killed by a signal, re-raise it so the
    // parent process reports the correct termination reason to callers.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            unsafe {
                // Reset to default handler so the re-raised signal terminates us
                libc::signal(sig, libc::SIG_DFL);
                libc::raise(sig);
            }
        }
    }

    // Flush before exit since process::exit() skips Drop
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let _ = std::io::Write::flush(&mut std::io::stdout());
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(unix)]
fn setup_signal_forwarding(child_pid: u32) {
    use std::sync::atomic::{AtomicU32, Ordering};

    static CHILD_PID: AtomicU32 = AtomicU32::new(0);
    CHILD_PID.store(child_pid, Ordering::SeqCst);

    // Use sigaction instead of signal for reliable handler persistence
    // across invocations (BSD semantics on all platforms).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = forward_signal as *const () as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);

        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }

    extern "C" fn forward_signal(sig: libc::c_int) {
        let pid = CHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
        if pid != 0 {
            unsafe {
                libc::kill(pid as libc::pid_t, sig);
            }
        }
    }
}
