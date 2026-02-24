use anyhow::{bail, Result};
use base64::Engine;
use clap::{Parser, Subcommand};

use crate::keys::alias;
use crate::keys::group;
use crate::keys::identity::{format_pubkey_file, EnsealIdentity, TrustedKey};
use crate::keys::store::KeyStore;
use crate::ui::display;

#[derive(Parser)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub command: KeysCommand,
}

#[derive(Subcommand)]
pub enum KeysCommand {
    /// Generate your keypair
    Init,

    /// Print your public key bundle (for sharing with teammates)
    Export,

    /// Add a colleague's public key to trusted keys
    Import {
        /// Path to a .pub file
        file: String,

        /// Skip confirmation prompt (for scripted workflows)
        #[arg(long)]
        yes: bool,
    },

    /// Show all trusted keys and aliases
    List,

    /// Remove a trusted key
    Remove {
        /// Identity to remove
        identity: String,
    },

    /// Show your key fingerprint
    Fingerprint,

    /// Map a short name to a full identity
    Alias {
        /// Short alias name
        name: String,

        /// Full identity (e.g. alice@example.com)
        identity: String,
    },

    /// Manage recipient groups
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
}

#[derive(Subcommand)]
pub enum GroupCommand {
    /// Create a named recipient group
    Create {
        /// Group name
        name: String,
    },

    /// Add an identity to a group
    Add {
        /// Group name
        group: String,

        /// Identity to add
        identity: String,
    },

    /// Remove an identity from a group
    Remove {
        /// Group name
        group: String,

        /// Identity to remove
        identity: String,
    },

    /// List groups or members of a specific group
    List {
        /// Show members of this group (omit to list all groups)
        name: Option<String>,
    },

    /// Delete a group
    Delete {
        /// Group name
        name: String,
    },
}

pub fn run(args: KeysArgs) -> Result<()> {
    match args.command {
        KeysCommand::Init => cmd_init(),
        KeysCommand::Export => cmd_export(),
        KeysCommand::Import { file, yes } => cmd_import(&file, yes),
        KeysCommand::List => cmd_list(),
        KeysCommand::Remove { identity } => cmd_remove(&identity),
        KeysCommand::Fingerprint => cmd_fingerprint(),
        KeysCommand::Alias { name, identity } => cmd_alias(&name, &identity),
        KeysCommand::Group { command } => cmd_group(command),
    }
}

fn cmd_init() -> Result<()> {
    let store = KeyStore::open()?;

    if store.is_initialized() {
        display::warning(
            "keys already initialized. Use 'enseal keys export' to view your public key.",
        );
        return Ok(());
    }

    let identity = EnsealIdentity::generate();
    identity.save(&store)?;

    display::ok("keypair generated");
    println!();
    println!("  fingerprint: {}", identity.fingerprint());
    println!("  keys stored in: {}", store.keys_dir().display());
    println!();
    println!("Share your public key with: enseal keys export");

    Ok(())
}

fn cmd_export() -> Result<()> {
    let store = KeyStore::open()?;
    let identity = EnsealIdentity::load(&store)?;

    let age_pub = identity.age_recipient.to_string();
    let sign_pub = base64::engine::general_purpose::STANDARD
        .encode(identity.signing_key.verifying_key().to_bytes());

    // Use hostname or "unknown" as the identity label
    let hostname = username_or_unknown();
    let content = format_pubkey_file(&hostname, &age_pub, &sign_pub);
    print!("{}", content);

    Ok(())
}

fn cmd_import(file: &str, skip_confirm: bool) -> Result<()> {
    let store = KeyStore::open()?;
    let content = std::fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("failed to read '{}': {}", file, e))?;

    // Extract identity from filename stem (e.g., alice@example.com.pub -> alice@example.com)
    let path = std::path::Path::new(file);
    let identity_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    // Validate identity name is safe for file paths
    crate::keys::store::validate_identity_name(identity_name)?;

    // Parse to validate
    let trusted = TrustedKey::parse(identity_name, &content)?;

    // Show fingerprint and ask for confirmation
    println!("Importing public key:");
    println!("  identity:    {}", identity_name);
    println!("  fingerprint: {}", trusted.fingerprint());
    println!();

    if !skip_confirm && !confirm("Trust this key?")? {
        println!("import cancelled");
        return Ok(());
    }

    // Write to trusted directory
    store.ensure_dirs()?;
    let dest = store.trusted_key_path(identity_name)?;
    std::fs::write(&dest, &content)?;

    display::ok(&format!("imported key for '{}'", identity_name));

    Ok(())
}

fn cmd_list() -> Result<()> {
    let store = KeyStore::open()?;

    // Own key
    if store.is_initialized() {
        let identity = EnsealIdentity::load(&store)?;
        println!("Own key:");
        println!("  fingerprint: {}", identity.fingerprint());
        println!();
    }

    // Trusted keys
    let trusted = store.list_trusted()?;
    if trusted.is_empty() {
        println!("No trusted keys. Import with: enseal keys import <file>");
    } else {
        println!("Trusted keys:");
        for name in &trusted {
            match TrustedKey::load(&store, name) {
                Ok(key) => println!("  {} ({})", name, key.fingerprint()),
                Err(_) => println!("  {} (error reading key)", name),
            }
        }
    }

    // Aliases
    let aliases = alias::list(&store)?;
    if !aliases.is_empty() {
        println!();
        println!("Aliases:");
        for (name, identity) in &aliases {
            println!("  {} -> {}", name, identity);
        }
    }

    // Groups
    let groups = group::list_groups(&store)?;
    if !groups.is_empty() {
        println!();
        println!("Groups:");
        for (name, entry) in &groups {
            if entry.members.is_empty() {
                println!("  {} (empty)", name);
            } else {
                println!("  {} ({})", name, entry.members.join(", "));
            }
        }
    }

    Ok(())
}

fn cmd_remove(identity: &str) -> Result<()> {
    crate::keys::store::validate_identity_name(identity)?;
    let store = KeyStore::open()?;
    let path = store.trusted_key_path(identity)?;

    if !path.exists() {
        bail!("no trusted key found for '{}'", identity);
    }

    std::fs::remove_file(&path)?;

    // Clean up aliases pointing to this identity
    let aliases = alias::list(&store)?;
    for (name, target) in &aliases {
        if target == identity {
            let _ = alias::remove(&store, name);
            display::warning(&format!(
                "removed alias '{}' (pointed to removed key)",
                name
            ));
        }
    }

    // Clean up group memberships
    let groups = group::list_groups(&store)?;
    for (name, entry) in &groups {
        if entry.members.contains(&identity.to_string()) {
            let _ = group::remove_member(&store, name, identity);
            display::warning(&format!("removed '{}' from group '{}'", identity, name));
        }
    }

    display::ok(&format!("removed trusted key for '{}'", identity));

    Ok(())
}

fn cmd_fingerprint() -> Result<()> {
    let store = KeyStore::open()?;
    let identity = EnsealIdentity::load(&store)?;
    println!("{}", identity.fingerprint());
    Ok(())
}

fn cmd_alias(name: &str, identity: &str) -> Result<()> {
    let store = KeyStore::open()?;
    alias::set(&store, name, identity)?;
    display::ok(&format!("alias '{}' -> '{}'", name, identity));
    Ok(())
}

fn cmd_group(command: GroupCommand) -> Result<()> {
    let store = KeyStore::open()?;

    match command {
        GroupCommand::Create { name } => {
            group::create(&store, &name)?;
            display::ok(&format!("created group '{}'", name));
        }
        GroupCommand::Add {
            group: grp,
            identity,
        } => {
            if group::add_member(&store, &grp, &identity)? {
                display::ok(&format!("added '{}' to group '{}'", identity, grp));
            } else {
                display::warning(&format!("'{}' is already a member of '{}'", identity, grp));
            }
        }
        GroupCommand::Remove {
            group: grp,
            identity,
        } => {
            if group::remove_member(&store, &grp, &identity)? {
                display::ok(&format!("removed '{}' from group '{}'", identity, grp));
            } else {
                display::warning(&format!("'{}' is not a member of '{}'", identity, grp));
            }
        }
        GroupCommand::List { name } => {
            if let Some(name) = name {
                match group::get_members(&store, &name)? {
                    Some(members) => {
                        println!("Group '{}':", name);
                        if members.is_empty() {
                            println!("  (no members)");
                        } else {
                            for m in &members {
                                println!("  {}", m);
                            }
                        }
                    }
                    None => {
                        bail!("group '{}' does not exist", name);
                    }
                }
            } else {
                let groups = group::list_groups(&store)?;
                if groups.is_empty() {
                    println!("No groups. Create one with: enseal keys group create <name>");
                } else {
                    println!("Groups:");
                    for (name, entry) in &groups {
                        println!("  {} ({} members)", name, entry.members.len());
                    }
                }
            }
        }
        GroupCommand::Delete { name } => {
            if group::delete_group(&store, &name)? {
                display::ok(&format!("deleted group '{}'", name));
            } else {
                bail!("group '{}' does not exist", name);
            }
        }
    }

    Ok(())
}

fn username_or_unknown() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn confirm(prompt: &str) -> Result<bool> {
    if !is_terminal::is_terminal(std::io::stdin()) {
        bail!("cannot prompt for confirmation in non-interactive mode. Use --yes to skip");
    }
    use dialoguer::Confirm;
    let result = Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()?;
    Ok(result)
}
