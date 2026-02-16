use anyhow::{bail, Result};
use clap::Args;

use crate::env::{self, redact as env_redact};
use crate::ui::display;

#[derive(Args)]
pub struct RedactArgs {
    /// Path to .env file to redact (default: .env)
    #[arg(default_value = ".env")]
    pub file: String,

    /// Write output to file instead of stdout
    #[arg(long)]
    pub output: Option<String>,
}

pub fn run(args: RedactArgs) -> Result<()> {
    if !std::path::Path::new(&args.file).exists() {
        bail!("{} not found", args.file);
    }

    let content = std::fs::read_to_string(&args.file)?;
    let env_file = env::parser::parse(&content)?;
    let redacted = env_redact::redact(&env_file);
    let output = redacted.to_string();

    if let Some(path) = &args.output {
        std::fs::write(path, &output)?;
        display::ok(&format!("redacted output written to {}", path));
    } else {
        print!("{}", output);
    }

    Ok(())
}
