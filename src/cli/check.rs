use std::path::Path;

use anyhow::{bail, Result};
use clap::Args;

use crate::env::{self, diff};
use crate::ui::display;

#[derive(Args)]
pub struct CheckArgs {
    /// Path to .env file to check (default: .env)
    #[arg(default_value = ".env")]
    pub file: String,

    /// Path to .env.example to check against (default: .env.example)
    #[arg(long, default_value = ".env.example")]
    pub example: String,
}

pub fn run(args: CheckArgs) -> Result<()> {
    if !Path::new(&args.file).exists() {
        bail!("{} not found", args.file);
    }
    if !Path::new(&args.example).exists() {
        bail!("{} not found (required for check)", args.example);
    }

    let env_content = std::fs::read_to_string(&args.file)?;
    let example_content = std::fs::read_to_string(&args.example)?;

    let env_file = env::parser::parse(&env_content)?;
    let example_file = env::parser::parse(&example_content)?;

    let d = diff::diff(&example_file, &env_file);

    if d.only_left.is_empty() {
        display::ok(&format!(
            "all {} vars from {} present in {}",
            example_file.var_count(),
            args.example,
            args.file
        ));
        return Ok(());
    }

    display::error(&format!(
        "missing from {} (present in {}):",
        args.file, args.example
    ));
    for key in &d.only_left {
        eprintln!("  {}", key);
    }

    if !d.only_right.is_empty() {
        display::warning(&format!(
            "extra in {} (not in {}):",
            args.file, args.example
        ));
        for key in &d.only_right {
            eprintln!("  {}", key);
        }
    }

    bail!("{} variables missing from {}", d.only_left.len(), args.file);
}
