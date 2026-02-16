use anyhow::{bail, Result};
use clap::Args;
use console::style;

use crate::env::{self, diff as env_diff};

#[derive(Args)]
pub struct DiffArgs {
    /// First .env file
    pub file1: String,

    /// Second .env file
    pub file2: String,
}

pub fn run(args: DiffArgs) -> Result<()> {
    if !std::path::Path::new(&args.file1).exists() {
        bail!("{} not found", args.file1);
    }
    if !std::path::Path::new(&args.file2).exists() {
        bail!("{} not found", args.file2);
    }

    let content1 = std::fs::read_to_string(&args.file1)?;
    let content2 = std::fs::read_to_string(&args.file2)?;

    let env1 = env::parser::parse(&content1)?;
    let env2 = env::parser::parse(&content2)?;

    let d = env_diff::diff(&env1, &env2);

    if d.only_left.is_empty() && d.only_right.is_empty() {
        eprintln!("no differences (both files have the same keys)");
        return Ok(());
    }

    for key in &d.only_left {
        println!("{} {:<30} (only in {})", style("-").red(), key, args.file1);
    }
    for key in &d.only_right {
        println!(
            "{} {:<30} (only in {})",
            style("+").green(),
            key,
            args.file2
        );
    }

    Ok(())
}
