use anyhow::{bail, Result};
use clap::Args;

use crate::env;
use crate::ui::display;

#[derive(Args)]
pub struct ValidateArgs {
    /// Path to .env file to validate
    #[arg(default_value = ".env")]
    pub file: String,

    /// Path to .enseal.toml manifest (default: .enseal.toml in current dir)
    #[arg(long)]
    pub config: Option<String>,
}

pub fn run(args: ValidateArgs) -> Result<()> {
    let content = std::fs::read_to_string(&args.file)
        .map_err(|e| anyhow::anyhow!("failed to read '{}': {}", args.file, e))?;

    let env_file = env::parser::parse(&content)?;

    let schema = env::schema::load_schema(args.config.as_deref())?;
    let schema = match schema {
        Some(s) => s,
        None => {
            display::warning("no [schema] section found in .enseal.toml");
            return Ok(());
        }
    };

    let errors = env::schema::validate(&env_file, &schema);

    if errors.is_empty() {
        let count = env_file.var_count();
        display::ok(&format!(
            "{}/{} variables passed validation",
            count, count
        ));
        return Ok(());
    }

    for err in &errors {
        display::error(&format!("{}", err));
    }

    let total = env_file.var_count();
    let passed = total.saturating_sub(
        errors
            .iter()
            .map(|e| e.key.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len(),
    );

    eprintln!();
    if passed == total {
        display::ok(&format!("{}/{} variables passed validation", passed, total));
    } else {
        display::error(&format!(
            "{}/{} variables passed validation",
            passed, total
        ));
        bail!("validation failed");
    }

    Ok(())
}
