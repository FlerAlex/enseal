use anyhow::Result;
use clap::Args;

use crate::env;
use crate::ui::display;

#[derive(Args)]
pub struct TemplateArgs {
    /// Path to .env file to generate template from
    #[arg(default_value = ".env")]
    pub file: String,

    /// Write to file instead of stdout
    #[arg(long)]
    pub output: Option<String>,

    /// Path to .enseal.toml manifest for schema descriptions
    #[arg(long)]
    pub config: Option<String>,
}

pub fn run(args: TemplateArgs) -> Result<()> {
    let content = std::fs::read_to_string(&args.file)
        .map_err(|e| anyhow::anyhow!("failed to read '{}': {}", args.file, e))?;

    let env_file = env::parser::parse(&content)?;

    // Load schema for descriptions
    let schema = env::schema::load_schema(args.config.as_deref())?;

    let mut output = String::new();

    for entry in &env_file.entries {
        match entry {
            env::Entry::KeyValue { key, value } => {
                // Try to get description from schema
                let description = schema
                    .as_ref()
                    .and_then(|s| s.rules.get(key.as_str()))
                    .and_then(|r| r.description.as_deref());

                let hint = if let Some(desc) = description {
                    desc.to_string()
                } else {
                    infer_type_hint(value)
                };

                output.push_str(&format!("{}=<{}>\n", key, hint));
            }
            env::Entry::Comment(text) => {
                output.push_str(text);
                output.push('\n');
            }
            env::Entry::Blank => {
                output.push('\n');
            }
        }
    }

    if let Some(ref path) = args.output {
        std::fs::write(path, &output)?;
        display::ok(&format!(
            "template written to {} ({} variables)",
            path,
            env_file.var_count()
        ));
    } else {
        print!("{}", output);
    }

    Ok(())
}

/// Infer a human-readable type hint from a value.
fn infer_type_hint(value: &str) -> String {
    // Check for boolean
    let lower = value.to_lowercase();
    if ["true", "false", "1", "0", "yes", "no"].contains(&lower.as_str()) {
        return "boolean".to_string();
    }

    // Check for integer
    if value.parse::<i64>().is_ok() {
        if let Ok(n) = value.parse::<u16>() {
            if (1024..=65535).contains(&n) {
                return format!("integer, {}", value.len());
            }
        }
        return "integer".to_string();
    }

    // Check for URL
    if value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("postgres://")
        || value.starts_with("mysql://")
        || value.starts_with("redis://")
        || value.starts_with("mongodb://")
    {
        // Extract the scheme
        if let Some(scheme) = value.split("://").next() {
            return format!("{} connection string", scheme);
        }
        return "URL".to_string();
    }

    // Check for email
    if value.contains('@') && value.contains('.') && !value.contains(' ') {
        return "email address".to_string();
    }

    // Default: describe by length
    let len = value.len();
    if len > 20 {
        format!("{}+ character string", len)
    } else {
        "string".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_boolean() {
        assert_eq!(infer_type_hint("true"), "boolean");
        assert_eq!(infer_type_hint("false"), "boolean");
        assert_eq!(infer_type_hint("0"), "boolean");
    }

    #[test]
    fn infer_integer() {
        assert_eq!(infer_type_hint("42"), "integer");
        assert_eq!(infer_type_hint("99999"), "integer");
    }

    #[test]
    fn infer_url() {
        assert!(infer_type_hint("https://api.example.com").contains("https"));
        assert!(infer_type_hint("postgres://localhost/db").contains("postgres"));
    }

    #[test]
    fn infer_email() {
        assert_eq!(infer_type_hint("user@example.com"), "email address");
    }

    #[test]
    fn infer_long_string() {
        let long = "abcdefghijklmnopqrstuvwxyz12345";
        assert!(infer_type_hint(long).contains("character string"));
    }

    #[test]
    fn infer_short_string() {
        assert_eq!(infer_type_hint("hello"), "string");
    }
}
