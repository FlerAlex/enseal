use super::EnvFile;

/// Validation issue found in an .env file.
#[derive(Debug)]
pub struct ValidationIssue {
    #[allow(dead_code)]
    pub key: String,
    pub message: String,
    #[allow(dead_code)]
    pub severity: Severity,
}

#[derive(Debug, PartialEq)]
pub enum Severity {
    #[allow(dead_code)]
    Error,
    Warning,
}

/// Validate an EnvFile for common issues.
/// Returns a list of issues found (may be empty if file is valid).
pub fn validate(env: &EnvFile) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

    for (i, (key, _value)) in env.vars().iter().enumerate() {
        // Check for non-standard key names
        if !key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            issues.push(ValidationIssue {
                key: key.to_string(),
                message: format!(
                    "key '{}' uses non-standard characters (expected uppercase, digits, underscore)",
                    key
                ),
                severity: Severity::Warning,
            });
        }

        // Check for duplicates
        if let Some(&prev_idx) = seen.get(key) {
            issues.push(ValidationIssue {
                key: key.to_string(),
                message: format!(
                    "duplicate key '{}' (occurrence {} and {})",
                    key,
                    prev_idx + 1,
                    i + 1
                ),
                severity: Severity::Warning,
            });
        }
        seen.insert(key, i);

        // Check for keys starting with a digit
        if key.starts_with(|c: char| c.is_ascii_digit()) {
            issues.push(ValidationIssue {
                key: key.to_string(),
                message: format!("key '{}' starts with a digit", key),
                severity: Severity::Warning,
            });
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::parser;

    #[test]
    fn valid_file() {
        let env = parser::parse("DATABASE_URL=postgres://...\nPORT=3000\n").unwrap();
        let issues = validate(&env);
        assert!(issues.is_empty());
    }

    #[test]
    fn non_standard_key() {
        let env = parser::parse("my-key=value\n").unwrap();
        let issues = validate(&env);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, Severity::Warning);
    }

    #[test]
    fn key_starts_with_digit() {
        let env = parser::parse("3SCALE_KEY=value\n").unwrap();
        let issues = validate(&env);
        assert!(issues
            .iter()
            .any(|i| i.message.contains("starts with a digit")));
    }
}
