use super::{Entry, EnvFile};

/// Produce a copy of an EnvFile with all values replaced by `<REDACTED>`.
/// Preserves keys, comments, and structure.
pub fn redact(env: &EnvFile) -> EnvFile {
    let entries = env
        .entries
        .iter()
        .map(|entry| match entry {
            Entry::KeyValue { key, .. } => Entry::KeyValue {
                key: key.clone(),
                value: "<REDACTED>".to_string(),
            },
            other => other.clone(),
        })
        .collect();

    EnvFile { entries }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::parser;

    #[test]
    fn redact_values() {
        let env = parser::parse("SECRET=hunter2\nPORT=3000\n").unwrap();
        let redacted = redact(&env);
        assert_eq!(redacted.get("SECRET"), Some("<REDACTED>"));
        assert_eq!(redacted.get("PORT"), Some("<REDACTED>"));
    }

    #[test]
    fn preserves_structure() {
        let env = parser::parse("# comment\n\nKEY=value\n").unwrap();
        let redacted = redact(&env);
        assert_eq!(redacted.entries.len(), 3);
        assert!(matches!(&redacted.entries[0], Entry::Comment(_)));
        assert!(matches!(&redacted.entries[1], Entry::Blank));
    }

    #[test]
    fn no_values_leak() {
        let env = parser::parse("SECRET=super_secret_password_123\n").unwrap();
        let redacted = redact(&env);
        let output = redacted.to_string();
        assert!(!output.contains("super_secret_password_123"));
        assert!(output.contains("<REDACTED>"));
    }
}
