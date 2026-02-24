pub mod diff;
pub mod filter;
pub mod interpolation;
pub mod parser;
pub mod profile;
pub mod redact;
pub mod schema;
pub mod validator;

use std::fmt;

/// A parsed .env file preserving structure (comments, blank lines, ordering).
#[derive(Debug, Clone)]
pub struct EnvFile {
    pub entries: Vec<Entry>,
}

/// A single line/entry in a .env file.
#[derive(Debug, Clone)]
pub enum Entry {
    /// A key-value pair.
    KeyValue { key: String, value: String },
    /// A comment line (including the leading `#`).
    Comment(String),
    /// A blank line.
    Blank,
}

impl EnvFile {
    /// Create an empty EnvFile.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Get all key-value pairs in order.
    pub fn vars(&self) -> Vec<(&str, &str)> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::KeyValue { key, value } => Some((key.as_str(), value.as_str())),
                _ => None,
            })
            .collect()
    }

    /// Get all keys in order.
    pub fn keys(&self) -> Vec<&str> {
        self.vars().into_iter().map(|(k, _)| k).collect()
    }

    /// Look up a value by key. Returns the last occurrence.
    #[allow(dead_code)]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.iter().rev().find_map(|e| match e {
            Entry::KeyValue { key: k, value } if k == key => Some(value.as_str()),
            _ => None,
        })
    }

    /// Number of key-value pairs.
    pub fn var_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e, Entry::KeyValue { .. }))
            .count()
    }
}

impl Default for EnvFile {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EnvFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for entry in &self.entries {
            match entry {
                Entry::KeyValue { key, value } => {
                    if value.contains(' ')
                        || value.contains('"')
                        || value.contains('\'')
                        || value.contains('#')
                        || value.contains('$')
                        || value.contains('\\')
                        || value.contains('\n')
                        || value.contains('\t')
                        || value.contains('\r')
                        || value.is_empty()
                    {
                        // Quote and escape values that need it
                        let escaped = value
                            .replace('\\', "\\\\")
                            .replace('"', "\\\"")
                            .replace('\n', "\\n")
                            .replace('\t', "\\t")
                            .replace('\r', "\\r");
                        writeln!(f, "{key}=\"{escaped}\"")?;
                    } else {
                        writeln!(f, "{key}={value}")?;
                    }
                }
                Entry::Comment(text) => writeln!(f, "{text}")?,
                Entry::Blank => writeln!(f)?,
            }
        }
        Ok(())
    }
}
