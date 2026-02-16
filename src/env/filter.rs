use anyhow::Result;
use regex::Regex;

use super::{Entry, EnvFile};

/// Filter an EnvFile by include/exclude regex patterns on variable names.
/// - `include`: if Some, only keep vars matching this pattern
/// - `exclude`: if Some, remove vars matching this pattern
///   Include is applied first, then exclude.
pub fn filter(env: &EnvFile, include: Option<&str>, exclude: Option<&str>) -> Result<EnvFile> {
    let include_re = include.map(Regex::new).transpose()?;
    let exclude_re = exclude.map(Regex::new).transpose()?;

    let entries = env
        .entries
        .iter()
        .filter(|entry| match entry {
            Entry::KeyValue { key, .. } => {
                if let Some(ref re) = include_re {
                    if !re.is_match(key) {
                        return false;
                    }
                }
                if let Some(ref re) = exclude_re {
                    if re.is_match(key) {
                        return false;
                    }
                }
                true
            }
            // Keep comments and blank lines
            _ => true,
        })
        .cloned()
        .collect();

    Ok(EnvFile { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::parser;

    #[test]
    fn include_filter() {
        let env = parser::parse("DB_HOST=h\nDB_PORT=p\nAPI_KEY=k\n").unwrap();
        let filtered = filter(&env, Some("^DB_"), None).unwrap();
        assert_eq!(filtered.var_count(), 2);
        assert!(filtered.get("API_KEY").is_none());
    }

    #[test]
    fn exclude_filter() {
        let env = parser::parse("DB_HOST=h\nPUBLIC_URL=u\nAPI_KEY=k\n").unwrap();
        let filtered = filter(&env, None, Some("^PUBLIC_")).unwrap();
        assert_eq!(filtered.var_count(), 2);
        assert!(filtered.get("PUBLIC_URL").is_none());
    }

    #[test]
    fn include_and_exclude() {
        let env = parser::parse("DB_HOST=h\nDB_DEBUG=d\nAPI_KEY=k\n").unwrap();
        let filtered = filter(&env, Some("^DB_"), Some("DEBUG")).unwrap();
        assert_eq!(filtered.var_count(), 1);
        assert_eq!(filtered.get("DB_HOST"), Some("h"));
    }

    #[test]
    fn no_filters() {
        let env = parser::parse("A=1\nB=2\n").unwrap();
        let filtered = filter(&env, None, None).unwrap();
        assert_eq!(filtered.var_count(), 2);
    }

    #[test]
    fn invalid_regex() {
        let env = parser::parse("A=1\n").unwrap();
        assert!(filter(&env, Some("[invalid"), None).is_err());
    }
}
