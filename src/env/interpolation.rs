use std::collections::{HashMap, HashSet};

use anyhow::{bail, Result};

use super::EnvFile;

/// Resolve `${VAR}` and `${VAR:-default}` references within an EnvFile.
/// Variables are resolved in order — forward references are rejected.
/// Circular references are detected and rejected.
pub fn interpolate(env: &EnvFile) -> Result<EnvFile> {
    let mut resolved: HashMap<String, String> = HashMap::new();
    let mut result = EnvFile::new();

    for entry in &env.entries {
        match entry {
            super::Entry::KeyValue { key, value } => {
                let new_value = resolve_value(value, key, &resolved)?;
                resolved.insert(key.clone(), new_value.clone());
                result.entries.push(super::Entry::KeyValue {
                    key: key.clone(),
                    value: new_value,
                });
            }
            other => {
                result.entries.push(other.clone());
            }
        }
    }

    Ok(result)
}

/// Resolve a single value string, substituting `${VAR}` and `${VAR:-default}`.
fn resolve_value(
    value: &str,
    current_key: &str,
    resolved: &HashMap<String, String>,
) -> Result<String> {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    // Track which vars this value references (for cycle detection)
    let mut seen_refs: HashSet<String> = HashSet::new();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'

            // Read until '}'
            let mut ref_content = String::new();
            let mut found_close = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    found_close = true;
                    break;
                }
                ref_content.push(ch);
            }

            if !found_close {
                bail!(
                    "unterminated ${{}} reference in value of '{}'",
                    current_key
                );
            }

            // Parse VAR or VAR:-default
            let (var_name, default_value) = if let Some(pos) = ref_content.find(":-") {
                (
                    ref_content[..pos].to_string(),
                    Some(ref_content[pos + 2..].to_string()),
                )
            } else {
                (ref_content, None)
            };

            if var_name.is_empty() {
                bail!("empty variable reference in value of '{}'", current_key);
            }

            // Self-reference check
            if var_name == current_key {
                bail!(
                    "circular reference: '{}' references itself",
                    current_key
                );
            }

            // Forward reference check
            if !resolved.contains_key(&var_name) {
                if let Some(default) = default_value {
                    result.push_str(&default);
                } else {
                    bail!(
                        "forward reference: '{}' references '{}' which is not yet defined. \
                         Move '{}' above '{}' or use ${{{}:-default}}",
                        current_key,
                        var_name,
                        var_name,
                        current_key,
                        var_name,
                    );
                }
                continue;
            }

            // Cycle detection
            if !seen_refs.insert(var_name.clone()) {
                bail!(
                    "circular reference detected: '{}' references '{}' multiple times",
                    current_key,
                    var_name,
                );
            }

            result.push_str(&resolved[&var_name]);
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::parser;

    fn interpolate_str(input: &str) -> Result<String> {
        let env = parser::parse(input)?;
        let resolved = interpolate(&env)?;
        Ok(resolved.to_string())
    }

    #[test]
    fn simple_reference() {
        let input = "HOST=localhost\nURL=http://${HOST}/api\n";
        let result = interpolate_str(input).unwrap();
        assert!(result.contains("URL=http://localhost/api"));
    }

    #[test]
    fn chained_references() {
        let input = "HOST=localhost\nPORT=3000\nURL=http://${HOST}:${PORT}/api\n";
        let result = interpolate_str(input).unwrap();
        assert!(result.contains("URL=http://localhost:3000/api"));
    }

    #[test]
    fn default_value() {
        let input = "URL=http://${HOST:-localhost}:${PORT:-3000}/api\n";
        let result = interpolate_str(input).unwrap();
        assert!(result.contains("URL=http://localhost:3000/api"));
    }

    #[test]
    fn default_overridden_by_defined_var() {
        let input = "HOST=myserver\nURL=http://${HOST:-localhost}/api\n";
        let result = interpolate_str(input).unwrap();
        assert!(result.contains("URL=http://myserver/api"));
    }

    #[test]
    fn no_references() {
        let input = "KEY=value\nOTHER=stuff\n";
        let result = interpolate_str(input).unwrap();
        assert!(result.contains("KEY=value"));
        assert!(result.contains("OTHER=stuff"));
    }

    #[test]
    fn forward_reference_rejected() {
        let input = "URL=http://${HOST}/api\nHOST=localhost\n";
        let result = interpolate_str(input);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("forward reference"));
    }

    #[test]
    fn self_reference_rejected() {
        let input = "X=${X}\n";
        let result = interpolate_str(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("circular"));
    }

    #[test]
    fn unterminated_reference() {
        let input = "X=${UNCLOSED\n";
        let result = interpolate_str(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unterminated"));
    }

    #[test]
    fn preserves_comments_and_blanks() {
        let input = "# comment\nKEY=value\n\nOTHER=${KEY}\n";
        let env = parser::parse(input).unwrap();
        let resolved = interpolate(&env).unwrap();
        assert_eq!(resolved.entries.len(), 4); // comment, kv, blank, kv
    }

    #[test]
    fn nested_resolution() {
        let input = "A=hello\nB=${A}\nC=${B}_world\n";
        let result = interpolate_str(input).unwrap();
        assert!(result.contains("B=hello"));
        assert!(result.contains("C=hello_world"));
    }

    #[test]
    fn dollar_without_brace_is_literal() {
        let input = "PRICE=$100\n";
        let result = interpolate_str(input).unwrap();
        assert!(result.contains("PRICE=$100"));
    }

    #[test]
    fn empty_default() {
        let input = "X=${MISSING:-}\n";
        let result = interpolate_str(input).unwrap();
        // Empty default means empty string
        assert!(result.contains("X="));
    }
}
