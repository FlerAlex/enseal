use anyhow::{bail, Result};

use super::{Entry, EnvFile};

/// Parse a .env file from a string.
///
/// Handles: KEY=value, KEY="quoted value", KEY='single quoted',
/// comments (#), blank lines. Warns on duplicates (keeps last).
/// Rejects multi-line values.
pub fn parse(input: &str) -> Result<EnvFile> {
    let mut entries = Vec::new();
    let mut seen_keys: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

    for (line_num, line) in input.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            entries.push(Entry::Blank);
            continue;
        }

        if trimmed.starts_with('#') {
            entries.push(Entry::Comment(line.to_string()));
            continue;
        }

        // Must contain '=' for a valid key-value pair
        let Some(eq_pos) = trimmed.find('=') else {
            bail!(
                "line {}: invalid syntax (no '=' found): {}",
                line_num + 1,
                trimmed
            );
        };

        let key = trimmed[..eq_pos].trim();

        // Validate key: uppercase alphanumeric + underscore
        if key.is_empty() {
            bail!("line {}: empty key", line_num + 1);
        }
        if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            tracing::warn!(
                "line {}: key '{}' contains non-standard characters",
                line_num + 1,
                key
            );
        }

        let raw_value = trimmed[eq_pos + 1..].trim();
        let value = parse_value(raw_value, line_num + 1)?;

        // Check for duplicates
        if let Some(&prev_line) = seen_keys.get(key) {
            tracing::warn!(
                "duplicate key '{}' (lines {} and {}), keeping last",
                key,
                prev_line,
                line_num + 1
            );
        }
        seen_keys.insert(key, line_num + 1);

        entries.push(Entry::KeyValue {
            key: key.to_string(),
            value,
        });
    }

    Ok(EnvFile { entries })
}

/// Parse the value portion of a KEY=VALUE line.
fn parse_value(raw: &str, line_num: usize) -> Result<String> {
    if raw.is_empty() {
        return Ok(String::new());
    }

    // Double-quoted value
    if raw.starts_with('"') {
        let content = strip_quotes(raw, '"', line_num)?;
        return Ok(unescape_double_quoted(&content));
    }

    // Single-quoted value (no escape processing)
    if raw.starts_with('\'') {
        let content = strip_quotes(raw, '\'', line_num)?;
        return Ok(content);
    }

    // Unquoted value: strip inline comments
    let value = if let Some(comment_pos) = find_inline_comment(raw) {
        raw[..comment_pos].trim_end()
    } else {
        raw
    };

    Ok(value.to_string())
}

/// Strip matching quotes from a value, handling escape sequences.
fn strip_quotes(raw: &str, quote: char, line_num: usize) -> Result<String> {
    let inner = &raw[1..]; // skip opening quote

    if quote == '"' {
        // For double quotes, handle escape sequences
        let mut result = String::new();
        let mut chars = inner.chars();
        loop {
            match chars.next() {
                Some('\\') => match chars.next() {
                    Some(c) => result.push(c),
                    None => bail!("line {}: unterminated escape sequence", line_num),
                },
                Some(c) if c == quote => {
                    // Closing quote found; rest should be empty or a comment
                    let rest: String = chars.collect();
                    let rest = rest.trim();
                    if !rest.is_empty() && !rest.starts_with('#') {
                        bail!("line {}: unexpected content after closing quote", line_num);
                    }
                    return Ok(result);
                }
                Some(c) => result.push(c),
                None => bail!("line {}: unterminated double quote", line_num),
            }
        }
    } else {
        // Single quotes: no escape processing
        if let Some(end) = inner.find(quote) {
            let rest = inner[end + 1..].trim();
            if !rest.is_empty() && !rest.starts_with('#') {
                bail!("line {}: unexpected content after closing quote", line_num);
            }
            Ok(inner[..end].to_string())
        } else {
            bail!("line {}: unterminated single quote", line_num)
        }
    }
}

/// Process escape sequences in double-quoted values.
fn unescape_double_quoted(s: &str) -> String {
    // Escapes already handled in strip_quotes for double-quoted values
    s.to_string()
}

/// Find the position of an inline comment in an unquoted value.
/// Comments start with ` #` (space + hash) to avoid matching `#` inside URLs etc.
fn find_inline_comment(s: &str) -> Option<usize> {
    // Look for ` #` pattern (space before #)
    let bytes = s.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'#' && bytes[i - 1] == b' ' {
            return Some(i - 1);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_key_value() {
        let env = parse("KEY=value").unwrap();
        assert_eq!(env.get("KEY"), Some("value"));
        assert_eq!(env.var_count(), 1);
    }

    #[test]
    fn empty_value() {
        let env = parse("KEY=").unwrap();
        assert_eq!(env.get("KEY"), Some(""));
    }

    #[test]
    fn double_quoted() {
        let env = parse(r#"KEY="hello world""#).unwrap();
        assert_eq!(env.get("KEY"), Some("hello world"));
    }

    #[test]
    fn single_quoted() {
        let env = parse("KEY='hello world'").unwrap();
        assert_eq!(env.get("KEY"), Some("hello world"));
    }

    #[test]
    fn double_quoted_with_escapes() {
        let env = parse(r#"KEY="hello \"world\"""#).unwrap();
        assert_eq!(env.get("KEY"), Some(r#"hello "world""#));
    }

    #[test]
    fn single_quoted_no_escapes() {
        // Single quotes don't process escapes. Backslash is literal.
        let env = parse(r"KEY='hello\\world'").unwrap();
        assert_eq!(env.get("KEY"), Some(r"hello\\world"));
    }

    #[test]
    fn comments_and_blanks() {
        let input = "# this is a comment\n\nKEY=value\n# another comment\n";
        let env = parse(input).unwrap();
        assert_eq!(env.var_count(), 1);
        assert_eq!(env.get("KEY"), Some("value"));
        assert_eq!(env.entries.len(), 4);
    }

    #[test]
    fn inline_comment() {
        let env = parse("KEY=value # this is a comment").unwrap();
        assert_eq!(env.get("KEY"), Some("value"));
    }

    #[test]
    fn hash_without_space_not_comment() {
        let env = parse("URL=http://example.com/#fragment").unwrap();
        assert_eq!(env.get("URL"), Some("http://example.com/#fragment"));
    }

    #[test]
    fn multiple_vars() {
        let input = "A=1\nB=2\nC=3\n";
        let env = parse(input).unwrap();
        assert_eq!(env.var_count(), 3);
        assert_eq!(env.get("A"), Some("1"));
        assert_eq!(env.get("B"), Some("2"));
        assert_eq!(env.get("C"), Some("3"));
    }

    #[test]
    fn equals_in_value() {
        let env = parse("KEY=a=b=c").unwrap();
        assert_eq!(env.get("KEY"), Some("a=b=c"));
    }

    #[test]
    fn whitespace_trimming() {
        let env = parse("  KEY  =  value  ").unwrap();
        assert_eq!(env.get("KEY"), Some("value"));
    }

    #[test]
    fn duplicate_keys_keeps_last() {
        let input = "KEY=first\nKEY=second\n";
        let env = parse(input).unwrap();
        assert_eq!(env.get("KEY"), Some("second"));
    }

    #[test]
    fn display_round_trip() {
        let input = "# comment\nSIMPLE=value\nQUOTED=hello world\nEMPTY=\n";
        let env = parse(input).unwrap();
        let output = env.to_string();
        let reparsed = parse(&output).unwrap();
        assert_eq!(env.var_count(), reparsed.var_count());
        for (k, v) in env.vars() {
            assert_eq!(reparsed.get(k), Some(v), "mismatch for key '{}'", k);
        }
    }

    #[test]
    fn unterminated_double_quote() {
        assert!(parse(r#"KEY="unterminated"#).is_err());
    }

    #[test]
    fn unterminated_single_quote() {
        assert!(parse("KEY='unterminated").is_err());
    }

    #[test]
    fn no_equals_sign() {
        assert!(parse("INVALID_LINE").is_err());
    }

    #[test]
    fn empty_input() {
        let env = parse("").unwrap();
        assert_eq!(env.var_count(), 0);
    }

    #[test]
    fn preserves_key_order() {
        let input = "Z=1\nA=2\nM=3\n";
        let env = parse(input).unwrap();
        let keys: Vec<&str> = env.keys();
        assert_eq!(keys, vec!["Z", "A", "M"]);
    }
}
