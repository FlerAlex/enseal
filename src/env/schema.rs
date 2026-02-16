use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::EnvFile;

/// Schema definition from `.enseal.toml` `[schema]` section.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct Schema {
    /// Variables that must be present.
    pub required: Vec<String>,
    /// Per-variable validation rules.
    pub rules: HashMap<String, Rule>,
}

/// Validation rule for a single variable.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct Rule {
    /// Expected type: "string", "integer", "boolean", "url", "email".
    #[serde(rename = "type")]
    pub var_type: Option<String>,
    /// Regex the value must match.
    pub pattern: Option<String>,
    /// Minimum value length.
    pub min_length: Option<usize>,
    /// Maximum value length.
    pub max_length: Option<usize>,
    /// Allowed integer range [min, max].
    pub range: Option<[i64; 2]>,
    /// List of allowed values.
    #[serde(rename = "enum")]
    pub allowed_values: Option<Vec<String>>,
    /// Human-readable description (used by template command).
    pub description: Option<String>,
}

/// A single validation error.
#[derive(Debug)]
pub struct SchemaError {
    pub key: String,
    pub message: String,
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.key, self.message)
    }
}

/// Validate an EnvFile against a Schema. Returns a list of errors.
pub fn validate(env: &EnvFile, schema: &Schema) -> Vec<SchemaError> {
    let mut errors = Vec::new();
    let vars: HashMap<&str, &str> = env.vars().into_iter().collect();

    // Check required vars
    for key in &schema.required {
        if !vars.contains_key(key.as_str()) {
            errors.push(SchemaError {
                key: key.clone(),
                message: "missing required variable".to_string(),
            });
        }
    }

    // Check rules
    for (key, rule) in &schema.rules {
        if let Some(&value) = vars.get(key.as_str()) {
            errors.extend(validate_rule(key, value, rule));
        }
        // If key is missing and it's in required, that's already caught above.
        // If key is missing and not required, no error — the rule just doesn't apply.
    }

    errors
}

fn validate_rule(key: &str, value: &str, rule: &Rule) -> Vec<SchemaError> {
    let mut errors = Vec::new();

    // Type check
    if let Some(ref var_type) = rule.var_type {
        match var_type.as_str() {
            "integer" => {
                if value.parse::<i64>().is_err() {
                    errors.push(SchemaError {
                        key: key.to_string(),
                        message: format!("value \"{}\" is not an integer", value),
                    });
                }
            }
            "boolean" => {
                let lower = value.to_lowercase();
                if !["true", "false", "1", "0", "yes", "no"].contains(&lower.as_str()) {
                    errors.push(SchemaError {
                        key: key.to_string(),
                        message: format!("value \"{}\" is not a boolean", value),
                    });
                }
            }
            "url" => {
                if !value.starts_with("http://")
                    && !value.starts_with("https://")
                    && !value.starts_with("postgres://")
                    && !value.starts_with("mysql://")
                    && !value.starts_with("redis://")
                    && !value.starts_with("amqp://")
                    && !value.starts_with("mongodb://")
                {
                    errors.push(SchemaError {
                        key: key.to_string(),
                        message: format!("value \"{}\" doesn't look like a URL", value),
                    });
                }
            }
            "email" => {
                if !value.contains('@') || !value.contains('.') {
                    errors.push(SchemaError {
                        key: key.to_string(),
                        message: format!("value \"{}\" doesn't look like an email", value),
                    });
                }
            }
            "string" | _ => {}
        }
    }

    // Pattern check
    if let Some(ref pattern) = rule.pattern {
        match regex::Regex::new(pattern) {
            Ok(re) => {
                if !re.is_match(value) {
                    errors.push(SchemaError {
                        key: key.to_string(),
                        message: format!("doesn't match pattern {}", pattern),
                    });
                }
            }
            Err(e) => {
                errors.push(SchemaError {
                    key: key.to_string(),
                    message: format!("invalid pattern '{}': {}", pattern, e),
                });
            }
        }
    }

    // Length checks
    if let Some(min) = rule.min_length {
        if value.len() < min {
            errors.push(SchemaError {
                key: key.to_string(),
                message: format!("length {} is below minimum {}", value.len(), min),
            });
        }
    }
    if let Some(max) = rule.max_length {
        if value.len() > max {
            errors.push(SchemaError {
                key: key.to_string(),
                message: format!("length {} exceeds maximum {}", value.len(), max),
            });
        }
    }

    // Range check (integer only)
    if let Some([min, max]) = rule.range {
        if let Ok(n) = value.parse::<i64>() {
            if n < min || n > max {
                errors.push(SchemaError {
                    key: key.to_string(),
                    message: format!("value {} is outside range [{}, {}]", n, min, max),
                });
            }
        }
    }

    // Enum check
    if let Some(ref allowed) = rule.allowed_values {
        if !allowed.iter().any(|a| a == value) {
            errors.push(SchemaError {
                key: key.to_string(),
                message: format!(
                    "value \"{}\" not in allowed values: {}",
                    value,
                    allowed.join(", ")
                ),
            });
        }
    }

    errors
}

/// Load a Schema from a .enseal.toml file, if one exists.
pub fn load_schema(config_path: Option<&str>) -> Result<Option<Schema>> {
    let path = config_path.unwrap_or(".enseal.toml");
    let path = std::path::Path::new(path);

    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    // Parse the whole TOML and extract the schema section
    let doc: toml::Value =
        toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))?;

    if let Some(schema_value) = doc.get("schema") {
        let schema: Schema = schema_value
            .clone()
            .try_into()
            .context("failed to parse [schema] section")?;
        Ok(Some(schema))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::parser;

    fn make_schema() -> Schema {
        let mut rules = HashMap::new();
        rules.insert(
            "PORT".to_string(),
            Rule {
                var_type: Some("integer".to_string()),
                range: Some([1024, 65535]),
                ..Default::default()
            },
        );
        rules.insert(
            "DATABASE_URL".to_string(),
            Rule {
                pattern: Some("^postgres://".to_string()),
                description: Some("PostgreSQL connection string".to_string()),
                ..Default::default()
            },
        );
        rules.insert(
            "API_KEY".to_string(),
            Rule {
                min_length: Some(32),
                ..Default::default()
            },
        );
        rules.insert(
            "DEBUG".to_string(),
            Rule {
                var_type: Some("boolean".to_string()),
                ..Default::default()
            },
        );
        rules.insert(
            "LOG_LEVEL".to_string(),
            Rule {
                allowed_values: Some(vec![
                    "debug".to_string(),
                    "info".to_string(),
                    "warn".to_string(),
                    "error".to_string(),
                ]),
                ..Default::default()
            },
        );

        Schema {
            required: vec![
                "DATABASE_URL".to_string(),
                "API_KEY".to_string(),
                "PORT".to_string(),
            ],
            rules,
        }
    }

    #[test]
    fn valid_env_passes() {
        let env = parser::parse(
            "DATABASE_URL=postgres://localhost/mydb\nAPI_KEY=abcdefghijklmnopqrstuvwxyz123456\nPORT=3000\nDEBUG=true\nLOG_LEVEL=info\n",
        ).unwrap();
        let schema = make_schema();
        let errors = validate(&env, &schema);
        assert!(
            errors.is_empty(),
            "unexpected errors: {:?}",
            errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn missing_required() {
        let env = parser::parse("PORT=3000\n").unwrap();
        let schema = make_schema();
        let errors = validate(&env, &schema);
        let missing: Vec<&str> = errors
            .iter()
            .filter(|e| e.message.contains("missing"))
            .map(|e| e.key.as_str())
            .collect();
        assert!(missing.contains(&"DATABASE_URL"));
        assert!(missing.contains(&"API_KEY"));
    }

    #[test]
    fn invalid_integer() {
        let env = parser::parse(
            "DATABASE_URL=postgres://x\nAPI_KEY=abcdefghijklmnopqrstuvwxyz123456\nPORT=abc\n",
        )
        .unwrap();
        let schema = make_schema();
        let errors = validate(&env, &schema);
        assert!(errors
            .iter()
            .any(|e| e.key == "PORT" && e.message.contains("not an integer")));
    }

    #[test]
    fn integer_out_of_range() {
        let env = parser::parse(
            "DATABASE_URL=postgres://x\nAPI_KEY=abcdefghijklmnopqrstuvwxyz123456\nPORT=80\n",
        )
        .unwrap();
        let schema = make_schema();
        let errors = validate(&env, &schema);
        assert!(errors
            .iter()
            .any(|e| e.key == "PORT" && e.message.contains("outside range")));
    }

    #[test]
    fn pattern_mismatch() {
        let env = parser::parse("DATABASE_URL=mysql://localhost/mydb\nAPI_KEY=abcdefghijklmnopqrstuvwxyz123456\nPORT=3000\n").unwrap();
        let schema = make_schema();
        let errors = validate(&env, &schema);
        assert!(errors
            .iter()
            .any(|e| e.key == "DATABASE_URL" && e.message.contains("pattern")));
    }

    #[test]
    fn min_length_violation() {
        let env = parser::parse("DATABASE_URL=postgres://x\nAPI_KEY=short\nPORT=3000\n").unwrap();
        let schema = make_schema();
        let errors = validate(&env, &schema);
        assert!(errors
            .iter()
            .any(|e| e.key == "API_KEY" && e.message.contains("below minimum")));
    }

    #[test]
    fn invalid_boolean() {
        let env = parser::parse("DATABASE_URL=postgres://x\nAPI_KEY=abcdefghijklmnopqrstuvwxyz123456\nPORT=3000\nDEBUG=maybe\n").unwrap();
        let schema = make_schema();
        let errors = validate(&env, &schema);
        assert!(errors
            .iter()
            .any(|e| e.key == "DEBUG" && e.message.contains("not a boolean")));
    }

    #[test]
    fn enum_violation() {
        let env = parser::parse("DATABASE_URL=postgres://x\nAPI_KEY=abcdefghijklmnopqrstuvwxyz123456\nPORT=3000\nLOG_LEVEL=trace\n").unwrap();
        let schema = make_schema();
        let errors = validate(&env, &schema);
        assert!(errors
            .iter()
            .any(|e| e.key == "LOG_LEVEL" && e.message.contains("not in allowed")));
    }

    #[test]
    fn schema_from_toml() {
        let toml_content = r#"
[schema]
required = ["DB_URL", "PORT"]

[schema.rules.PORT]
type = "integer"
range = [1024, 65535]

[schema.rules.DB_URL]
pattern = "^postgres://"
description = "PostgreSQL connection string"

[schema.rules.LOG_LEVEL]
enum = ["debug", "info", "warn", "error"]
"#;
        let doc: toml::Value = toml::from_str(toml_content).unwrap();
        let schema: Schema = doc.get("schema").unwrap().clone().try_into().unwrap();

        assert_eq!(schema.required, vec!["DB_URL", "PORT"]);
        assert!(schema.rules.contains_key("PORT"));
        assert!(schema.rules.contains_key("DB_URL"));
        assert!(schema.rules.contains_key("LOG_LEVEL"));
        assert_eq!(schema.rules["PORT"].var_type.as_deref(), Some("integer"));
    }
}
