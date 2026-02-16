use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Resolve an environment profile name to a file path.
///
/// Given `--env staging`, looks for (in order):
/// 1. `.env.staging` in the given directory
/// 2. `.env.staging.local` in the given directory
///
/// Returns the path if found, or an error if neither exists.
pub fn resolve(profile: &str, dir: &Path) -> Result<PathBuf> {
    let primary = dir.join(format!(".env.{}", profile));
    if primary.exists() {
        return Ok(primary);
    }

    let local = dir.join(format!(".env.{}.local", profile));
    if local.exists() {
        return Ok(local);
    }

    bail!(
        "no .env file found for profile '{}'. Expected {} or {}",
        profile,
        primary.display(),
        local.display()
    );
}

/// Resolve a file argument that might be a profile name or a path.
/// If `env_profile` is Some, it takes priority and resolves to `.env.<profile>`.
/// Otherwise, falls back to the given file path (or default `.env`).
pub fn resolve_file(file: Option<&str>, env_profile: Option<&str>, dir: &Path) -> Result<PathBuf> {
    if let Some(profile) = env_profile {
        return resolve(profile, dir);
    }

    let file = file.unwrap_or(".env");
    let path = PathBuf::from(file);
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn resolve_primary() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".env.staging"), "KEY=value\n").unwrap();

        let path = resolve("staging", dir.path()).unwrap();
        assert_eq!(path, dir.path().join(".env.staging"));
    }

    #[test]
    fn resolve_local_fallback() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".env.staging.local"), "KEY=local\n").unwrap();

        let path = resolve("staging", dir.path()).unwrap();
        assert_eq!(path, dir.path().join(".env.staging.local"));
    }

    #[test]
    fn resolve_primary_preferred_over_local() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".env.staging"), "KEY=primary\n").unwrap();
        std::fs::write(dir.path().join(".env.staging.local"), "KEY=local\n").unwrap();

        let path = resolve("staging", dir.path()).unwrap();
        assert_eq!(path, dir.path().join(".env.staging"));
    }

    #[test]
    fn resolve_missing_profile() {
        let dir = TempDir::new().unwrap();
        let result = resolve("production", dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("production"));
    }

    #[test]
    fn resolve_file_with_profile() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".env.dev"), "KEY=dev\n").unwrap();

        let path = resolve_file(Some("other.env"), Some("dev"), dir.path()).unwrap();
        assert_eq!(path, dir.path().join(".env.dev"));
    }

    #[test]
    fn resolve_file_without_profile() {
        let dir = TempDir::new().unwrap();
        let path = resolve_file(Some("custom.env"), None, dir.path()).unwrap();
        assert_eq!(path, PathBuf::from("custom.env"));
    }

    #[test]
    fn resolve_file_defaults() {
        let dir = TempDir::new().unwrap();
        let path = resolve_file(None, None, dir.path()).unwrap();
        assert_eq!(path, PathBuf::from(".env"));
    }
}
