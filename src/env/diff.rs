use std::collections::BTreeSet;

use super::EnvFile;

/// Result of diffing two .env files by keys only (never compares values).
#[derive(Debug)]
pub struct EnvDiff {
    /// Keys only in the first file.
    pub only_left: Vec<String>,
    /// Keys only in the second file.
    pub only_right: Vec<String>,
    /// Keys present in both files.
    pub common: Vec<String>,
}

/// Diff two EnvFiles by keys only. Never exposes values.
pub fn diff(left: &EnvFile, right: &EnvFile) -> EnvDiff {
    let left_keys: BTreeSet<String> = left.keys().into_iter().map(|k| k.to_string()).collect();
    let right_keys: BTreeSet<String> = right.keys().into_iter().map(|k| k.to_string()).collect();

    let only_left = left_keys.difference(&right_keys).cloned().collect();
    let only_right = right_keys.difference(&left_keys).cloned().collect();
    let common = left_keys.intersection(&right_keys).cloned().collect();

    EnvDiff {
        only_left,
        only_right,
        common,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::parser;

    #[test]
    fn identical_files() {
        let a = parser::parse("A=1\nB=2\n").unwrap();
        let b = parser::parse("A=x\nB=y\n").unwrap();
        let d = diff(&a, &b);
        assert!(d.only_left.is_empty());
        assert!(d.only_right.is_empty());
        assert_eq!(d.common.len(), 2);
    }

    #[test]
    fn missing_and_extra() {
        let a = parser::parse("A=1\nB=2\nC=3\n").unwrap();
        let b = parser::parse("B=2\nD=4\n").unwrap();
        let d = diff(&a, &b);
        assert_eq!(d.only_left, vec!["A", "C"]);
        assert_eq!(d.only_right, vec!["D"]);
        assert_eq!(d.common, vec!["B"]);
    }

    #[test]
    fn empty_files() {
        let a = parser::parse("").unwrap();
        let b = parser::parse("").unwrap();
        let d = diff(&a, &b);
        assert!(d.only_left.is_empty());
        assert!(d.only_right.is_empty());
        assert!(d.common.is_empty());
    }
}
