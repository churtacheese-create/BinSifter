//! Triage disposition history - port of `binsifter.core.disposition`.
//!
//! One `SHA1|Disposition` line per file in
//! `<report_dir>/.bsifter-disposition-history.txt`, keyed by SHA-1
//! (case-insensitive) so the same binary keeps its analyst-set disposition
//! across re-scans and across different source directories. The whole file
//! is rewritten on each save - simple and safe at the scale this is meant
//! for (thousands of entries, not millions).
//!
//! A blank report directory or an unreadable file just means "no history",
//! never an error - the same graceful-skip behaviour as NSRL / blocklist.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tracing::warn;

const HISTORY_FILENAME: &str = ".bsifter-disposition-history.txt";

/// The four choices the Results grid offers, matching the other variants'
/// `_DISPOSITION_CHOICES`.
pub const DISPOSITION_CHOICES: [&str; 4] = ["Untriaged", "Benign", "Suspicious", "Escalated"];

pub fn is_valid_disposition(value: &str) -> bool {
    DISPOSITION_CHOICES.contains(&value)
}

fn history_path(report_directory: &str) -> PathBuf {
    Path::new(report_directory).join(HISTORY_FILENAME)
}

fn parse_entries(text: &str) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.split('|');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            entries.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    entries
}

/// Read the whole history file into a map keyed by lowercase SHA-1. Empty
/// map if `report_directory` is blank, the file is missing, or it can't be
/// read.
pub fn load_disposition_history(report_directory: &str) -> BTreeMap<String, String> {
    if report_directory.is_empty() {
        return BTreeMap::new();
    }
    let path = history_path(report_directory);
    if !path.is_file() {
        return BTreeMap::new();
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_entries(&text),
        Err(e) => {
            warn!("Could not read disposition history {}: {e}", path.display());
            BTreeMap::new()
        }
    }
}

/// Update one SHA-1's disposition and rewrite the whole history file. No-op
/// if `sha1` is blank or `report_directory` isn't a usable directory.
pub fn save_disposition_entry(
    report_directory: &str,
    sha1: &str,
    disposition: &str,
) -> std::io::Result<()> {
    if sha1.is_empty() || report_directory.is_empty() || !Path::new(report_directory).is_dir() {
        return Ok(());
    }
    let path = history_path(report_directory);
    let mut entries = match std::fs::read_to_string(&path) {
        Ok(text) => parse_entries(&text),
        Err(_) => BTreeMap::new(),
    };
    entries.insert(sha1.to_ascii_lowercase(), disposition.to_string());

    let body = entries
        .iter()
        .map(|(k, v)| format!("{k}|{v}"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_case_insensitive_key() {
        let dir = tempfile::tempdir().unwrap();
        let rd = dir.path().to_string_lossy().into_owned();

        assert!(load_disposition_history(&rd).is_empty());

        save_disposition_entry(&rd, "ABCDEF0000000000000000000000000000000000", "Escalated")
            .unwrap();
        save_disposition_entry(&rd, "1111111111111111111111111111111111111111", "Benign").unwrap();
        // overwrite via different case
        save_disposition_entry(
            &rd,
            "abcdef0000000000000000000000000000000000",
            "Suspicious",
        )
        .unwrap();

        let hist = load_disposition_history(&rd);
        assert_eq!(hist.len(), 2);
        assert_eq!(
            hist.get("abcdef0000000000000000000000000000000000")
                .map(String::as_str),
            Some("Suspicious")
        );
        assert_eq!(
            hist.get("1111111111111111111111111111111111111111")
                .map(String::as_str),
            Some("Benign")
        );
    }

    #[test]
    fn blank_inputs_are_noops() {
        assert!(load_disposition_history("").is_empty());
        // no panic, no file created
        save_disposition_entry("", "aa", "Benign").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let rd = dir.path().to_string_lossy().into_owned();
        save_disposition_entry(&rd, "", "Benign").unwrap();
        assert!(!history_path(&rd).exists());
    }

    #[test]
    fn validity_check() {
        assert!(is_valid_disposition("Escalated"));
        assert!(!is_valid_disposition("escalated"));
        assert!(!is_valid_disposition("Nonsense"));
    }
}
