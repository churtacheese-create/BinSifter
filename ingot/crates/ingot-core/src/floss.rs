//! FLOSS string-extraction fallback - shells out to the official standalone
//! `floss` binary (see [`crate::tool_bootstrap`]) instead of the
//! `flare-floss` Python library the Winnow variant calls in-process.
//!
//! Port of `floss_scan.py`: runs FLOSS's default extraction (static, stack,
//! tight and decoded strings) with `--only` passed explicitly so FLOSS's
//! interactive "enable deobfuscation?" prompt (which would resolve to "no"
//! against a captured stdout) never fires. Returns an empty result on any
//! failure - a file FLOSS can't handle just means this fallback recovers
//! nothing, never a scan-ending error.
//!
//! `static_strings` is kept separate from the combined `strings` list
//! because draft YARA rule generation ([`crate::yara_rule_gen`]) intersects
//! only static strings across cluster members.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;
use tracing::{info, warn};
use wait_timeout::ChildExt;

pub const DEFAULT_TIMEOUT_SECONDS: u64 = 600;

#[derive(Debug, Clone, Default)]
pub struct FlossResult {
    pub string_count: i32,
    pub strings: Vec<String>,
    pub static_strings: Vec<String>,
}

pub fn timeout() -> Duration {
    let secs = std::env::var("INGOT_FLOSS_TIMEOUT_SECONDS")
        .ok()
        .and_then(|r| r.trim().parse::<u64>().ok())
        .map(|v| v.clamp(30, 3600))
        .unwrap_or(DEFAULT_TIMEOUT_SECONDS);
    Duration::from_secs(secs)
}

/// Run FLOSS against `target`. Never errors.
pub fn scan_file(floss_bin: &Path, target: &Path, timeout: Duration) -> FlossResult {
    let out = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            warn!("FLOSS: could not create temp file: {e}");
            return FlossResult::default();
        }
    };

    let child = Command::new(floss_bin)
        .args([
            "--json", "--quiet", "--only", "static", "stack", "tight", "decoded", "--",
        ])
        .arg(target)
        .stdin(Stdio::null())
        .stdout(
            out.reopen()
                .unwrap_or_else(|_| std::fs::File::create(out.path()).unwrap()),
        )
        .stderr(Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            warn!("FLOSS: could not launch {}: {e}", floss_bin.display());
            return FlossResult::default();
        }
    };

    match child.wait_timeout(timeout) {
        Ok(Some(status)) if status.success() => {}
        Ok(Some(status)) => {
            info!(
                "FLOSS returned {status} for {} - no strings recovered",
                target.display()
            );
            return FlossResult::default();
        }
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            warn!("FLOSS timed out after {timeout:?} for {}", target.display());
            return FlossResult::default();
        }
        Err(e) => {
            warn!("FLOSS: wait failed: {e}");
            return FlossResult::default();
        }
    }

    let bytes = std::fs::read(out.path()).unwrap_or_default();
    parse(&bytes).unwrap_or_else(|| {
        warn!("Could not parse FLOSS JSON output for {}", target.display());
        FlossResult::default()
    })
}

fn collect(section: &Value, key: &str) -> Vec<String> {
    section
        .get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("string").and_then(Value::as_str))
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn parse(bytes: &[u8]) -> Option<FlossResult> {
    let doc: Value = serde_json::from_slice(bytes).ok()?;
    let section = doc.get("strings")?;
    let static_strings = collect(section, "static_strings");
    let mut strings = static_strings.clone();
    for key in ["stack_strings", "tight_strings", "decoded_strings"] {
        strings.extend(collect(section, key));
    }
    Some(FlossResult {
        string_count: strings.len() as i32,
        strings,
        static_strings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_four_string_kinds() {
        let json = serde_json::json!({
            "strings": {
                "static_strings": [
                    {"encoding": "ascii", "offset": 1, "string": "static one"},
                    {"encoding": "ascii", "offset": 2, "string": ""},
                    {"encoding": "ascii", "offset": 3, "string": "static two"}
                ],
                "stack_strings": [{"string": "stack one"}],
                "tight_strings": [{"string": "tight one"}],
                "decoded_strings": [{"string": "decoded one"}],
                "language_strings": [{"string": "ignored"}]
            }
        })
        .to_string();
        let r = parse(json.as_bytes()).unwrap();
        assert_eq!(r.static_strings, vec!["static one", "static two"]);
        assert_eq!(r.string_count, 5);
        assert_eq!(
            r.strings,
            vec![
                "static one",
                "static two",
                "stack one",
                "tight one",
                "decoded one"
            ]
        );
        // language_strings is not collected
        assert!(!r.strings.iter().any(|s| s == "ignored"));
    }

    #[test]
    fn missing_strings_key_is_none() {
        assert!(parse(br#"{"metadata":{}}"#).is_none());
        assert!(parse(b"not json").is_none());
    }

    #[test]
    fn missing_binary_is_empty_not_panic() {
        let r = scan_file(
            Path::new("/no/such/floss"),
            Path::new("/tmp/x"),
            Duration::from_secs(5),
        );
        assert_eq!(r.string_count, 0);
        assert!(r.strings.is_empty());
    }
}
