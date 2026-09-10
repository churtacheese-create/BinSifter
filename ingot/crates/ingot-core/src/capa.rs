//! CAPA capability detection - shells out to the official standalone `capa`
//! binary (see [`crate::tool_bootstrap`]) instead of the `flare-capa` Python
//! library the Winnow variant uses.
//!
//! The standalone binary bundles its own rules and FLIRT signatures, so
//! unlike Winnow (`flare-capa` from pip bundles neither) capa runs whenever
//! the binary is available and the file is capa-eligible. A `capa_rules`
//! directory in Settings, if set, is passed as `-r` to override the bundled
//! rules.
//!
//! Output parsing mirrors `capa_scan.py::_summarize`: `detection_count` is
//! the number of matched rules; `output` is one `"<rule> - <description>"`
//! (or just `"<rule>"`) line per matched rule, sorted by name.
//!
//! Shellcode: `-f sc32` then `-f sc64` are tried in that order (headerless
//! input can't disambiguate bitness); whichever exits cleanly wins and sets
//! `shellcode_format`. If both fail, no detection - a graceful skip, not an
//! error, matching the other variants.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;
use tracing::warn;
use wait_timeout::ChildExt;

pub const DEFAULT_TIMEOUT_SECONDS: u64 = 300;
const MIN_TIMEOUT_SECONDS: u64 = 30;
const MAX_TIMEOUT_SECONDS: u64 = 3600;

#[derive(Debug, Clone, Default)]
pub struct CapaResult {
    pub detection_count: i32,
    pub output: String,
    /// `"sc32"` / `"sc64"` when the match came from the shellcode path.
    pub shellcode_format: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum CapaError {
    #[error("capa analysis timed out after {0:?}")]
    Timeout(Duration),
    #[error("capa analysis did not complete: {0}")]
    Failed(String),
}

/// Timeout for one capa invocation - `DEFAULT_TIMEOUT_SECONDS`, overridable
/// via `INGOT_CAPA_TIMEOUT_SECONDS`, clamped to a sane band.
pub fn timeout() -> Duration {
    Duration::from_secs(resolve_timeout_secs(
        std::env::var("INGOT_CAPA_TIMEOUT_SECONDS").ok().as_deref(),
    ))
}

fn resolve_timeout_secs(raw: Option<&str>) -> u64 {
    raw.and_then(|r| r.trim().parse::<u64>().ok())
        .map(|v| v.clamp(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS))
        .unwrap_or(DEFAULT_TIMEOUT_SECONDS)
}

struct Run {
    ok: bool,
    stdout: Vec<u8>,
    stderr_tail: String,
}

fn run_capa(
    capa_bin: &Path,
    target: &Path,
    rules_dir: Option<&Path>,
    input_format: Option<&str>,
    timeout: Duration,
) -> Result<Run, CapaError> {
    // stdout/stderr to temp files so a full pipe buffer can't deadlock a
    // long-running capa against our timeout wait.
    let out = tempfile::NamedTempFile::new().map_err(|e| CapaError::Failed(e.to_string()))?;
    let err = tempfile::NamedTempFile::new().map_err(|e| CapaError::Failed(e.to_string()))?;

    let mut cmd = Command::new(capa_bin);
    cmd.arg("-j");
    if let Some(dir) = rules_dir {
        cmd.arg("-r").arg(dir);
    }
    if let Some(fmt) = input_format {
        cmd.arg("-f").arg(fmt);
    }
    cmd.arg(target);
    cmd.stdin(Stdio::null())
        .stdout(out.reopen().map_err(|e| CapaError::Failed(e.to_string()))?)
        .stderr(err.reopen().map_err(|e| CapaError::Failed(e.to_string()))?);

    let mut child = cmd
        .spawn()
        .map_err(|e| CapaError::Failed(format!("could not launch capa: {e}")))?;

    match child
        .wait_timeout(timeout)
        .map_err(|e| CapaError::Failed(e.to_string()))?
    {
        Some(status) => {
            let stdout = std::fs::read(out.path()).unwrap_or_default();
            let stderr = std::fs::read_to_string(err.path()).unwrap_or_default();
            let stderr_tail = stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | ");
            Ok(Run {
                ok: status.success(),
                stdout,
                stderr_tail,
            })
        }
        None => {
            let _ = child.kill();
            let _ = child.wait();
            Err(CapaError::Timeout(timeout))
        }
    }
}

/// `capa_scan.py::_summarize`.
fn summarize(json: &[u8]) -> Result<(i32, String), CapaError> {
    let doc: Value = serde_json::from_slice(json)
        .map_err(|e| CapaError::Failed(format!("could not parse capa JSON: {e}")))?;
    let Some(rules) = doc.get("rules").and_then(Value::as_object) else {
        return Ok((0, String::new()));
    };
    let mut names: Vec<&String> = rules.keys().collect();
    names.sort();
    let lines: Vec<String> = names
        .iter()
        .map(|name| {
            let desc = rules[*name]
                .get("meta")
                .and_then(|m| m.get("description"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if desc.is_empty() {
                (*name).clone()
            } else {
                format!("{name} - {desc}")
            }
        })
        .collect();
    Ok((names.len() as i32, lines.join("\n")))
}

/// Analyse `target` with capa. `rules_dir` overrides the bundled rules.
pub fn scan_file(
    capa_bin: &Path,
    target: &Path,
    rules_dir: Option<&Path>,
    is_shellcode: bool,
    timeout: Duration,
) -> Result<CapaResult, CapaError> {
    if !is_shellcode {
        let run = run_capa(capa_bin, target, rules_dir, None, timeout)?;
        if !run.ok {
            return Err(CapaError::Failed(format!(
                "capa exited with an error ({})",
                run.stderr_tail
            )));
        }
        let (count, output) = summarize(&run.stdout)?;
        return Ok(CapaResult {
            detection_count: count,
            output,
            shellcode_format: None,
        });
    }

    for (fmt, label) in [("sc32", "sc32"), ("sc64", "sc64")] {
        match run_capa(capa_bin, target, rules_dir, Some(fmt), timeout) {
            Ok(run) if run.ok => {
                let (count, output) = summarize(&run.stdout)?;
                return Ok(CapaResult {
                    detection_count: count,
                    output,
                    shellcode_format: Some(label.to_string()),
                });
            }
            Ok(_) => continue, // this bitness didn't parse; try the other
            Err(CapaError::Timeout(d)) => return Err(CapaError::Timeout(d)),
            Err(_) => continue,
        }
    }
    // both bitness guesses failed - graceful skip
    warn!(
        "capa could not analyse {} as sc32 or sc64",
        target.display()
    );
    Ok(CapaResult::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_counts_and_formats_rules() {
        let json = serde_json::json!({
            "meta": { "version": "9.4.0" },
            "rules": {
                "beta rule": { "meta": { "description": "does beta things" } },
                "alpha rule": { "meta": { "description": "" } },
                "gamma rule": { "meta": {} }
            }
        })
        .to_string();
        let (count, output) = summarize(json.as_bytes()).unwrap();
        assert_eq!(count, 3);
        // sorted by name; blank/absent description -> bare name
        assert_eq!(
            output,
            "alpha rule\nbeta rule - does beta things\ngamma rule"
        );
    }

    #[test]
    fn summarize_no_rules_key_is_empty() {
        let (count, output) = summarize(br#"{"meta":{}}"#).unwrap();
        assert_eq!(count, 0);
        assert_eq!(output, "");
    }

    #[test]
    fn timeout_override_clamped() {
        assert_eq!(resolve_timeout_secs(Some("5")), MIN_TIMEOUT_SECONDS);
        assert_eq!(resolve_timeout_secs(Some("99999")), MAX_TIMEOUT_SECONDS);
        assert_eq!(resolve_timeout_secs(Some(" 600 ")), 600);
        assert_eq!(
            resolve_timeout_secs(Some("garbage")),
            DEFAULT_TIMEOUT_SECONDS
        );
        assert_eq!(resolve_timeout_secs(None), DEFAULT_TIMEOUT_SECONDS);
    }

    #[test]
    fn missing_binary_is_failed_not_panic() {
        let r = scan_file(
            Path::new("/no/such/capa"),
            Path::new("/tmp/x"),
            None,
            false,
            Duration::from_secs(5),
        );
        assert!(matches!(r, Err(CapaError::Failed(_))));
    }
}
