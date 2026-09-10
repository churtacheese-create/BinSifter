//! YARA scanning + severity bucketing + MITRE ATT&CK enrichment - port of
//! `binsifter.core.yara_scan`.
//!
//! Uses `yara-x` (pure-Rust YARA) instead of libyara / yara-python:
//! `relaxed_re_syntax` is enabled so rule sets written against classic YARA
//! compile, and `include` statements resolve relative to the rules file's
//! own path.
//!
//! The severity-bucketing logic is copied faithfully from the C#
//! `SeverityScorer` (via the Python port) - getting it subtly wrong would
//! silently change what counts as "Critical" on the dashboard:
//!
//! 1. an explicit 0-100 `score` meta -> CVSS-style bands
//! 2. else ReversingLabs' 0-5 `tc_detection_factor` (x20) -> same bands
//! 3. else a plain severity word (`severity` / `tc_policy_severity` /
//!    `importance`)
//! 4. else `Unknown` - never a guessed default
//!
//! ATT&CK techniques are resolved from each matched rule's metadata in the
//! same loop, deduplicated across every match for the file.

use std::collections::HashSet;
use std::path::Path;

use tracing::warn;
use yara_x::{Compiler, MetaValue, Rules, Scanner, SourceCode};

use crate::attack::AttackDb;

#[derive(Debug, Clone)]
pub struct YaraMatchResult {
    pub rule_names: Vec<String>,
    pub hit_count: usize,
    /// "Critical" / "High" / "Medium" / "Low" / "Unknown"
    pub severity: String,
    /// 0-100 normalised, or -1 when the bucket came from a word not a number
    pub severity_score: i32,
    /// Semicolon-joined `T#### Name [Tactic]` entries, or `None`
    pub attack_techniques: Option<String>,
}

impl YaraMatchResult {
    fn empty() -> Self {
        YaraMatchResult {
            rule_names: Vec::new(),
            hit_count: 0,
            severity: "Unknown".to_string(),
            severity_score: -1,
            attack_techniques: None,
        }
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    }
}

/// Compile a single rules file (which may itself `include` others).
pub fn compile_rules(rules_path: &Path) -> anyhow::Result<Rules> {
    let text = std::fs::read_to_string(rules_path)?;
    let mut compiler = Compiler::new();
    compiler.relaxed_re_syntax(true);
    let source = SourceCode::from(text.as_str()).with_origin(rules_path.to_string_lossy());
    compiler
        .add_source(source)
        .map_err(|e| anyhow::anyhow!("YARA compile error in {}: {e}", rules_path.display()))?;
    Ok(compiler.build())
}

/// Owned copy of one metadata value, so it outlives the borrowed scan
/// results.
#[derive(Debug, Clone)]
enum OwnedMeta {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(String),
}

impl OwnedMeta {
    /// Python `str(value)`.
    fn display(&self) -> String {
        match self {
            OwnedMeta::Int(i) => i.to_string(),
            OwnedMeta::Float(f) => f.to_string(),
            OwnedMeta::Bool(b) => if *b { "True" } else { "False" }.to_string(),
            OwnedMeta::Str(s) => s.clone(),
        }
    }

    /// Python `int(value)` - `None` when it can't be coerced.
    fn as_int(&self) -> Option<i64> {
        match self {
            OwnedMeta::Int(i) => Some(*i),
            OwnedMeta::Float(f) => Some(f.trunc() as i64),
            OwnedMeta::Bool(b) => Some(*b as i64),
            OwnedMeta::Str(s) => s.trim().parse::<i64>().ok(),
        }
    }
}

fn from_meta_value(v: MetaValue<'_>) -> OwnedMeta {
    match v {
        MetaValue::Integer(i) => OwnedMeta::Int(i),
        MetaValue::Float(f) => OwnedMeta::Float(f),
        MetaValue::Bool(b) => OwnedMeta::Bool(b),
        MetaValue::String(s) => OwnedMeta::Str(s.to_string()),
        MetaValue::Bytes(b) => OwnedMeta::Str(b.to_string()),
    }
}

/// First-insertion-order key list with last-value-wins on a duplicate key -
/// matches how yara-python collapses a rule's `meta:` block into a dict.
fn collect_meta(pairs: impl Iterator<Item = (String, OwnedMeta)>) -> Vec<(String, OwnedMeta)> {
    let mut out: Vec<(String, OwnedMeta)> = Vec::new();
    for (k, v) in pairs {
        if let Some(slot) = out.iter_mut().find(|(ek, _)| *ek == k) {
            slot.1 = v;
        } else {
            out.push((k, v));
        }
    }
    out
}

fn meta_get<'a>(meta: &'a [(String, OwnedMeta)], key: &str) -> Option<&'a OwnedMeta> {
    meta.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn bucket_score(score: i64) -> &'static str {
    if score >= 90 {
        "Critical"
    } else if score >= 70 {
        "High"
    } else if score >= 40 {
        "Medium"
    } else if score >= 1 {
        "Low"
    } else {
        "Unknown"
    }
}

fn normalize_word(word: &str) -> Option<&'static str> {
    match word.trim().to_lowercase().as_str() {
        "low" => Some("Low"),
        "medium" | "moderate" => Some("Medium"),
        "high" => Some("High"),
        "critical" | "severe" => Some("Critical"),
        _ => None,
    }
}

fn resolve_severity(meta: &[(String, OwnedMeta)]) -> (&'static str, i32) {
    if let Some(v) = meta_get(meta, "score") {
        if let Some(score) = v.as_int() {
            return (bucket_score(score), score as i32);
        }
    }
    if let Some(v) = meta_get(meta, "tc_detection_factor") {
        if let Some(raw) = v.as_int() {
            let scaled = raw * 20;
            return (bucket_score(scaled), scaled as i32);
        }
    }
    for key in ["severity", "tc_policy_severity", "importance"] {
        if let Some(v) = meta_get(meta, key) {
            if let Some(word) = normalize_word(&v.display()) {
                return (word, -1);
            }
        }
    }
    ("Unknown", -1)
}

/// Scan one file. Never errors - a scan failure logs a warning and returns
/// an empty (no-hit) result, matching the Python variant's best-effort
/// contract.
pub fn scan_file(
    scanner: &mut Scanner,
    target_path: &Path,
    attack_db: Option<&AttackDb>,
) -> YaraMatchResult {
    let results = match scanner.scan_file(target_path) {
        Ok(r) => r,
        Err(e) => {
            warn!("YARA scan failed for {}: {e}", target_path.display());
            return YaraMatchResult::empty();
        }
    };

    let matching = results.matching_rules();
    if matching.len() == 0 {
        return YaraMatchResult::empty();
    }

    let mut rule_names: Vec<String> = Vec::new();
    let mut best_severity = "Unknown";
    let mut best_score: i32 = -1;
    let mut attack_hits: Vec<String> = Vec::new();
    let mut attack_seen: HashSet<String> = HashSet::new();

    for rule in matching {
        rule_names.push(rule.identifier().to_string());

        let meta = collect_meta(
            rule.metadata()
                .map(|(k, v)| (k.to_string(), from_meta_value(v))),
        );

        let (severity, score) = resolve_severity(&meta);
        if severity_rank(severity) > severity_rank(best_severity) {
            best_severity = severity;
            best_score = score;
        }

        if let Some(db) = attack_db {
            let displays: Vec<String> = meta.iter().map(|(_, v)| v.display()).collect();
            for tech in db.resolve(displays.iter().map(String::as_str)) {
                if attack_seen.insert(tech.id.to_lowercase()) {
                    attack_hits.push(format!(
                        "{} {} [{}]",
                        tech.id,
                        tech.name,
                        tech.tactic.as_deref().unwrap_or("")
                    ));
                }
            }
        }
    }

    YaraMatchResult {
        hit_count: rule_names.len(),
        rule_names,
        severity: best_severity.to_string(),
        severity_score: best_score,
        attack_techniques: (!attack_hits.is_empty()).then(|| attack_hits.join("; ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn rules(src: &str) -> Rules {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(src.as_bytes()).unwrap();
        f.flush().unwrap();
        compile_rules(f.path()).unwrap()
    }

    fn scan(rules: &Rules, data: &[u8]) -> YaraMatchResult {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sample");
        std::fs::write(&p, data).unwrap();
        let mut scanner = Scanner::new(rules);
        scan_file(&mut scanner, &p, None)
    }

    #[test]
    fn no_match_is_unknown() {
        let r = rules(r#"rule r { strings: $a = "zzzznope" condition: $a }"#);
        let res = scan(&r, b"hello world");
        assert_eq!(res.hit_count, 0);
        assert_eq!(res.severity, "Unknown");
        assert_eq!(res.severity_score, -1);
        assert!(res.attack_techniques.is_none());
    }

    #[test]
    fn score_meta_buckets() {
        let r = rules(
            r#"
            rule low  { meta: score = 20  strings: $a = "AAA" condition: $a }
            rule crit { meta: score = 95  strings: $b = "BBB" condition: $b }
            "#,
        );
        let res = scan(&r, b"xx AAA yy BBB zz");
        assert_eq!(res.hit_count, 2);
        assert_eq!(res.severity, "Critical"); // worst-case wins
        assert_eq!(res.severity_score, 95);
        let mut names = res.rule_names.clone();
        names.sort();
        assert_eq!(names, ["crit", "low"]);
    }

    #[test]
    fn tc_detection_factor_scaled() {
        let r =
            rules(r#"rule r { meta: tc_detection_factor = 4 strings: $a = "AAA" condition: $a }"#);
        let res = scan(&r, b"AAA");
        assert_eq!(res.severity, "High"); // 4 * 20 = 80
        assert_eq!(res.severity_score, 80);
    }

    #[test]
    fn severity_word_fallback() {
        let r =
            rules(r#"rule r { meta: severity = "moderate" strings: $a = "AAA" condition: $a }"#);
        let res = scan(&r, b"AAA");
        assert_eq!(res.severity, "Medium");
        assert_eq!(res.severity_score, -1);
    }

    #[test]
    fn string_score_is_coerced() {
        let r = rules(r#"rule r { meta: score = "72" strings: $a = "AAA" condition: $a }"#);
        let res = scan(&r, b"AAA");
        assert_eq!(res.severity, "High");
        assert_eq!(res.severity_score, 72);
    }

    #[test]
    fn attack_enrichment_from_meta_url() {
        use std::io::Write as _;
        // build a tiny ATT&CK db
        let bundle = serde_json::json!({"objects":[
            {"type":"attack-pattern","id":"attack-pattern--x","name":"Process Injection",
             "external_references":[{"source_name":"mitre-attack","external_id":"T1055"}]}
        ]})
        .to_string();
        let mut bf = tempfile::NamedTempFile::new().unwrap();
        bf.write_all(bundle.as_bytes()).unwrap();
        bf.flush().unwrap();
        let db = crate::attack::AttackDb::load(bf.path()).unwrap();

        let r = rules(
            r#"rule r { meta: reference = "https://attack.mitre.org/techniques/T1055" strings: $a = "AAA" condition: $a }"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s");
        std::fs::write(&p, b"AAA").unwrap();
        let mut scanner = Scanner::new(&r);
        let res = scan_file(&mut scanner, &p, Some(&db));
        assert_eq!(
            res.attack_techniques.as_deref(),
            Some("T1055 Process Injection []")
        );
    }
}
