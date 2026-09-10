//! AI-ready export - port of `binsifter.core.ai_export`.
//!
//! Formats one file's **already-computed** findings into a compact Markdown
//! document and a JSON object for the analyst to hand to whatever AI they
//! choose. Ingot never runs or calls any AI here - this is a specialised
//! report writer, nothing more.
//!
//! Empty / zero / `false` / sentinel fields are dropped rather than padded
//! with noise; `CapaOutput` is truncated so one file's export stays a
//! pasteable size.

use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Value};

use crate::model::FileRecord;

const TRUNCATE_AT: usize = 4000;

const DISCLAIMER: &str = "This document contains only automated findings BinSifter already extracted for this file - no AI analysis has been run on it. Any conclusions an AI draws from the data below are a hypothesis for further investigation, not a detection.";

fn truncate(s: &str) -> String {
    if s.chars().count() <= TRUNCATE_AT {
        return s.to_string();
    }
    let head: String = s.chars().take(TRUNCATE_AT).collect();
    format!("{head}\n...(truncated, {} chars total)", s.chars().count())
}

/// `"C:\a\b.exe"` / `"/a/b.exe"` -> `"b.exe"` - handles both separators
/// regardless of host OS (record paths come from whichever machine ran the
/// scan).
fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn stem(path: &str) -> &str {
    let name = basename(path);
    name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name)
}

/// The findings worth an AI's attention - drops "not computed" sentinels.
pub fn compact_record(r: &FileRecord) -> Value {
    let mut out = serde_json::Map::new();

    // identity - always kept
    out.insert("path".into(), json!(r.path));
    if let Some(v) = &r.md5 {
        out.insert("md5".into(), json!(v));
    }
    if let Some(v) = &r.sha1 {
        out.insert("sha1".into(), json!(v));
    }
    if let Some(v) = &r.sha256 {
        out.insert("sha256".into(), json!(v));
    }
    out.insert("disposition".into(), json!(r.disposition)); // meaningful even at "Untriaged"

    let mut opt_str = |k: &str, v: &Option<String>| {
        if let Some(v) = v.as_deref().filter(|s| !s.is_empty()) {
            out.insert(k.into(), json!(truncate(v)));
        }
    };
    opt_str("ssdeep", &r.ssdeep);
    opt_str("imphash", &r.imphash);
    opt_str("richHash", &r.rich_hash);
    opt_str("yaraMatches", &r.yara_matches);
    opt_str("yaraAttackTechniques", &r.yara_attack_techniques);
    opt_str("capaOutput", &r.capa_output);
    opt_str("capaShellcodeFormat", &r.capa_shellcode_format);
    opt_str("ssdeepMatches", &r.ssdeep_matches);
    opt_str("error", &r.error);

    let mut nonempty = |k: &str, v: &str| {
        if !v.is_empty() {
            out.insert(k.into(), json!(v));
        }
    };
    nonempty("signatureStatus", &r.signature_status);
    nonempty("signerName", &r.signer_name);
    nonempty("extractedIocs", &r.extracted_iocs);
    nonempty("reputationStatus", &r.reputation_status);
    nonempty("reputationSource", &r.reputation_source);
    nonempty("packerDetected", &r.packer_detected);
    nonempty("compiler", &r.compiler);
    nonempty("sourceArchive", &r.source_archive);

    if r.nsrl_match {
        out.insert("nsrlMatch".into(), json!(true));
    }
    if r.yara_hit_count > 0 {
        out.insert("yaraHitCount".into(), json!(r.yara_hit_count));
    }
    if r.yara_severity != "Unknown" {
        out.insert("yaraSeverity".into(), json!(r.yara_severity));
    }
    if r.yara_severity_score >= 0 {
        out.insert("yaraSeverityScore".into(), json!(r.yara_severity_score));
    }
    if r.capa_eligible {
        out.insert("capaEligible".into(), json!(true));
    }
    if r.capa_detection_count > 0 {
        out.insert("capaDetectionCount".into(), json!(r.capa_detection_count));
    }
    if r.possible_false_negative {
        out.insert("possibleFalseNegative".into(), json!(true));
    }
    if r.entropy >= 0.0 {
        out.insert(
            "entropy".into(),
            json!((r.entropy * 1000.0).round() / 1000.0),
        );
    }
    if r.floss_string_count >= 0 {
        out.insert("flossStringCount".into(), json!(r.floss_string_count));
    }
    if r.ssdeep_cluster_size > 0 {
        out.insert("ssdeepClusterSize".into(), json!(r.ssdeep_cluster_size));
    }
    if r.ssdeep_has_high_similarity {
        out.insert("ssdeepHasHighSimilarity".into(), json!(true));
    }
    if r.ssdeep_previously_seen {
        out.insert("ssdeepPreviouslySeen".into(), json!(true));
    }
    if r.imphash_cluster_size > 0 {
        out.insert("imphashClusterSize".into(), json!(r.imphash_cluster_size));
    }
    if r.ioc_count > 0 {
        out.insert("iocCount".into(), json!(r.ioc_count));
    }

    Value::Object(out)
}

pub fn build_json(record: &FileRecord) -> Value {
    json!({
        "_meta": {
            "generatedBy": "BinSifter Ingot",
            "generatedAt": Utc::now().to_rfc3339(),
            "note": DISCLAIMER,
        },
        "findings": compact_record(record),
    })
}

pub fn build_markdown(record: &FileRecord) -> String {
    let d = compact_record(record);
    let get = |k: &str| d.get(k);
    let s = |k: &str| get(k).and_then(Value::as_str);
    let name = {
        let b = basename(&record.path);
        if b.is_empty() {
            record.path.as_str()
        } else {
            b
        }
    };

    let mut out = format!("# BinSifter finding: {name}\n\n");
    out.push_str(&format!(
        "**Path:** `{}`\n",
        s("path").unwrap_or(&record.path)
    ));
    let hashes: Vec<String> = [("MD5", "md5"), ("SHA1", "sha1"), ("ssdeep", "ssdeep")]
        .iter()
        .filter_map(|(label, key)| s(key).map(|v| format!("{label} `{v}`")))
        .collect();
    if !hashes.is_empty() {
        out.push_str(&format!("**Hashes:** {}\n", hashes.join(" · ")));
    }
    out.push('\n');

    fn section(out: &mut String, title: &str, rows: &[(&str, Option<String>)]) {
        let present: Vec<_> = rows.iter().filter(|(_, v)| v.is_some()).collect();
        if present.is_empty() {
            return;
        }
        out.push_str(&format!("## {title}\n"));
        for (label, value) in present {
            out.push_str(&format!("- {label}: {}\n", value.as_ref().unwrap()));
        }
        out.push('\n');
    }

    // Render values the way Python's f-strings do: bare strings without JSON
    // quotes, and `True`/`False` for booleans (matching Winnow's output).
    let disp = |k: &str| {
        get(k).map(|v| match v {
            Value::Bool(true) => "True".to_string(),
            Value::Bool(false) => "False".to_string(),
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    };

    section(
        &mut out,
        "Signature",
        &[
            ("Status", disp("signatureStatus")),
            ("Signer", disp("signerName")),
        ],
    );
    let severity = get("yaraSeverity").and_then(Value::as_str).map(|sev| {
        match get("yaraSeverityScore").and_then(Value::as_i64) {
            Some(score) => format!("{sev} (score {score})"),
            None => sev.to_string(),
        }
    });
    section(
        &mut out,
        "YARA",
        &[
            ("Hits", disp("yaraHitCount")),
            ("Severity", severity),
            ("Rules matched", disp("yaraMatches")),
            ("ATT&CK techniques", disp("yaraAttackTechniques")),
        ],
    );
    section(
        &mut out,
        "capa",
        &[
            ("Eligible", disp("capaEligible")),
            ("Detections", disp("capaDetectionCount")),
            ("Possible false negative", disp("possibleFalseNegative")),
            ("Shellcode format", disp("capaShellcodeFormat")),
        ],
    );
    if let Some(capa_out) = s("capaOutput") {
        out.push_str("### Raw capa output\n```\n");
        out.push_str(capa_out);
        out.push_str("\n```\n\n");
    }
    section(
        &mut out,
        "ssdeep / imphash clustering",
        &[
            ("ssdeep cluster size", disp("ssdeepClusterSize")),
            (
                "ssdeep high similarity to another file",
                disp("ssdeepHasHighSimilarity"),
            ),
            ("ssdeep matches", disp("ssdeepMatches")),
            ("Imphash", disp("imphash")),
            ("Imphash cluster size", disp("imphashClusterSize")),
        ],
    );
    if let Some(iocs) = s("extractedIocs") {
        let count = get("iocCount")
            .and_then(Value::as_i64)
            .map(|c| format!(" ({c})"))
            .unwrap_or_default();
        out.push_str(&format!("## Extracted IOCs{count}\n"));
        for ioc in iocs.split("; ") {
            out.push_str(&format!("- {ioc}\n"));
        }
        out.push('\n');
    }
    section(
        &mut out,
        "Other",
        &[
            ("Entropy", disp("entropy")),
            ("FLOSS string count", disp("flossStringCount")),
            ("Reputation status", disp("reputationStatus")),
            ("Disposition", disp("disposition")),
            ("Source archive", disp("sourceArchive")),
            ("Scan error", disp("error")),
        ],
    );

    out.push_str("---\n");
    out.push_str(&format!(
        "_Generated by BinSifter Ingot on {}. {DISCLAIMER}_\n",
        Utc::now().format("%Y-%m-%d")
    ));
    out
}

/// Write the `.md` + `.json` export for one file into `output_dir`, named by
/// SHA-1 (or the file stem if unhashed). Returns `(markdown_path, json_path)`.
pub fn export_file(record: &FileRecord, output_dir: &Path) -> std::io::Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(output_dir)?;
    let stem = match record.sha1.as_deref().filter(|s| !s.is_empty()) {
        Some(sha1) => format!("BinSifter_{sha1}"),
        None => format!("BinSifter_{}", stem(&record.path)),
    };
    let md_path = output_dir.join(format!("{stem}.md"));
    let json_path = output_dir.join(format!("{stem}.json"));
    std::fs::write(&md_path, build_markdown(record))?;
    std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&build_json(record)).unwrap(),
    )?;
    Ok((md_path, json_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_sentinels_keeps_real_findings() {
        let mut r = FileRecord::new("C:\\evidence\\bad.exe");
        r.sha1 = Some("abcd".into());
        r.md5 = Some("ef01".into());
        r.entropy = 7.55;
        r.yara_hit_count = 2;
        r.yara_severity = "Critical".into();
        r.yara_severity_score = 95;
        r.signature_status = "NotTrusted".into();
        r.ioc_count = 3;
        r.extracted_iocs = "1.2.3.4; evil.example.com".into();

        let c = compact_record(&r);
        // dropped: floss_string_count (-1), reputation ("" ), capa (0/false)
        assert!(c.get("flossStringCount").is_none());
        assert!(c.get("reputationStatus").is_none());
        assert!(c.get("capaDetectionCount").is_none());
        // kept
        assert_eq!(c["yaraHitCount"], 2);
        assert_eq!(c["yaraSeverity"], "Critical");
        assert_eq!(c["disposition"], "Untriaged"); // always kept
        assert_eq!(c["entropy"], 7.55);

        let md = build_markdown(&r);
        assert!(md.contains("# BinSifter finding: bad.exe"));
        assert!(md.contains("Status: NotTrusted"));
        assert!(md.contains("Severity: Critical (score 95)"));
        assert!(md.contains("- 1.2.3.4"));
        assert!(md.contains("- evil.example.com"));
        assert!(md.contains("no AI analysis has been run"));
    }

    #[test]
    fn export_writes_both_files_named_by_sha1() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = FileRecord::new("/x/sample");
        r.sha1 = Some("deadbeef".into());
        let (md, js) = export_file(&r, dir.path()).unwrap();
        assert!(md.ends_with("BinSifter_deadbeef.md"));
        assert!(js.ends_with("BinSifter_deadbeef.json"));
        let parsed: Value = serde_json::from_str(&std::fs::read_to_string(&js).unwrap()).unwrap();
        assert_eq!(parsed["_meta"]["generatedBy"], "BinSifter Ingot");
        assert!(parsed["findings"]["path"] == "/x/sample");
    }
}
