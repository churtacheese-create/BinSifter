//! CSV report writing - port of `binsifter.core.report`.
//!
//! **Not** a generic "dump every field" writer. The exact 37-column list,
//! order, and per-column blank-if-default formatting below is what analysts
//! open in Excel and import into other tooling across all three variants -
//! it must match byte-for-byte:
//!
//! * UTF-8 **with a BOM**, CRLF line endings.
//! * Booleans render `True` / `False` (Python `str(bool)` capitalisation).
//! * `Entropy` to 3 decimals, blank when `< 0`.
//! * Sentinel int columns (`-1` / `0`) render blank, not the number.
//!
//! Four files per scan, all stamped with the same scan timestamp:
//! `BinSifter_Triage_`, `suspicious_unknown_`, `yara_matches_`,
//! `capa_compatible_` + `<timestamp>.csv`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::model::FileRecord;

/// Exact column list/order from the C# `CsvWriter.WriteReport`.
pub const COLUMNS: [&str; 37] = [
    "FilePath",
    "SHA1",
    "MD5",
    "SSDEEP",
    "IsKnownGood",
    "YaraHitCount",
    "YaraMatches",
    "YaraSeverity",
    "YaraSeverityScore",
    "AttackTechniques",
    "CapaEligible",
    "PossibleFalseNegative",
    "CapaDetections",
    "Status",
    "Error",
    "Entropy",
    "CapaShellcodeFormat",
    "FlossStringCount",
    "SsdeepMatches",
    "SsdeepClusterId",
    "SsdeepClusterSize",
    "SsdeepHighSimilarity",
    "SsdeepPreviouslySeen",
    "PackerDetected",
    "Compiler",
    "Imphash",
    "RichHash",
    "ImphashClusterId",
    "ImphashClusterSize",
    "SignatureStatus",
    "SignerName",
    "IocCount",
    "ExtractedIOCs",
    "ReputationStatus",
    "ReputationSource",
    "Disposition",
    "SourceArchive",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportMode {
    Full,
    Suspicious,
    Yara,
    Capa,
}

/// Python `str(bool)`.
fn pybool(b: bool) -> &'static str {
    if b {
        "True"
    } else {
        "False"
    }
}

fn opt(s: &Option<String>) -> &str {
    s.as_deref().unwrap_or("")
}

fn row_for(r: &FileRecord) -> Vec<String> {
    vec![
        r.path.clone(),
        opt(&r.sha1).to_string(),
        opt(&r.md5).to_string(),
        opt(&r.ssdeep).to_string(),
        pybool(r.nsrl_match).to_string(),
        r.yara_hit_count.to_string(),
        opt(&r.yara_matches).to_string(),
        r.yara_severity.clone(),
        r.yara_severity_score.to_string(),
        opt(&r.yara_attack_techniques).to_string(),
        pybool(r.capa_eligible).to_string(),
        pybool(r.possible_false_negative).to_string(),
        r.capa_detection_count.to_string(),
        r.status.clone(),
        opt(&r.error).to_string(),
        if r.entropy >= 0.0 {
            format!("{:.3}", r.entropy)
        } else {
            String::new()
        },
        opt(&r.capa_shellcode_format).to_string(),
        if r.floss_string_count >= 0 {
            r.floss_string_count.to_string()
        } else {
            String::new()
        },
        opt(&r.ssdeep_matches).to_string(),
        if r.ssdeep_cluster_id >= 0 {
            r.ssdeep_cluster_id.to_string()
        } else {
            String::new()
        },
        if r.ssdeep_cluster_size > 0 {
            r.ssdeep_cluster_size.to_string()
        } else {
            String::new()
        },
        pybool(r.ssdeep_has_high_similarity).to_string(),
        pybool(r.ssdeep_previously_seen).to_string(),
        r.packer_detected.clone(),
        r.compiler.clone(),
        opt(&r.imphash).to_string(),
        opt(&r.rich_hash).to_string(),
        if r.imphash_cluster_id >= 0 {
            r.imphash_cluster_id.to_string()
        } else {
            String::new()
        },
        if r.imphash_cluster_size > 0 {
            r.imphash_cluster_size.to_string()
        } else {
            String::new()
        },
        r.signature_status.clone(),
        r.signer_name.clone(),
        if r.ioc_count > 0 {
            r.ioc_count.to_string()
        } else {
            String::new()
        },
        r.extracted_iocs.clone(),
        r.reputation_status.clone(),
        r.reputation_source.clone(),
        r.disposition.clone(),
        r.source_archive.clone(),
    ]
}

fn include(record: &FileRecord, mode: ReportMode) -> bool {
    match mode {
        ReportMode::Full => true,
        ReportMode::Suspicious => !record.nsrl_match,
        ReportMode::Yara => record.yara_hit_count > 0,
        ReportMode::Capa => record.capa_eligible,
    }
}

/// Serialize records to CSV bytes (UTF-8 BOM + CRLF), filtered by `mode`.
pub fn render(records: &[FileRecord], mode: ReportMode) -> Vec<u8> {
    let mut wtr = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(vec![0xEF, 0xBB, 0xBF]);
    wtr.write_record(COLUMNS).expect("header write to Vec");
    for record in records.iter().filter(|r| include(r, mode)) {
        wtr.write_record(row_for(record)).expect("row write to Vec");
    }
    wtr.into_inner().expect("flush to Vec")
}

pub fn write_report(path: &Path, records: &[FileRecord], mode: ReportMode) -> std::io::Result<()> {
    let mut f = fs::File::create(path)?;
    f.write_all(&render(records, mode))?;
    f.flush()
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportPaths {
    pub full: String,
    pub suspicious: String,
    pub yara_matches: String,
    pub capa_compatible: String,
}

/// Write all four report files into `report_directory`, stamped `timestamp`.
pub fn write_all_reports(
    records: &[FileRecord],
    report_directory: &str,
    timestamp: &str,
) -> std::io::Result<ReportPaths> {
    let root = PathBuf::from(report_directory);
    fs::create_dir_all(&root)?;

    let full = root.join(format!("BinSifter_Triage_{timestamp}.csv"));
    let suspicious = root.join(format!("suspicious_unknown_{timestamp}.csv"));
    let yara_matches = root.join(format!("yara_matches_{timestamp}.csv"));
    let capa_compatible = root.join(format!("capa_compatible_{timestamp}.csv"));

    write_report(&full, records, ReportMode::Full)?;
    write_report(&suspicious, records, ReportMode::Suspicious)?;
    write_report(&yara_matches, records, ReportMode::Yara)?;
    write_report(&capa_compatible, records, ReportMode::Capa)?;

    Ok(ReportPaths {
        full: full.to_string_lossy().into_owned(),
        suspicious: suspicious.to_string_lossy().into_owned(),
        yara_matches: yara_matches.to_string_lossy().into_owned(),
        capa_compatible: capa_compatible.to_string_lossy().into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_count_is_37() {
        assert_eq!(COLUMNS.len(), 37);
    }

    #[test]
    fn bom_crlf_and_python_style_formatting() {
        let mut r = FileRecord::new("C:\\evidence\\a.bin");
        r.sha1 = Some("aaaa".into());
        r.md5 = Some("bbbb".into());
        r.status = "Completed".into();
        r.entropy = 7.123456;
        r.nsrl_match = false;

        let bytes = render(&[r], ReportMode::Full);
        assert_eq!(&bytes[..3], &[0xEF, 0xBB, 0xBF], "missing UTF-8 BOM");

        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\r\n"), "expected CRLF line endings");
        let header = text.lines().next().unwrap().trim_start_matches('\u{feff}');
        assert_eq!(header, COLUMNS.join(","));

        let data_line = text.lines().nth(1).unwrap();
        // IsKnownGood renders "False", Entropy to 3dp
        assert!(data_line.contains("False"), "line: {data_line}");
        assert!(data_line.contains("7.123"), "line: {data_line}");
    }

    #[test]
    fn sentinel_ints_render_blank() {
        let r = FileRecord::new("x"); // all defaults: cluster ids -1, floss -1, ioc 0
        let text = String::from_utf8(render(&[r], ReportMode::Full)).unwrap();
        let fields: Vec<&str> = text.lines().nth(1).unwrap().split(',').collect();
        // FlossStringCount is column index 17
        assert_eq!(fields[17], "");
        // SsdeepClusterId index 19
        assert_eq!(fields[19], "");
        // Entropy index 15 (default -1.0 -> blank)
        assert_eq!(fields[15], "");
    }

    #[test]
    fn mode_filters() {
        let mut known = FileRecord::new("good");
        known.nsrl_match = true;
        let mut bad = FileRecord::new("bad");
        bad.yara_hit_count = 2;
        bad.capa_eligible = true;
        let records = [known, bad];

        let susp = String::from_utf8(render(&records, ReportMode::Suspicious)).unwrap();
        assert!(!susp.contains("good"));
        assert!(susp.contains("bad"));

        let yara = String::from_utf8(render(&records, ReportMode::Yara)).unwrap();
        assert_eq!(yara.lines().count(), 2); // header + "bad"
    }
}
