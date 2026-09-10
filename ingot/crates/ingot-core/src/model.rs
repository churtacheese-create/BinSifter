//! Per-file scan record.
//!
//! Field-for-field port of `binsifter.core.models.FileRecord` (the Python
//! variant, Winnow), which is itself a port of the C# `BinSifter.FileRecord`
//! embedded in the original PowerShell variant. Rust names are snake_case;
//! the CSV column names/order live separately in [`crate::report`] and match
//! the other variants exactly. JSON goes to the browser UI as camelCase.
//!
//! The non-zero defaults matter and are load-bearing sentinels shared with
//! the CSV writer: `entropy = -1.0` ("not computed"), `*_cluster_id = -1`
//! ("not in a cluster"), `floss_string_count = -1` ("FLOSS not run"),
//! `yara_severity = "Unknown"`, `disposition = "Untriaged"`.

use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRecord {
    pub path: String,
    pub status: String,
    pub progress: i32,

    pub md5: Option<String>,
    pub sha1: Option<String>,
    /// Not written to CSV (neither the Python nor the C# record carries a
    /// SHA-256 column) - kept here only so the blocklist check and the UI
    /// can show it.
    pub sha256: Option<String>,
    pub ssdeep: Option<String>,
    pub nsrl_match: bool,

    pub yara_matches: Option<String>,
    pub yara_hit_count: i32,

    pub capa_eligible: bool,
    pub possible_false_negative: bool,
    pub capa_output: Option<String>,
    pub capa_detection_count: i32,
    pub capa_shellcode_format: Option<String>,

    pub yara_severity: String,
    pub yara_severity_score: i32,
    pub yara_attack_techniques: Option<String>,

    pub entropy: f64,
    pub error: Option<String>,
    /// RFC 3339 UTC timestamp of when this record was created.
    pub added: String,

    pub floss_string_count: i32,

    pub ssdeep_matches: Option<String>,
    pub ssdeep_cluster_id: i32,
    pub ssdeep_cluster_size: i32,
    pub ssdeep_has_high_similarity: bool,
    pub ssdeep_previously_seen: bool,

    pub packer_detected: String,
    pub compiler: String,

    pub imphash: Option<String>,
    pub rich_hash: Option<String>,
    pub imphash_cluster_id: i32,
    pub imphash_cluster_size: i32,

    pub signature_status: String,
    pub signer_name: String,

    pub ioc_count: i32,
    pub extracted_iocs: String,

    pub reputation_status: String,
    pub reputation_source: String,

    pub disposition: String,

    pub source_archive: String,
}

impl FileRecord {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            status: "Queued".to_string(),
            progress: 0,
            md5: None,
            sha1: None,
            sha256: None,
            ssdeep: None,
            nsrl_match: false,
            yara_matches: None,
            yara_hit_count: 0,
            capa_eligible: false,
            possible_false_negative: false,
            capa_output: None,
            capa_detection_count: 0,
            capa_shellcode_format: None,
            yara_severity: "Unknown".to_string(),
            yara_severity_score: -1,
            yara_attack_techniques: None,
            entropy: -1.0,
            error: None,
            added: Utc::now().to_rfc3339(),
            floss_string_count: -1,
            ssdeep_matches: None,
            ssdeep_cluster_id: -1,
            ssdeep_cluster_size: 0,
            ssdeep_has_high_similarity: false,
            ssdeep_previously_seen: false,
            packer_detected: String::new(),
            compiler: String::new(),
            imphash: None,
            rich_hash: None,
            imphash_cluster_id: -1,
            imphash_cluster_size: 0,
            signature_status: String::new(),
            signer_name: String::new(),
            ioc_count: 0,
            extracted_iocs: String::new(),
            reputation_status: String::new(),
            reputation_source: String::new(),
            disposition: "Untriaged".to_string(),
            source_archive: String::new(),
        }
    }
}
