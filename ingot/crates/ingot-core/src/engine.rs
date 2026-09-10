//! Scan orchestration - port of `binsifter.core.engine.scan_directory`.
//!
//! Per-file pipeline, in order: a single hash+entropy pass, prior-disposition
//! lookup, NSRL known-good lookup, the offline known-bad blocklist, then -
//! only for files NSRL did not vouch for - the PE import hash, YARA matching
//! (with severity bucketing + MITRE ATT&CK enrichment), and, for files YARA
//! flagged, PE/ELF/shellcode classification (capa-eligibility). Work runs on
//! a bounded `rayon` thread pool (capped at 16, matching the Python
//! variant's `MAX_SCAN_WORKERS`); with no GIL this is a plain data-parallel
//! map rather than a process pool, with one reused `yara_x::Scanner` per
//! worker thread.
//!
//! Gates match the other variants: NSRL-known files skip imphash / YARA /
//! capa-eligibility; capa-eligibility (`file_type`) is only computed for a
//! file with at least one YARA hit. Prior disposition is applied to every
//! file regardless, before any gate.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::Local;
use rayon::prelude::*;
use tracing::{error, info, warn};
use walkdir::WalkDir;
use yara_x::Scanner;

use crate::attack::{self, AttackDb};
use crate::blocklist;
use crate::config::IngotConfig;
use crate::disposition;
use crate::file_type;
use crate::hashing;
use crate::imphash;
use crate::model::FileRecord;
use crate::nsrl::{self, NsrlIndex};
use crate::report::{self, ReportPaths};
use crate::yara_scan;

/// Same ceiling as the Python variant's `MAX_SCAN_WORKERS`.
pub const MAX_SCAN_WORKERS: usize = 16;

pub struct ScanResult {
    pub records: Vec<FileRecord>,
    /// `None` when `report_directory` was blank/unusable.
    pub report_paths: Option<ReportPaths>,
}

/// Progress event handed to the caller's sink once per file completion.
pub struct Progress<'a> {
    pub done: usize,
    pub total: usize,
    pub record: &'a FileRecord,
}

fn default_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, MAX_SCAN_WORKERS)
}

/// Recursively enumerate files under `src_dir`. One unreadable subtree is
/// skipped, not fatal (matches the other variants' per-directory isolation).
pub fn enumerate_files(src_dir: &str) -> Vec<String> {
    let mut files = Vec::new();
    for entry in WalkDir::new(src_dir).follow_links(false) {
        match entry {
            Ok(e) if e.file_type().is_file() => {
                files.push(e.path().to_string_lossy().into_owned());
            }
            Ok(_) => {}
            Err(err) => warn!("Skipping unreadable path during enumeration: {err}"),
        }
    }
    files
}

struct FileScanCtx<'a> {
    nsrl_index: &'a NsrlIndex,
    blocklist: Option<&'a std::collections::HashSet<String>>,
    disposition_history: &'a BTreeMap<String, String>,
    attack_db: Option<&'a AttackDb>,
}

fn process_one_file(
    path: &str,
    ctx: &FileScanCtx<'_>,
    yara_scanner: Option<&mut Scanner>,
) -> FileRecord {
    let mut record = FileRecord::new(path);
    let target = Path::new(path);

    match hashing::hash_and_score_file(target) {
        Ok(h) => {
            record.md5 = Some(h.md5.clone());
            record.sha1 = Some(h.sha1.clone());
            record.sha256 = Some(h.sha256.clone());
            record.entropy = h.entropy;

            // Prior analyst disposition, keyed by SHA-1 - applied to every
            // file, before the NSRL gate (same as the other variants).
            if let Some(prior) = ctx.disposition_history.get(&h.sha1.to_ascii_lowercase()) {
                record.disposition = prior.clone();
            }

            record.nsrl_match = ctx.nsrl_index.contains(&h.sha1);

            if let Some(bl) = ctx.blocklist {
                let (status, source) = blocklist::check_reputation(&h.md5, &h.sha1, &h.sha256, bl);
                record.reputation_status = status;
                record.reputation_source = source;
            }

            // NSRL-known-good gate: a file NSRL vouches for skips imphash,
            // YARA and capa-eligibility (and later ssdeep / capa / FLOSS).
            if !record.nsrl_match {
                record.imphash = imphash::compute_imphash(target);

                if let Some(scanner) = yara_scanner {
                    let yr = yara_scan::scan_file(scanner, target, ctx.attack_db);
                    record.yara_matches =
                        (!yr.rule_names.is_empty()).then(|| yr.rule_names.join("; "));
                    record.yara_hit_count = yr.hit_count as i32;
                    record.yara_severity = yr.severity;
                    record.yara_severity_score = yr.severity_score;
                    record.yara_attack_techniques = yr.attack_techniques;
                }

                // capa-eligibility is only computed for a file YARA flagged,
                // matching engine.py (capa never runs against an unflagged
                // file). capa/FLOSS themselves land in a later phase.
                if record.yara_hit_count > 0 {
                    let ft = file_type::classify(target, h.length);
                    record.capa_eligible = ft.capa_eligible;
                    record.possible_false_negative =
                        file_type::is_possible_false_negative(&ft, record.yara_hit_count, target);
                }
            }

            record.status = "Completed".to_string();
        }
        Err(e) => {
            record.status = "Error".to_string();
            record.error = Some(e.to_string());
            warn!("Error processing {path}: {e}");
        }
    }
    record
}

/// Run the currently-implemented pipeline over every file under
/// `config.src_dir`. `on_progress` is invoked once per file as results
/// complete (not in submission order); it must be cheap and `Sync`.
pub fn scan_directory<F>(config: &IngotConfig, on_progress: F) -> ScanResult
where
    F: Fn(Progress) + Sync + Send,
{
    info!("Enumerating files under {}...", config.src_dir);
    let paths = enumerate_files(&config.src_dir);
    let total = paths.len();
    info!("Found {total} file(s) to scan.");

    // --- NSRL index --------------------------------------------------------
    let nsrl_index = match nsrl::prepare_nsrl_index(&config.nsrl_path, &config.report_directory) {
        Some(cache_path) => {
            let idx = nsrl::open_index(&cache_path);
            info!("NSRL index ready: {} hash(es).", idx.count());
            idx
        }
        None => {
            if !config.nsrl_path.is_empty() {
                warn!(
                    "NSRL path not usable, known-good lookup disabled: {}",
                    config.nsrl_path
                );
            } else {
                info!("No NSRL hash set configured - known-good lookup disabled.");
            }
            NsrlIndex::empty()
        }
    };

    // --- blocklist -------------------------------------------------------
    let blocklist_hashes =
        if !config.blocklist_path.is_empty() && Path::new(&config.blocklist_path).is_file() {
            let set = blocklist::load_blocklist_hashes(Path::new(&config.blocklist_path));
            info!("Blocklist loaded: {} hash(es).", set.len());
            Some(set)
        } else {
            None
        };

    // --- prior triage dispositions (by SHA-1, persisted across scans) ----
    let disposition_history = disposition::load_disposition_history(&config.report_directory);
    if !disposition_history.is_empty() {
        info!(
            "Loaded {} prior disposition(s) from history.",
            disposition_history.len()
        );
    }

    // --- YARA rules ----------------------------------------------------
    // Compiled once here; each worker thread gets its own reused Scanner
    // borrowing this ruleset. A compile failure disables YARA for the scan
    // (logged at ERROR) rather than aborting - the Logs tab surfaces it.
    let yara_rules = if !config.yara_rules.is_empty() {
        info!("Compiling YARA rules from {}...", config.yara_rules);
        match yara_scan::compile_rules(Path::new(&config.yara_rules)) {
            Ok(rules) => Some(rules),
            Err(e) => {
                error!("YARA rules failed to compile - YARA disabled for this scan: {e}");
                None
            }
        }
    } else {
        None
    };

    // --- MITRE ATT&CK enrichment data (optional) ----------------------
    let attack_db = attack::load_optional(&config.attack_data_path);
    if let Some(db) = &attack_db {
        info!(
            "MITRE ATT&CK data loaded: {} techniques indexed.",
            db.technique_count()
        );
    } else if config.attack_data_path.is_empty() {
        info!("No MITRE ATT&CK data configured - TTP mapping disabled for this scan.");
    }

    // --- parallel per-file pass ----------------------------------------
    let worker_count = default_worker_count().min(total.max(1));
    info!("Scanning {total} file(s) with {worker_count} worker thread(s)...");

    let counter = Arc::new(AtomicUsize::new(0));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .thread_name(|i| format!("ingot-scan-{i}"))
        .build()
        .expect("rayon pool");

    let on_progress = &on_progress;
    let counter_ref = &counter;
    let ctx = FileScanCtx {
        nsrl_index: &nsrl_index,
        blocklist: blocklist_hashes.as_ref(),
        disposition_history: &disposition_history,
        attack_db: attack_db.as_ref(),
    };
    let ctx_ref = &ctx;
    let yara_rules_ref = yara_rules.as_ref();

    let mut records: Vec<FileRecord> = pool.install(|| {
        paths
            .par_iter()
            .map_init(
                || yara_rules_ref.map(Scanner::new),
                |scanner, path| {
                    let record = process_one_file(path, ctx_ref, scanner.as_mut());
                    let done = counter_ref.fetch_add(1, Ordering::SeqCst) + 1;
                    on_progress(Progress {
                        done,
                        total,
                        record: &record,
                    });
                    record
                },
            )
            .collect()
    });

    records.sort_by(|a, b| a.path.cmp(&b.path));

    // --- reports ---------------------------------------------------------
    let report_paths = if config.report_directory.is_empty() {
        None
    } else {
        let timestamp = Local::now().format("%Y-%m-%d_%H%M%S").to_string();
        match report::write_all_reports(&records, &config.report_directory, &timestamp) {
            Ok(p) => {
                info!("Reports written to {}", config.report_directory);
                Some(p)
            }
            Err(e) => {
                warn!("Could not write reports: {e}");
                None
            }
        }
    };

    ScanResult {
        records,
        report_paths,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn cfg_for(dir: &Path, reports: &Path) -> IngotConfig {
        IngotConfig {
            src_dir: dir.to_string_lossy().into_owned(),
            nsrl_path: String::new(),
            yara_rules: String::new(),
            capa_rules: String::new(),
            tools_dir: String::new(),
            ghidra_dir: String::new(),
            catalog_directory: String::new(),
            report_directory: reports.to_string_lossy().into_owned(),
            attack_data_path: String::new(),
            blocklist_path: String::new(),
        }
    }

    #[test]
    fn end_to_end_hash_nsrl_blocklist_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let reports = dir.path().join("reports");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(src.join("nested")).unwrap();
        std::fs::write(src.join("a.txt"), b"abc").unwrap();
        std::fs::write(src.join("nested").join("b.bin"), b"hello world").unwrap();

        // NSRL set that vouches for "abc"
        let nsrl_src = dir.path().join("nsrl.txt");
        std::fs::write(&nsrl_src, "a9993e364706816aba3e25717850c26c9cd0d89d\n").unwrap();

        // blocklist that flags "hello world" (its md5)
        let bl = dir.path().join("bl.txt");
        std::fs::write(&bl, "5eb63bbbe01eeed093cb22bb8f5acdc3\n").unwrap();

        let mut config = cfg_for(&src, &reports);
        config.nsrl_path = nsrl_src.to_string_lossy().into_owned();
        config.blocklist_path = bl.to_string_lossy().into_owned();

        let seen = Mutex::new(Vec::<(usize, usize)>::new());
        let result = scan_directory(&config, |p| {
            seen.lock().unwrap().push((p.done, p.total));
        });

        assert_eq!(result.records.len(), 2);
        assert_eq!(seen.lock().unwrap().len(), 2);

        let a = result
            .records
            .iter()
            .find(|r| r.path.ends_with("a.txt"))
            .unwrap();
        assert_eq!(a.status, "Completed");
        assert!(a.nsrl_match, "abc should be NSRL-known");
        assert_eq!(a.md5.as_deref(), Some("900150983cd24fb0d6963f7d28e17f72"));

        let b = result
            .records
            .iter()
            .find(|r| r.path.ends_with("b.bin"))
            .unwrap();
        assert!(!b.nsrl_match);
        assert_eq!(b.reputation_status, "KnownBad");
        assert_eq!(b.reputation_source, "MD5");

        let paths = result.report_paths.expect("reports written");
        assert!(Path::new(&paths.full).is_file());
        let full = std::fs::read_to_string(&paths.full).unwrap();
        assert!(full.contains("a.txt") && full.contains("b.bin"));
        // suspicious report excludes the NSRL-known file
        let susp = std::fs::read_to_string(&paths.suspicious).unwrap();
        assert!(!susp.contains("a.txt"));
        assert!(susp.contains("b.bin"));
    }

    #[test]
    fn empty_source_dir_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let reports = dir.path().join("reports");
        std::fs::create_dir_all(&src).unwrap();
        let result = scan_directory(&cfg_for(&src, &reports), |_| {});
        assert!(result.records.is_empty());
    }

    #[test]
    fn prior_disposition_is_applied_and_imphash_gated_by_nsrl() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let reports = dir.path().join("reports");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&reports).unwrap();

        // a real PE, and a plain file
        let pe_src =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/ingot.exe");
        let have_pe = pe_src.is_file();
        if have_pe {
            std::fs::copy(&pe_src, src.join("sample.exe")).unwrap();
        }
        std::fs::write(src.join("plain.txt"), b"abc").unwrap();

        // seed a prior disposition for "abc" (its SHA-1)
        let abc_sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d";
        crate::disposition::save_disposition_entry(
            reports.to_str().unwrap(),
            abc_sha1,
            "Escalated",
        )
        .unwrap();

        let mut config = cfg_for(&src, &reports);
        // NSRL vouches for "abc" -> imphash-style stages must skip it
        let nsrl_src = dir.path().join("nsrl.txt");
        std::fs::write(&nsrl_src, format!("{abc_sha1}\n")).unwrap();
        config.nsrl_path = nsrl_src.to_string_lossy().into_owned();

        let result = scan_directory(&config, |_| {});

        let plain = result
            .records
            .iter()
            .find(|r| r.path.ends_with("plain.txt"))
            .unwrap();
        assert_eq!(
            plain.disposition, "Escalated",
            "prior disposition not applied"
        );
        assert!(plain.nsrl_match);
        assert_eq!(plain.imphash, None, "NSRL-known file must skip imphash");

        if have_pe {
            let pe = result
                .records
                .iter()
                .find(|r| r.path.ends_with("sample.exe"))
                .unwrap();
            assert!(!pe.nsrl_match);
            let mine = pe.imphash.clone().expect("PE should have an imphash");
            let direct = crate::imphash::compute_imphash(&src.join("sample.exe")).unwrap();
            assert_eq!(mine, direct);
            assert_eq!(mine.len(), 32);
        }
    }

    #[test]
    fn yara_matches_drive_severity_and_capa_eligibility_gate() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let reports = dir.path().join("reports");
        std::fs::create_dir_all(&src).unwrap();

        // one file the rule hits, one it doesn't
        std::fs::write(src.join("hit.bin"), b"....MALWARE_MARKER_42....").unwrap();
        std::fs::write(src.join("clean.bin"), b"nothing to see here").unwrap();

        let rules = dir.path().join("rules.yar");
        std::fs::write(
            &rules,
            r#"rule marker {
                 meta:
                   score = 95
                   reference = "https://attack.mitre.org/techniques/T1055"
                 strings:
                   $m = "MALWARE_MARKER_42"
                 condition:
                   $m
               }"#,
        )
        .unwrap();

        // tiny ATT&CK bundle for the technique the rule references
        let bundle = dir.path().join("attack.json");
        std::fs::write(
            &bundle,
            serde_json::json!({"objects":[
                {"type":"attack-pattern","id":"attack-pattern--z","name":"Process Injection",
                 "external_references":[{"source_name":"mitre-attack","external_id":"T1055"}]}
            ]})
            .to_string(),
        )
        .unwrap();

        let mut config = cfg_for(&src, &reports);
        config.yara_rules = rules.to_string_lossy().into_owned();
        config.attack_data_path = bundle.to_string_lossy().into_owned();

        let result = scan_directory(&config, |_| {});

        let hit = result
            .records
            .iter()
            .find(|r| r.path.ends_with("hit.bin"))
            .unwrap();
        assert_eq!(hit.yara_hit_count, 1);
        assert_eq!(hit.yara_matches.as_deref(), Some("marker"));
        assert_eq!(hit.yara_severity, "Critical");
        assert_eq!(hit.yara_severity_score, 95);
        assert_eq!(
            hit.yara_attack_techniques.as_deref(),
            Some("T1055 Process Injection []")
        );
        // .bin under 100k with a YARA hit -> shellcode -> capa-eligible
        assert!(
            hit.capa_eligible,
            "YARA-flagged small .bin should be capa-eligible"
        );

        let clean = result
            .records
            .iter()
            .find(|r| r.path.ends_with("clean.bin"))
            .unwrap();
        assert_eq!(clean.yara_hit_count, 0);
        assert_eq!(clean.yara_severity, "Unknown");
        // no YARA hit -> capa-eligibility never computed
        assert!(!clean.capa_eligible);
    }
}
