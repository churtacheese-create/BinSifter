//! Scan orchestration - port of `binsifter.core.engine.scan_directory`.
//!
//! Phase 1 wires the stages that need no external engine: recursive file
//! enumeration, a single hash+entropy pass, NSRL known-good lookup, and the
//! offline known-bad blocklist. Per-file work runs on a bounded `rayon`
//! thread pool (capped at 16, matching the Python variant's
//! `MAX_SCAN_WORKERS`); with no GIL this is a plain data-parallel map rather
//! than a process pool.
//!
//! Later phases slot in here, gated behind the same NSRL-known-good check
//! the other variants use (a file NSRL vouches for skips imphash / ssdeep /
//! YARA / capa / FLOSS entirely).

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::Local;
use rayon::prelude::*;
use tracing::{info, warn};
use walkdir::WalkDir;

use crate::blocklist;
use crate::config::IngotConfig;
use crate::hashing;
use crate::model::FileRecord;
use crate::nsrl::{self, NsrlIndex};
use crate::report::{self, ReportPaths};

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

fn process_one_file(
    path: &str,
    nsrl_index: &NsrlIndex,
    blocklist: Option<&std::collections::HashSet<String>>,
) -> FileRecord {
    let mut record = FileRecord::new(path);

    match hashing::hash_and_score_file(Path::new(path)) {
        Ok(h) => {
            record.md5 = Some(h.md5.clone());
            record.sha1 = Some(h.sha1.clone());
            record.sha256 = Some(h.sha256.clone());
            record.entropy = h.entropy;

            record.nsrl_match = nsrl_index.contains(&h.sha1);

            if let Some(bl) = blocklist {
                let (status, source) = blocklist::check_reputation(&h.md5, &h.sha1, &h.sha256, bl);
                record.reputation_status = status;
                record.reputation_source = source;
            }

            // NSRL-known-good gate: imphash / ssdeep / YARA / capa / FLOSS
            // (Phase 2+) all skip here when `record.nsrl_match` is true.

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

/// Run the Phase 1 pipeline over every file under `config.src_dir`.
/// `on_progress` is invoked once per file as results complete (not in
/// submission order); it must be cheap and `Sync`.
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
    let nsrl_ref = &nsrl_index;
    let bl_ref = blocklist_hashes.as_ref();
    let counter_ref = &counter;

    let mut records: Vec<FileRecord> = pool.install(|| {
        paths
            .par_iter()
            .map(|path| {
                let record = process_one_file(path, nsrl_ref, bl_ref);
                let done = counter_ref.fetch_add(1, Ordering::SeqCst) + 1;
                on_progress(Progress {
                    done,
                    total,
                    record: &record,
                });
                record
            })
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
}
