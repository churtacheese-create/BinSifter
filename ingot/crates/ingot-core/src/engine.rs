//! Scan orchestration - port of `binsifter.core.engine.scan_directory`.
//!
//! Archives found under the source directory are expanded in a serial
//! pre-scan pass (before the worker pool) so their contents scan as
//! ordinary files. Per file, in order: a single hash+entropy pass,
//! prior-disposition lookup, Authenticode verification (unconditional),
//! NSRL known-good lookup, the offline known-bad blocklist, then - only for
//! files NSRL did not vouch for - the PE import hash, SSDEEP fuzzy hash,
//! YARA matching (severity + MITRE ATT&CK), and, for files YARA flagged,
//! PE/ELF/shellcode classification then capa or the FLOSS/IOC fallback.
//! Post-scan: SSDEEP + imphash clustering and per-cluster draft YARA rules.
//! Work runs on a bounded `rayon` pool (capped at 16); one reused
//! `yara_x::Scanner` per worker thread.
//!
//! Gates match the other variants: NSRL-known files skip imphash / SSDEEP /
//! YARA / capa; capa-eligibility is only computed for a file with a YARA
//! hit. Disposition and Authenticode apply to every file, before any gate.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::Local;
use rayon::prelude::*;
use tracing::{error, info, warn};
use walkdir::WalkDir;
use yara_x::Scanner;

use crate::archive;
use crate::attack::{self, AttackDb};
use crate::authenticode;
use crate::blocklist;
use crate::capa;
use crate::config::IngotConfig;
use crate::disposition;
use crate::file_type;
use crate::floss;
use crate::hashing;
use crate::imphash;
use crate::iocs;
use crate::model::FileRecord;
use crate::nsrl::{self, NsrlIndex};
use crate::report::{self, ReportPaths};
use crate::ssdeep;
use crate::yara_rule_gen;
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
    capa_bin: Option<&'a Path>,
    floss_bin: Option<&'a Path>,
    capa_rules_dir: Option<&'a Path>,
}

/// A `FileRecord` plus the per-file byproduct the post-scan draft-rule pass
/// needs (FLOSS static strings for `PossibleFalseNegative` files).
struct FileOutcome {
    record: FileRecord,
    floss_static_strings: Option<Vec<String>>,
}

fn process_one_file(
    path: &str,
    ctx: &FileScanCtx<'_>,
    yara_scanner: Option<&mut Scanner>,
) -> FileOutcome {
    let mut record = FileRecord::new(path);
    let mut floss_static_strings: Option<Vec<String>> = None;
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

            // Authenticode - unconditional, like entropy: "signed vs
            // unsigned is meaningful regardless of hash reputation".
            let auth = authenticode::check_signature(target);
            record.signature_status = auth.status;
            record.signer_name = auth.signer_name;

            record.nsrl_match = ctx.nsrl_index.contains(&h.sha1);

            if let Some(bl) = ctx.blocklist {
                let (status, source) = blocklist::check_reputation(&h.md5, &h.sha1, &h.sha256, bl);
                record.reputation_status = status;
                record.reputation_source = source;
            }

            // NSRL-known-good gate: a file NSRL vouches for skips imphash,
            // ssdeep, YARA and capa-eligibility (and later capa / FLOSS).
            if !record.nsrl_match {
                record.imphash = imphash::compute_imphash(target);
                record.ssdeep = ssdeep::compute_ssdeep_hash(target);

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
                // file).
                if record.yara_hit_count > 0 {
                    let ft = file_type::classify(target, h.length);
                    record.capa_eligible = ft.capa_eligible;
                    record.possible_false_negative =
                        file_type::is_possible_false_negative(&ft, record.yara_hit_count, target);

                    if let (Some(capa_bin), true) = (ctx.capa_bin, record.capa_eligible) {
                        // Own try scope: a capa timeout/failure is common on
                        // a real corpus and must not discard everything else
                        // already learned about the file (engine.py does the
                        // same).
                        match capa::scan_file(
                            capa_bin,
                            target,
                            ctx.capa_rules_dir,
                            ft.is_shellcode,
                            capa::timeout(),
                        ) {
                            Ok(cr) => {
                                record.capa_detection_count = cr.detection_count;
                                record.capa_output = (!cr.output.is_empty()).then_some(cr.output);
                                record.capa_shellcode_format = cr.shellcode_format;
                            }
                            Err(e) => {
                                record.error = Some(e.to_string());
                                warn!("capa analysis failed for {path}: {e}");
                            }
                        }
                    } else if record.possible_false_negative {
                        if let Some(floss_bin) = ctx.floss_bin {
                            let fr = floss::scan_file(floss_bin, target, floss::timeout());
                            record.floss_string_count = fr.string_count;
                            if !fr.static_strings.is_empty() {
                                floss_static_strings = Some(fr.static_strings);
                            }
                            let ioc = iocs::extract_iocs(&fr.strings);
                            record.ioc_count = ioc.count as i32;
                            record.extracted_iocs = ioc.display;
                        }
                    }
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
    FileOutcome {
        record,
        floss_static_strings,
    }
}

/// Run the currently-implemented pipeline over every file under
/// `config.src_dir`. `on_progress` is invoked once per file as results
/// complete (not in submission order); it must be cheap and `Sync`.
pub fn scan_directory<F>(config: &IngotConfig, on_progress: F) -> ScanResult
where
    F: Fn(Progress) + Sync + Send,
{
    scan_directory_with(config, &HashMap::new(), on_progress)
}

/// Like [`scan_directory`], but `archive_passwords` (`archive path -> password`)
/// is offered to any password-protected archive found under the source
/// directory; anything without a supplied password is copied to
/// `<report_dir>/password_protected/` for external cracking.
pub fn scan_directory_with<F>(
    config: &IngotConfig,
    archive_passwords: &HashMap<String, String>,
    on_progress: F,
) -> ScanResult
where
    F: Fn(Progress) + Sync + Send,
{
    info!("Enumerating files under {}...", config.src_dir);
    let mut paths = enumerate_files(&config.src_dir);
    info!("Found {} file(s) to scan.", paths.len());

    // --- archive expansion (serial pre-scan pass) ----------------------
    let mut source_archive_by_path: HashMap<String, String> = HashMap::new();
    let archive_paths = archive::find_archives(&paths);
    if !archive_paths.is_empty() && !config.report_directory.is_empty() {
        let extraction_root = Path::new(&config.report_directory).join("extracted_archives");
        info!("Expanding {} archive(s)...", archive_paths.len());
        let p1 = archive::expand_archives(&archive_paths, &extraction_root);
        paths.extend(p1.extracted_files.iter().cloned());
        source_archive_by_path.extend(p1.source_archive_by_path);
        info!(
            "Archive expansion: {} file(s) extracted, {} archive(s) need a password.",
            p1.extracted_files.len(),
            p1.locked_archives.len()
        );

        if !p1.locked_archives.is_empty() {
            let unresolved_dir = Path::new(&config.report_directory).join("password_protected");
            let p2 = archive::resolve_locked_archives(
                &p1.locked_archives,
                archive_passwords,
                &extraction_root,
                &unresolved_dir,
            );
            paths.extend(p2.extracted_files.iter().cloned());
            source_archive_by_path.extend(p2.source_archive_by_path);
            if !p2.unresolved_archives.is_empty() {
                info!(
                    "{} password-protected archive(s) saved to {} for external cracking.",
                    p2.unresolved_archives.len(),
                    unresolved_dir.display()
                );
            }
        }
    } else if !archive_paths.is_empty() {
        warn!(
            "{} archive(s) found but no report directory is configured - archive expansion skipped.",
            archive_paths.len()
        );
    }
    let total = paths.len();

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

    // --- capa / FLOSS binaries (optional) ----------------------------
    let capa_bin = (!config.capa_exe.is_empty()).then(|| PathBuf::from(&config.capa_exe));
    let floss_bin = (!config.floss_exe.is_empty()).then(|| PathBuf::from(&config.floss_exe));
    let capa_rules_dir = (!config.capa_rules.is_empty()).then(|| PathBuf::from(&config.capa_rules));
    match &capa_bin {
        Some(p) => info!("capa: {}", p.display()),
        None => info!(
            "capa binary not available - capa analysis disabled (install it on the Tools page)."
        ),
    }
    match &floss_bin {
        Some(p) => info!("FLOSS: {}", p.display()),
        None => info!("FLOSS binary not available - the string-extraction fallback is disabled."),
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
        capa_bin: capa_bin.as_deref(),
        floss_bin: floss_bin.as_deref(),
        capa_rules_dir: capa_rules_dir.as_deref(),
    };
    let ctx_ref = &ctx;
    let yara_rules_ref = yara_rules.as_ref();

    let outcomes: Vec<FileOutcome> = pool.install(|| {
        paths
            .par_iter()
            .map_init(
                || yara_rules_ref.map(Scanner::new),
                |scanner, path| {
                    let FileOutcome {
                        record,
                        floss_static_strings,
                    } = process_one_file(path, ctx_ref, scanner.as_mut());
                    let done = counter_ref.fetch_add(1, Ordering::SeqCst) + 1;
                    on_progress(Progress {
                        done,
                        total,
                        record: &record,
                    });
                    FileOutcome {
                        record,
                        floss_static_strings,
                    }
                },
            )
            .collect()
    });

    let mut floss_static_by_path: HashMap<String, Vec<String>> = HashMap::new();
    let mut records: Vec<FileRecord> = Vec::with_capacity(outcomes.len());
    for FileOutcome {
        mut record,
        floss_static_strings,
    } in outcomes
    {
        if let Some(s) = floss_static_strings {
            floss_static_by_path.insert(record.path.clone(), s);
        }
        if let Some(src) = source_archive_by_path.get(&record.path) {
            record.source_archive = src.clone();
        }
        records.push(record);
    }

    records.sort_by(|a, b| a.path.cmp(&b.path));
    let timestamp = Local::now().format("%Y-%m-%d_%H%M%S").to_string();

    // --- post-scan clustering (single-threaded, over the whole batch) ----
    // Iterated in ascending path order so cluster numbering is reproducible
    // across a rescan of the same batch.
    let imphashes: BTreeMap<String, Option<String>> = records
        .iter()
        .map(|r| (r.path.clone(), r.imphash.clone()))
        .collect();
    let imphash_clusters = imphash::cluster_by_imphash(&imphashes);
    let idx_by_path: BTreeMap<String, usize> = records
        .iter()
        .enumerate()
        .map(|(i, r)| (r.path.clone(), i))
        .collect();
    for (path, (cid, size)) in &imphash_clusters {
        if let Some(&i) = idx_by_path.get(path) {
            records[i].imphash_cluster_id = *cid;
            records[i].imphash_cluster_size = *size;
        }
    }

    let ssdeep_hashes: BTreeMap<String, String> = records
        .iter()
        .filter_map(|r| r.ssdeep.clone().map(|h| (r.path.clone(), h)))
        .collect();
    if !ssdeep_hashes.is_empty() {
        let clusters = ssdeep::cluster_by_ssdeep(&ssdeep_hashes);
        let mut cluster_count = 0;
        for (path, info) in &clusters {
            if let Some(&i) = idx_by_path.get(path) {
                records[i].ssdeep_cluster_id = info.cluster_id;
                records[i].ssdeep_cluster_size = info.cluster_size;
                records[i].ssdeep_has_high_similarity = info.has_high_similarity;
                records[i].ssdeep_matches =
                    (!info.matches_summary.is_empty()).then(|| info.matches_summary.clone());
            }
            cluster_count = cluster_count.max(info.cluster_id + 1);
        }
        info!(
            "SSDEEP clustering: {} file(s) hashed, {} cluster(s).",
            ssdeep_hashes.len(),
            cluster_count
        );
    }

    // --- draft YARA rules from size>=2 SSDEEP clusters (best-effort) -----
    if !config.report_directory.is_empty() {
        let mut by_cluster: BTreeMap<i32, Vec<&FileRecord>> = BTreeMap::new();
        for r in &records {
            if r.ssdeep_cluster_id >= 0 && r.ssdeep_cluster_size >= 2 {
                by_cluster.entry(r.ssdeep_cluster_id).or_default().push(r);
            }
        }
        if !by_cluster.is_empty() {
            match yara_rule_gen::generate_draft_rules(
                &by_cluster,
                &floss_static_by_path,
                &config.report_directory,
                ssdeep::CLUSTER_THRESHOLD,
                &timestamp,
            ) {
                Ok(res) if res.rules_written > 0 => info!(
                    "Generated {} draft YARA rule(s) from SSDEEP clusters - review under {}",
                    res.rules_written, res.output_dir
                ),
                Ok(_) => {}
                Err(e) => warn!("Draft YARA rule generation skipped due to error: {e}"),
            }
        }
    }

    // --- reports ---------------------------------------------------------
    let report_paths = if config.report_directory.is_empty() {
        None
    } else {
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
            capa_exe: String::new(),
            floss_exe: String::new(),
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
    fn prior_disposition_applied_and_ssdeep_imphash_gated_by_nsrl() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let reports = dir.path().join("reports");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&reports).unwrap();

        std::fs::write(src.join("known.txt"), b"abc").unwrap();
        std::fs::write(src.join("unknown.txt"), vec![0x41u8; 4096]).unwrap();

        let abc_sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d";
        crate::disposition::save_disposition_entry(
            reports.to_str().unwrap(),
            abc_sha1,
            "Escalated",
        )
        .unwrap();

        let mut config = cfg_for(&src, &reports);
        let nsrl_src = dir.path().join("nsrl.txt");
        std::fs::write(&nsrl_src, format!("{abc_sha1}\n")).unwrap();
        config.nsrl_path = nsrl_src.to_string_lossy().into_owned();

        let result = scan_directory(&config, |_| {});

        let known = result
            .records
            .iter()
            .find(|r| r.path.ends_with("known.txt"))
            .unwrap();
        assert_eq!(
            known.disposition, "Escalated",
            "prior disposition not applied"
        );
        assert!(known.nsrl_match);
        assert_eq!(known.imphash, None, "NSRL-known file must skip imphash");
        assert_eq!(known.ssdeep, None, "NSRL-known file must skip ssdeep");

        let unknown = result
            .records
            .iter()
            .find(|r| r.path.ends_with("unknown.txt"))
            .unwrap();
        assert!(!unknown.nsrl_match);
        assert_eq!(unknown.imphash, None, "non-PE has no imphash");
        assert!(
            unknown.ssdeep.is_some(),
            "non-NSRL file should be ssdeep-hashed"
        );
    }

    #[test]
    fn post_scan_clustering_populates_records_and_draft_rules() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let reports = dir.path().join("reports");
        std::fs::create_dir_all(&src).unwrap();

        // three near-identical files: a shared pseudo-random 24 KB body
        // (varied bytes so spamsum produces a real hash) + a tiny per-file tail
        let body: Vec<u8> = (0..24_000u32)
            .map(|n| (n.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        for i in 0..3 {
            let mut b = body.clone();
            b.extend_from_slice(format!("--variant-{i}-specific-tail--").as_bytes());
            std::fs::write(src.join(format!("fam_{i}.bin")), &b).unwrap();
        }
        // an unrelated file of similar size
        let other: Vec<u8> = (0..24_000u32)
            .map(|n| (n.wrapping_mul(40_503) >> 7) as u8)
            .collect();
        std::fs::write(src.join("lonely.bin"), &other).unwrap();

        let result = scan_directory(&cfg_for(&src, &reports), |_| {});

        let fam: Vec<_> = result
            .records
            .iter()
            .filter(|r| r.path.contains("fam_"))
            .collect();
        assert_eq!(fam.len(), 3);
        let cid = fam[0].ssdeep_cluster_id;
        assert!(cid >= 0);
        assert!(fam.iter().all(|r| r.ssdeep_cluster_id == cid));
        assert!(fam.iter().all(|r| r.ssdeep_cluster_size == 3));
        assert!(fam.iter().all(|r| r.ssdeep_matches.is_some()));

        let lonely = result
            .records
            .iter()
            .find(|r| r.path.ends_with("lonely.bin"))
            .unwrap();
        assert_eq!(lonely.ssdeep_cluster_size, 1, "singleton cluster");
        assert!(lonely.ssdeep_matches.is_none());

        // a size>=2 ssdeep cluster -> a draft rule was written (skeleton, since
        // no FLOSS strings yet)
        let gen_dir = reports.join("generated_rules");
        let rules: Vec<_> = std::fs::read_dir(&gen_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "yar"))
            .collect();
        assert_eq!(rules.len(), 1);
        let text = std::fs::read_to_string(rules[0].path()).unwrap();
        assert!(text.contains("AUTO-GENERATED DRAFT"));
        assert!(text.contains("cluster_size = 3"));
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
