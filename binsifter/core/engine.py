"""Scan orchestration - the Python equivalent of Start-ScanEngine in the
PowerShell version.

Wires together every automatic per-file/bulk-scan stage (hashing, NSRL,
blocklist, YARA, imphash, ssdeep clustering, capa, FLOSS, Authenticode, IOC
extraction, MITRE ATT&CK enrichment, draft YARA rule generation, CSV report
writing) - each swapped in as its own module was finished, a hard gate per
step rather than a rewrite-then-test-everything-at-the-end approach, per
Steve's stated priority on accuracy over speed of delivery.

scan_directory() runs files through a bounded multiprocessing.Pool (see
MAX_SCAN_WORKERS below) instead of one at a time - added 2026-08-03 after a
real 657-file scan against the full capa-rules-9.4.0 corpus took 18+
minutes for just 30 files under the original single-threaded loop. The
PowerShell version's own worker-pool dispatcher (ThrottleLimit capped at
16) was the parity target; this is the first pass at matching it, not
"finishing the port" of that specific piece as a first-pass skeleton
anymore. See _pool_worker_init()/_process_one_file() below for why YARA
rules are recompiled per worker process while NSRL/blocklist/ATT&CK/
disposition-history data is loaded once in the parent and handed down.

Speakeasy (core/speakeasy_scan.py) is a real, tested module too now, but
deliberately NOT wired into this file's scan_directory() loop - the
PowerShell version treated Speakeasy as a single-file, analyst-initiated,
confirmation-gated Results-grid action (same category as Ghidra/Sigcheck/
x64dbg/x32dbg), never a bulk-scan step, since it's execution-adjacent and
can run up to 120 seconds per file. Wiring it in here would be a real
behavior change, not "finishing the port" - it stays a standalone building
block for a future GUI action to call on one analyst-selected file at a
time.

NOTE on a design question not yet resolved: the PowerShell version's
FileRecord.Entropy doc comment implies NSRL-known files skip entropy
computation entirely ("-1 = not computed, e.g. an NSRL-known file never
reaches this stage") - suggesting SHA-1/NSRL lookup may happen via a
lighter pass before the full hash+entropy read. This port currently always
does the full hash_and_score_file() read up front (simpler, but does
strictly more work than the original for NSRL-known files). Worth
revisiting once there's a real performance benchmark to justify the
added complexity either way - don't "fix" this speculatively.
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import queue
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from binsifter.core.config import BinSifterConfig
from binsifter.core.models import FileRecord
from binsifter.core import attack_db as attack_db_mod
from binsifter.core import authenticode
from binsifter.core import blocklist as blocklist_mod
from binsifter.core import capa_scan
from binsifter.core import disposition as disposition_mod
from binsifter.core import file_type as file_type_mod
from binsifter.core import floss_scan
from binsifter.core import hashing
from binsifter.core import imphash as imphash_mod
from binsifter.core import iocs as iocs_mod
from binsifter.core import nsrl as nsrl_mod
from binsifter.core import report as report_mod
from binsifter.core import ssdeep_cluster
from binsifter.core import yara_rule_gen
from binsifter.core import yara_scan

logger = logging.getLogger(__name__)

# Bounded worker count for the concurrent scan pool - same ceiling as the
# PowerShell version's ThrottleLimit (capped at 16 "regardless of core
# count" per its own comment). Unlike that version, which spent most of
# each file's wall-clock time waiting on a spawned yara64.exe/capa.exe
# process (I/O/process-launch-bound), this rewrite runs YARA/capa as
# in-process libraries inside each worker, so oversubscribing past the
# real core count buys nothing but context-switch overhead - see
# _default_worker_count().
MAX_SCAN_WORKERS = 16


def _default_worker_count() -> int:
    return max(1, min(MAX_SCAN_WORKERS, os.cpu_count() or 4))


# ================= Concurrent scan pool: worker-process state =================
# Set once per worker process by _pool_worker_init(), then reused for every
# file that worker goes on to process - these are per-WORKER-PROCESS
# globals (multiprocessing.Pool spawns up to _default_worker_count() child
# processes, each running its own independent copy of this module, so each
# child gets its own copy of these names), not per-file state and not
# shared with the parent process or other workers.
_worker_config: BinSifterConfig | None = None
_worker_yara_rules = None
_worker_nsrl_hashes: set = set()
_worker_blocklist_hashes: set = set()
_worker_attack_db = None
_worker_disposition_history: dict = {}


def _pool_worker_init(
    config: BinSifterConfig,
    nsrl_hashes: set,
    blocklist_hashes: set,
    attack_db,
    disposition_history: dict,
) -> None:
    """Runs exactly once in each freshly-spawned worker process, before that
    worker picks up its first file (multiprocessing.Pool guarantees this).

    nsrl_hashes/blocklist_hashes/attack_db/disposition_history are handed
    down from the parent, which already loaded them once - no reason to
    have every one of up to 16 workers separately re-parse the same
    multi-thousand-line NSRL/blocklist file or STIX JSON bundle.

    YARA rules are the one exception: a compiled yara.Rules object wraps a
    native library handle that isn't safely shareable across a process
    boundary (the same reason capa_scan.py's scan_file_with_timeout()
    already reloads its RuleSet fresh in its own child process rather than
    reusing a parent-compiled one - see that module's docstring), so each
    worker compiles its own copy here, once, from the same YaraRules path
    the parent already validated.
    """
    global _worker_config, _worker_yara_rules, _worker_nsrl_hashes
    global _worker_blocklist_hashes, _worker_attack_db, _worker_disposition_history

    _worker_config = config
    _worker_yara_rules = yara_scan.compile_rules(config.YaraRules) if config.YaraRules else None
    _worker_nsrl_hashes = nsrl_hashes
    _worker_blocklist_hashes = blocklist_hashes
    _worker_attack_db = attack_db
    _worker_disposition_history = disposition_history


@dataclass
class _WorkerFileResult:
    """What a pool worker sends back to the parent for one file: the
    FileRecord itself, plus the handful of per-file byproducts the
    post-scan clustering/draft-rule-generation passes need but that don't
    belong on FileRecord itself - the same three loose dicts
    (imphashes[path], ssdeep_hashes[path], floss_static_strings[path]) the
    previous single-threaded loop body built up directly as local
    variables. Since each file is now processed in its own worker process,
    only what's returned from _process_one_file() crosses back to the
    parent - these have to travel explicitly instead."""

    record: FileRecord
    imphash: str | None
    ssdeep_hash: str | None
    floss_static_strings: list[str] | None


def _process_one_file(path: str) -> _WorkerFileResult:
    """Top-level (picklable, spawn-safe) per-file pipeline - the pool
    worker's task function, submitted once per file via pool.apply_async().
    Reads this worker's own _worker_* globals (set up once by
    _pool_worker_init) instead of scan_directory()'s local variables, since
    a pool task function can't close over its caller's locals across a
    process boundary.

    Same processing steps, in the same order, as the single-threaded loop
    body this replaced - see git history for the pre-2026-08-03 version of
    this function if a side-by-side comparison is ever needed.

    Never raises: any exception during processing is caught here and turned
    into a Status="Error" record carrying the exception text, the same
    contract the original sequential loop's try/except had. A pool worker
    function that raises instead would just look like a silent task
    failure to the parent's error_callback (see scan_directory() below) -
    that path exists purely as a last-resort net for a bug in THIS
    function, not as the expected way per-file errors get reported.
    """
    config = _worker_config
    record = FileRecord(Path=path)
    imphash: str | None = None
    ssdeep_hash: str | None = None
    floss_static_strings: list[str] | None = None
    try:
        hash_result = hashing.hash_and_score_file(path)
        record.MD5 = hash_result.md5
        record.SHA1 = hash_result.sha1
        record.Entropy = hash_result.entropy

        prior_disposition = _worker_disposition_history.get(hash_result.sha1.lower())
        if prior_disposition:
            record.Disposition = prior_disposition

        auth_result = authenticode.check_signature(path)
        record.SignatureStatus = auth_result.status
        record.SignerName = auth_result.signer_name

        record.NsrlMatch = nsrl_mod.is_known_good(hash_result.sha1, _worker_nsrl_hashes)

        record.ReputationStatus, record.ReputationSource = blocklist_mod.check_reputation(
            hash_result.md5, hash_result.sha1, hash_result.sha256, _worker_blocklist_hashes
        ) if _worker_blocklist_hashes else ("", "")

        if _worker_yara_rules is not None:
            yara_result = yara_scan.scan_file(_worker_yara_rules, path, attack_db=_worker_attack_db)
            record.YaraMatches = "; ".join(yara_result.rule_names) or None
            record.YaraHitCount = yara_result.hit_count
            record.YaraSeverity = yara_result.severity
            record.YaraSeverityScore = yara_result.severity_score
            record.YaraAttackTechniques = yara_result.attack_techniques

        ft = file_type_mod.classify(path, hash_result.length)
        record.CapaEligible = ft.capa_eligible
        record.PossibleFalseNegative = file_type_mod.is_possible_false_negative(
            ft, record.YaraHitCount, path
        )

        if config.CapaRules and record.CapaEligible:
            # scan_file_with_timeout() spawns its own further child process
            # per call (the vivisect hang safety net) - so a capa scan
            # inside a pool worker means a grandchild process relative to
            # the GUI's own process, which is fine: multiprocessing "spawn"
            # supports nesting, and __main__.py already has the required
            # `if __name__ == "__main__":` guard.
            capa_result = capa_scan.scan_file_with_timeout(path, config.CapaRules, is_shellcode=ft.is_shellcode)
            record.CapaDetectionCount = capa_result.detection_count
            record.CAPAOutput = capa_result.output or None
            record.CapaShellcodeFormat = capa_result.shellcode_format
        elif record.PossibleFalseNegative:
            floss_result = floss_scan.scan_file(path)
            record.FlossStringCount = floss_result.string_count
            if floss_result.static_strings:
                floss_static_strings = floss_result.static_strings

            ioc_result = iocs_mod.extract_iocs(floss_result.strings)
            record.IocCount = ioc_result.count
            record.ExtractedIOCs = ioc_result.display

        imphash = imphash_mod.compute_imphash(path)
        ssdeep_hash = ssdeep_cluster.compute_ssdeep_hash(path)
        if ssdeep_hash:
            record.SSDEEP = ssdeep_hash

        record.Status = "Completed"
    except Exception as exc:  # noqa: BLE001 - one bad file shouldn't abort the batch
        record.Status = "Error"
        record.Error = str(exc)
        logger.exception("Error processing %s", path)

    return _WorkerFileResult(
        record=record, imphash=imphash, ssdeep_hash=ssdeep_hash, floss_static_strings=floss_static_strings
    )


@dataclass
class ScanResult:
    records: list[FileRecord]
    # None when config.ReportDirectory wasn't usable (blank, or the
    # directory couldn't be created) - a scan without a report destination
    # is still a valid result (e.g. a future GUI page reading `records`
    # directly), just one with nothing written to disk.
    report_paths: report_mod.ReportPaths | None


def enumerate_files(src_dir: str) -> list[str]:
    """Port of the C# FileScanner.EnumerateFiles - the original was
    explicitly stack-based rather than recursive to avoid stack depth
    issues on a deep tree. Path.rglob is iterative under the hood (not
    Python-level recursion), so it already avoids that problem without
    needing the manual stack the PowerShell/C# version had to build.
    One bad subfolder (permissions, etc.) is skipped rather than aborting
    the whole enumeration - same as the original's per-directory error
    isolation.
    """
    files: list[str] = []
    root = Path(src_dir)
    try:
        for entry in root.rglob("*"):
            try:
                if entry.is_file():
                    files.append(str(entry))
            except OSError:
                continue
    except OSError as exc:
        logger.warning("Could not fully enumerate %s: %s", src_dir, exc)
    return files


def scan_directory(
    config: BinSifterConfig,
    progress_callback: Callable[[int, int, str, FileRecord], None] | None = None,
    should_pause: Callable[[], bool] | None = None,
    should_stop: Callable[[], bool] | None = None,
    max_workers: int | None = None,
) -> ScanResult:
    """Runs the currently-implemented pipeline stages over every file under
    config.SrcDir: hash + entropy, NSRL, blocklist, YARA, imphash. Returns
    a ScanResult (records + the paths of any CSV reports written);
    ssdeep/imphash clustering, draft YARA rule generation, and report
    writing are all applied as post-scan passes across the whole batch,
    same as the PowerShell version.

    Per-file work runs on a bounded multiprocessing.Pool (max_workers,
    defaulting to _default_worker_count() - see MAX_SCAN_WORKERS) instead of
    one file at a time in this process, matching the PowerShell version's
    own bounded worker-pool dispatcher (ThrottleLimit capped at 16). Each
    file is submitted to the pool via apply_async() as soon as it's
    dispatched; progress_callback fires once per file at submission time
    (Status == "Scanning") and once again when that file's result actually
    comes back from a worker (Status == "Completed"/"Error"/whatever that
    worker produced) - completion notifications arrive in true finish
    order, which is not necessarily submission order, since files don't
    all take the same amount of time. ScanQueuePage.upsert_record() is
    keyed by record.Path already, so it handles out-of-order completions
    correctly with no GUI-side changes needed.

    Known simplification: submission (all files quickly marked "Scanning")
    and completion draining currently happen as two back-to-back phases
    rather than fully interleaved - in practice this means the queue view
    will show every row flip to "Scanning" almost immediately, then start
    flipping to a terminal status one by one as workers finish, rather than
    a slower drip of individual rows going "Scanning" one at a time. This
    still delivers real concurrency and correct, path-keyed progress
    reporting; true single-file "picked up by a worker just now" timing
    would need a cross-process progress channel (e.g. a
    multiprocessing.Manager queue) and isn't implemented yet.

    should_pause()/should_stop(), if given, are polled BETWEEN submissions,
    mirroring the PowerShell dispatcher's own cooperative gate
    (BinSifter_v1.3.0-alpha.2.ps1 lines ~2895/2867: pause blocks starting new
    files, already-dispatched ones finish; stop aborts before the next file
    is submitted, never mid-file). On stop, every file that hadn't been
    submitted to the pool yet is marked Status="Cancelled" - same as the
    PowerShell version's "force-remaining to Cancelled" (line ~2941).
    """
    paths = enumerate_files(config.SrcDir)
    records: dict[str, FileRecord] = {p: FileRecord(Path=p) for p in paths}

    # One timestamp per scan, reused everywhere a filename needs to be
    # stamped (draft YARA rule names, the 4 CSV reports below) - same role
    # as the PowerShell version's $timestamp (Get-Date -Format
    # 'yyyy-MM-dd_HHmmss'), computed once so every output from this run
    # sorts/groups together.
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    nsrl_hashes = nsrl_mod.load_nsrl_hashes(config.NsrlPath) if config.NsrlPath else set()
    # BlocklistPath (unlike NsrlPath/YaraRules/CapaRules) always has a real
    # default value - Reports/Attack/Blocklist default next to the install
    # even when the analyst never asked for blocklist checking - so guard
    # on the file actually existing, not just the path being non-empty.
    # Otherwise every scan logs a "could not read blocklist" warning until
    # someone places a blocklist file there, which is misleading noise for
    # a feature that was never configured in the first place.
    blocklist_hashes = (
        blocklist_mod.load_blocklist_hashes(config.BlocklistPath)
        if config.BlocklistPath and Path(config.BlocklistPath).is_file()
        else set()
    )
    # Compiled/loaded here too (in the parent), even though the actual
    # per-file scanning happens in worker processes that each load their
    # own copy - this is deliberate fail-fast validation, so a bad YARA/capa
    # rules path raises here, before a single worker process is spawned,
    # instead of every worker independently discovering (and logging) the
    # same error. Neither object is passed down to the workers - a compiled
    # yara.Rules wraps a native handle, and capa's RuleSet "can't be passed
    # across the process boundary" per capa_scan.py's own docstring - so
    # these two locals exist purely for this validation pass.
    if config.YaraRules:
        yara_scan.compile_rules(config.YaraRules)
    if config.CapaRules:
        capa_scan.load_rules(config.CapaRules)

    # v1.3-proto1: prior triage dispositions, persisted by SHA-1 so
    # re-scanning the same files (or re-opening the same case directory
    # later) keeps earlier Benign/Suspicious/Escalated calls instead of
    # resetting everything to Untriaged - written by the Results page's
    # Disposition column edits, read back here once per scan (see
    # BinSifter_v1.3.0-alpha.2.ps1 lines ~2775-2782).
    disposition_history = disposition_mod.load_disposition_history(config.ReportDirectory)

    # MITRE ATT&CK mapping is optional, same as the PowerShell version - a
    # blank/missing AttackDataPath just means TTP mapping is disabled for
    # this scan, not an error. Unlike the other loads above, this one is
    # wrapped in its own try/except: the PowerShell version explicitly
    # catches AttackDb.Load() failures (bad/partial JSON, wrong schema) and
    # logs "TTP mapping disabled for this scan" rather than aborting the
    # whole scan over an optional enrichment feature - see
    # BinSifter_v1.3.0-alpha.2.ps1 lines ~2799-2811.
    attack_db = None
    if config.AttackDataPath and Path(config.AttackDataPath).is_file():
        try:
            attack_db = attack_db_mod.AttackDb.load(config.AttackDataPath)
            logger.info(
                "MITRE ATT&CK data loaded: %d techniques indexed.", attack_db.technique_count
            )
        except Exception as exc:  # noqa: BLE001 - optional enrichment, never fatal to the scan
            logger.warning(
                "Could not load MITRE ATT&CK data, TTP mapping disabled for this scan: %s", exc
            )
            attack_db = None
    else:
        logger.info("No MITRE ATT&CK data configured - TTP mapping disabled for this scan.")

    imphashes: dict[str, str | None] = {}
    ssdeep_hashes: dict[str, str] = {}
    # Only populated for files that actually ran FLOSS - feeds the draft
    # YARA rule generator's per-cluster string intersection below. Kept
    # in-memory rather than persisted to disk per-file, unlike the
    # PowerShell version - see yara_rule_gen.py's module docstring.
    floss_static_strings: dict[str, list[str]] = {}

    worker_count = max_workers if max_workers else _default_worker_count()
    # No point spinning up more worker processes than there are files -
    # each spawned process has real startup cost (a fresh Python
    # interpreter + re-importing binsifter), so a 2-file scan shouldn't pay
    # for 16 of them.
    if paths:
        worker_count = max(1, min(worker_count, len(paths)))
    logger.info("Scanning %d file(s) with %d worker process(es).", len(paths), worker_count)

    stopped_at: int | None = None

    if paths:
        ctx = multiprocessing.get_context("spawn")
        result_queue: "queue.Queue" = queue.Queue()

        def _on_result(result: _WorkerFileResult) -> None:
            # Runs in a Pool-internal result-handler thread inside THIS
            # (parent) process, not in the worker - safe to touch
            # result_queue directly since queue.Queue is thread-safe.
            result_queue.put(("ok", result))

        def _on_error(exc: BaseException) -> None:
            # Only fires for a bug in _process_one_file itself - that
            # function catches its own exceptions and returns a
            # Status="Error" record instead of raising, so this is a
            # last-resort net, not the expected per-file-error path.
            result_queue.put(("error", exc))

        with ctx.Pool(
            processes=worker_count,
            initializer=_pool_worker_init,
            initargs=(config, nsrl_hashes, blocklist_hashes, attack_db, disposition_history),
        ) as pool:
            submitted = 0
            for i, path in enumerate(paths):
                if should_stop and should_stop():
                    stopped_at = i
                    break

                # should_stop() is only polled a second time here if the
                # pause loop actually ran - avoids calling it twice per
                # file in the common (never-paused) case, which would
                # otherwise make a stop-callback that flips state on each
                # call (like the real GUI's) fire once too often per
                # iteration.
                stopped_while_paused = False
                while should_pause and should_pause():
                    time.sleep(0.15)
                    if should_stop and should_stop():
                        stopped_while_paused = True
                        break
                if stopped_while_paused:
                    stopped_at = i
                    break

                record = records[path]
                record.Status = "Scanning"
                if progress_callback:
                    # "done" here is the SUBMITTED count, not the completed
                    # one - matches the previous version's own
                    # pre-processing call (which fired right before that
                    # one file started too), just potentially several files
                    # ahead of the true completed count now that files run
                    # concurrently.
                    progress_callback(submitted, len(paths), path, record)
                pool.apply_async(_process_one_file, (path,), callback=_on_result, error_callback=_on_error)
                submitted += 1

            # Drain exactly `submitted` results, in true completion order
            # (not submission order): apply_async's callback fires the
            # instant each worker returns, regardless of which file was
            # dispatched first, so this loop naturally reports whichever
            # file actually finished next - which is exactly what
            # ScanQueuePage.upsert_record()'s path-keyed updates already
            # handle correctly.
            completed = 0
            for _ in range(submitted):
                status, payload = result_queue.get()
                if status == "error":
                    logger.error("Scan worker failed unexpectedly: %s", payload)
                    continue

                result: _WorkerFileResult = payload
                records[result.record.Path] = result.record
                imphashes[result.record.Path] = result.imphash
                if result.ssdeep_hash:
                    ssdeep_hashes[result.record.Path] = result.ssdeep_hash
                if result.floss_static_strings:
                    floss_static_strings[result.record.Path] = result.floss_static_strings

                completed += 1
                if progress_callback:
                    progress_callback(completed, len(paths), result.record.Path, result.record)

    if stopped_at is not None:
        for remaining_path in paths[stopped_at:]:
            # Only files that were never submitted to the pool are still at
            # their default "Queued" status - guards against clobbering the
            # status of a file that was already in flight or finished by
            # the time the stop was noticed.
            if records[remaining_path].Status == "Queued":
                records[remaining_path].Status = "Cancelled"
        cancelled = sum(1 for r in records.values() if r.Status == "Cancelled")
        logger.info(
            "Scan stopped by request - %d/%d file(s) were not processed.",
            cancelled, len(paths),
        )

    # Post-scan clustering passes
    imphash_clusters = imphash_mod.cluster_by_imphash(imphashes)
    for path, (cluster_id, cluster_size) in imphash_clusters.items():
        records[path].ImphashClusterId = cluster_id
        records[path].ImphashClusterSize = cluster_size

    if ssdeep_hashes:
        ssdeep_clusters = ssdeep_cluster.cluster_by_ssdeep(ssdeep_hashes)
        for path, info in ssdeep_clusters.items():
            records[path].SsdeepClusterId = info.cluster_id
            records[path].SsdeepClusterSize = info.cluster_size
            records[path].SsdeepHasHighSimilarity = info.has_high_similarity
            records[path].SsdeepMatches = info.matches_summary or None

    record_list = list(records.values())

    # ================= Draft YARA rule generation (v1.3-proto1) =================
    # Best-effort and gracefully skipped on error - this is the same inner
    # try/except scope the PowerShell version used around just this block
    # (BinSifter_v1.3.0-alpha.2.ps1 lines ~3233/3317-3320), separate from
    # the CSV report writing below, which is NOT similarly swallowed.
    records_by_cluster: dict[int, list[FileRecord]] = {}
    for r in record_list:
        if r.SsdeepClusterId >= 0 and r.SsdeepClusterSize >= 2:
            records_by_cluster.setdefault(r.SsdeepClusterId, []).append(r)

    if records_by_cluster and config.ReportDirectory:
        try:
            rule_gen_result = yara_rule_gen.generate_draft_rules(
                records_by_cluster,
                floss_static_strings,
                config.ReportDirectory,
                ssdeep_cluster.CLUSTER_THRESHOLD,
                timestamp=timestamp,
            )
            if rule_gen_result.rules_written > 0:
                logger.info(
                    "Generated %d draft YARA rule(s) from SSDEEP clusters - review under: %s",
                    rule_gen_result.rules_written, rule_gen_result.output_dir,
                )
        except Exception as exc:  # noqa: BLE001 - optional feature, never fatal to the scan
            logger.warning("Draft YARA rule generation skipped due to error: %s", exc)

    # ================= CSV/report writing =================
    # Unlike rule generation above, NOT wrapped in a swallow-all except:
    # a report-write failure (disk full, permissions) was a real
    # scan-ending error in the PowerShell version too (its try/catch sat
    # one level up, around this and the rule-gen block together, but only
    # rule-gen had its own inner catch - see BinSifter_v1.3.0-alpha.2.ps1
    # lines ~3322-3338 vs. ~3340). Skipped (not raised) only when
    # ReportDirectory itself is blank - same "optional, off by default
    # absence" treatment as every other Config path field.
    report_paths = None
    if config.ReportDirectory:
        report_paths = report_mod.write_all_reports(record_list, config.ReportDirectory, timestamp)
        logger.info("Full report saved: %s", report_paths.full)
        logger.info("Suspicious/unknown (non-NSRL) list saved: %s", report_paths.suspicious)
        logger.info("YARA matches list saved: %s", report_paths.yara_matches)
        logger.info("Capa-compatible list saved: %s", report_paths.capa_compatible)
    else:
        logger.info("No ReportDirectory configured - skipping CSV report writing.")

    return ScanResult(records=record_list, report_paths=report_paths)
