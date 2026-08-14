"""Scan orchestration - the Python equivalent of Start-ScanEngine in the
PowerShell version.

Wires together every automatic per-file/bulk-scan stage (hashing, NSRL,
blocklist, YARA, imphash, ssdeep clustering, capa, FLOSS, Authenticode, IOC
extraction, MITRE ATT&CK enrichment, draft YARA rule generation, CSV report
writing) - each swapped in as its own module was finished, a hard gate per
step rather than a rewrite-then-test-everything-at-the-end approach, per
the stated priority on accuracy over speed of delivery.

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

Archive/compressed-file support (2026-08-07, core/archive.py): archives
found under config.SrcDir (zip/tar/gzip/7z) are expanded to real files on
disk in a SERIAL pre-scan step, before the multiprocessing.Pool below is
even created - see scan_directory()'s "Archive expansion" section. This
was originally flagged in TODO.md as an open architecture question (how
would a POOL WORKER PROCESS prompt for a password mid-scan?) that turned
out not to apply: archive expansion runs once, in this function, in the
parent process's own background QThread (see main_window.py's
_ScanWorker) - a real thread, not a separate process - so it can signal
the GUI thread and block on a threading.Event for a password batch-prompt
using ordinary, safe Qt cross-thread coordination. By the time paths is
handed to the pool below, every extracted file is just an ordinary file
with a real path; _process_one_file()/_pool_worker_init() needed zero
changes for this feature.
"""

from __future__ import annotations

import logging
import logging.handlers
import multiprocessing
import multiprocessing.pool
import os
import queue
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from binsifter.core.config import BinSifterConfig
from binsifter.core.models import FileRecord
from binsifter.core import archive as archive_mod
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

# 2026-08-14: hard ceiling on how long scan_directory()'s result-draining
# loop will wait with ZERO forward progress before giving up on the rest of
# the batch, rather than blocking forever. capa is the only per-file stage
# with its own hang-safety net (PersistentCapaWorker's 90s timeout, see
# capa_scan.py) - hashing/authenticode/imphash/ssdeep/YARA/FLOSS all run
# directly in the pool worker process with nothing bounding them. A real
# scan on a FLARE VM (Winnow_scanLogs_08142026.txt) got to 651/652 files and
# then produced literally zero further log output - no "Finished:", no
# error, nothing - for over 3 hours before it was force-closed (the elapsed
# timer read past 5:30:00). Root-caused by diffing every "Scanning:" path
# against every "Finished:" path in that log: exactly one file
# (WindowsXP-KB936929-SP3-x86-RUS.exe, a large XP-era self-extracting
# hotfix installer) was submitted and never came back. The draining loop
# below used to be a plain, un-timed-out `result_queue.get()` - once a pool
# worker got stuck inside ANY untimed stage for that one file, its callback
# never fired, so the loop's `for _ in range(submitted): result_queue.get()`
# blocked on that exact slot forever, which blocks the `with _NoDaemonPool
# (...) as pool:` block from ever exiting, which blocks the entire scan -
# every other file had already finished, so there was nothing left to make
# progress on, just an unbounded wait for one worker that was never coming
# back. 20 minutes is deliberately generous relative to the worst normal
# per-file time actually observed in that same log (530.0s, ~8.8 minutes,
# for AcroRd32.dll) - more than double it - so this should never trip on a
# genuinely slow-but-progressing file, only on a real hang.
RESULT_STALL_TIMEOUT_SECONDS = 1200


def _default_worker_count() -> int:
    return max(1, min(MAX_SCAN_WORKERS, os.cpu_count() or 4))


# ================= Non-daemonic pool (required for capa's own subprocess) =====
# multiprocessing.Pool always marks its own worker processes daemonic - and
# Python unconditionally forbids a daemonic process from spawning children
# of its own (Process.start() hard-asserts on it: "daemonic processes are
# not allowed to have children"). But _process_one_file() needs to do
# exactly that for CapaEligible files: PersistentCapaWorker (see
# capa_scan.py) spawns and owns its own further child process per worker
# (the vivisect hang-safety net - see subprocess_timeout.py's module
# docstring for the same rationale applied there). Confirmed as a real,
# majority-of-files failure mode in a live scan run on 2026-08-03 - a vanilla Pool made
# every capa call inside a worker raise that AssertionError.
#
# The fix (a well-known pattern for "pool whose workers need their own
# children") is to give the Pool a Process class whose `daemon` property is
# hard-pinned to False, so pool workers themselves come up as ordinary,
# non-daemonic processes. Normal shutdown is unaffected: Pool.__exit__
# still calls terminate() on the pool regardless of the daemon flag, and
# that's the only shutdown path this codebase relies on (see the `with
# ctx.Pool(...) as pool:` block in scan_directory() below). The one
# tradeoff, accepted here: if the GUI process were to crash hard without
# going through that context-manager exit, non-daemonic workers (and their
# own capa grandchild processes) wouldn't be auto-reaped the way daemonic
# ones would - a low-probability edge case, not worth more machinery for.
_BaseSpawnProcess = multiprocessing.get_context("spawn").Process


class _NoDaemonProcess(_BaseSpawnProcess):
    @property
    def daemon(self) -> bool:
        return False

    @daemon.setter
    def daemon(self, value: bool) -> None:
        pass  # Pool always tries to set this True on its workers - ignored


class _NoDaemonSpawnContext(type(multiprocessing.get_context("spawn"))):
    Process = _NoDaemonProcess


_NO_DAEMON_SPAWN_CONTEXT = _NoDaemonSpawnContext()


class _NoDaemonPool(multiprocessing.pool.Pool):
    def __init__(self, *args, **kwargs) -> None:
        kwargs["context"] = _NO_DAEMON_SPAWN_CONTEXT
        super().__init__(*args, **kwargs)


def _reap_capa_children(capa_pid_queue: "multiprocessing.Queue") -> None:
    """Best-effort cleanup for every PersistentCapaWorker child spawned
    during this scan, called once from the parent process after the scan
    pool itself has been torn down (see scan_directory()).

    Necessary because scan_directory() always exits its `with
    _NoDaemonPool(...) as pool:` block via Pool.__exit__, which calls
    pool.terminate() - an abrupt kill of every worker process, on every
    scan, even a fully successful one. Killing a worker does not kill that
    worker's own children (neither Windows nor POSIX auto-reap a killed
    process's descendants), so without this, every scan would leak one
    still-running, capa/vivisect-loaded orphan process per worker that ever
    handled a CapaEligible file - a real, accumulating problem over many
    scans in one long BinSifter session, not just a theoretical one.

    Draining capa_pid_queue (rather than tracking child Process objects
    directly) is what makes this work regardless of how the pool shut
    down: each worker reported its own child's PID the moment it spawned
    one, so the parent can kill by PID directly without needing any
    cooperation from the (now-dead) worker that spawned it.
    """
    pids: list[int] = []
    while True:
        try:
            pids.append(capa_pid_queue.get_nowait())
        except queue.Empty:
            break

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass  # already exited on its own, or never fully started - nothing to clean up


# ================= Cross-process log forwarding (2026-08-04) =================
_LOG_QUEUE_SENTINEL = None  # None is never a real LogRecord, safe as a stop signal


def _drain_log_queue(log_queue: "multiprocessing.Queue") -> None:
    """Runs in a background thread IN THE PARENT PROCESS for the lifetime of
    the scan (started just before the pool is created, stopped/joined just
    after it's torn down - see scan_directory()). Pulls LogRecords placed on
    log_queue by any worker's QueueHandler (see _pool_worker_init()) and
    re-dispatches each one through logging.getLogger(record.name).handle(),
    which runs it back through the PARENT's own configured logging tree -
    the same tree the GUI's QtLogHandler is already attached to (see
    log_bridge.py) and that a headless CLI run would have a StreamHandler
    on. This is the standard `logging` cookbook pattern for multiprocessing
    (queue + QueueHandler in each producer, a listener loop in the
    consumer) rather than anything BinSifter-specific - see
    https://docs.python.org/3/howto/logging-cookbook.html for the same
    recipe.

    A plain thread (not logging.handlers.QueueListener) so it can be started
    before the pool exists and stopped with an explicit sentinel from
    exactly one place in scan_directory() - QueueListener works fine here
    too, this is just as few moving parts as the job needs.
    """
    while True:
        record = log_queue.get()
        if record is _LOG_QUEUE_SENTINEL:
            return
        try:
            logging.getLogger(record.name).handle(record)
        except Exception:  # noqa: BLE001 - a malformed record shouldn't kill the whole drain thread
            pass


# ================= Concurrent scan pool: worker-process state =================
# Set once per worker process by _pool_worker_init(), then reused for every
# file that worker goes on to process - these are per-WORKER-PROCESS
# globals (multiprocessing.Pool spawns up to _default_worker_count() child
# processes, each running its own independent copy of this module, so each
# child gets its own copy of these names), not per-file state and not
# shared with the parent process or other workers.
_worker_config: BinSifterConfig | None = None
_worker_yara_rules = None
# "set" here means the empty-set "not configured" sentinel - the real,
# configured case holds an nsrl.NsrlIndex (mmap-backed, see nsrl.py's
# module docstring for why this is no longer a parsed-and-handed-down
# Python set of hashes). Both support `in`, so is_known_good() didn't need
# to change.
_worker_nsrl_hashes: "nsrl_mod.NsrlIndex | set" = set()
_worker_blocklist_hashes: set = set()
# 2026-08-08: pre-parsed catalog (.cat) files for Authenticode catalog
# verification - see authenticode.py's parse_catalogs()/check_signature().
# Compiled once per worker from config.CatalogDirectory, same reasoning as
# _worker_yara_rules just above (a parsed CertificateTrustList wraps
# cryptography objects that aren't cleanly picklable across a process
# boundary, so each worker parses its own copy here rather than the parent
# handing down an already-parsed list the way blocklist_hashes/attack_db
# do).
_worker_catalogs: list = []
_worker_attack_db = None
_worker_disposition_history: dict = {}
# One warm capa child process per scan-pool worker, reused across every
# file that worker processes - see capa_scan.PersistentCapaWorker's
# docstring for why (avoids re-spawning + re-importing capa/vivisect from
# scratch for every single file, confirmed as a major contributor to a real
# 34-minute, 652-file scan versus the PowerShell version's ~5 minutes for
# the same batch, 2026-08-03). None when CapaRules isn't configured.
_worker_persistent_capa: "capa_scan.PersistentCapaWorker | None" = None


def _pool_worker_init(
    config: BinSifterConfig,
    nsrl_cache_path: str | None,
    blocklist_hashes: set,
    attack_db,
    disposition_history: dict,
    capa_pid_queue: "multiprocessing.Queue | None",
    log_queue: "multiprocessing.Queue | None" = None,
) -> None:
    """Runs exactly once in each freshly-spawned worker process, before that
    worker picks up its first file (multiprocessing.Pool guarantees this).

    blocklist_hashes/attack_db/disposition_history are handed down from the
    parent, which already loaded them once - no reason to have every one of
    up to 16 workers separately re-parse the same multi-thousand-line
    blocklist file or STIX JSON bundle. These are small enough (thousands,
    not tens of millions, of entries) that pickling a copy per worker is a
    non-issue.

    nsrl_cache_path is deliberately NOT the parsed data - it's the path to
    the binary cache file build_index() already wrote in the parent, and
    each worker calls nsrl.open_index() on it independently here, once, at
    worker startup (see nsrl.py's module docstring for why: NSRL sets are
    routinely tens of millions of entries, and handing down a parsed Python
    set the way the other three do would mean pickling/duplicating a
    multi-GB object into every one of up to 16 processes). Memory-mapping
    the same file from each worker shares the underlying OS page cache
    instead of duplicating it, and degrades gracefully (page faults, not a
    memory-demand failure) on a lower-RAM machine.

    YARA rules are the one exception: a compiled yara.Rules object wraps a
    native library handle that isn't safely shareable across a process
    boundary (the same reason capa's own RuleSet can't be handed down
    either - see PersistentCapaWorker), so each worker compiles its own
    copy here, once, from the same YaraRules path the parent already
    validated.

    capa_pid_queue is handed straight through to PersistentCapaWorker so it
    can report its child's PID back to the parent process for cleanup -
    see _reap_capa_children() below for why that's necessary at all.

    log_queue (2026-08-04): a spawned worker process has its OWN, entirely
    separate `logging` module state - Python does not share logger/handler
    configuration across a process boundary the way it does across threads.
    Confirmed as a real gap, not a hypothetical: the GUI's QtLogHandler (see
    log_bridge.py) is only ever attached in the parent/GUI process, so every
    logger.info()/warning() call made from INSIDE a worker (capa failures,
    per-file warnings in yara_scan/floss_scan/authenticode/etc.) was
    silently going nowhere the GUI could see it - at best to that worker's
    own stderr, invisible in a windowed app with no console attached. This
    attaches a QueueHandler to the worker's ROOT logger so every log record
    emitted anywhere in this process (any module, any level >= INFO) gets
    put on log_queue instead, for the parent's _drain_log_queue() thread (see
    scan_directory()) to re-inject into ITS OWN logging tree - which the GUI
    already listens to. Root handlers are cleared first so records aren't
    ALSO duplicated to this worker's own default stderr handler-of-last-
    resort.
    """
    global _worker_config, _worker_yara_rules, _worker_nsrl_hashes
    global _worker_blocklist_hashes, _worker_attack_db, _worker_disposition_history
    global _worker_persistent_capa, _worker_catalogs

    if log_queue is not None:
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.addHandler(logging.handlers.QueueHandler(log_queue))
        root_logger.setLevel(logging.INFO)

    _worker_config = config
    _worker_yara_rules = yara_scan.compile_rules(config.YaraRules) if config.YaraRules else None
    _worker_catalogs = authenticode.parse_catalogs(config.CatalogDirectory) if config.CatalogDirectory else []
    _worker_nsrl_hashes = nsrl_mod.open_index(nsrl_cache_path) if nsrl_cache_path else set()
    _worker_blocklist_hashes = blocklist_hashes
    _worker_attack_db = attack_db
    _worker_disposition_history = disposition_history
    _worker_persistent_capa = (
        capa_scan.PersistentCapaWorker(config.CapaRules, pid_report_queue=capa_pid_queue)
        if config.CapaRules
        else None
    )


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
    # Wall-clock seconds spent in each pipeline stage for THIS file, keyed by
    # stage name ("hash", "authenticode", "yara", "capa", "floss_iocs",
    # "imphash", "ssdeep") - only present for stages that actually ran.
    # Added 2026-08-04 purely to answer "where did the time actually go" on
    # a real scan (a 652-file batch went 36min on a fast workstation, 67min
    # on a third-as-powerful PC - worse than either "CPU-bound, scales with
    # cores" or "I/O-bound" alone predicts, and guessing further from source
    # reading alone wasn't productive). Deliberately NOT added to FileRecord
    # itself - this is scan-run diagnostic data, not a triage field, and
    # FileRecord's shape is also the CSV report schema (see report.py) which
    # this shouldn't perturb. Aggregated into a summary log line by
    # scan_directory() after the batch finishes; never written to disk.
    stage_seconds: dict[str, float]


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
    stage_seconds: dict[str, float] = {}
    file_start = time.perf_counter()

    # Added 2026-08-04 alongside the log_queue/QueueHandler wiring in
    # _pool_worker_init(): forwarding worker logs to the GUI is only half
    # the fix if there's nothing to forward - before this, the only per-file
    # log lines were WARNINGs on failure (capa timeout, etc.), so a clean
    # run of hundreds of files produced no log activity at all for the
    # entire scan. This start/finish pair is what actually answers "what is
    # Winnow working on right now" on the Logs page during a long scan.
    logger.info("Scanning: %s", path)

    def _stage_start() -> float:
        return time.perf_counter()

    def _stage_end(label: str, t0: float) -> None:
        stage_seconds[label] = stage_seconds.get(label, 0.0) + (time.perf_counter() - t0)

    try:
        t0 = _stage_start()
        hash_result = hashing.hash_and_score_file(path)
        _stage_end("hash", t0)
        record.MD5 = hash_result.md5
        record.SHA1 = hash_result.sha1
        record.Entropy = hash_result.entropy

        prior_disposition = _worker_disposition_history.get(hash_result.sha1.lower())
        if prior_disposition:
            record.Disposition = prior_disposition

        t0 = _stage_start()
        auth_result = authenticode.check_signature(path, catalogs=_worker_catalogs)
        _stage_end("authenticode", t0)
        record.SignatureStatus = auth_result.status
        record.SignerName = auth_result.signer_name

        record.NsrlMatch = nsrl_mod.is_known_good(hash_result.sha1, _worker_nsrl_hashes)

        record.ReputationStatus, record.ReputationSource = blocklist_mod.check_reputation(
            hash_result.md5, hash_result.sha1, hash_result.sha256, _worker_blocklist_hashes
        ) if _worker_blocklist_hashes else ("", "")

        # 2026-08-05: restored the NSRL-known-good gate that was missing
        # here - imphash, ssdeep, YARA (and, nested further in, capa/FLOSS)
        # all skip entirely for a file NSRL already resolved as known-good,
        # matching Rowan's actual implementation (BinSifter-Rowan_v1.3.0-
        # beta.1.ps1:2208, "if (-not $isKnownGood) {...}") and the intended
        # design: there's nothing left to triage once NSRL has vouched for
        # a file. Before this fix, imphash/ssdeep/YARA ran unconditionally
        # on every file regardless of NsrlMatch - confirmed against a real
        # 652-file scan (2026-08-04 logs) where all 652 files, including
        # the 103 NSRL matches, went through YARA.
        if not record.NsrlMatch:
            t0 = _stage_start()
            imphash = imphash_mod.compute_imphash(path)
            _stage_end("imphash", t0)

            t0 = _stage_start()
            ssdeep_hash = ssdeep_cluster.compute_ssdeep_hash(path)
            _stage_end("ssdeep", t0)
            if ssdeep_hash:
                record.SSDEEP = ssdeep_hash

            if _worker_yara_rules is not None:
                t0 = _stage_start()
                yara_result = yara_scan.scan_file(_worker_yara_rules, path, attack_db=_worker_attack_db)
                _stage_end("yara", t0)
                record.YaraMatches = "; ".join(yara_result.rule_names) or None
                record.YaraHitCount = yara_result.hit_count
                record.YaraSeverity = yara_result.severity
                record.YaraSeverityScore = yara_result.severity_score
                record.YaraAttackTechniques = yara_result.attack_techniques

            # 2026-08-05: restored the YARA-hit gate around CapaEligible/
            # capa/FLOSS that was also missing - Rowan only ever computes
            # CapaEligible INSIDE its "if ($yaraText not empty)" branch
            # (same file, lines ~2257-2459), so capa never runs against a
            # file YARA didn't flag. Before this fix, CapaEligible was
            # computed - and capa invoked - for every format-eligible file
            # regardless of YaraHitCount: on the same 652-file/1-YARA-hit
            # scan referenced above, capa ran on 549 files instead of at
            # most 1, which is what every capa-timeout-tuning pass that day
            # (120s/90s/60s) was actually measuring the cost of.
            if record.YaraHitCount > 0:
                ft = file_type_mod.classify(path, hash_result.length)
                record.CapaEligible = ft.capa_eligible
                record.PossibleFalseNegative = file_type_mod.is_possible_false_negative(
                    ft, record.YaraHitCount, path
                )

                if config.CapaRules and record.CapaEligible:
                    # _worker_persistent_capa keeps ONE capa child process warm for
                    # this worker's entire lifetime instead of spawning a fresh one
                    # (and re-importing capa/vivisect from scratch) for every single
                    # file - see capa_scan.PersistentCapaWorker's docstring. The
                    # hang-safety net is unchanged: a stuck file still times out and
                    # gets a fresh replacement child on the next call, it just no
                    # longer costs a respawn for every well-behaved file too.
                    #
                    # This call is wrapped in its OWN try/except, separate from the
                    # outer one - confirmed 2026-08-03 against a real 652-file scan
                    # that capa timing out (its own hang-safety-net, not a bug in
                    # this code) is common enough on a real-world corpus that it was
                    # wiping out the WHOLE file's results: hashing, YARA, NSRL,
                    # signature status all already succeeded and were sitting on
                    # `record` by this point, but the outer except caught capa's
                    # TimeoutError and marked the entire file Status="Error" anyway,
                    # discarding everything already learned about it. A capa
                    # failure now only means "capa specifically didn't finish" -
                    # noted on record.Error for transparency - not "this file's scan
                    # failed"; every other already-computed field is left standing
                    # and the file still finishes as Status="Completed" below.
                    t0 = _stage_start()
                    try:
                        capa_result = _worker_persistent_capa.scan_file(
                            path, ft.is_shellcode, timeout_seconds=capa_scan.DEFAULT_TIMEOUT_SECONDS
                        )
                        record.CapaDetectionCount = capa_result.detection_count
                        record.CAPAOutput = capa_result.output or None
                        record.CapaShellcodeFormat = capa_result.shellcode_format
                    except Exception as exc:  # noqa: BLE001 - capa's own failure, not this file's scan failing
                        record.Error = f"capa analysis did not complete: {exc}"
                        logger.warning("capa analysis failed for %s: %s", path, exc)
                    finally:
                        _stage_end("capa", t0)
                elif record.PossibleFalseNegative:
                    t0 = _stage_start()
                    floss_result = floss_scan.scan_file(path)
                    record.FlossStringCount = floss_result.string_count
                    if floss_result.static_strings:
                        floss_static_strings = floss_result.static_strings

                    ioc_result = iocs_mod.extract_iocs(floss_result.strings)
                    record.IocCount = ioc_result.count
                    record.ExtractedIOCs = ioc_result.display
                    _stage_end("floss_iocs", t0)

        record.Status = "Completed"
    except Exception as exc:  # noqa: BLE001 - one bad file shouldn't abort the batch
        record.Status = "Error"
        record.Error = str(exc)
        logger.exception("Error processing %s", path)

    logger.info(
        "Finished: %s - %s (%.1fs)", path, record.Status, time.perf_counter() - file_start
    )

    return _WorkerFileResult(
        record=record,
        imphash=imphash,
        ssdeep_hash=ssdeep_hash,
        floss_static_strings=floss_static_strings,
        stage_seconds=stage_seconds,
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
    password_prompt_callback: Callable[[list[str]], dict[str, str]] | None = None,
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
    (BinSifter-Rowan_v1.3.0-beta.1.ps1 lines ~2895/2867: pause blocks starting new
    files, already-dispatched ones finish; stop aborts before the next file
    is submitted, never mid-file). On stop, every file that hadn't been
    submitted to the pool yet is marked Status="Cancelled" - same as the
    PowerShell version's "force-remaining to Cancelled" (line ~2941).

    password_prompt_callback (2026-08-07, see core/archive.py): called at
    most ONCE per scan, synchronously, from THIS function - not from a pool
    worker - if archive expansion's pass 1 finds any password-protected
    archives under config.SrcDir. Receives the list of locked archive
    paths, must return a dict[str, str] mapping whichever of those paths
    the caller has a password for (any not present in the returned dict
    are treated as "unknown" and saved to <ReportDirectory>/
    password_protected/ for external cracking, same as if this callback
    were never supplied at all). MainWindow's caller uses this to bounce
    the request over to the GUI thread (a Qt signal + threading.Event,
    since this runs on the scan's background QThread) and show one batch
    password dialog; a headless/CLI run can simply omit it, which just
    means every locked archive found goes straight to unresolved without
    ever attempting to prompt for anything.
    """
    # ================= Pre-scan setup - now narrated (2026-08-04) =================
    # Every load/validation step below used to run completely silently before
    # the worker pool started - confirmed (against a real 67-minute scan on
    # slower hardware) to be the actual explanation for BinSifter appearing
    # "frozen" for the first several minutes: no log line, no progress
    # signal, and no file-queue row exists yet, all before a single byte of
    # actual scanning has happened. NSRL hash-set loading is the prime
    # suspect - a real-world NSRL RDS export can be tens of millions of rows,
    # parsed here in pure Python (see nsrl.py) - but rather than guess which
    # step is slow, every step now logs its own start/finish + elapsed time,
    # so the Logs page shows real activity from the first second and the
    # next slow run tells us exactly which step to optimize, not just "it
    # was slow somewhere before the pool started."
    setup_start = time.perf_counter()

    logger.info("Enumerating files under %s...", config.SrcDir)
    t0 = time.perf_counter()
    paths = enumerate_files(config.SrcDir)
    logger.info("Found %d file(s) to scan (%.1fs).", len(paths), time.perf_counter() - t0)

    # ================= Archive expansion (2026-08-07) =================
    # Serial, in-process, BEFORE the multiprocessing pool below is created -
    # see this module's docstring and core/archive.py's for why that's the
    # right place for this rather than something the pool's per-file
    # workers need to handle. Archive files themselves stay in `paths` too
    # (still scanned as an ordinary file in their own right, in case the
    # archive itself matches a YARA rule or similar) - this only ADDS the
    # files found inside them.
    source_archive_by_path: dict[str, str] = {}
    archive_paths = archive_mod.find_archives(paths)
    if archive_paths and config.ReportDirectory:
        extraction_root = str(Path(config.ReportDirectory) / "extracted_archives")
        logger.info("Found %d archive(s) under %s - expanding...", len(archive_paths), config.SrcDir)
        t0 = time.perf_counter()
        expansion = archive_mod.expand_archives(archive_paths, extraction_root)
        paths.extend(expansion.extracted_files)
        source_archive_by_path.update(expansion.source_archive_by_path)
        logger.info(
            "Archive expansion pass 1: %d file(s) extracted, %d archive(s) need a password "
            "(%.1fs).",
            len(expansion.extracted_files), len(expansion.locked_archives), time.perf_counter() - t0,
        )

        if expansion.locked_archives:
            password_map: dict[str, str] = {}
            if password_prompt_callback is not None:
                try:
                    password_map = password_prompt_callback(expansion.locked_archives) or {}
                except Exception as exc:  # noqa: BLE001 - a GUI-side prompting failure shouldn't abort the whole scan
                    logger.warning(
                        "Password prompt failed, treating all %d locked archive(s) as "
                        "unresolved: %s", len(expansion.locked_archives), exc,
                    )
            else:
                logger.info(
                    "%d locked archive(s) found but no password-prompt callback was supplied "
                    "(e.g. a headless/CLI run) - saving all of them for external cracking "
                    "without prompting.", len(expansion.locked_archives),
                )

            unresolved_dir = str(Path(config.ReportDirectory) / "password_protected")
            t0 = time.perf_counter()
            resolution = archive_mod.resolve_locked_archives(
                expansion.locked_archives, password_map, extraction_root, unresolved_dir
            )
            paths.extend(resolution.extracted_files)
            source_archive_by_path.update(resolution.source_archive_by_path)
            logger.info(
                "Archive expansion pass 2: %d more file(s) extracted, %d archive(s) saved to "
                "%s for external cracking (%.1fs).",
                len(resolution.extracted_files), len(resolution.unresolved_archives),
                unresolved_dir, time.perf_counter() - t0,
            )
    elif archive_paths:
        logger.warning(
            "%d archive(s) found under %s but no ReportDirectory is configured - archive "
            "expansion needs somewhere on disk to extract to, so it's being skipped this run. "
            "Archives will still be scanned as opaque single files, just not their contents.",
            len(archive_paths), config.SrcDir,
        )

    records: dict[str, FileRecord] = {p: FileRecord(Path=p) for p in paths}

    # One timestamp per scan, reused everywhere a filename needs to be
    # stamped (draft YARA rule names, the 4 CSV reports below) - same role
    # as the PowerShell version's $timestamp (Get-Date -Format
    # 'yyyy-MM-dd_HHmmss'), computed once so every output from this run
    # sorts/groups together.
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    # Cached, memory-mapped binary index (2026-08-04 rewrite) instead of a
    # Python set loaded once and pickled into every worker - see nsrl.py's
    # module docstring for the full "24.5-minute reparse + duplicated into
    # up to 16 worker processes" story this replaces. What crosses the
    # process boundary now is nsrl_cache_path, a plain string - each worker
    # opens/mmaps it independently in _pool_worker_init() below.
    nsrl_cache_path: str | None = None
    if config.NsrlPath and Path(config.NsrlPath).is_file():
        cache_path = nsrl_mod.get_cache_path(config.NsrlPath, config.ReportDirectory)
        if nsrl_mod.cache_is_fresh(cache_path, config.NsrlPath):
            logger.info("Loading NSRL from cache (fast path): %s...", cache_path)
            t0 = time.perf_counter()
            count = nsrl_mod.read_cached_count(cache_path)
            logger.info("NSRL cache loaded: %d hash(es) indexed (%.1fs).", count, time.perf_counter() - t0)
        else:
            logger.info(
                "Building NSRL cache from source %s (first run against this file - "
                "subsequent scans will load from cache instead)...", config.NsrlPath,
            )
            t0 = time.perf_counter()
            count = nsrl_mod.build_index(config.NsrlPath, cache_path)
            logger.info(
                "NSRL cache built: %d hash(es) indexed (%.1fs) - saved to %s.",
                count, time.perf_counter() - t0, cache_path,
            )
        nsrl_cache_path = cache_path
    elif config.NsrlPath:
        logger.warning("Configured NSRL path does not exist, skipping: %s", config.NsrlPath)
    else:
        logger.info("No NSRL hash set configured - known-good lookup disabled for this scan.")

    # BlocklistPath (unlike NsrlPath/YaraRules/CapaRules) always has a real
    # default value - Reports/Attack/Blocklist default next to the install
    # even when the analyst never asked for blocklist checking - so guard
    # on the file actually existing, not just the path being non-empty.
    # Otherwise every scan logs a "could not read blocklist" warning until
    # someone places a blocklist file there, which is misleading noise for
    # a feature that was never configured in the first place.
    if config.BlocklistPath and Path(config.BlocklistPath).is_file():
        logger.info("Loading known-bad hash blocklist from %s...", config.BlocklistPath)
        t0 = time.perf_counter()
        blocklist_hashes = blocklist_mod.load_blocklist_hashes(config.BlocklistPath)
        logger.info(
            "Blocklist loaded: %d hash(es) indexed (%.1fs).",
            len(blocklist_hashes), time.perf_counter() - t0,
        )
    else:
        blocklist_hashes = set()

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
        logger.info("Compiling YARA rules from %s...", config.YaraRules)
        t0 = time.perf_counter()
        yara_scan.compile_rules(config.YaraRules)
        logger.info("YARA rules compiled (%.1fs).", time.perf_counter() - t0)
    if config.CapaRules:
        logger.info("Loading capa rules from %s (this can take a while for a large rule corpus)...", config.CapaRules)
        t0 = time.perf_counter()
        capa_scan.load_rules(config.CapaRules)
        logger.info("capa rules loaded (%.1fs).", time.perf_counter() - t0)

    # v1.3-proto1: prior triage dispositions, persisted by SHA-1 so
    # re-scanning the same files (or re-opening the same case directory
    # later) keeps earlier Benign/Suspicious/Escalated calls instead of
    # resetting everything to Untriaged - written by the Results page's
    # Disposition column edits, read back here once per scan (see
    # BinSifter-Rowan_v1.3.0-beta.1.ps1 lines ~2775-2782).
    disposition_history = disposition_mod.load_disposition_history(config.ReportDirectory)

    # MITRE ATT&CK mapping is optional, same as the PowerShell version - a
    # blank/missing AttackDataPath just means TTP mapping is disabled for
    # this scan, not an error. Unlike the other loads above, this one is
    # wrapped in its own try/except: the PowerShell version explicitly
    # catches AttackDb.Load() failures (bad/partial JSON, wrong schema) and
    # logs "TTP mapping disabled for this scan" rather than aborting the
    # whole scan over an optional enrichment feature - see
    # BinSifter-Rowan_v1.3.0-beta.1.ps1 lines ~2799-2811.
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
    logger.info(
        "Setup complete (%.1fs). Scanning %d file(s) with %d worker process(es)...",
        time.perf_counter() - setup_start, len(paths), worker_count,
    )

    stopped_at: int | None = None

    # Diagnostic-only timing (2026-08-04, see _WorkerFileResult.stage_seconds
    # docstring for why this exists at all). total_stage_seconds sums each
    # stage's cost ACROSS every file, including files processed concurrently
    # in different worker processes - this is aggregate CPU-seconds spent in
    # that stage, not wall-clock time, so it tells you relative SHARE of
    # total work per stage, not how many minutes it added to the clock.
    # pool_wall_seconds (measured below) is the actual wall-clock time the
    # concurrent section took, for comparison against the aggregate.
    total_stage_seconds: dict[str, float] = {}
    stage_file_counts: dict[str, int] = {}
    pool_wall_start = time.perf_counter()

    if paths:
        result_queue: "queue.Queue" = queue.Queue()
        # Every worker's PersistentCapaWorker reports its child's PID here
        # the moment it spawns one - see _reap_capa_children() below for why
        # this is needed (pool.terminate() kills workers abruptly, which
        # does NOT kill those workers' own children).
        capa_pid_queue: "multiprocessing.Queue" = multiprocessing.get_context("spawn").Queue()

        # Every worker's QueueHandler (see _pool_worker_init) puts its
        # LogRecords here; _drain_log_queue (running in this thread, in the
        # parent) re-injects them into the parent's own logging tree so the
        # GUI's Logs page actually shows per-file worker activity instead of
        # going dark for the whole scan - see that function's docstring.
        log_queue: "multiprocessing.Queue" = multiprocessing.get_context("spawn").Queue()
        log_drain_thread = threading.Thread(target=_drain_log_queue, args=(log_queue,), daemon=True)
        log_drain_thread.start()

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

        # _NoDaemonPool, not a plain multiprocessing.Pool - see that
        # class's docstring above: capa's own per-file hang-safety
        # subprocess (spawned from inside _process_one_file) requires its
        # parent (the pool worker) to be non-daemonic, or Python's own
        # multiprocessing module refuses to let it start.
        with _NoDaemonPool(
            processes=worker_count,
            initializer=_pool_worker_init,
            initargs=(
                config, nsrl_cache_path, blocklist_hashes, attack_db, disposition_history,
                capa_pid_queue, log_queue,
            ),
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
            #
            # 2026-08-14: polls with a timeout and tracks how long it's been
            # since the LAST result of any kind arrived, instead of a plain
            # blocking result_queue.get() - see RESULT_STALL_TIMEOUT_SECONDS'
            # comment above for the real scan that hung indefinitely because
            # of this. Any single result (ok or error) resets the clock, so
            # this only trips when NOTHING has come back for the full
            # ceiling, not just because one file happens to be slow while
            # others keep finishing around it.
            completed = 0
            last_progress_monotonic = time.monotonic()
            stalled = False
            # min(30, ...) so a shorter-than-30s stall ceiling (only ever
            # done in tests - production always uses the real 1200s default)
            # still gets checked promptly instead of waiting out a fixed 30s
            # poll first regardless of how small the ceiling is.
            poll_seconds = min(30, RESULT_STALL_TIMEOUT_SECONDS)
            while completed < submitted:
                try:
                    status, payload = result_queue.get(timeout=poll_seconds)
                except queue.Empty:
                    if time.monotonic() - last_progress_monotonic >= RESULT_STALL_TIMEOUT_SECONDS:
                        stalled = True
                        break
                    continue

                last_progress_monotonic = time.monotonic()
                if status == "error":
                    logger.error("Scan worker failed unexpectedly: %s", payload)
                    completed += 1
                    continue

                result: _WorkerFileResult = payload
                records[result.record.Path] = result.record
                imphashes[result.record.Path] = result.imphash
                if result.ssdeep_hash:
                    ssdeep_hashes[result.record.Path] = result.ssdeep_hash
                if result.floss_static_strings:
                    floss_static_strings[result.record.Path] = result.floss_static_strings
                for stage, seconds in result.stage_seconds.items():
                    total_stage_seconds[stage] = total_stage_seconds.get(stage, 0.0) + seconds
                    stage_file_counts[stage] = stage_file_counts.get(stage, 0) + 1

                completed += 1
                if progress_callback:
                    progress_callback(completed, len(paths), result.record.Path, result.record)

            if stalled:
                # Every path dispatched to the pool got its placeholder
                # record's Status flipped to "Scanning" at submission time
                # (above) - a path whose real result never came back still
                # shows that same placeholder Status untouched, which is
                # exactly how "still outstanding" is identified here with no
                # extra bookkeeping needed.
                stuck_paths = [p for p in paths[:submitted] if records[p].Status == "Scanning"]
                logger.error(
                    "Scan stalled: no worker result for over %ds - %d file(s) still "
                    "outstanding (e.g. %s), abandoning the rest of this batch so the "
                    "scan can finish instead of hanging indefinitely.",
                    RESULT_STALL_TIMEOUT_SECONDS, len(stuck_paths),
                    stuck_paths[0] if stuck_paths else "?",
                )
                for stuck_path in stuck_paths:
                    stuck_record = records[stuck_path]
                    stuck_record.Status = "Error"
                    stuck_record.Error = (
                        f"Scan worker did not respond within {RESULT_STALL_TIMEOUT_SECONDS}s "
                        "and was abandoned so the rest of the scan could finish. This "
                        "file likely hit a hang in a stage with no timeout protection "
                        "(hashing/authenticode/YARA/ssdeep/FLOSS all lack one - only "
                        "capa has its own 90s cutoff)."
                    )
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, len(paths), stuck_path, stuck_record)
                # The `with _NoDaemonPool(...) as pool:` block's own __exit__,
                # right below, terminates every worker process unconditionally
                # (see that class's docstring) - this is what actually kills
                # the permanently-stuck worker and frees it, the same
                # mechanism a normal scan completion already relies on.

        # Pool.__exit__ (just ran, above) tears down worker processes via
        # terminate() - an abrupt kill that does NOT clean up each worker's
        # own persistent capa child. Reap them explicitly, by PID, now that
        # every worker has had a chance to report one (or more, across
        # respawns) via capa_pid_queue.
        _reap_capa_children(capa_pid_queue)

        # Every worker is gone (pool.terminate() above), so no more
        # LogRecords can arrive on log_queue - safe to stop the drain
        # thread. Records already queued but not yet drained are still
        # picked up: the sentinel is only processed after everything ahead
        # of it in the queue.
        log_queue.put(_LOG_QUEUE_SENTINEL)
        log_drain_thread.join(timeout=5)

    pool_wall_seconds = time.perf_counter() - pool_wall_start

    # 2026-08-07: applied HERE, not when `records` was first built above -
    # each pool worker's returned result.record (see the `records[
    # result.record.Path] = result.record` assignment in the completion-
    # draining loop above) is a brand-new FileRecord built fresh inside
    # _process_one_file(), with no knowledge of source_archive_by_path at
    # all. Setting SourceArchive on the placeholder FileRecord built above,
    # before the pool ran, would just get silently overwritten the moment
    # that file's real result came back - confirmed the hard way via a real
    # end-to-end scan against a source folder containing a zip, where every
    # extracted file's SourceArchive came back blank despite this exact
    # line existing earlier in the function.
    for extracted_path, source_path in source_archive_by_path.items():
        if extracted_path in records:
            records[extracted_path].SourceArchive = source_path

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

    # Post-scan clustering passes - unlike the per-file stages above, this
    # runs single-threaded in the PARENT process, after every worker has
    # already finished, so it's a pure serial addition to wall-clock time
    # with zero benefit from the worker pool. Timed separately (not folded
    # into total_stage_seconds) since it's real wall time, not aggregate
    # per-file CPU time like the stages above.
    cluster_wall_start = time.perf_counter()

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

    cluster_wall_seconds = time.perf_counter() - cluster_wall_start

    record_list = list(records.values())

    # ================= Stage-timing summary (diagnostic only) =================
    # Logged at INFO so it shows up in the normal log file/console without
    # needing debug logging enabled - this is exactly the data needed to
    # answer "where did the N minutes go" on a real scan without guessing
    # from source reading. total_stage_seconds values are SUMMED across
    # however many files ran that stage, potentially across up to
    # worker_count concurrent processes - divide by pool_wall_seconds to see
    # how many "worker-equivalents" of wall time a stage represents, not a
    # literal wall-clock duration for that stage alone.
    if total_stage_seconds:
        grand_total = sum(total_stage_seconds.values()) or 1.0
        logger.info(
            "Scan stage timing (aggregate CPU-seconds across %d worker process(es), "
            "pool wall-clock = %.1fs, post-scan clustering wall-clock = %.1fs):",
            worker_count, pool_wall_seconds, cluster_wall_seconds,
        )
        for stage, total in sorted(total_stage_seconds.items(), key=lambda kv: kv[1], reverse=True):
            count = stage_file_counts.get(stage, 0)
            avg_ms = (total / count * 1000) if count else 0.0
            pct = total / grand_total * 100
            logger.info(
                "  %-14s %8.1fs total  (%5.1f%%)  over %5d file(s)  -  avg %7.1f ms/file",
                stage, total, pct, count, avg_ms,
            )

    # ================= Draft YARA rule generation (v1.3-proto1) =================
    # Best-effort and gracefully skipped on error - this is the same inner
    # try/except scope the PowerShell version used around just this block
    # (BinSifter-Rowan_v1.3.0-beta.1.ps1 lines ~3233/3317-3320), separate from
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
    # rule-gen had its own inner catch - see BinSifter-Rowan_v1.3.0-beta.1.ps1
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

    # ================= Grand-total summary (2026-08-04) =================
    # Everything above (setup timing, per-file stage timing, pool/clustering
    # wall time) is broken out piece by piece - this is the one line that
    # ties it back to "how long did the WHOLE thing take", plus os.cpu_count()
    # so a machine-to-machine comparison (e.g. this PC vs. a faster
    # workstation) doesn't depend on remembering to check Task Manager /
    # System Info separately - it's just in the log next to everything else.
    total_elapsed = time.perf_counter() - setup_start
    completed_count = sum(1 for r in record_list if r.Status == "Completed")
    error_count = sum(1 for r in record_list if r.Status == "Error")
    cancelled_count = sum(1 for r in record_list if r.Status == "Cancelled")
    logger.info(
        "Scan finished: %d file(s) total - %d completed, %d error, %d cancelled - "
        "%.1fs elapsed (%.1f min) - %d CPU core(s) detected, %d worker process(es) used.",
        len(record_list), completed_count, error_count, cancelled_count,
        total_elapsed, total_elapsed / 60.0, os.cpu_count() or 0, worker_count,
    )

    return ScanResult(records=record_list, report_paths=report_paths)
