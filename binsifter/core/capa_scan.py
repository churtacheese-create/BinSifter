"""CAPA capability detection - real library integration.

Verified against capa's own source (not guessed) before writing this:
- github.com/mandiant/capa/blob/master/capa/ghidra/capa_ghidra.py showed the
  general shape (capa.rules.get_rules(), capa.capabilities.common.
  find_capabilities()), but that script targets a different capa version -
  it destructures find_capabilities()'s return as a (capabilities, counts)
  tuple, which does NOT match the currently-installed flare-capa 9.4.0.
- github.com/mandiant/capa/blob/master/capa/capabilities/common.py (the
  actual installed version's source) confirms find_capabilities() returns a
  single `Capabilities` dataclass with a `.matches` dict (rule name -> list
  of (address, Result)) and a `.feature_counts` field - NOT a tuple. This
  mismatch between two "official-looking" examples is exactly why each
  capa/FLOSS/Speakeasy module's docstring insists on checking the installed
  version's real source rather than trusting one example script.
- github.com/mandiant/capa/blob/master/capa/loader.py provided
  get_extractor(), which is the real standalone-file (non-Ghidra/IDA)
  entrypoint, using backend="vivisect" by default - the same backend
  capa's own CLI (and the compiled capa.exe the PowerShell version shelled
  out to) uses, so detection fidelity should match the original, not a
  faster-but-shallower alternative (backend="pefile" also exists and skips
  vivisect entirely, but only extracts file-level features - no function/
  basic-block-scope rules would match, which would be a real accuracy
  regression versus the original capa.exe. Not used here for that reason.)

KNOWN GAP: sigpaths (FLIRT library-code-identification signatures) are
passed as an empty list - the original capa.exe binary has these bundled;
flare-capa via pip does not (see capa's own install docs). This can
increase false-attribution of statically-linked library code as
"developer-authored" capability matches. No BinSifter Settings field
exists for a sigs directory yet - flagged here rather than silently
accepted or unilaterally adding a new Settings field (Steve was
deliberate about keeping the Settings page to 6 fields).
"""

from __future__ import annotations

import logging
import multiprocessing
import pathlib
import queue
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# capa.main is never called directly here, but importing it is required:
# capa's internals (e.g. capa.rules.get_rules()) reach for submodules like
# capa.rules.cache via attribute access, which Python only binds onto the
# capa.rules module once that submodule has actually been imported
# somewhere in the process. capa's own CLI always goes through capa.main
# first, which transitively imports the whole tree as a side effect -
# importing just capa.rules/capa.loader/capa.capabilities.common (as this
# module originally did) skips that wiring and produces
# "AttributeError: module 'capa.rules' has no attribute 'cache'" the first
# time get_rules() runs. Confirmed by hitting this exact error against a
# real capa rules directory, not a hypothetical.
import capa.main  # noqa: F401

import capa.capabilities.common
import capa.loader
import capa.rules
from capa.features.common import FORMAT_AUTO, FORMAT_SC32, FORMAT_SC64, OS_AUTO

from binsifter.core.subprocess_timeout import run_with_timeout

# Confirmed necessary, not a defensive guess: modern (2025-toolchain-built)
# Windows binaries - bash.exe, curl.exe, notepad.exe all reproduced this on
# 2026-07-30 - can get vivisect's aarch64 register-context construction
# stuck for 30-90+ seconds inside envi's own code (a third-party bug, not
# something in this module).
#
# Raised from 60 to 120 on 2026-08-03 on the theory that files hitting the
# 60s cutoff were still making real, forward-progress vivisect analysis on
# genuinely complex binaries (large C++ libraries like xerces-c, xul.dll)
# and just needed more room to finish.
#
# Lowered back to 60 on 2026-08-04, and this wasn't a guess - a real
# 652-file scan run at 120s (Loom_scanLogs_08042026.txt) gave the data to
# check the 08-03 theory directly. Stage-timing summary from that run:
# capa = 31,082.7 CPU-seconds total (93.6% of all stage time), and of the
# 549 files capa ran against, 186 (28.5%) hit the full 120s timeout and
# produced nothing. Those 186 timeouts alone account for 22,320 of the
# 31,082.7 capa-seconds - ~72% of all capa time spent on files that
# ultimately yield zero result. Meanwhile the 363 files that *did* finish
# averaged only ~24s each (8,762.7s / 363) - real successes cluster well
# under even the old 60s ceiling, so the 08-03 theory (more room helps
# borderline-but-progressing files) isn't what the data shows for this
# corpus: the files timing out at 120s look like they'd time out at any
# reasonable ceiling, not files that were one more minute from finishing.
# Doubling the timeout doubled the number of workers can waste per stuck
# file without measurably rescuing more of them.
#
# Raised to 90 on 2026-08-04 (same day, second pass), after the 60s run
# (Loom_scanLogs_08042026-1641.txt) showed the 08-03 theory wasn't fully
# wrong after all. Total scan time did drop hard - 4192.7s to 1539.5s
# (-63%), capa CPU time 31,082.7s to 18,075.1s - but timeout count went UP,
# not down: 186/652 at 120s to 252/652 at 60s. Of the 549 files capa runs
# against, completion rate fell from 66.1% (363/549) to 54.1% (297/549) -
# 66 more files got zero capa result than at 120s. That's direct evidence
# some files genuinely need the 60-120s window and weren't just stuck -
# the 08-04 note above overcorrected by treating every 60s-cutoff file as
# equivalent to a 120s-cutoff file, which this run disproved.
#
# 90s is a deliberate split, not a new theory: keep most of the 08-04
# wall-clock win while clawing back some of the completion-rate loss.
# Check the next real scan's stage-timing summary against both prior runs
# (120s: 186/549 timeout, 31,082.7 capa-s, 4192.7s total; 60s: 252/549
# timeout, 18,075.1 capa-s, 1539.5s total) to see where 90s actually lands
# on both axes before treating it as settled.
DEFAULT_TIMEOUT_SECONDS = 90


@dataclass
class CapaResult:
    detection_count: int
    output: str
    shellcode_format: str | None  # "sc32"/"sc64"/None


def load_rules(capa_rules_dir: str) -> capa.rules.RuleSet:
    """CapaRules is a directory (BinSifter's existing Settings field type),
    matching capa.rules.get_rules()'s expected input."""
    rules = capa.rules.get_rules([pathlib.Path(capa_rules_dir)])
    # Loud on purpose (info, not debug): a rule silently failing to load
    # (bad YAML, a schema validation issue) looks identical to "capa ran
    # and legitimately found nothing" from the FileRecord output alone -
    # the difference matters a lot when trying to tell "the pipeline is
    # broken" from "this file really doesn't match anything".
    rule_names = sorted(rules.rules.keys())
    logger.info("Loaded %d capa rule(s) from %s: %s", len(rule_names), capa_rules_dir, rule_names)
    return rules


def _find_capabilities(rules: capa.rules.RuleSet, target_path: pathlib.Path, input_format: str):
    extractor = capa.loader.get_extractor(
        target_path,
        input_format,
        OS_AUTO,
        capa.loader.BACKEND_VIV,
        sigpaths=[],
        disable_progress=True,
    )
    return capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)


def _summarize(rules: capa.rules.RuleSet, capabilities: capa.capabilities.common.Capabilities) -> tuple[int, str]:
    matched_names = sorted(capabilities.matches.keys())
    lines = []
    for rule_name in matched_names:
        rule = rules[rule_name]
        description = rule.meta.get("description", "")
        lines.append(f"{rule_name} - {description}" if description else rule_name)
    return len(matched_names), "\n".join(lines)


def scan_file(target_path: str, rules: capa.rules.RuleSet, is_shellcode: bool = False) -> CapaResult:
    path = pathlib.Path(target_path)

    if not is_shellcode:
        capabilities = _find_capabilities(rules, path, FORMAT_AUTO)
        count, output = _summarize(rules, capabilities)
        return CapaResult(detection_count=count, output=output, shellcode_format=None)

    # Shellcode: -f sc32 then -f sc64, same order the PowerShell version
    # used (real headers can't disambiguate bitness for headerless input,
    # so both are tried explicitly). Whichever format doesn't raise wins;
    # if both raise, no detection - matches the original's graceful-skip
    # behavior rather than surfacing a hard error for ambiguous shellcode.
    for input_format, label in ((FORMAT_SC32, "sc32"), (FORMAT_SC64, "sc64")):
        try:
            capabilities = _find_capabilities(rules, path, input_format)
        except Exception:  # noqa: BLE001 - trying the other bitness next is the whole point
            continue
        count, output = _summarize(rules, capabilities)
        return CapaResult(detection_count=count, output=output, shellcode_format=label)

    return CapaResult(detection_count=0, output="", shellcode_format=None)


def _scan_file_worker_entrypoint(target_path: str, capa_rules_dir: str, is_shellcode: bool) -> CapaResult:
    """Top-level (picklable) entrypoint for the child process spawned by
    scan_file_with_timeout(). Reloads rules here instead of passing the
    parent's already-loaded capa.rules.RuleSet across the process boundary
    - that object isn't confirmed picklable, and rule loading itself is
    fast (~30ms measured against smoketest/capa_rules), so reloading per
    file is a trivial cost next to the actual analysis time."""
    rules = load_rules(capa_rules_dir)
    return scan_file(target_path, rules, is_shellcode=is_shellcode)


def scan_file_with_timeout(
    target_path: str,
    capa_rules_dir: str,
    is_shellcode: bool = False,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> CapaResult:
    """Safety-net wrapper around scan_file() - runs it in a child process
    with a hard, OS-level timeout instead of calling it directly in-process.
    See subprocess_timeout.py's module docstring for why a subprocess (not
    a signal-based timeout) is required here specifically. Raises
    TimeoutError if analysis doesn't finish in time, or RuntimeError if the
    worker process failed some other way - both are ordinary exceptions
    engine.py's existing per-file try/except already handles (marks that
    one file Status="Error" with the exception text, keeps the rest of the
    batch going), so no engine.py error-handling changes were needed beyond
    calling this instead of scan_file() directly.
    """
    return run_with_timeout(
        _scan_file_worker_entrypoint,
        (target_path, capa_rules_dir, is_shellcode),
        timeout_seconds,
        label="capa analysis",
    )


# ================= Persistent (warm) capa worker =================
# scan_file_with_timeout() above is correct but expensive when called once
# per file across a large batch: every single call spawns a brand-new
# Python process and re-imports capa/vivisect from scratch (capa.main,
# capa.loader, envi, vivisect, and everything they pull in - a genuinely
# heavy import, confirmed as a major contributor to a real 34-minute,
# 652-file Python-side scan versus the PowerShell version's ~5 minutes for
# the same batch, 2026-08-03). PersistentCapaWorker instead keeps ONE capa
# child process warm (rules loaded once, interpreter already started) and
# reuses it across every file engine.py's pool worker processes - the
# import/rule-load cost is paid roughly once per scan-pool worker instead
# of once per file.
#
# The hang-safety guarantee from scan_file_with_timeout() is preserved: if
# a request doesn't come back within timeout_seconds, the (presumably
# stuck) child is terminated/killed and discarded; the NEXT call
# transparently spawns a fresh one. The only added cost is that a genuine
# timeout now also pays a one-time respawn cost on the following file -
# negligible next to the alternative of paying that cost on every file
# regardless of whether it was ever going to hang.
#
# Accepted tradeoff, same category as engine.py's _NoDaemonPool: if the
# whole scan pool were killed abruptly rather than exiting through its own
# `with pool:` block (e.g. a hard crash of the GUI process), a persistent
# capa child could be left running as an orphan rather than being reaped
# automatically the way a daemonic process would be. Normal operation -
# Stop button, scan completion, or a clean GUI close - always goes through
# engine.py's `with _NoDaemonPool(...) as pool:`, which calls close() on
# every PersistentCapaWorker via _pool_worker_shutdown() (see engine.py)
# before the pool itself tears down.


def _capa_worker_loop(
    capa_rules_dir: str,
    request_queue: "multiprocessing.Queue",
    result_queue: "multiprocessing.Queue",
) -> None:
    """Runs in the persistent capa child process for its entire lifetime -
    loads rules exactly once, then services requests until told to stop.
    Top-level (picklable) by necessity: "spawn" needs to reimport this by
    name in the fresh child interpreter.

    Request protocol: request_queue yields either a (target_path,
    is_shellcode) tuple, or None as the shutdown sentinel. Every non-None
    request gets exactly one ("ok", CapaResult) or ("error", str) reply on
    result_queue - errors from an individual scan_file() call are caught
    here and reported back rather than crashing this loop, so a single
    bad-but-not-hanging file doesn't cost a respawn the way a real timeout
    does.
    """
    rules = load_rules(capa_rules_dir)
    while True:
        request = request_queue.get()
        if request is None:
            return
        target_path, is_shellcode = request
        try:
            result = scan_file(target_path, rules, is_shellcode=is_shellcode)
            result_queue.put(("ok", result))
        except Exception as exc:  # noqa: BLE001 - report back, don't crash the warm worker over one file
            result_queue.put(("error", str(exc)))


class PersistentCapaWorker:
    """One warm capa child process, lazily (re)spawned as needed. See the
    module-level comment above for the full rationale. Not thread-safe and
    not meant to be shared - one instance per scan-pool worker process,
    created once in engine.py's _pool_worker_init() and reused for every
    file that worker processes.

    pid_report_queue, if given, receives this worker's child PID (as a
    plain int) every time a new child is spawned. This exists because
    killing a scan-pool worker does NOT kill that worker's own children -
    engine.py's scan_directory() always tears the pool down via
    `pool.terminate()` (even on a normal, successful scan completion - see
    Pool.__exit__), which abruptly kills worker processes rather than
    letting them exit on their own, so an atexit-style hook inside the
    worker would never fire. Reporting PIDs back to the parent lets
    scan_directory() clean up every persistent capa child explicitly, by
    PID, regardless of how the pool itself shut down - see
    engine.py's _reap_capa_children().
    """

    def __init__(self, capa_rules_dir: str, pid_report_queue: "multiprocessing.Queue | None" = None) -> None:
        self._capa_rules_dir = capa_rules_dir
        self._ctx = multiprocessing.get_context("spawn")
        self._pid_report_queue = pid_report_queue
        self._process: multiprocessing.process.BaseProcess | None = None
        self._request_queue: "multiprocessing.Queue | None" = None
        self._result_queue: "multiprocessing.Queue | None" = None

    def _ensure_alive(self) -> None:
        if self._process is not None and self._process.is_alive():
            return
        self._request_queue = self._ctx.Queue()
        self._result_queue = self._ctx.Queue()
        # daemon=False: this child's own parent (the scan-pool worker that
        # owns this PersistentCapaWorker) is itself already non-daemonic
        # (see engine.py's _NoDaemonPool) specifically so it's allowed to
        # have children at all - no reason for THIS child to be daemonic
        # either, and Process() defaults to inheriting the calling
        # process's daemon flag otherwise, which could vary.
        self._process = self._ctx.Process(
            target=_capa_worker_loop,
            args=(self._capa_rules_dir, self._request_queue, self._result_queue),
            daemon=False,
        )
        self._process.start()
        if self._pid_report_queue is not None:
            try:
                self._pid_report_queue.put(self._process.pid)
            except (OSError, ValueError):
                pass  # best-effort - a failed report just means one less PID to clean up later

    def scan_file(self, target_path: str, is_shellcode: bool, timeout_seconds: float) -> "CapaResult":
        """Same contract as scan_file_with_timeout(): returns a CapaResult,
        raises TimeoutError if the warm worker doesn't respond in time (and
        discards it - the next call gets a fresh one), or RuntimeError if
        the file itself failed analysis (the warm worker survives that
        case and stays ready for the next file)."""
        self._ensure_alive()
        self._request_queue.put((target_path, is_shellcode))
        try:
            status, payload = self._result_queue.get(timeout=timeout_seconds)
        except queue.Empty:
            self._discard(force=True)
            raise TimeoutError(f"capa analysis timed out after {timeout_seconds}s")

        if status == "error":
            raise RuntimeError(f"capa analysis raised in worker process: {payload}")
        return payload

    def _discard(self, force: bool = False) -> None:
        """Terminates the current child (if any) and clears state so the
        next scan_file() call transparently spawns a fresh one."""
        process, self._process = self._process, None
        self._request_queue = None
        self._result_queue = None
        if process is None or not process.is_alive():
            return
        process.terminate()
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join()

    def close(self) -> None:
        """Graceful shutdown for the common case (scan finished, Stop was
        pressed, or the pool worker is exiting normally) - sends the
        sentinel and gives the child a moment to exit on its own before
        falling back to the same terminate/kill escalation as a timeout.
        Safe to call even if no child was ever spawned."""
        if self._process is None:
            return
        if self._process.is_alive() and self._request_queue is not None:
            try:
                self._request_queue.put(None)
            except (OSError, ValueError):
                pass  # queue's already gone/closed - fall through to a hard discard
            self._process.join(5)
        self._discard()
