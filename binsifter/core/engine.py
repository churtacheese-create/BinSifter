"""Scan orchestration - the Python equivalent of Start-ScanEngine in the
PowerShell version.

This is a first-pass skeleton, not a finished port: it wires together every
automatic per-file/bulk-scan stage (hashing, NSRL, blocklist, YARA, imphash,
ssdeep clustering, capa, FLOSS, Authenticode, IOC extraction, MITRE ATT&CK
enrichment, draft YARA rule generation, CSV report writing) - each swapped
in as its own module was finished, a hard gate per step rather than a
rewrite-then-test-everything-at-the-end approach, per Steve's stated
priority on accuracy over speed of delivery.

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
) -> ScanResult:
    """Runs the currently-implemented pipeline stages over every file under
    config.SrcDir: hash + entropy, NSRL, blocklist, YARA, imphash. Returns
    a ScanResult (records + the paths of any CSV reports written);
    ssdeep/imphash clustering, draft YARA rule generation, and report
    writing are all applied as post-scan passes across the whole batch,
    same as the PowerShell version.

    progress_callback(done, total, current_path, record) is called TWICE per
    file - once with record.Status == "Scanning" right before processing
    starts, once again after with Status == "Completed"/"Error" - so a live
    queue view can show an in-flight row, not just a jump from Queued
    straight to a finished state. This is a single-threaded sequential scan
    (unlike the PowerShell version's bounded worker-pool dispatcher), so only
    one row will ever show "Scanning" at a time here - a known, existing
    simplification of this port, not something this change alters.

    should_pause()/should_stop(), if given, are polled BETWEEN files, mirroring
    the PowerShell dispatcher's own cooperative gate (BinSifter_v1.3.0-alpha.2.ps1
    lines ~2895/2867: pause blocks starting new files, already-dispatched ones
    finish; stop aborts before the next file starts, never mid-file). On stop,
    every file that hadn't started yet is marked Status="Cancelled" - same as
    the PowerShell version's "force-remaining to Cancelled" (line ~2941).
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
    yara_rules = yara_scan.compile_rules(config.YaraRules) if config.YaraRules else None
    capa_rules = capa_scan.load_rules(config.CapaRules) if config.CapaRules else None

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

    stopped_at: int | None = None
    for i, path in enumerate(paths):
        if should_stop and should_stop():
            stopped_at = i
            break

        # should_stop() is only polled a second time here if the pause loop
        # actually ran - avoids calling it twice per file in the common
        # (never-paused) case, which would otherwise make a stop-callback
        # that flips state on each call (like the real GUI's) fire once too
        # often per iteration.
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
            progress_callback(i, len(paths), path, record)
        try:
            hash_result = hashing.hash_and_score_file(path)
            record.MD5 = hash_result.md5
            record.SHA1 = hash_result.sha1
            record.Entropy = hash_result.entropy

            prior_disposition = disposition_history.get(hash_result.sha1.lower())
            if prior_disposition:
                record.Disposition = prior_disposition

            # Authenticode check runs unconditionally, like entropy - same
            # rationale as the PowerShell version (line ~2141): "signed" vs
            # "unsigned" is meaningful regardless of NSRL/hash reputation,
            # and it's a single read against the file already on disk.
            auth_result = authenticode.check_signature(path)
            record.SignatureStatus = auth_result.status
            record.SignerName = auth_result.signer_name

            record.NsrlMatch = nsrl_mod.is_known_good(hash_result.sha1, nsrl_hashes)

            record.ReputationStatus, record.ReputationSource = blocklist_mod.check_reputation(
                hash_result.md5, hash_result.sha1, hash_result.sha256, blocklist_hashes
            ) if blocklist_hashes else ("", "")

            if yara_rules is not None:
                yara_result = yara_scan.scan_file(yara_rules, path, attack_db=attack_db)
                record.YaraMatches = "; ".join(yara_result.rule_names) or None
                record.YaraHitCount = yara_result.hit_count
                record.YaraSeverity = yara_result.severity
                record.YaraSeverityScore = yara_result.severity_score
                record.YaraAttackTechniques = yara_result.attack_techniques

            # PE/ELF/shellcode classification - direct port of the
            # PowerShell version's magic-byte sniff (see file_type.py),
            # gates both capa eligibility and the FLOSS fallback below.
            ft = file_type_mod.classify(path, hash_result.length)
            record.CapaEligible = ft.capa_eligible
            record.PossibleFalseNegative = file_type_mod.is_possible_false_negative(
                ft, record.YaraHitCount, path
            )

            if capa_rules is not None and record.CapaEligible:
                capa_result = capa_scan.scan_file(path, capa_rules, is_shellcode=ft.is_shellcode)
                record.CapaDetectionCount = capa_result.detection_count
                record.CAPAOutput = capa_result.output or None
                record.CapaShellcodeFormat = capa_result.shellcode_format
            elif record.PossibleFalseNegative:
                # Best-effort fallback for the PossibleFalseNegative case:
                # capa couldn't run at all, so recover what we can via
                # FLOSS's string extraction instead - same rationale as the
                # PowerShell version's fallback at this exact branch.
                floss_result = floss_scan.scan_file(path)
                record.FlossStringCount = floss_result.string_count
                if floss_result.static_strings:
                    floss_static_strings[path] = floss_result.static_strings

                # Mines the same FLOSS strings just extracted above for
                # IOC-shaped values (IPs, URLs, domains, registry paths) -
                # see iocs.py. Never a second FLOSS invocation, and never
                # allowed to affect FlossStringCount above (same "best
                # effort, mining failure isn't a scan failure" rationale
                # as the PowerShell version).
                ioc_result = iocs_mod.extract_iocs(floss_result.strings)
                record.IocCount = ioc_result.count
                record.ExtractedIOCs = ioc_result.display

            imphashes[path] = imphash_mod.compute_imphash(path)
            ssdeep_hash = ssdeep_cluster.compute_ssdeep_hash(path)
            if ssdeep_hash:
                ssdeep_hashes[path] = ssdeep_hash
                record.SSDEEP = ssdeep_hash

            record.Status = "Completed"
        except Exception as exc:  # noqa: BLE001 - one bad file shouldn't abort the batch
            record.Status = "Error"
            record.Error = str(exc)
            logger.exception("Error processing %s", path)

        if progress_callback:
            progress_callback(i + 1, len(paths), path, record)

    if stopped_at is not None:
        for remaining_path in paths[stopped_at:]:
            records[remaining_path].Status = "Cancelled"
        logger.info(
            "Scan stopped by request - %d/%d file(s) were not processed.",
            len(paths) - stopped_at, len(paths),
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
