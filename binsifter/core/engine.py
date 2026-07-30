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
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from binsifter.core.config import BinSifterConfig
from binsifter.core.models import FileRecord
from binsifter.core import attack_db as attack_db_mod
from binsifter.core import authenticode
from binsifter.core import blocklist as blocklist_mod
from binsifter.core import capa_scan
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


def scan_directory(config: BinSifterConfig, progress_callback=None) -> ScanResult:
    """Runs the currently-implemented pipeline stages over every file under
    config.SrcDir: hash + entropy, NSRL, blocklist, YARA, imphash. Returns
    a ScanResult (records + the paths of any CSV reports written);
    ssdeep/imphash clustering, draft YARA rule generation, and report
    writing are all applied as post-scan passes across the whole batch,
    same as the PowerShell version.

    progress_callback(done: int, total: int, current_path: str), if given,
    is called after each file - the GUI's progress bar should be driven off
    this rather than polling.
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

    for i, path in enumerate(paths):
        record = records[path]
        try:
            hash_result = hashing.hash_and_score_file(path)
            record.MD5 = hash_result.md5
            record.SHA1 = hash_result.sha1
            record.Entropy = hash_result.entropy

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
            progress_callback(i + 1, len(paths), path)

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
