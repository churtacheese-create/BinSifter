"""Scan orchestration - the Python equivalent of Start-ScanEngine in the
PowerShell version.

This is a first-pass skeleton, not a finished port: it wires together the
modules that are already real (hashing, NSRL, blocklist, YARA, imphash,
ssdeep clustering) and clearly marks the ones that still throw
NotImplementedError (capa, FLOSS, Speakeasy, Authenticode, MITRE ATT&CK
enrichment) so a scan can be exercised end-to-end today without those,
and each one gets swapped in as its own module is finished - a hard gate
per step, not a rewrite-then-test-everything-at-the-end approach, per
Steve's stated priority on accuracy over speed of delivery.

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
from pathlib import Path

from binsifter.core.config import BinSifterConfig
from binsifter.core.models import FileRecord
from binsifter.core import blocklist as blocklist_mod
from binsifter.core import hashing
from binsifter.core import imphash as imphash_mod
from binsifter.core import nsrl as nsrl_mod
from binsifter.core import ssdeep_cluster
from binsifter.core import yara_scan

logger = logging.getLogger(__name__)


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


def scan_directory(config: BinSifterConfig, progress_callback=None) -> list[FileRecord]:
    """Runs the currently-implemented pipeline stages over every file under
    config.SrcDir: hash + entropy, NSRL, blocklist, YARA, imphash. Returns
    the full FileRecord list; ssdeep/imphash clustering is applied as a
    post-scan pass across the whole batch, same as the PowerShell version.

    progress_callback(done: int, total: int, current_path: str), if given,
    is called after each file - the GUI's progress bar should be driven off
    this rather than polling.
    """
    paths = enumerate_files(config.SrcDir)
    records: dict[str, FileRecord] = {p: FileRecord(Path=p) for p in paths}

    nsrl_hashes = nsrl_mod.load_nsrl_hashes(config.NsrlPath) if config.NsrlPath else set()
    blocklist_hashes = (
        blocklist_mod.load_blocklist_hashes(config.BlocklistPath) if config.BlocklistPath else set()
    )
    yara_rules = yara_scan.compile_rules(config.YaraRules) if config.YaraRules else None

    imphashes: dict[str, str | None] = {}
    ssdeep_hashes: dict[str, str] = {}

    for i, path in enumerate(paths):
        record = records[path]
        try:
            hash_result = hashing.hash_and_score_file(path)
            record.MD5 = hash_result.md5
            record.SHA1 = hash_result.sha1
            record.Entropy = hash_result.entropy

            record.NsrlMatch = nsrl_mod.is_known_good(hash_result.sha1, nsrl_hashes)

            record.ReputationStatus, record.ReputationSource = blocklist_mod.check_reputation(
                hash_result.md5, hash_result.sha1, hash_result.sha256, blocklist_hashes
            ) if blocklist_hashes else ("", "")

            if yara_rules is not None:
                yara_result = yara_scan.scan_file(yara_rules, path)
                record.YaraMatches = "; ".join(yara_result.rule_names) or None
                record.YaraHitCount = yara_result.hit_count
                record.YaraSeverity = yara_result.severity
                record.YaraSeverityScore = yara_result.severity_score

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

    # TODO, each gated behind its own module being finished:
    #   - capa/FLOSS for PossibleFalseNegative-eligible files
    #   - Authenticode verification
    #   - MITRE ATT&CK technique enrichment (YaraAttackTechniques)
    #   - draft YARA rule auto-generation per ssdeep cluster
    #   - CSV/report writing to config.ReportDirectory

    return list(records.values())
