"""CSV report writing - direct port of the C# CsvWriter class embedded in
BinSifter_v1.3.0-alpha.2.ps1 (lines ~431-499).

Deliberately NOT a generic "dump every FileRecord field" writer - the
original hand-picks a specific 36-column list, in a specific order, and
applies specific blank-if-default formatting per column (Entropy to 3
decimal places; several -1/0-sentinel int fields blanked instead of shown
as "-1"/"0"/negative numbers). Matching that exactly matters here since
this report format is what an analyst actually opens in Excel/imports into
other tooling, not an internal data structure - a "cleaner"
reflection-based column set (`[f.name for f in fields(FileRecord)]`, which
is what cli.py's placeholder writer did before this module existed) would
silently change what every existing BinSifter user's tooling/muscle-memory
expects, and would also include internal-only fields (Progress, Added,
CAPAOutput) the original never wrote to CSV at all.

Writes the same 4 report files as the original, filtered from one shared
column/row-building pass ('full'/'suspicious'/'yara'/'capa' modes):
  - BinSifter_Triage_<timestamp>.csv - every record.
  - suspicious_unknown_<timestamp>.csv - NSRL-known-good files excluded.
  - yara_matches_<timestamp>.csv - only files with 1+ YARA hit.
  - capa_compatible_<timestamp>.csv - only CapaEligible files.

UTF-8 with a BOM (encoding="utf-8-sig"), matching the C# version's
`new UTF8Encoding(true)` - needed for Excel to reliably detect UTF-8
rather than mis-decoding non-ASCII file paths.

Known gaps carried over as-is, not silently filled in: SsdeepPreviouslySeen
(cross-run cluster history), PackerDetected, and Compiler are real
FileRecord fields this writer faithfully outputs, but no Python module
populates them yet (DIE integration and the persisted ssdeep-cluster-
history file are both still-PowerShell-only features) - expect these
columns to be blank/False in every report until those are ported.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from binsifter.core.models import FileRecord

# Exact column list/order from the C# CsvWriter.WriteReport - see module
# docstring for why this isn't just every FileRecord field via reflection.
COLUMNS = [
    "FilePath", "SHA1", "MD5", "SSDEEP", "IsKnownGood", "YaraHitCount",
    "YaraMatches", "YaraSeverity", "YaraSeverityScore", "AttackTechniques",
    "CapaEligible", "PossibleFalseNegative", "CapaDetections", "Status",
    "Error", "Entropy", "CapaShellcodeFormat", "FlossStringCount",
    "SsdeepMatches", "SsdeepClusterId", "SsdeepClusterSize",
    "SsdeepHighSimilarity", "SsdeepPreviouslySeen", "PackerDetected",
    "Compiler", "Imphash", "RichHash", "ImphashClusterId",
    "ImphashClusterSize", "SignatureStatus", "SignerName", "IocCount",
    "ExtractedIOCs", "ReputationStatus", "ReputationSource", "Disposition",
]


def _row_for(record: FileRecord) -> list[str]:
    return [
        record.Path or "",
        record.SHA1 or "",
        record.MD5 or "",
        record.SSDEEP or "",
        str(record.NsrlMatch),
        str(record.YaraHitCount),
        record.YaraMatches or "",
        record.YaraSeverity or "",
        str(record.YaraSeverityScore),
        record.YaraAttackTechniques or "",
        str(record.CapaEligible),
        str(record.PossibleFalseNegative),
        str(record.CapaDetectionCount),
        record.Status or "",
        record.Error or "",
        f"{record.Entropy:.3f}" if record.Entropy >= 0 else "",
        record.CapaShellcodeFormat or "",
        str(record.FlossStringCount) if record.FlossStringCount >= 0 else "",
        record.SsdeepMatches or "",
        str(record.SsdeepClusterId) if record.SsdeepClusterId >= 0 else "",
        str(record.SsdeepClusterSize) if record.SsdeepClusterSize > 0 else "",
        str(record.SsdeepHasHighSimilarity),
        str(record.SsdeepPreviouslySeen),
        record.PackerDetected or "",
        record.Compiler or "",
        record.Imphash or "",
        record.RichHash or "",
        str(record.ImphashClusterId) if record.ImphashClusterId >= 0 else "",
        str(record.ImphashClusterSize) if record.ImphashClusterSize > 0 else "",
        record.SignatureStatus or "",
        record.SignerName or "",
        str(record.IocCount) if record.IocCount > 0 else "",
        record.ExtractedIOCs or "",
        record.ReputationStatus or "",
        record.ReputationSource or "",
        record.Disposition or "",
    ]


def write_report(path: str, records: list[FileRecord], mode: str = "full") -> None:
    """mode: "full" | "suspicious" | "yara" | "capa" - same 4 modes as the
    C# version, filtering which rows get written (see module docstring).
    """
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh, lineterminator="\r\n")
        writer.writerow(COLUMNS)
        for record in records:
            if mode == "suspicious" and record.NsrlMatch:
                continue
            if mode == "yara" and record.YaraHitCount <= 0:
                continue
            if mode == "capa" and not record.CapaEligible:
                continue
            writer.writerow(_row_for(record))


@dataclass
class ReportPaths:
    full: str
    suspicious: str
    yara_matches: str
    capa_compatible: str


def write_all_reports(records: list[FileRecord], report_directory: str, timestamp: str) -> ReportPaths:
    """Writes the same 4 report files the PowerShell version did, all
    stamped with the same scan timestamp used elsewhere (the SSDEEP
    cluster-match CSV, draft YARA rule filenames) - see engine.py's
    scan_directory(). Unlike draft-rule generation, this is NOT wrapped in
    a swallow-all try/except by the caller: a report-write failure (disk
    full, permissions) was a real scan-ending error in the original too,
    not a gracefully-skipped optional feature.
    """
    root = Path(report_directory)
    root.mkdir(parents=True, exist_ok=True)

    paths = ReportPaths(
        full=str(root / f"BinSifter_Triage_{timestamp}.csv"),
        suspicious=str(root / f"suspicious_unknown_{timestamp}.csv"),
        yara_matches=str(root / f"yara_matches_{timestamp}.csv"),
        capa_compatible=str(root / f"capa_compatible_{timestamp}.csv"),
    )

    write_report(paths.full, records, mode="full")
    write_report(paths.suspicious, records, mode="suspicious")
    write_report(paths.yara_matches, records, mode="yara")
    write_report(paths.capa_compatible, records, mode="capa")

    return paths
