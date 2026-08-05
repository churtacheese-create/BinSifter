"""Data models for the scan engine.

FileRecord below is a field-for-field port of the C# `BinSifter.FileRecord`
class embedded in the PowerShell version (BinSifter-Rowan_v1.3.0-beta.1.ps1,
around line 262). Field names are kept in PascalCase (not idiomatic Python)
and in the original order, deliberately - the whole point of this pass is a
close, low-risk 1:1 port with the old version open side by side, so extra
transformations like renaming to snake_case are deferred to a cleanup pass
once every feature has been ported and verified against the same test files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class FileRecord:
    Path: str
    Status: str = "Queued"
    Progress: int = 0

    MD5: str | None = None
    SHA1: str | None = None
    SSDEEP: str | None = None
    NsrlMatch: bool = False

    YaraMatches: str | None = None
    YaraHitCount: int = 0

    CapaEligible: bool = False
    PossibleFalseNegative: bool = False
    CAPAOutput: str | None = None
    CapaDetectionCount: int = 0
    # "sc32"/"sc64" when CapaEligible came from the shellcode heuristic and
    # capa succeeded under that bitness guess; None for PE/ELF (capa
    # auto-detects those from real headers, no guess needed) or when both
    # shellcode formats failed to produce a detection.
    CapaShellcodeFormat: str | None = None

    # Worst-case (highest) severity across every YARA rule that matched this
    # file. "Unknown" means no matched rule carried a recognizable severity
    # field - deliberately not guessed. YaraSeverityScore is the normalized
    # 0-100 value behind the bucket, or -1 when the bucket came from a plain
    # word (e.g. tc_policy_severity) rather than a number.
    YaraSeverity: str = "Unknown"
    YaraSeverityScore: int = -1
    # Semicolon-joined "T#### Name [Tactic]" entries resolved from any
    # matched rule's meta fields via the local MITRE ATT&CK dataset. None
    # when no rule referenced ATT&CK or no ATT&CK data file is configured.
    YaraAttackTechniques: str | None = None

    # -1 = not computed (e.g. an NSRL-known file never reaches this stage).
    # 0.0-8.0 bits/byte Shannon entropy over the whole file. Computed for
    # every file that gets hashed, not just PossibleFalseNegative ones,
    # since it's free once the file is already being read for SHA-1/MD5.
    Entropy: float = -1.0
    Error: str | None = None
    Added: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # -1 = floss wasn't run (not a PossibleFalseNegative file). Best-effort
    # string/IOC recovery fallback for files YARA flagged that couldn't go
    # through capa.
    FlossStringCount: int = -1

    # "path (score); path (score)" - other files in this same run whose
    # ssdeep fuzzy hash scored above threshold against this file's hash.
    # Populated in a post-scan pass, not per-file.
    SsdeepMatches: str | None = None
    # -1 = not in any cluster (never ssdeep-hashed, e.g. an NSRL-known file).
    # 0+ = the cluster this file belongs to; size-1 clusters are singletons
    # (hashed, but matched nothing above threshold).
    SsdeepClusterId: int = -1
    SsdeepClusterSize: int = 0
    # True if any of this file's matches scored >= 85 against another file -
    # drives the heat map's "Files above 85%" tile.
    SsdeepHasHighSimilarity: bool = False
    # True if this file's cluster (size >= 2) shares a member with a cluster
    # from a PRIOR run, per the persisted cluster history file.
    SsdeepPreviouslySeen: bool = False

    # ===== v1.3-proto1 fields =====

    # DIE (Detect It Easy) console-mode packer/compiler detection. Empty
    # string = DIE wasn't run on this file, not "nothing detected".
    PackerDetected: str = ""
    Compiler: str = ""

    # Import-table hash (imphash) - MD5 of the ordered "dllname.funcname"
    # list from the PE import table, lowercased. Survives repacks/rebuilds
    # that change ssdeep's fuzzy-hash score. None when the file isn't a
    # parseable PE, has no import table, or parsing failed.
    Imphash: str | None = None
    # Rich header hash - present only for PE files built with MSVC that
    # retained the Rich header. A secondary, coarser toolchain-fingerprint
    # signal.
    RichHash: str | None = None
    ImphashClusterId: int = -1
    ImphashClusterSize: int = 0

    # Authenticode verification result. Status is a string, not a bool,
    # since "not signed" and "signed but invalid" are very different triage
    # signals. Ported 2026-07-30 using the `signify` library (pure Python,
    # cross-platform) in place of the PowerShell version's
    # Get-AuthenticodeSignature - see core/authenticode.py for the real
    # implementation and important caveats about trust-store differences.
    SignatureStatus: str = ""
    SignerName: str = ""

    # Regex-mined from FLOSS output already generated for
    # PossibleFalseNegative files. Empty when FLOSS didn't run on this file
    # or nothing matched.
    IocCount: int = 0
    ExtractedIOCs: str = ""

    # Local offline blocklist lookup, same shape as the NSRL known-good
    # check but for known-bad hashes. "" = blocklist not configured or file
    # not checked; "Clean" = checked, no match; "KnownBad" = matched.
    ReputationStatus: str = ""
    ReputationSource: str = ""

    # Analyst-set triage disposition. Defaults to Untriaged; persisted by
    # SHA-1 across runs so re-opening a case or re-scanning the same files
    # keeps prior calls.
    Disposition: str = "Untriaged"
