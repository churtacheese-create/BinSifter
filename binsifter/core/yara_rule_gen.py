"""Draft YARA rule auto-generation per SSDEEP cluster - direct port of the
v1.3-proto1 PowerShell logic (BinSifter-Rowan.ps1, lines
~3225-3320).

Best-effort, clearly-labeled-as-draft rules built from strings common to
every member of a size>=2 SSDEEP cluster. Only cluster members that went
through the PossibleFalseNegative FLOSS fallback contribute strings (many
won't - that's expected, not a bug); a cluster with no contributing members
falls back to a filesize-range-only skeleton rule explicitly flagged as
needing manual work rather than being silently skipped. Written to
config.ReportDirectory/generated_rules for manual review - never
auto-imported into BinSifter's own YaraRules/CapaRules by this code.

Deliberate simplification versus the PowerShell version: that version
persisted each file's raw FLOSS JSON output to disk
(ReportDirectory/floss_reports/<sha1>.json) during the per-file scan pass,
then re-read and re-parsed those files back from disk during this later
clustering pass - a round-trip that made sense for its out-of-process
runspace architecture. Since this Python port already holds every file's
FLOSS static strings in memory for the duration of scan_directory() (no
separate process to hand data back from), engine.py passes them straight
through as an in-memory dict instead - no JSON files are read or written
by this module. Functionally equivalent, less I/O.

Known, deliberately-NOT-fixed quirk carried over from the original: the
YARA condition for a rule with common strings always reads "(3 of them)"
regardless of how many strings were actually found (1 to 12) - a rule
built from only 1 or 2 common strings can therefore never match anything.
Ported as-is rather than "improved" to e.g. min(3, len(strings)) of them,
since these are explicitly unreviewed drafts (the header comment already
says so) and silently changing detection logic here would defeat the
"draft to be reviewed by a human" premise as much as leaving the bug in.
Flag before changing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from binsifter.core.models import FileRecord

# Same constants as the PowerShell version - see module docstring.
_MIN_STRING_LEN = 8
_MAX_STRING_LEN = 128
_MAX_COMMON_STRINGS = 12
_MIN_CLUSTER_SIZE_FOR_RULE = 2
_FIXED_MATCH_COUNT = 3  # "(3 of them)" - see the known-quirk note above.

_RULE_NAME_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_]")


@dataclass
class DraftRuleGenResult:
    rules_written: int
    output_dir: str


def generate_draft_rules(
    records_by_cluster: dict[int, list[FileRecord]],
    static_strings_by_path: dict[str, list[str]],
    report_directory: str,
    ssdeep_cluster_threshold: int,
    timestamp: str | None = None,
) -> DraftRuleGenResult:
    """records_by_cluster: {cluster_id: [FileRecord, ...]} - callers should
    only include clusters with 2+ members (same as the PowerShell version's
    `if ($members.Count -lt 2) { continue }`); re-checked here too as a
    defensive guard.

    static_strings_by_path: {file_path: [raw FLOSS static strings]} - only
    present for files that actually ran FLOSS (the PossibleFalseNegative
    fallback); a cluster member missing from this dict simply doesn't
    contribute to the string intersection, same as a missing
    floss_reports/<sha1>.json did in the original.
    """
    timestamp = timestamp or datetime.now().strftime("%Y-%m-%d_%H%M%S")
    output_dir = Path(report_directory) / "generated_rules"
    output_dir.mkdir(parents=True, exist_ok=True)

    rules_written = 0

    for cluster_id, members in records_by_cluster.items():
        if len(members) < _MIN_CLUSTER_SIZE_FOR_RULE:
            continue

        common_strings = _intersect_static_strings(members, static_strings_by_path)
        size_condition = _build_size_condition(members)
        rule_name = _RULE_NAME_SANITIZE_RE.sub("_", f"bsifter_ssdeep_cluster_{cluster_id}_{timestamp}")

        lines = _build_rule_lines(
            rule_name=rule_name,
            cluster_id=cluster_id,
            cluster_size=len(members),
            threshold=ssdeep_cluster_threshold,
            common_strings=common_strings,
            size_condition=size_condition,
            timestamp=timestamp,
        )

        rule_path = output_dir / f"{rule_name}.yar"
        rule_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        rules_written += 1

    return DraftRuleGenResult(rules_written=rules_written, output_dir=str(output_dir))


def _intersect_static_strings(
    members: list[FileRecord], static_strings_by_path: dict[str, list[str]]
) -> list[str]:
    """Length-filters (8-128 chars) each member's static strings into a
    per-member set, then intersects across every member that had any -
    same as the PowerShell version's HashSet[string](Ordinal - i.e.
    case-sensitive) IntersectWith chain. Needs 2+ contributing members to
    produce anything; a single contributing member has nothing to
    intersect against, same as the original.

    Order/cap: the first contributing member's original string order is
    used as the iteration basis (a deterministic stand-in for .NET's
    HashSet enumeration order, which the original relied on for
    Select-Object -First 12 without a documented ordering guarantee),
    capped at 12 entries.
    """
    per_member_sets: list[set[str]] = []
    ordered_candidates: list[str] | None = None

    for member in members:
        if not member.Path:
            continue
        raw_strings = static_strings_by_path.get(member.Path)
        if not raw_strings:
            continue
        filtered = [s for s in raw_strings if s and _MIN_STRING_LEN <= len(s) <= _MAX_STRING_LEN]
        if not filtered:
            continue
        if ordered_candidates is None:
            ordered_candidates = filtered
        per_member_sets.append(set(filtered))

    if len(per_member_sets) < 2 or ordered_candidates is None:
        return []

    common = set(per_member_sets[0])
    for s in per_member_sets[1:]:
        common &= s

    return [s for s in ordered_candidates if s in common][:_MAX_COMMON_STRINGS]


def _build_size_condition(members: list[FileRecord]) -> str | None:
    sizes = []
    for member in members:
        if not member.Path:
            continue
        try:
            sizes.append(os.path.getsize(member.Path))
        except OSError:
            continue

    if not sizes:
        return None

    min_size = min(sizes)
    max_size = max(sizes)
    # PowerShell's `if ($minSize -and $maxSize)` treats 0 as falsy, same as
    # Python's `if min_size and max_size` - an all-empty-files edge case
    # (min_size == 0) intentionally skips the size condition, matching the
    # original rather than "fixing" it to handle a zero-byte minimum.
    if not (min_size and max_size):
        return None

    return f"filesize >= {max(0, min_size - 4096)} and filesize <= {max_size + 4096}"


def _build_rule_lines(
    *,
    rule_name: str,
    cluster_id: int,
    cluster_size: int,
    threshold: int,
    common_strings: list[str],
    size_condition: str | None,
    timestamp: str,
) -> list[str]:
    lines = [
        "// AUTO-GENERATED DRAFT - review before use. BinSifter Python rewrite.",
        f"// Built from SSDEEP cluster {cluster_id} ({cluster_size} files, threshold {threshold}).",
        f"// Common-string basis: {len(common_strings)} string(s) shared across FLOSS-analyzed cluster members.",
        f"rule {rule_name}",
        "{",
        "    meta:",
        '        source = "BinSifter auto-generated - DRAFT, not reviewed"',
        f"        cluster_size = {cluster_size}",
        f'        generated = "{timestamp}"',
    ]

    if common_strings:
        lines.append("    strings:")
        for i, s in enumerate(common_strings):
            escaped = s.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'        $s{i} = "{escaped}"')
        lines.append("    condition:")
        cond = "uint16(0) == 0x5A4D and " + (f"{size_condition} and " if size_condition else "")
        cond += f"({_FIXED_MATCH_COUNT} of them)"
        lines.append(f"        {cond}")
    else:
        # No shared strings found (no cluster member had a usable FLOSS
        # static-strings contribution, or nothing survived the
        # intersection) - fall back to a filesize-range-only skeleton
        # that's explicitly flagged as needing manual work rather than
        # silently omitting the rule.
        lines.append("    condition:")
        fallback_cond = "uint16(0) == 0x5A4D" + (f" and {size_condition}" if size_condition else "")
        lines.append(f"        {fallback_cond} // TODO: no common strings found - add real detection logic before use")

    lines.append("}")
    return lines
