"""AI-ready export - formats one file's already-extracted BinSifter findings
into a compact Markdown document and a JSON object, for handing to whatever
AI the analyst wants to use: paste the Markdown into a cloud chat interface
(Claude.ai, ChatGPT, etc.), or feed the JSON to a script hitting a local
model's API.

Added 2026-08-08, right after the AI-assisted-triage prototype
(prototype_ollama_triage.py) was concluded NOT viable on real hardware -
running local inference from inside BinSifter itself caused a full GPU/
display lockup on the test machine (see TODO.md's "AI-assisted triage
exploration" section for the full story). This module is the safer
follow-up: BinSifter NEVER runs or calls out to any AI itself here, cloud
or local - it only FORMATS data that's already been computed. There is
zero inference risk, zero network calls, zero new attack surface, because
this is nothing more than a specialized report writer sitting next to
report.py.

Reuses the same "only include fields that actually carry signal" design as
prototype_ollama_triage.py's _compact_row() - empty/zero/False fields are
dropped rather than padding the output with a wall of "None"/"" noise, and
long fields (raw capa output in particular) are truncated so a single
file's export stays a reasonable size to pack into a chat prompt's context.

Deliberately excludes: Status/Progress/Added (internal scan-state
bookkeeping, not relevant to an AI trying to reason about intent), raw
cluster ID numbers (SsdeepClusterId/ImphashClusterId - meaningless without
cross-referencing other files in the same run, unlike ClusterSize which is
self-contained).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from binsifter.core.models import FileRecord

_TRUNCATE_AT = 4000  # generous vs. prototype_ollama_triage.py's 800 - this
                      # export is meant to be read by a human or pasted into
                      # a large-context chat model, not packed alongside 5+
                      # other files' findings in a single tight API prompt.

_DISCLAIMER = (
    "This document contains only automated findings BinSifter already "
    "extracted for this file - no AI analysis has been run on it. Any "
    "conclusions an AI draws from the data below are a hypothesis for "
    "further investigation, not a detection."
)


def _truncate(value: str) -> str:
    if len(value) <= _TRUNCATE_AT:
        return value
    return value[:_TRUNCATE_AT] + f"\n...(truncated, {len(value)} chars total)"


def _windows_basename(path: str) -> str:
    """FileRecord.Path values are always Windows paths (backslash
    separators) - both variants only ever run on Windows. Deliberately NOT
    using pathlib.Path(...).name here: on a POSIX host (this project's dev
    sandbox, or anyone's CI), pathlib treats backslashes as plain
    characters rather than separators, so Path("C:\\a\\b.exe").name would
    return the WHOLE string instead of "b.exe". Plain string splitting
    gives the same, correct answer on every OS this ever actually runs on.
    """
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _windows_stem(path: str) -> str:
    name = _windows_basename(path)
    return name.rsplit(".", 1)[0] if "." in name else name


def compact_record(record: FileRecord) -> dict:
    """Build a dict of only the fields worth an AI's attention - empty
    string, zero, False, and -1 (BinSifter's "not computed" sentinel used
    by Entropy/FlossStringCount/SsdeepClusterId) are all dropped rather
    than included as noise. Path/MD5/SHA1 are always kept even if somehow
    empty, since they're the file's identity, not a finding about it.
    Disposition is always kept even at its "Untriaged" default - unlike the
    other sentinels, that's a real, meaningful state (nobody has assessed
    this file yet), not a "not computed" placeholder.
    """
    always_keep = {"Path", "MD5", "SHA1", "Disposition"}
    # Per-field "not computed" sentinels that aren't blank/zero/False/-1 and
    # so wouldn't be caught by the generic check below - YaraSeverity's
    # "Unknown" default means the same thing YaraSeverityScore's -1 does
    # (no YARA hit worth assessing), it's just spelled as a word instead of
    # a number.
    field_sentinels = {"YaraSeverity": "Unknown"}
    raw = asdict(record)
    # Added is a datetime, not JSON-serializable as-is and not useful to an
    # AI reasoning about file behavior anyway - drop unconditionally.
    raw.pop("Added", None)
    raw.pop("Progress", None)
    raw.pop("Status", None)
    raw.pop("SsdeepClusterId", None)
    raw.pop("ImphashClusterId", None)

    out: dict = {}
    for key, value in raw.items():
        if key in always_keep:
            pass
        elif value in ("", 0, False, -1, None):
            continue
        elif key in field_sentinels and value == field_sentinels[key]:
            continue
        if isinstance(value, str):
            value = _truncate(value)
        out[key] = value
    return out


def build_json(record: FileRecord) -> dict:
    """JSON-serializable dict for one file, with a `_meta` block explaining
    what this is (and isn't) for anyone/anything consuming it without the
    surrounding context this module's docstring provides.
    """
    return {
        "_meta": {
            "generated_by": "BinSifter",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "note": _DISCLAIMER,
        },
        "findings": compact_record(record),
    }


def build_markdown(record: FileRecord) -> str:
    """One self-contained Markdown document for a single file - readable on
    its own, and meant to be pasted directly into a cloud AI chat interface
    without any additional explanation needed from the analyst.
    """
    data = compact_record(record)
    name = _windows_basename(record.Path) or record.Path
    lines: list[str] = [f"# BinSifter finding: {name}", ""]

    lines.append(f"**Path:** `{data.get('Path', record.Path)}`")
    hash_bits = [f"{label} `{data[key]}`" for label, key in
                 (("MD5", "MD5"), ("SHA1", "SHA1"), ("ssdeep", "SSDEEP")) if data.get(key)]
    if hash_bits:
        lines.append(f"**Hashes:** {' · '.join(hash_bits)}")
    lines.append("")

    def section(title: str, rows: list[tuple[str, object]]) -> None:
        present = [(label, value) for label, value in rows if value is not None]
        if not present:
            return
        lines.append(f"## {title}")
        for label, value in present:
            lines.append(f"- {label}: {value}")
        lines.append("")

    section("Signature", [
        ("Status", data.get("SignatureStatus")),
        ("Signer", data.get("SignerName")),
    ])
    # YaraSeverity ("Unknown" default) and YaraSeverityScore (-1 default,
    # dropped by compact_record as a "not computed" sentinel) can each
    # survive compaction independently of the other, so build this line from
    # whichever half is actually present instead of assuming both travel
    # together.
    severity_value = None
    if "YaraSeverity" in data:
        score_part = f" (score {data['YaraSeverityScore']})" if "YaraSeverityScore" in data else ""
        severity_value = f"{data['YaraSeverity']}{score_part}"

    section("YARA", [
        ("Hits", data.get("YaraHitCount")),
        ("Severity", severity_value),
        ("Rules matched", data.get("YaraMatches")),
        ("ATT&CK techniques", data.get("YaraAttackTechniques")),
    ])
    section("capa", [
        ("Eligible", data.get("CapaEligible")),
        ("Detections", data.get("CapaDetectionCount")),
        ("Possible false negative", data.get("PossibleFalseNegative")),
        ("Shellcode format", data.get("CapaShellcodeFormat")),
    ])
    if data.get("CAPAOutput"):
        lines.append("### Raw capa output")
        lines.append("```")
        lines.append(data["CAPAOutput"])
        lines.append("```")
        lines.append("")
    section("ssdeep / imphash clustering", [
        ("ssdeep cluster size", data.get("SsdeepClusterSize")),
        ("ssdeep high similarity to another file", data.get("SsdeepHasHighSimilarity")),
        ("ssdeep previously seen (prior run)", data.get("SsdeepPreviouslySeen")),
        ("ssdeep matches", data.get("SsdeepMatches")),
        ("Imphash", data.get("Imphash")),
        ("Imphash cluster size", data.get("ImphashClusterSize")),
        ("Rich header hash", data.get("RichHash")),
    ])
    ioc_count = data.get("IocCount")
    if data.get("ExtractedIOCs"):
        lines.append(f"## Extracted IOCs{f' ({ioc_count})' if ioc_count else ''}")
        for ioc in str(data["ExtractedIOCs"]).split("; "):
            lines.append(f"- {ioc}")
        lines.append("")
    section("Other", [
        ("Entropy", data.get("Entropy")),
        ("FLOSS string count", data.get("FlossStringCount")),
        ("Packer detected", data.get("PackerDetected")),
        ("Compiler", data.get("Compiler")),
        ("Reputation status", data.get("ReputationStatus")),
        ("Reputation source", data.get("ReputationSource")),
        ("Disposition", data.get("Disposition")),
        ("Source archive", data.get("SourceArchive")),
        ("Scan error", data.get("Error")),
    ])

    lines.append("---")
    lines.append(f"_Generated by BinSifter on {datetime.now(timezone.utc).strftime('%Y-%m-%d')}. {_DISCLAIMER}_")
    return "\n".join(lines)


def export_file(record: FileRecord, output_dir: Path) -> tuple[Path, Path]:
    """Write both the Markdown and JSON export for one file into
    output_dir, named by SHA1 (falling back to the file's own stem if no
    SHA1 is available - e.g. a file that errored before hashing) - same
    naming convention _launch_ghidra() already uses for project folders,
    so exports and Ghidra projects for the same file are easy to
    cross-reference by name. Returns (markdown_path, json_path).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"BinSifter_{record.SHA1}" if record.SHA1 else f"BinSifter_{_windows_stem(record.Path)}"

    md_path = output_dir / f"{stem}.md"
    md_path.write_text(build_markdown(record), encoding="utf-8")

    json_path = output_dir / f"{stem}.json"
    json_path.write_text(json.dumps(build_json(record), indent=2), encoding="utf-8")

    return md_path, json_path
