"""Capa rules directory listing - pure Python (no Qt import), split out from
the page widget so it's unit-testable without a display. Port of
Update-CapaRulesList's file-enumeration half (BinSifter-Rowan_v1.3.0-beta.1.ps1,
lines ~5485-5496).

One minor, deliberate UX-only deviation: results are returned sorted by
path. Get-ChildItem's enumeration order isn't guaranteed sorted (it's
whatever order the filesystem hands back), so this is a small improvement
over the original rather than a faithfulness break - nothing in BinSifter
depends on this list's order for anything besides display.
"""

from __future__ import annotations

from pathlib import Path

_RULE_FILE_SUFFIXES = (".yml", ".yaml", ".json")


def list_capa_rule_files(directory: str) -> list[str]:
    """Every *.yml/*.yaml/*.json file recursively under `directory`, sorted.
    Empty list if directory is blank, doesn't exist, or isn't a directory -
    caller distinguishes "not configured" from "configured but empty" the
    same way Update-CapaRulesList does (by checking the directory itself
    first), not by inspecting this return value alone."""
    if not directory:
        return []
    root = Path(directory)
    if not root.is_dir():
        return []

    matches = [
        str(p) for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in _RULE_FILE_SUFFIXES
    ]
    return sorted(matches)
