"""FLOSS string-extraction fallback - TODO, not yet ported.

Same reasoning as capa_scan.py: flare-floss is a real dependency in
pyproject.toml, but its Python library API (vs. its CLI) isn't something
I can port correctly from memory - verify against the installed version's
own examples before implementing scan_file() below.

Original behavior to reproduce: only runs on YARA-flagged files that fail
capa's PE/ELF eligibility check (PossibleFalseNegative), recovering
strings/IOCs when capa can't run at all. IOC extraction (iocs.py, also not
yet written) mines the output this produces.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FlossResult:
    string_count: int
    strings: list[str]


def scan_file(target_path: str) -> FlossResult:
    raise NotImplementedError(
        "FLOSS library integration not yet ported - see module docstring."
    )
