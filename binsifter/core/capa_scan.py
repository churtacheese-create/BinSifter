"""CAPA capability detection - TODO, not yet ported.

flare-capa (pip install flare-capa) is a real dependency already declared
in pyproject.toml, but its Python API has changed across major versions
(the rules-loading and result-object shapes are not stable enough for me
to port from memory with confidence) - guessing here risks silently wrong
capability detections, which is exactly the kind of "accuracy" failure
that matters most for this tool. Wire this up by reading capa's own
`capa.main`/`capa.capabilities` usage examples from the installed
version's source (`python -c "import capa; print(capa.__file__)"`) before
writing scan_file() below, and verify against a known test sample before
trusting it.

Original PowerShell behavior this needs to reproduce (BinSifter_v1.3.0-
alpha.2.ps1, CAPA integration): only run capa on files flagged
PossibleFalseNegative-eligible or otherwise CapaEligible; on shellcode
input, try -f sc32 then -f sc64 explicitly (auto-detection can't work
without real headers) and record which format succeeded in
CapaShellcodeFormat.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CapaResult:
    detection_count: int
    output: str
    shellcode_format: str | None  # "sc32"/"sc64"/None


def scan_file(target_path: str, capa_rules_dir: str, is_shellcode: bool = False) -> CapaResult:
    raise NotImplementedError(
        "capa library integration not yet ported - see module docstring. "
        "Falls back to the PowerShell version's capa.exe path in the meantime "
        "if you need this working today."
    )
