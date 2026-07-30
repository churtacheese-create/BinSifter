"""Settings-Save validation - pure Python (no Qt import), split out from the
page widget so it's unit-testable without a display. Ports the validation
block from the PowerShell version's $settings.BtnSave.Add_Click handler
(BinSifter_v1.3.0-alpha.2.ps1, lines ~5092-5178).

One deliberate deviation from the original, not a bug: the PowerShell
version additionally requires yara64.exe/capa.exe/ssdeep.exe to be found
somewhere under ToolsDir before Save succeeds (lines ~5144-5157). This
Python port imports YARA/capa/ssdeep as in-process libraries (see
pyproject.toml's dependencies and config.py's TOOL_FILE_NAMES comment) -
there is no exe for any of the three to find anymore, so that sub-check is
structurally inapplicable here and has been dropped. ToolsDir just needs to
exist as a directory now, same as CapaRules.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path

# (field key, required PathType) - SrcDir/CapaRules/ToolsDir must be
# directories, NsrlPath/YaraRules must be files. GhidraDir is handled
# separately below since blank is valid for it (optional feature) but not
# for any of these five.
_REQUIRED_DIR_FIELDS = ("SrcDir", "CapaRules", "ToolsDir")
_REQUIRED_FILE_FIELDS = ("NsrlPath", "YaraRules")


@dataclass
class SettingsValidationResult:
    ok: bool
    # Resolved (absolute) values ready to write onto BinSifterConfig -
    # only meaningful when ok is True.
    candidate: dict[str, str] = field(default_factory=dict)
    # User-facing message for the status label - set whenever ok is False.
    error_message: str | None = None


def validate_settings(values: dict[str, str], report_directory: str) -> SettingsValidationResult:
    """values must have keys for all of SrcDir/NsrlPath/YaraRules/CapaRules/
    ToolsDir/GhidraDir (GhidraDir may be blank/whitespace - every other key
    must be a non-blank, existing path of the right type)."""
    invalid: list[str] = []
    candidate: dict[str, str] = {}

    for key in _REQUIRED_DIR_FIELDS:
        value = values.get(key, "").strip()
        if not value or not Path(value).is_dir():
            invalid.append(key)
        else:
            candidate[key] = str(Path(value).resolve())

    for key in _REQUIRED_FILE_FIELDS:
        value = values.get(key, "").strip()
        if not value or not Path(value).is_file():
            invalid.append(key)
        else:
            candidate[key] = str(Path(value).resolve())

    ghidra_value = values.get("GhidraDir", "").strip()
    if not ghidra_value:
        candidate["GhidraDir"] = ""
    elif Path(ghidra_value).is_dir():
        candidate["GhidraDir"] = str(Path(ghidra_value).resolve())
    else:
        invalid.append("GhidraDir")

    if invalid:
        return SettingsValidationResult(ok=False, error_message=f"Invalid or missing: {', '.join(invalid)}")

    # Existence isn't the same as write access - catching a read-only report
    # folder here beats finding out only after a multi-hour scan finishes.
    # Only the WRITE is checked for real; cleanup deliberately swallows its
    # own error and never fails Save - matches the PowerShell version's
    # `Remove-Item ... -ErrorAction SilentlyContinue` sitting outside the
    # try/catch that guards WriteAllText (lines ~5169-5178). A filesystem
    # that permits creating a file but not deleting it (seen for real on
    # this port's sandboxed cross-boundary mount) is still "writable" by
    # this definition, same as the original.
    probe_path = Path(report_directory) / f".bsifter-write-test-{uuid.uuid4().hex}.tmp"
    try:
        probe_path.write_text("test", encoding="utf-8")
    except OSError as exc:
        return SettingsValidationResult(ok=False, error_message=f"Report directory is not writable: {exc}")
    try:
        probe_path.unlink(missing_ok=True)
    except OSError:
        pass

    return SettingsValidationResult(ok=True, candidate=candidate)
