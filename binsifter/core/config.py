"""Settings/config model for BinSifter's scan engine.

Ports $BinSifterRoot / $ToolFileNames / Find-ToolPath /
Set-ToolPathsFromDirectory and the default Reports/Attack/Blocklist
location logic from the PowerShell version (BinSifter-Rowan_v1.3.0-beta.1.ps1,
roughly lines 1694-1830).

Field names below are kept in PascalCase, matching the PowerShell $Config
hashtable's keys exactly - see models.py's note on FileRecord for why (a
close, low-risk 1:1 port takes priority over PEP8 naming for now).
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


def get_binsifter_root() -> Path:
    """The folder BinSifter's own code (or, when frozen, its own installed
    exe) lives in - anchor for every default location (Reports/, Attack/,
    Blocklist/, the settings cache file, and the horizontal logo PNGs
    loaded by main_window.py/about.py).

    This is one of the concrete, unglamorous wins of the Python rewrite:
    __file__ is reliably populated for a properly installed/packaged
    console-script entry point, unlike PowerShell's $PSScriptRoot /
    $MyInvocation.MyCommand.Path, which came back empty under VS Code's
    "Run and Debug" on the FRED and needed a defensive fallback chain (see
    BinSifter-Rowan_v1.3.0-beta.1.ps1's $BinSifterRoot block for that whole
    saga).

    2026-08-08 addition: when frozen by PyInstaller (installer/winnow.spec),
    `sys.frozen` is set and `__file__`-based resolution no longer means
    anything real - the "package" isn't sitting on disk as loose .py files
    at all anymore. Deliberately reads `sys.executable`'s OWN directory in
    that case (stable across launches), NOT `sys._MEIPASS` (which, for a
    --onefile build, is a fresh temp-extraction folder every single launch -
    would silently break the Reports/settings-cache persistence this
    function exists to anchor, rebuilding the NSRL cache and losing cached
    Settings on every run). This is exactly why installer/winnow.spec
    deliberately builds --onedir, not --onefile: sys.executable's directory
    IS where every bundled file actually, persistently lives in that mode,
    the same "next to the installed exe" convention Rowan's own
    $BinSifterRoot uses.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    # binsifter/core/config.py -> up to the installed package root
    return Path(__file__).resolve().parent.parent.parent


# Maps each tool's Config field to the fixed filename BinSifter looks for
# under ToolsDir - single source of truth, same role as $ToolFileNames in
# the PowerShell version. NOTE: YaraExe/CapaExe/SsdeepExe/FlossExe/
# SpeakeasyExe are deliberately NOT here anymore - those five are imported
# as in-process Python libraries now (see pyproject.toml), not discovered
# as external executables. Only tools with no Python-library equivalent
# still need to be found on disk.
TOOL_FILE_NAMES: dict[str, str] = {
    "DieExe": "die.exe",
    "DieConsoleExe": "diec.exe",
    "PEStudioExe": "pestudio.exe",
    "CffExplorerExe": "CFF Explorer.exe",
    "ResourceHackerExe": "ResourceHacker.exe",
    "SigcheckExe": "sigcheck.exe",
    "X64dbgExe": "x64dbg.exe",
    "X32dbgExe": "x32dbg.exe",
}


def find_tool_path(directory: str | Path | None, filename: str) -> str:
    """Recursively search `directory` for `filename`; first match (sorted by
    full path) wins - same tiebreak rule as the PowerShell Find-ToolPath.
    Returns "" if not found or directory is falsy/missing, mirroring the
    PowerShell version's blank-tolerant/graceful-skip behavior.
    """
    if not directory:
        return ""
    root = Path(directory)
    if not root.is_dir():
        return ""
    matches = sorted(root.rglob(filename), key=lambda p: str(p))
    if not matches:
        return ""
    if len(matches) > 1:
        logger.info(
            "Found %d copies of %s under %s - using %s",
            len(matches), filename, root, matches[0],
        )
    return str(matches[0])


def set_tool_paths_from_directory(config: "BinSifterConfig", directory: str | Path | None) -> None:
    """Re-resolves every entry in TOOL_FILE_NAMES against `directory` and
    writes the results onto `config` in place - same role as the
    PowerShell Set-ToolPathsFromDirectory, called on Settings Save and once
    at startup for a cached ToolsDir.
    """
    for field_name, filename in TOOL_FILE_NAMES.items():
        setattr(config, field_name, find_tool_path(directory, filename))


@dataclass
class BinSifterConfig:
    """Mirrors the PowerShell $Config hashtable. Settings-page fields first
    (the same 6-field consolidation as the PowerShell version), then
    derived/default fields that Settings no longer asks the user for.
    """

    # Settings-page fields
    SrcDir: str = ""
    NsrlPath: str = ""
    YaraRules: str = ""
    CapaRules: str = ""
    ToolsDir: str = ""
    GhidraDir: str = ""
    # 2026-08-08: catalog-based (.cat) Authenticode verification - see
    # authenticode.py's module docstring for why this exists (a large
    # fraction of Windows' own inbox binaries are validated via a system
    # catalog rather than an embedded signature, and signify doesn't check
    # catalogs unless one is explicitly loaded via add_catalog()). Optional,
    # like GhidraDir - blank means "skip catalog checks, embedded-signature
    # verification only," not an error. A directory (not a single file)
    # since a real CatRoot holds many .cat files, one per driver/component.
    CatalogDirectory: str = ""

    # Derived by searching ToolsDir/GhidraDir - never user-entered directly
    GhidraHeadlessExe: str = ""
    DieExe: str = ""
    DieConsoleExe: str = ""
    PEStudioExe: str = ""
    CffExplorerExe: str = ""
    ResourceHackerExe: str = ""
    SigcheckExe: str = ""
    X64dbgExe: str = ""
    X32dbgExe: str = ""

    # Fixed default locations next to the BinSifter install - not Settings
    # fields at all, same as the PowerShell version.
    ReportDirectory: str = ""
    AttackDataPath: str = ""
    BlocklistPath: str = ""


# Settings-page fields that get round-tripped to the cache file - deliberately
# just the 6 Settings-page fields, not the derived ToolsDir/GhidraDir search
# results (which get re-resolved fresh on every load instead of trusting a
# stale cached path).
_CACHE_FIELDS = ["SrcDir", "NsrlPath", "YaraRules", "CapaRules", "ToolsDir", "GhidraDir", "CatalogDirectory"]


def _settings_cache_path(root: Path) -> Path:
    return root / ".bsifter-settings-cache.json"


def _load_cached_settings(config: BinSifterConfig, root: Path) -> None:
    cache_path = _settings_cache_path(root)
    if not cache_path.is_file():
        return
    try:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        # Same graceful-skip behavior as the PowerShell version: a corrupt
        # or unreadable cache just means starting from blank fields, not a
        # hard failure.
        logger.warning("Could not read settings cache %s: %s", cache_path, exc)
        return
    for key in _CACHE_FIELDS:
        value = cached.get(key)
        if isinstance(value, str):
            setattr(config, key, value)


def save_settings_cache(config: BinSifterConfig) -> None:
    """Writes the Settings-page fields to the cache file - only called after
    a successful Settings Save, not on every config mutation.
    """
    root = get_binsifter_root()
    cache_path = _settings_cache_path(root)
    payload = {key: getattr(config, key) for key in _CACHE_FIELDS}
    cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def build_default_config() -> BinSifterConfig:
    """Constructs a BinSifterConfig with Reports/Attack/Blocklist defaulted
    next to BinSifter's own install, auto-created if missing, then loads
    any cached Settings-page values on top - same convention as the
    PowerShell version's $reportsDefaultDir/$attackDefaultPath/
    $blocklistDefaultPath plus $cachedSettings.
    """
    root = get_binsifter_root()
    reports_dir = root / "Reports"
    attack_path = root / "Attack" / "enterprise-attack.json"
    blocklist_path = root / "Blocklist" / "blocklist.csv"

    for default_dir in (reports_dir, attack_path.parent, blocklist_path.parent):
        default_dir.mkdir(parents=True, exist_ok=True)

    config = BinSifterConfig(
        ReportDirectory=str(reports_dir),
        AttackDataPath=str(attack_path),
        BlocklistPath=str(blocklist_path),
    )
    _load_cached_settings(config, root)
    return config
