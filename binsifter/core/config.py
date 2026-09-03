"""Settings/config model for BinSifter's scan engine.

Ports $BinSifterRoot / $ToolFileNames / Find-ToolPath /
Set-ToolPathsFromDirectory and the default Reports/Attack/Blocklist
location logic from the PowerShell version (BinSifter-Rowan.ps1,
roughly lines 1694-1830).

Field names below are kept in PascalCase, matching the PowerShell $Config
hashtable's keys exactly - see models.py's note on FileRecord for why (a
close, low-risk 1:1 port takes priority over PEP8 naming for now).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
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
    BinSifter-Rowan.ps1's $BinSifterRoot block for that whole
    saga).

    When frozen by PyInstaller (installer/winnow.spec), `sys.frozen` is set
    and `__file__`-based resolution no longer means anything real - the
    "package" isn't sitting on disk as loose .py files at all anymore.
    Deliberately reads `sys.executable`'s OWN directory in
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


def get_binsifter_data_root() -> Path:
    """Where BinSifter actually writes its own runtime data (Reports/,
    Attack/, Blocklist/, the settings cache, the NSRL mmap cache) - almost
    always the same directory as get_binsifter_root(), but falls back to a
    per-user, always-writable location if that directory turns out not to
    be writable.

    An installer test crashed Winnow at startup with an unhandled
    PermissionError ([WinError 5] Access is denied) trying to mkdir
    'C:\\Program Files\\BinSifter Winnow\\Reports'.
    Winnow.iss deliberately offers a per-user (default) OR an all-users/
    admin install choice (PrivilegesRequiredOverridesAllowed=dialog) - the
    per-user path lands under %LOCALAPPDATA%\\Programs, which is always
    writable by that user, but the all-users path lands under Program
    Files, which a normal (non-elevated) launch can never write to.
    build_default_config() and save_settings_cache() used to assume
    get_binsifter_root() was always writable; that assumption only held
    for the per-user install.

    Rather than special-casing "am I under Program Files," this actually
    probes for write access (permission bits don't reliably predict real
    NTFS/UAC write access) and falls back to
    %LOCALAPPDATA%\\BinSifter Winnow\\ - the standard per-user data
    location, always writable, no elevation needed - if the probe fails.
    Leaves the common case (per-user install, or running from source)
    completely unchanged.
    """
    root = get_binsifter_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".bsifter-write-probe"
        probe.touch()
        probe.unlink()
        return root
    except OSError as exc:
        fallback = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "BinSifter Winnow"
        fallback.mkdir(parents=True, exist_ok=True)
        logger.warning(
            "%s is not writable (%s) - likely an all-users/Program Files install - "
            "using %s for Reports/settings/cache data instead.",
            root, exc, fallback,
        )
        return fallback


def get_bundled_asset_path(filename: str) -> Path:
    """Resolves a read-only bundled asset (the two logo PNGs, the window-
    icon PNG) - deliberately separate from get_binsifter_root(), which
    means "where BinSifter's PERSISTENT, writable data belongs" and must
    stay stable across launches (see that function's docstring on why it
    avoids sys._MEIPASS for exactly that reason).

    The first real-Windows test round where Winnow's window actually
    rendered surfaced every logo (sidebar, About page) coming up blank on
    BOTH a host machine and a FLARE VM, with no error anywhere - likely
    broken since Winnow's very first installer build, just never observed
    until now.

    Root cause: installer/winnow.spec's own_datas (the two logo PNGs)
    are bundled with a "." destination, which used to land directly next
    to the built exe under older PyInstaller onedir layouts - but neither
    build_winnow.ps1 nor the release workflow pins a PyInstaller version
    (`pip install pyinstaller`, no constraint, in both places), so every
    real build already gets whatever's newest on PyPI. PyInstaller 6.0
    changed the onedir default layout to nest bundled datas one level
    deeper, under an auto-generated _internal/ subdirectory, instead of
    flat next to the exe - get_binsifter_root() / filename silently
    stopped finding them, and the calling code's `if logo_path.is_file():`
    guard (see main_window.py/about.py) was written to skip gracefully
    rather than error, so this failed completely silently.

    sys._MEIPASS is PyInstaller's own documented, version-independent
    pointer to wherever datas actually landed, regardless of onedir vs.
    onefile or which layout a given PyInstaller version uses - exactly
    the right tool for a read-only bundled asset with no persistence
    requirement (unlike Reports/the settings cache). Tries the exe's own
    directory too, in case a future PyInstaller version reverts the
    layout again - checking both costs nothing and doesn't hard-code
    either assumption.
    """
    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / filename)
    candidates.append(get_binsifter_root() / filename)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[-1]  # not found anywhere - same fallback callers already .is_file()-guard against


# Maps each tool's Config field to the filename(s) BinSifter looks for
# under ToolsDir - single source of truth, same role as $ToolFileNames in
# the PowerShell (Rowan) version, but rebuilt for Winnow's Linux-only quick-
# launch set (2026-08-26 - see results.py's module docstring for the full
# rationale). Each entry is a tuple of candidate filenames tried in order,
# not one fixed name, because none of these five projects ship one single
# canonical Linux binary name across every distro/packaging format the way
# a Windows .exe usually does - PE-bear's AppImage/build output, Anya's own
# binary name, and DIE's console vs. GUI builds all vary. First candidate
# that's actually found under ToolsDir wins; if your install uses a
# different filename than what's listed here, rename/symlink it to match
# (or widen the tuple) rather than fighting the lookup.
#
# NOTE: YaraExe/CapaExe/SsdeepExe/FlossExe/SpeakeasyExe are deliberately NOT
# here - those five are imported as in-process Python libraries (see
# pyproject.toml), not discovered as external executables. Only tools with
# no Python-library equivalent still need to be found on disk.
TOOL_FILE_NAMES: dict[str, tuple[str, ...]] = {
    "PeBearExe": ("PE-bear", "pe-bear", "PEBear"),
    "AnyaExe": ("anya", "Anya"),
    "DieExe": ("diec", "die"),
    # Rizin replaced with Cutter 2026-09-03 (see tool_bootstrap.py) - Rizin
    # is a terminal-native REPL with no window of its own, so launching it
    # via a bare subprocess.Popen from a GUI app (no attached terminal)
    # produced no visible effect at all; a real user's install log showed
    # exactly this ("PE-Bear nor Rizin would work when selected"). Cutter is
    # rizin's own official Qt GUI front-end - same analysis engine, but an
    # actual window a Popen launch can show.
    "CutterExe": ("Cutter", "cutter"),
    "AngrExe": ("angr",),
    # GDB itself is deliberately never auto-installed (needs apt/dnf/pacman,
    # not root-free-installable) - PATH-only discovery, same as Rizin used
    # to be before it got its own installer. GEF is layered on top of
    # whatever gdb find_tool_path() finds and IS root-free-installable (a
    # single curl'd Python script sourced from ~/.gdbinit), so it gets its
    # own separate bootstrap entry in tool_bootstrap.py even though there's
    # no separate "GefExe" to launch - GEF isn't a program, it's a gdb
    # extension.
    "GdbExe": ("gdb",),
    "BinwalkExe": ("binwalk",),
    "MalwoverviewExe": ("malwoverview", "malwoverview.py"),
}


def find_tool_path(directory: str | Path | None, filenames: str | tuple[str, ...]) -> str:
    """Recursively search `directory` for the first of `filenames` (a single
    name or an ordered tuple of candidates) that turns up anywhere in the
    tree; within one candidate, first match sorted by full path wins - same
    tiebreak rule as the PowerShell Find-ToolPath.

    Falls back to the OS's own PATH (via shutil.which()) for any candidate
    not found under `directory` - added 2026-09-02 so a tool that's already
    runnable from a terminal (installed via apt/pacman, `pipx install`, a
    plain symlink into ~/.local/bin, an AppImage the user already put on
    PATH, etc.) is found automatically without also being staged into
    "Path to tools". This matters most for tools that don't want to live as
    a lone binary in one curated folder at all - angr is a PyPI package
    that explicitly recommends installing into its own dedicated
    virtualenv (see angr's own INSTALL docs; several of its dependencies
    ship forked native libraries that can collide with system copies), and
    `pipx install` already solves exactly that: one isolated venv per tool,
    exposed as a single ordinary command on PATH. PE-bear/DIE/Cutter
    AppImages and GDB's native distro package also normally end up on PATH
    rather than copied into a scratch directory, so this removes the
    "central location" requirement for all of them, not just angr.

    Directory is still checked first for each candidate (an explicit copy
    staged under `directory` wins over an incidental system install) before
    falling back to PATH for that same candidate; only once every candidate
    has been tried both ways does this return "". `directory` may be falsy
    or missing entirely - that just skips straight to the PATH check for
    every candidate, mirroring the old blank-tolerant/graceful-skip
    behavior for the directory half while still gaining the PATH half.
    """
    candidates = (filenames,) if isinstance(filenames, str) else filenames
    root = Path(directory) if directory else None
    has_root = root is not None and root.is_dir()

    for filename in candidates:
        if has_root:
            # REAL BUG FIXED 2026-09-03: rglob(filename) matches directories
            # as well as files, with no filtering - confirmed from a real
            # user's install log where AutoInstalledTools/anya/ (the
            # extraction directory _install_appimage_tool creates) and
            # AutoInstalledTools/anya/anya (the actual binary inside it)
            # both matched, and the directory's path string being a strict
            # prefix of the file's path string meant the directory sorted
            # first and won the old sorted(...)[0] tiebreak. That directory
            # path then failed every later Path(x).is_file() check, greying
            # out the tool in the right-click menu even though the real
            # binary was one level down. Filtering to is_file() here means
            # only a real, launchable file can ever be returned.
            matches = sorted(
                (p for p in root.rglob(filename) if p.is_file()),
                key=lambda p: str(p),
            )
            if matches:
                if len(matches) > 1:
                    logger.info(
                        "Found %d copies of %s under %s - using %s",
                        len(matches), filename, root, matches[0],
                    )
                return str(matches[0])
        found_on_path = shutil.which(filename)
        if found_on_path:
            logger.info(
                "Found %s on PATH at %s (not staged under %s)",
                filename, found_on_path, root if root else "<no ToolsDir set>",
            )
            return found_on_path
    return ""


def get_auto_installed_tools_dir() -> Path:
    """Fixed, per-user directory where core/tool_bootstrap.py's first-run
    auto-installer places anything it downloads for the quick-launch tools
    (PE-bear/DIE/Anya/Cutter AppImages, Angr/Binwalk/Malwoverview's private
    venvs, Ghidra's release zip + portable JDK) - separate from the user's
    own "Path to tools" directory so
    auto-installed copies never mix with or overwrite anything the user
    placed there themselves. Added 2026-09-03 alongside tool_bootstrap.py;
    see that module's docstring for why auto-installing at all is safe to
    do without root (everything here is a per-user download, never a
    system package).
    """
    return get_binsifter_data_root() / "AutoInstalledTools"


def set_tool_paths_from_directory(config: "BinSifterConfig", directory: str | Path | None) -> None:
    """Re-resolves every entry in TOOL_FILE_NAMES against `directory` and
    writes the results onto `config` in place - same role as the
    PowerShell Set-ToolPathsFromDirectory, called on Settings Save and once
    at startup for a cached ToolsDir.

    Falls back to get_auto_installed_tools_dir() for any tool `directory`
    (and, via find_tool_path()'s own PATH check, the system PATH too)
    couldn't find - added 2026-09-03 so a tool the first-run auto-installer
    downloaded is picked back up on every later startup with no separate
    persistence logic needed, the same way a manually-curated ToolsDir
    already is. Priority order per tool: explicit ToolsDir > PATH (checked
    inside the first find_tool_path() call) > BinSifter's own
    auto-installed copy - an explicit user choice always wins, a real
    system install is preferred over BinSifter re-downloading its own copy,
    and the auto-installed copy is only ever the last resort.
    """
    auto_dir = get_auto_installed_tools_dir()
    for field_name, filenames in TOOL_FILE_NAMES.items():
        found = find_tool_path(directory, filenames)
        if not found:
            found = find_tool_path(auto_dir, filenames)
        setattr(config, field_name, found)


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
    # Catalog-based (.cat) Authenticode verification - see
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
    PeBearExe: str = ""
    AnyaExe: str = ""
    DieExe: str = ""
    CutterExe: str = ""
    AngrExe: str = ""
    GdbExe: str = ""
    BinwalkExe: str = ""
    MalwoverviewExe: str = ""

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
    root = get_binsifter_data_root()
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
    root = get_binsifter_data_root()
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
    # REAL BUG FIXED 2026-09-03: this used to stop right after loading the
    # cached ToolsDir/GhidraDir *strings* - it never actually re-resolved
    # PeBearExe/AnyaExe/DieExe/RizinExe/AngrExe/GhidraHeadlessExe from them,
    # even though set_tool_paths_from_directory()'s own docstring has
    # always claimed this happens "once at startup for a cached ToolsDir".
    # In practice every single quick-launch menu item showed "(not
    # configured)" on every fresh launch, no matter how the tools were
    # installed, until the user opened Settings and clicked Save once with
    # nothing changed - the only place this resolution call actually
    # existed was settings.py's own Save handler. Fixed by doing the exact
    # same two calls here that Save already does, so a remembered ToolsDir/
    # GhidraDir is honored immediately on launch, not just after a manual
    # round-trip through Settings.
    set_tool_paths_from_directory(config, config.ToolsDir)
    config.GhidraHeadlessExe = find_tool_path(config.GhidraDir, "analyzeHeadless")
    if not config.GhidraHeadlessExe:
        # Ghidra auto-install added 2026-09-03 (see tool_bootstrap.py) - same
        # AutoInstalledTools fallback every other quick-launch tool already
        # gets via set_tool_paths_from_directory(), applied here by hand
        # since Ghidra's own resolution (GhidraDir -> analyzeHeadless) sits
        # outside that helper.
        config.GhidraHeadlessExe = find_tool_path(
            get_auto_installed_tools_dir() / "ghidra", "analyzeHeadless"
        )
    return config
