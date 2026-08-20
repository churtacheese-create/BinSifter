"""Speakeasy isolated code emulation - real library integration.

Direct port of the PowerShell version's "Run isolated Speakeasy emulation"
Results-grid quick-launch action (BinSifter-Rowan.ps1, lines
~4407-4473): confirmation-gated (execution-adjacent), a longer timeout than
other captured tools (emulation of a nontrivial sample routinely runs past
30s), and a best-effort summary (API call count, file operations, network
indicators) layered on top of the full raw report.

Deliberately NOT wired into engine.py's automatic scan_directory() loop -
same treatment as the Ghidra/Sigcheck/x64dbg/x32dbg deep-analysis actions
(see the "BinSifter v1.3.0-alpha.2" project note): Speakeasy is a
single-file, analyst-initiated, on-demand action in the original, not a
bulk-scan step, precisely because it's execution-adjacent and can run for
up to 120 seconds per file - running it automatically over every file in a
batch would be a real behavior change, not a straightforward "finish the
port" step, and was never how the original worked. This module is the
building block a future Results-grid action calls for one analyst-selected
file at a time.

Verified against the installed speakeasy 1.5.11's own cli.py - the
PowerShell version's assumed JSON shape (top-level .apis/.network/
.file_access) does not match the real library output:
  - speakeasy.Speakeasy(config=...).load_module(path) + .run_module(module,
    all_entrypoints=True) is the real in-process API (cli.py's own
    emulate_binary() helper), not a "-t <file> -o json" CLI invocation -
    there's no subprocess/JSON-parsing round-trip needed at all now.
  - se.get_report() returns a dict (get_json_report() is just
    json.dumps(get_report())) whose real per-entry-point data lives under
    report["entry_points"][i], not at the report's top level. Each entry
    point only gains an "apis" list unconditionally; "network_events"/
    "file_access"/"registry_access"/"process_events"/"dropped_files" are
    only present when speakeasy's own profiler.get_report() actually found
    something for that key - so summarization below treats every one of
    those keys as optional, not default-empty.
  - Network data is further split into report["entry_points"][i]
    ["network_events"]["dns"] (list of {"query", "response"} dicts) and
    ["network_events"]["traffic"] (list of {"server", "proto", "port", ...}
    dicts from profiler.py's log_http/log_network) - not a flat list of
    strings the way the PowerShell version's ".network" field implied.
  - A per-entry-point "error" key (e.g. an unsupported-API-stub hit
    mid-emulation) is a NORMAL, expected part of a real report - Speakeasy
    does not raise a Python exception for this, it just records what it
    could and stops that entry point's run early (seen in practice: calc.exe
    hitting an api-ms-win-core-* forwarder stub). Only a genuine
    Python-level exception (bad PE pefile can't parse at all, etc.) should
    surface as SpeakeasyResult.error here.
  - The emulation timeout is a REAL, engine-enforced cutoff, not merely
    advisory: config["timeout"] (seconds) is converted to microseconds and
    passed straight into Unicorn's own emu_start(..., timeout=...)
    (speakeasy/engines/unicorn_eng.py's start() method) - Unicorn's C core
    enforces it directly, so running this in-process (like capa/FLOSS
    already do, no subprocess needed) is safe from a "will this hang
    forever" perspective. The one residual risk versus the original's
    subprocess-isolated design is a genuine Unicorn/native-code crash
    taking down the whole BinSifter process instead of just a disposable
    child process - a deliberate tradeoff (same one capa/FLOSS already
    made).

Known, deliberate scope limit: only PE/module emulation (se.load_module +
run_module) is implemented, matching exactly what the PowerShell quick-
launch action did - it never had a raw-shellcode/-r mode either. Shellcode
emulation (se.load_shellcode + run_shellcode, architecture-forced via
-a x86/amd64) is a real speakeasy capability but was not exercised here
since there's no real shellcode sample on hand to verify it against - flag
before adding it rather than shipping an unverified code path.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Importing speakeasy used to crash the entire app at STARTUP - before the
# main window ever appeared - with an ImportError chain ending in
# unicorn's own "ERROR: fail to load the dynamic library." speakeasy's own
# __init__.py eagerly imports its full Windows-emulation stack down to
# `unicorn` (speakeasy -> speakeasy.windows.win32 -> ... -> speakeasy.binemu
# -> speakeasy.engines.unicorn_eng -> unicorn), which loads unicorn's native
# DLL via ctypes at IMPORT TIME, not lazily. Since results.py imports this
# module at ITS OWN top level (to build the Speakeasy quick-launch menu
# item), any failure to load that native DLL took down the entire
# application, even for a user who never intends to use Speakeasy at all.
# speakeasy-emulator pins an old unicorn release (1.0.2, see pyproject.toml)
# whose prebuilt Windows wheel is known to need the Microsoft Visual C++
# Redistributable (x64) - the likely root cause on affected machines.
#
# Fixed with the same graceful-degradation philosophy emulate_file() below
# already uses for a target file speakeasy can't handle: the import itself
# is now wrapped, the failure is stored instead of raised, and
# emulate_file() returns a normal, actionable SpeakeasyResult.error instead
# of letting this exception propagate up through results.py's import and
# crash app startup. Every other BinSifter feature (YARA, capa, ssdeep,
# hashing, Authenticode, the whole rest of the Results grid) has zero
# dependency on unicorn/speakeasy and is unaffected either way.
try:
    import speakeasy
    _IMPORT_ERROR: Exception | None = None
except Exception as exc:  # noqa: BLE001 - deliberately broad: any import-time failure (missing native DLL, incompatible runtime, etc.) must not take the whole app down with it
    speakeasy = None  # type: ignore[assignment]
    _IMPORT_ERROR = exc
    logger.warning("Speakeasy emulation is unavailable - failed to import: %s", exc)


def _patch_speakeasy_root_path_normalization() -> None:
    """Works around a genuine bug in the installed speakeasy 1.5.11 package
    itself, not BinSifter's own code. The default config's
    module_directory_x86/x64 values are literal strings like
    "$ROOT$/winenv/decoys/x86" (forward slash, hardcoded in
    speakeasy/configs/default.json). speakeasy.common.normalize_package_path()
    resolves "$ROOT$" with a plain str.replace(root_var, root) with no path
    normalization afterward, so on Windows, where the package root is a
    backslash path, the result is a mixed-separator string like
    "...\\_internal\\speakeasy/winenv/decoys/x86". winemu.py's
    get_native_module_path() then os.path.join()s a filename onto that
    (Windows tolerates forward slashes for os.listdir/os.path.join, so this
    part silently succeeds), but pefile.PE()'s open()/mmap() call on the
    resulting malformed path raises "[Errno 22] Invalid argument". This is
    why it worked on one machine and failed on another with the exact same
    code and file - a path-string correctness bug that Windows' filesystem
    APIs happen to tolerate most of the time, not a machine-specific
    difference in the decoy file itself.

    Same monkeypatch-the-installed-library pattern already used twice in
    authenticode.py for real signify bugs - not a vendored fork. Wrapping
    the result in os.path.normpath() collapses the mixed separators (and
    resolves any stray ".."/"." segments) into a single, unambiguous
    OS-native path, with zero behavior change on Linux/macOS where "/" was
    already the only separator in play.
    """
    if speakeasy is None:
        return
    try:
        from speakeasy import common as _speakeasy_common
    except Exception:  # noqa: BLE001 - if this submodule ever moves/renames, degrade to the unpatched (occasionally-broken) behavior rather than crashing import
        return

    original = _speakeasy_common.normalize_package_path
    if getattr(original, "_bs_patched", False):
        return

    def _normalize_package_path(path):
        return os.path.normpath(original(path))

    _normalize_package_path._bs_patched = True
    _speakeasy_common.normalize_package_path = _normalize_package_path
    # winemu.py does `from .. import common` (or similar) and calls
    # common.normalize_package_path(...) through that module reference, so
    # patching the attribute on the common module itself (above) is enough
    # to reach every call site - no need to also patch winenv/winemu.py's
    # own namespace.


_patch_speakeasy_root_path_normalization()

_DEFAULT_CONFIG_PATH = (
    os.path.join(os.path.dirname(speakeasy.__file__), "configs", "default.json")
    if speakeasy is not None else ""
)

_UNAVAILABLE_MESSAGE = (
    "Speakeasy's emulation engine (Unicorn) failed to load on this machine: {error}. "
    "This usually means the Microsoft Visual C++ Redistributable (x64) isn't installed - "
    "install the latest version from Microsoft's website and restart BinSifter. Every other "
    "BinSifter feature is unaffected by this."
)

# Longer than the 30s default the PowerShell version used for Sigcheck/other
# quick captured tools - emulation of a nontrivial sample routinely runs
# well past that (same comment as the original's Speakeasy quick-launch
# handler). This becomes speakeasy's own config["timeout"], a real
# Unicorn-enforced cutoff (see module docstring), not a subprocess
# wall-clock timeout - there's no subprocess anymore.
_EMULATION_TIMEOUT_SECONDS = 120


@dataclass
class SpeakeasyResult:
    api_call_count: int
    file_operation_count: int
    # Deduplicated, insertion-ordered "domain -> ip" (DNS) and
    # "server:port (proto)" (traffic) strings - a readable stand-in for the
    # PowerShell version's guessed flat ".network" list, built from the
    # real (differently-shaped) network_events data instead.
    network_indicators: list[str] = field(default_factory=list)
    # Full, unmodified speakeasy report - always populated on success (even
    # when every summary count above is 0), so a future GUI report viewer
    # can show the raw dump the same way Show-ToolReportWindow did.
    raw_report: dict = field(default_factory=dict)
    # None on success. Only set for a genuine Python-level failure (target
    # not a parseable PE, speakeasy itself raising) - NOT set just because
    # one or more entry points hit an internal emulation error/unsupported
    # API mid-run, which is normal and already reflected in raw_report.
    error: str | None = None


def _load_config() -> dict:
    with open(_DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["timeout"] = _EMULATION_TIMEOUT_SECONDS
    # Same scaling speakeasy's own CLI applies when a custom timeout is
    # requested (cli.py: `self.cfg.update({'max_api_count': self.timeout *
    # 500})`) - without raising this too, the default profile's
    # max_api_count (10000, sized for the default 60s) could cut emulation
    # short well before the new 120s timeout is reached.
    cfg["max_api_count"] = _EMULATION_TIMEOUT_SECONDS * 500
    return cfg


def emulate_file(target_path: str) -> SpeakeasyResult:
    """Emulates target_path as a PE module and summarizes the result.
    Never raises - a target speakeasy can't load/parse at all (or any other
    genuine failure) folds into SpeakeasyResult.error, same graceful-
    degradation philosophy as the rest of core/ (capa/FLOSS/Authenticode
    all degrade to an empty/best-effort result rather than aborting the
    file's scan). Also the one place the module-level import failure
    (see _IMPORT_ERROR above) actually surfaces - as a normal, contained
    result the Results-grid report window already knows how to display,
    not an app-crashing exception.
    """
    if _IMPORT_ERROR is not None:
        return SpeakeasyResult(
            api_call_count=0, file_operation_count=0,
            error=_UNAVAILABLE_MESSAGE.format(error=_IMPORT_ERROR),
        )
    try:
        cfg = _load_config()
        se = speakeasy.Speakeasy(config=cfg)
        module = se.load_module(target_path)
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
    except Exception as exc:  # noqa: BLE001 - a target speakeasy can't handle must not fail the file's scan
        logger.info("Speakeasy emulation failed for %s: %s", target_path, exc)
        return SpeakeasyResult(api_call_count=0, file_operation_count=0, error=str(exc))

    return _summarize(report)


def _summarize(report: dict) -> SpeakeasyResult:
    """Aggregates across every entry point speakeasy ran - all_entrypoints
    =True means a DLL's exports/TLS callbacks can each contribute their own
    entry_points[] entry, not just a single main(). Every per-entry-point
    key besides "apis" is genuinely optional (see module docstring), so
    everything here goes through .get(..., default).
    """
    api_call_count = 0
    file_operation_count = 0
    network_indicators: list[str] = []
    seen: set[str] = set()

    for ep in report.get("entry_points", []):
        api_call_count += len(ep.get("apis", []) or [])
        file_operation_count += len(ep.get("file_access", []) or [])

        network = ep.get("network_events") or {}
        for dns_entry in network.get("dns", []) or []:
            _add_unique(network_indicators, seen, _format_dns(dns_entry))
        for conn in network.get("traffic", []) or []:
            _add_unique(network_indicators, seen, _format_traffic(conn))

    return SpeakeasyResult(
        api_call_count=api_call_count,
        file_operation_count=file_operation_count,
        network_indicators=network_indicators,
        raw_report=report,
    )


def _add_unique(items: list[str], seen: set[str], value: str) -> None:
    if value and value not in seen:
        seen.add(value)
        items.append(value)


def _format_dns(entry: dict) -> str:
    # {"query": domain, "response": ip} per profiler.py's log_dns().
    query = entry.get("query") or ""
    response = entry.get("response") or ""
    if not query:
        return ""
    return f"{query} -> {response}" if response else query


def _format_traffic(conn: dict) -> str:
    # {"server", "proto", "port", ...} per profiler.py's log_http()/
    # log_network().
    server = conn.get("server") or ""
    if not server:
        return ""
    port = conn.get("port")
    proto = conn.get("proto") or ""
    if port:
        return f"{server}:{port} ({proto})" if proto else f"{server}:{port}"
    return f"{server} ({proto})" if proto else server
