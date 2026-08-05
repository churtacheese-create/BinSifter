"""Speakeasy isolated code emulation - real library integration.

Direct port of the PowerShell version's "Run isolated Speakeasy emulation"
Results-grid quick-launch action (BinSifter-Rowan_v1.3.0-beta.1.ps1, lines
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

Verified against the installed speakeasy 1.5.11's own cli.py (not guessed)
before writing this - and it's a good thing it was verified, because the
PowerShell version's assumed JSON shape (top-level .apis/.network/
.file_access, per its own "guessed, not verified" note in project memory)
does not match the real library output at all:
  - speakeasy.Speakeasy(config=...).load_module(path) + .run_module(module,
    all_entrypoints=True) is the real in-process API (cli.py's own
    emulate_binary() helper), not a "-t <file> -o json" CLI invocation -
    there's no subprocess/JSON-parsing round-trip needed at all now.
  - se.get_report() returns a dict (get_json_report() is just
    json.dumps(get_report())) whose real per-entry-point data lives under
    report["entry_points"][i], not at the report's top level. Each entry
    point only gains an "apis" list unconditionally, but "network_events"/
    "file_access"/"registry_access"/"process_events"/"dropped_files" are
    only present AT ALL when speakeasy's own profiler.get_report()
    actually found something to report for that key (confirmed by reading
    profiler.py directly, not assumed) - so summarization below must
    treat every one of those keys as optional, not default-empty.
  - Network data is further split into report["entry_points"][i]
    ["network_events"]["dns"] (list of {"query", "response"} dicts) and
    ["network_events"]["traffic"] (list of {"server", "proto", "port", ...}
    dicts from profiler.py's log_http/log_network) - not a flat list of
    strings the way the PowerShell version's guessed ".network" field
    implied.
  - A per-entry-point "error" key (e.g. an unsupported-API-stub hit mid-
    emulation) is a NORMAL, expected part of a real report - Speakeasy
    itself does not raise a Python exception for this, it just records
    what it could and stops that entry point's run early. Confirmed
    against a real sample (calc.exe hit an api-ms-win-core-* forwarder
    stub, the same API Set forwarding quirk noted in the capa API Set
    project memory - a different tool, the same underlying Windows
    mechanism tripping it up). Only a genuine Python-level exception
    (bad PE pefile can't parse at all, etc.) should surface as
    SpeakeasyResult.error here.
  - The emulation timeout is a REAL, engine-enforced cutoff, not merely
    advisory: config["timeout"] (seconds) is converted to microseconds and
    passed straight into Unicorn's own emu_start(..., timeout=...)
    (confirmed in speakeasy/engines/unicorn_eng.py's start() method) -
    Unicorn's C core enforces it directly, so running this in-process
    (like capa/FLOSS already do, no subprocess needed) is safe from a
    "will this hang forever" perspective. The one residual risk versus the
    original's subprocess-isolated design is a genuine Unicorn/native-code
    crash taking down the whole BinSifter process instead of just a
    disposable child process - a real, deliberate tradeoff (same one
    capa/FLOSS already made), not something worked around here.

Known, deliberate scope limit: only PE/module emulation (se.load_module +
run_module) is implemented, matching exactly what the PowerShell quick-
launch action did - it never had a raw-shellcode/-r mode either. Shellcode
emulation (se.load_shellcode + run_shellcode, architecture-forced via
-a x86/amd64) is a real speakeasy capability but was not exercised here
since there's no real shellcode sample on hand to verify it against - flag
to Steve before adding it rather than shipping an unverified code path.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

import speakeasy

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(speakeasy.__file__), "configs", "default.json")

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
    file's scan).
    """
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
    # log_network() - field names confirmed against both, not guessed.
    server = conn.get("server") or ""
    if not server:
        return ""
    port = conn.get("port")
    proto = conn.get("proto") or ""
    if port:
        return f"{server}:{port} ({proto})" if proto else f"{server}:{port}"
    return f"{server} ({proto})" if proto else server
