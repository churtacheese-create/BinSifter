"""Footer tool-version metadata - port of Start-ToolMetadataRefresh and the
status bar text it produces (BinSifter_v1.3.0-alpha.2.ps1: the function at
lines ~1895-1965, the joined "Engine: X | YARA: X | ..." string built at
lines ~5818-5825).

Real adaptation, not a like-for-like language port: the original shells out
to yara64.exe/capa.exe/ssdeep.exe with a --version/-V flag, captures stdout
with a 3-second-per-tool timeout, and does all of that on a background
PowerShell runspace specifically because a subprocess round-trip on the UI
thread would visibly stall the window. This port has no such executables to
query - YARA, capa, and ssdeep (via ppdeep) are in-process Python libraries
- so "version" here is just each installed package's own distribution
version (importlib.metadata.version(...)), which is a dict lookup, not a
process spawn. That makes the whole thing synchronous and safe to call
directly on the UI thread; no runspace/timeout/background-refresh machinery
is needed or ported. NSRL's "version" is unchanged from the original: the
configured file's last-modified date.
"""

from __future__ import annotations

import datetime
import importlib.metadata
from dataclasses import dataclass
from pathlib import Path

# (field, PyPI/importlib distribution name) - yara-python and flare-capa
# report their own dist name back exactly; ppdeep is BinSifter's stand-in
# for ssdeep (see pyproject.toml's dependency comment for why - pure Python,
# no libfuzzy dependency), so its version is shown under the "SSDEEP" label
# the original used, not under its own package name.
_DIST_NAMES = {
    "yara": "yara-python",
    "capa": "flare-capa",
    "ssdeep": "ppdeep",
}


@dataclass
class ToolMetadata:
    yara: str
    capa: str
    ssdeep: str
    nsrl_date: str


def _package_version(dist_name: str) -> str:
    try:
        return importlib.metadata.version(dist_name)
    except importlib.metadata.PackageNotFoundError:
        # Same graceful-degradation intent as the original's "version
        # unavailable"/"not configured" - shouldn't happen in practice since
        # all three are required BinSifter dependencies, but a missing/
        # corrupted install shouldn't crash the footer.
        return "not installed"


def _nsrl_date(nsrl_path: str) -> str:
    if not nsrl_path:
        return "not configured"
    path = Path(nsrl_path)
    if not path.is_file():
        return "not configured"
    return datetime.datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d")


def refresh_tool_metadata(nsrl_path: str) -> ToolMetadata:
    """Computes fresh footer values - called once at startup (covering a
    cached NsrlPath, same as the original refreshing once right after the
    window first appears) and again after every Settings save."""
    return ToolMetadata(
        yara=_package_version(_DIST_NAMES["yara"]),
        capa=_package_version(_DIST_NAMES["capa"]),
        ssdeep=_package_version(_DIST_NAMES["ssdeep"]),
        nsrl_date=_nsrl_date(nsrl_path),
    )


def format_status_line(app_version: str, metadata: ToolMetadata) -> str:
    """Same join format/order as the original's $statusBits -join '   |   '."""
    bits = [
        f"Engine: {app_version}",
        f"YARA: {metadata.yara}",
        f"Capa: {metadata.capa}",
        f"SSDEEP: {metadata.ssdeep}",
        f"NSRL: {metadata.nsrl_date}",
    ]
    return "   |   ".join(bits)
