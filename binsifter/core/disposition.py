"""Triage disposition history - port of Save-DispositionEntry
(BinSifter-Rowan.ps1, lines ~5341-5364). One "SHA1|Disposition"
line per file, keyed by SHA-1 so the same binary keeps its analyst-set
disposition across re-scans and across different source directories.

Same tradeoff as the PowerShell version: the whole file is rewritten on
every save rather than appended-to, which is simple and safe at the scale
this is meant for (thousands of entries, not millions) - the SSDEEP cluster
history file makes the same call.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_HISTORY_FILENAME = ".bsifter-disposition-history.txt"


def _history_path(report_directory: str) -> Path:
    return Path(report_directory) / _HISTORY_FILENAME


def load_disposition_history(report_directory: str) -> dict[str, str]:
    """Reads the whole history file into a dict keyed by SHA-1 (case-
    insensitive, matching the PowerShell version's
    StringComparer.OrdinalIgnoreCase dictionary). Returns {} if
    report_directory is blank or the file doesn't exist yet or can't be
    read - same graceful-skip behavior as every other optional BinSifter
    data file (NSRL, blocklist, ATT&CK)."""
    if not report_directory:
        return {}
    path = _history_path(report_directory)
    if not path.is_file():
        return {}

    entries: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            fields = line.split("|")
            if len(fields) >= 2:
                entries[fields[0].strip().lower()] = fields[1].strip()
    except OSError as exc:
        logger.warning("Could not read disposition history %s: %s", path, exc)
        return {}
    return entries


def save_disposition_entry(report_directory: str, sha1: str, disposition: str) -> None:
    """Updates one SHA-1's disposition and rewrites the whole history file -
    a no-op if sha1 is blank or report_directory isn't a usable directory,
    same guard the PowerShell version applies before touching the file."""
    if not sha1 or not report_directory or not Path(report_directory).is_dir():
        return

    path = _history_path(report_directory)
    # Lowercased keys throughout, matching the PowerShell version's
    # OrdinalIgnoreCase dictionary - SHA-1s from hashing.py are always
    # lowercase hex anyway, but this keeps lookups/overwrites
    # case-insensitive regardless, so a mismatched-case sha1 argument can
    # never create a duplicate entry alongside an existing one.
    entries: dict[str, str] = {}
    if path.is_file():
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                fields = line.split("|")
                if len(fields) >= 2:
                    entries[fields[0].strip().lower()] = fields[1].strip()
        except OSError:
            pass  # a corrupt/unreadable existing file just means starting fresh, same as load

    entries[sha1.lower()] = disposition
    try:
        path.write_text("\n".join(f"{k}|{v}" for k, v in entries.items()), encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not save disposition history: %s", exc)
