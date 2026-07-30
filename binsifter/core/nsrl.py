"""NSRL known-good hash lookup.

Real, working implementation - loads whatever the analyst points BinSifter
at (a plain SHA-1-per-line list, or an NSRL RDS-format CSV export where
SHA-1 is one of the quoted columns) into an in-memory set for O(1) lookups
during a scan. Tolerant of both because real-world NSRL exports vary by
version/source, and BinSifter shouldn't fail a whole scan over a format
mismatch - same graceful-degradation philosophy as the PowerShell version.
"""

from __future__ import annotations

import csv
import logging
import re

logger = logging.getLogger(__name__)

_SHA1_RE = re.compile(r"^[0-9A-Fa-f]{40}$")


def load_nsrl_hashes(path: str) -> set[str]:
    """Returns a set of uppercase SHA-1 hashes. Empty set (not an
    exception) if the file can't be read or parsed - the caller should
    treat that as "NSRL check unavailable this run," same as the
    PowerShell version's blank-tolerant handling of a missing/invalid
    NSRL path.
    """
    hashes: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            sniff = fh.read(4096)
            fh.seek(0)
            if "," in sniff and "SHA-1" in sniff.upper():
                # NSRL RDS-format CSV: "SHA-1","MD5","CRC32","FileName",...
                reader = csv.reader(fh)
                header = next(reader, None)
                if not header:
                    return hashes
                try:
                    sha1_col = [h.strip().upper() for h in header].index("SHA-1")
                except ValueError:
                    logger.warning("NSRL file %s looked like CSV but had no SHA-1 column", path)
                    return hashes
                for row in reader:
                    if len(row) > sha1_col and _SHA1_RE.match(row[sha1_col]):
                        hashes.add(row[sha1_col].upper())
            else:
                # Plain one-hash-per-line list
                for line in fh:
                    candidate = line.strip()
                    if _SHA1_RE.match(candidate):
                        hashes.add(candidate.upper())
    except OSError as exc:
        logger.warning("Could not read NSRL hash set %s: %s", path, exc)
        return set()

    return hashes


def is_known_good(sha1: str, nsrl_hashes: set[str]) -> bool:
    return sha1.upper() in nsrl_hashes
