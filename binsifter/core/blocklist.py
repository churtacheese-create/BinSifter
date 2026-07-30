"""Offline known-bad hash blocklist - the mirror image of nsrl.py.

Accepts a plain SHA-1/MD5-per-line list or a MalwareBazaar-style CSV
export (comment lines starting with '#', hash in one of the columns).
Same graceful-degradation rule as everywhere else in core/: a missing or
unparsable blocklist just means the check is skipped this run, not a
scan-ending error.
"""

from __future__ import annotations

import csv
import logging
import re

logger = logging.getLogger(__name__)

_HASH_RE = re.compile(r"^[0-9A-Fa-f]{32}$|^[0-9A-Fa-f]{40}$|^[0-9A-Fa-f]{64}$")


def load_blocklist_hashes(path: str) -> set[str]:
    """Returns a set of uppercase hashes (MD5/SHA-1/SHA-256, whatever the
    source file contains - ReputationStatus lookups check the record's own
    hash of matching length, see engine.py).
    """
    hashes: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            sample_lines = [fh.readline() for _ in range(5)]
            fh.seek(0)
            looks_like_csv = any("," in line for line in sample_lines if line and not line.startswith("#"))

            if looks_like_csv:
                reader = csv.reader(line for line in fh if not line.startswith("#"))
                for row in reader:
                    for cell in row:
                        candidate = cell.strip().strip('"')
                        if _HASH_RE.match(candidate):
                            hashes.add(candidate.upper())
            else:
                for line in fh:
                    if line.startswith("#"):
                        continue
                    candidate = line.strip()
                    if _HASH_RE.match(candidate):
                        hashes.add(candidate.upper())
    except OSError as exc:
        logger.warning("Could not read blocklist %s: %s", path, exc)
        return set()

    return hashes


def check_reputation(md5: str, sha1: str, sha256: str, blocklist_hashes: set[str]) -> tuple[str, str]:
    """Returns (ReputationStatus, ReputationSource) - "KnownBad"/hash-kind
    on a hit, "Clean"/"" otherwise. Checks all three hash kinds since a
    blocklist export might key on any of them.
    """
    if sha256.upper() in blocklist_hashes:
        return "KnownBad", "SHA-256"
    if sha1.upper() in blocklist_hashes:
        return "KnownBad", "SHA-1"
    if md5.upper() in blocklist_hashes:
        return "KnownBad", "MD5"
    return "Clean", ""
