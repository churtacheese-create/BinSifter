"""Hashing and Shannon entropy - the one pass every scanned file goes
through regardless of what else is configured.

Port of the C# hashing/entropy code embedded in BinSifter_v1.3.0-alpha.2.ps1
(BinSifter.EntropyAnalyzer + the streaming MD5/SHA-1 read loop). Real,
working implementation - unlike the tool-integration stubs elsewhere in
core/, this has no external dependency and no ambiguous library API to get
wrong, so it's fully ported now rather than left as a TODO.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

_CHUNK_SIZE = 1024 * 1024  # 1 MiB - matches the PowerShell version's read buffer size


@dataclass
class HashResult:
    md5: str
    sha1: str
    sha256: str
    entropy: float  # bits/byte, 0.0-8.0
    length: int


def hash_and_score_file(path: str) -> HashResult:
    """Single streaming read - hashes and a byte-frequency table are built
    in the same pass, same as the PowerShell version's rationale ("free
    once the file is already being read for SHA-1/MD5").
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    byte_counts = [0] * 256
    total = 0

    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            total += len(chunk)
            for b in chunk:
                byte_counts[b] += 1

    entropy = _shannon_entropy(byte_counts, total)
    return HashResult(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        entropy=entropy,
        length=total,
    )


def _shannon_entropy(byte_counts: list[int], total_length: int) -> float:
    """0.0-8.0 bits/byte. -1 for a zero-length file (undefined, not zero -
    matches the PowerShell version's -1 "not computed" sentinel elsewhere)."""
    if total_length == 0:
        return -1.0
    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / total_length
        entropy -= p * math.log2(p)
    return entropy
