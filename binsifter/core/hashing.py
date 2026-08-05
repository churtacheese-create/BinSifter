"""Hashing and Shannon entropy - the one pass every scanned file goes
through regardless of what else is configured.

Port of the C# hashing/entropy code embedded in BinSifter-Rowan_v1.3.0-beta.1.ps1
(BinSifter.EntropyAnalyzer + the streaming MD5/SHA-1 read loop). Real,
working implementation - unlike the tool-integration stubs elsewhere in
core/, this has no external dependency and no ambiguous library API to get
wrong, so it's fully ported now rather than left as a TODO.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
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

    Byte-frequency counting uses Counter.update(chunk) instead of a manual
    `for b in chunk: byte_counts[b] += 1` Python-level loop - the latter was
    confirmed (2026-08-03, profiling a slow real-world scan) to be a
    meaningful, entirely avoidable cost paid on EVERY file regardless of
    config, since this is the one stage every file goes through
    unconditionally. Counter.update() on a bytes object hits CPython's
    C-accelerated _count_elements path (collections/__init__.py imports it
    from the _collections extension module when available), so the actual
    counting loop runs in C instead of the Python interpreter loop - same
    result, no new dependency, meaningfully faster on large files.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    byte_counts: Counter = Counter()
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
            byte_counts.update(chunk)

    entropy = _shannon_entropy(byte_counts, total)
    return HashResult(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        entropy=entropy,
        length=total,
    )


def _shannon_entropy(byte_counts: Counter, total_length: int) -> float:
    """0.0-8.0 bits/byte. -1 for a zero-length file (undefined, not zero -
    matches the PowerShell version's -1 "not computed" sentinel elsewhere).
    byte_counts only holds keys for byte values actually seen (a Counter,
    not a dense 256-slot list), so there's no zero-count entries to skip
    here anymore - every value iterated is a real, present byte value."""
    if total_length == 0:
        return -1.0
    entropy = 0.0
    for count in byte_counts.values():
        p = count / total_length
        entropy -= p * math.log2(p)
    return entropy
