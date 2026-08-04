"""NSRL known-good hash lookup - cached, memory-mapped binary index.

Rewritten 2026-08-04 to replace the original in-memory `set[str]`
implementation, after a real 652-file scan showed exactly why that design
doesn't scale to a real NSRL RDS export (72,015,335 hashes here):

1. Parsing was the dominant cost of the whole scan's "setup" phase: 1468s
   (24.5 minutes) of pure-Python CSV row iteration + a per-row regex match,
   paid on EVERY scan, even repeat scans against the same unchanged NSRL
   file.
2. The parsed set was then handed to `_pool_worker_init()` via
   multiprocessing's initargs for each of up to 16 worker processes.
   Multiprocessing pickles and copies initargs into every worker
   independently - there is no sharing. A ~72-million-entry Python
   `set[str]` is plausibly 8-12+ GB; 16 independent copies is a
   triple-digit-GB memory demand. This lined up exactly with a previously
   unexplained ~15-minute gap between "worker pool started" and "first file
   actually began scanning" in a real run's logs, and very likely
   contributed to unrelated per-file stages (imphash, ssdeep) running far
   slower than their intrinsic cost during the scan itself, via memory
   pressure/contention.

The fix: parse once, write a sorted flat binary cache (20-byte SHA-1
digests, no hex/CSV overhead) next to the report directory (NOT next to the
NSRL source - see _cache_path_for()'s docstring), and have each worker
process independently memory-map (mmap) that cache file instead of
receiving a copy of parsed data. Memory-mapping the SAME file from multiple
processes shares the underlying OS page cache rather than duplicating
memory per process, AND - this matters specifically for lower-RAM machines,
not just for avoiding duplication - a read-only file-backed mapping lets
the OS evict pages under memory pressure and cheaply re-read them from disk
on demand, rather than requiring the whole structure to stay resident the
way an in-memory Python set does. The index is usable on a modest-RAM
machine; it just may page fault more often, not fail or force full-set
duplication.

The one-time (per source-file-version) parse+sort itself also got faster:
numpy's void20 dtype sort (verified 2026-08-04 to produce byte-identical
ordering to Python's own lexicographic bytes sort on the same input) avoids
the per-object overhead of sorting 72 million individual Python `bytes`
objects - benchmarked at ~2.3s for 5,000,000 records, extrapolating to
roughly 30-60s for 72 million, versus multiple minutes the naive approach
would cost on top of the parse itself.

Cross-reference: the PowerShell version (BinSifter_v1.3.0-alpha.2.ps1,
BinSifter.NsrlLoader, ~line 147) already does something similar - parse
once, cache a flat 20-byte-record file, fast-load from cache on repeat
runs - and that's a real, legitimate contributor to its faster NSRL
handling. The difference: PowerShell's parallelism is runspaces (threads)
within ONE process, so its HashSet is naturally loaded once and shared by
reference - it never had the "duplicated N times across processes" problem
this rewrite's process-based parallelism (required to get real multi-core
throughput past Python's GIL) reintroduced. Porting PowerShell's cache
alone would have fixed the reparse cost but not the duplication cost; the
mmap design here fixes both.
"""

from __future__ import annotations

import csv
import hashlib
import logging
import os
import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

_SHA1_RE = re.compile(r"^[0-9A-Fa-f]{40}$")

_RECORD_SIZE = 20  # bytes per binary SHA-1 digest
_MAGIC = b"BSNL"
_FORMAT_VERSION = 1
# <  little-endian, no padding
# 4s magic / I version / Q record_count / q source_mtime_ns / Q source_size
_HEADER = struct.Struct("<4sIQqQ")
_HEADER_SIZE = _HEADER.size


@dataclass
class NsrlIndex:
    """Read-only view over a sorted array of 20-byte binary SHA-1 digests,
    backed by a numpy memmap (real data) or a zero-length in-memory array
    (empty/not-configured case - see open_index()). `count == 0` for both
    "not configured" and "configured but genuinely empty" - callers that
    care about the difference should check the caller-side path/None
    instead, same as the old load_nsrl_hashes()'s empty-set convention.

    __contains__ is the entire public lookup surface, by design: this
    exists so `sha1.upper() in nsrl_index` (is_known_good()'s existing
    call shape) keeps working completely unchanged - every caller of
    is_known_good() needed zero changes for this rewrite.
    """

    _records: np.ndarray  # shape (N,), dtype 'V20', sorted ascending
    count: int

    def __contains__(self, sha1_hex: str) -> bool:
        if self.count == 0:
            return False
        try:
            needle = bytes.fromhex(sha1_hex)
        except ValueError:
            return False
        if len(needle) != _RECORD_SIZE:
            return False
        needle_arr = np.frombuffer(needle, dtype="V20")
        idx = int(np.searchsorted(self._records, needle_arr)[0])
        if idx >= self.count:
            return False
        return bytes(self._records[idx]) == needle


def _cache_path_for(nsrl_path: str, report_directory: str) -> str:
    """Cache lives under report_directory/.bsifter-nsrl-cache/, NOT beside
    the NSRL source file - mirrors the PowerShell version's own reasoning
    (BinSifter_v1.3.0-alpha.2.ps1, ~line 2656): NSRL reference sets are
    routinely staged on read-only or write-blocked evidentiary drives, and
    a cache-write failure there shouldn't be able to affect the scan even
    though the NSRL data itself parsed fine. Named by a hash of the
    (case-normalized) source path so multiple differently-located NSRL
    files can't collide on a cache filename.
    """
    cache_dir = Path(report_directory) / ".bsifter-nsrl-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(os.path.normcase(nsrl_path).encode("utf-8")).hexdigest()[:16]
    stem = Path(nsrl_path).stem or "nsrl"
    return str(cache_dir / f"{stem}_{digest}.bsifter-nsrl-idx")


def get_cache_path(nsrl_path: str, report_directory: str) -> str:
    """Public wrapper over _cache_path_for() - the name callers outside this
    module should use."""
    return _cache_path_for(nsrl_path, report_directory)


def _read_header(cache_path: str) -> tuple[int, int, int] | None:
    """Returns (record_count, source_mtime_ns, source_size) from an existing
    cache file's header, or None if the file doesn't exist, is too short,
    or doesn't carry BinSifter's own magic/version - any of which just
    means "treat this as a cache miss," not an error."""
    try:
        with open(cache_path, "rb") as fh:
            raw = fh.read(_HEADER_SIZE)
    except OSError:
        return None
    if len(raw) != _HEADER_SIZE:
        return None
    magic, version, count, mtime_ns, size = _HEADER.unpack(raw)
    if magic != _MAGIC or version != _FORMAT_VERSION:
        return None
    return count, mtime_ns, size


def cache_is_fresh(cache_path: str, source_path: str) -> bool:
    """True if a cache file exists at cache_path, was built by this format
    version, and its recorded source mtime+size still match source_path's
    current stat - the same two-field staleness check the PowerShell
    version's own cache uses. A false here (missing/stale/corrupt cache)
    just means "build (or rebuild) it," not an error condition."""
    header = _read_header(cache_path)
    if header is None:
        return False
    _count, cached_mtime_ns, cached_size = header
    try:
        st = os.stat(source_path)
    except OSError:
        return False
    return st.st_mtime_ns == cached_mtime_ns and st.st_size == cached_size


def read_cached_count(cache_path: str) -> int:
    """Record count from an existing cache's header, without opening/mmap'ing
    the (potentially huge) data section - used purely for logging "loaded N
    hashes from cache" without paying even the small cost of a full
    open_index() call. Returns 0 if the header can't be read."""
    header = _read_header(cache_path)
    return header[0] if header else 0


def _extract_hex_hashes(path: str) -> Iterator[str]:
    """Streaming generator over every valid 40-char hex SHA-1 field found in
    `path` - handles both an NSRL RDS-format CSV (SHA-1 in a "SHA-1"
    column) and a plain one-hash-per-line list, same format-sniffing logic
    the original load_nsrl_hashes() used. Never holds more than one
    line/row in memory at a time, so parsing itself doesn't need the source
    file to be small - only the (bounded, ~20 bytes/record) accumulated
    output does.
    """
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        sniff = fh.read(4096)
        fh.seek(0)
        if "," in sniff and "SHA-1" in sniff.upper():
            reader = csv.reader(fh)
            header = next(reader, None)
            if not header:
                return
            try:
                sha1_col = [h.strip().upper() for h in header].index("SHA-1")
            except ValueError:
                logger.warning("NSRL file %s looked like CSV but had no SHA-1 column", path)
                return
            for row in reader:
                if len(row) > sha1_col and _SHA1_RE.match(row[sha1_col]):
                    yield row[sha1_col]
        else:
            for line in fh:
                candidate = line.strip()
                if _SHA1_RE.match(candidate):
                    yield candidate


def build_index(source_path: str, cache_path: str) -> int:
    """Parses source_path exactly once and writes a sorted, header-prefixed
    binary cache to cache_path. Returns the record count. Expensive (this
    is the ~24-minute-on-a-72-million-row-file operation) - callers should
    only reach this when cache_is_fresh() says the existing cache (if any)
    is missing or stale, not on every scan.

    Written to a .tmp path first and then os.replace()'d into place, which
    is atomic on both POSIX and Windows - a crash or kill mid-build leaves
    either no cache file or the previous good one, never a half-written one
    that a later cache_is_fresh() check could mistake for valid.
    """
    buf = bytearray()
    for hexstr in _extract_hex_hashes(source_path):
        buf += bytes.fromhex(hexstr)

    count = len(buf) // _RECORD_SIZE
    if count:
        # np.frombuffer over a (mutable) bytearray gives a WRITABLE view,
        # not a copy - sorting it in place sorts `buf` itself too, avoiding
        # a second ~1.4GB-at-72M-records allocation just to sort. Verified
        # 2026-08-04 that this in-place sort on a bytearray-backed view
        # produces byte-identical results to Python's own list.sort() over
        # the equivalent bytes objects.
        np.frombuffer(buf, dtype="V20").sort()

    st = os.stat(source_path)
    tmp_path = cache_path + ".tmp"
    with open(tmp_path, "wb") as fh:
        fh.write(_HEADER.pack(_MAGIC, _FORMAT_VERSION, count, st.st_mtime_ns, st.st_size))
        fh.write(buf)
    os.replace(tmp_path, cache_path)
    return count


def open_index(cache_path: str) -> NsrlIndex:
    """Memory-maps an existing cache file built by build_index(). Cheap
    (mmap doesn't read the whole file, just maps it - actual pages are
    faulted in on first access, and shared across every process that maps
    the same file) - meant to be called independently by EVERY worker
    process, not loaded once and handed down. See this module's docstring
    for why per-process mmap, not a shared parsed object, is the point of
    this whole rewrite.

    Returns a count=0 NsrlIndex (never raises) if the cache is missing or
    its header can't be read - same graceful-degradation contract the
    original load_nsrl_hashes() had for a missing/invalid NSRL file.
    """
    header = _read_header(cache_path)
    if header is None:
        return NsrlIndex(_records=np.frombuffer(b"", dtype="V20"), count=0)
    count, _mtime_ns, _size = header
    if count == 0:
        return NsrlIndex(_records=np.frombuffer(b"", dtype="V20"), count=0)
    records = np.memmap(cache_path, dtype="V20", mode="r", offset=_HEADER_SIZE, shape=(count,))
    return NsrlIndex(_records=records, count=count)


def prepare_nsrl_index(nsrl_path: str, report_directory: str) -> str | None:
    """Convenience all-in-one for callers (like the NSRL page's manual
    Reload preview) that don't need engine.py's own separate
    build-vs-cache-hit logging around each step - ensures a fresh cache
    exists for nsrl_path and returns its path, building it first if
    missing/stale. Returns None if nsrl_path is blank or not a real file.
    engine.py's scan_directory() calls the lower-level pieces
    (get_cache_path/cache_is_fresh/build_index/read_cached_count)
    individually instead, purely so it can log which branch it took.
    """
    if not nsrl_path or not Path(nsrl_path).is_file():
        return None
    cache_path = _cache_path_for(nsrl_path, report_directory)
    if not cache_is_fresh(cache_path, nsrl_path):
        build_index(nsrl_path, cache_path)
    return cache_path


def is_known_good(sha1: str, nsrl_index: "NsrlIndex | set") -> bool:
    """Unchanged contract from the original: works identically whether
    nsrl_index is a real NsrlIndex, the empty-set "not configured"
    sentinel some callers still pass, or (in tests) a plain set/dict for
    convenience - all three support `in`."""
    return sha1.upper() in nsrl_index
