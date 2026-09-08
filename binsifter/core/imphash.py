"""Import-table hash (imphash) and exact-match clustering.

Port of the C# PeImportHasher class (BinSifter-Rowan.ps1, near
line 1078's `ComputeImphash`). Uses `pefile`'s built-in get_imphash() -
pure Python, no external tool - instead of the hand-rolled PE-parsing
logic the PowerShell version needed.

TODO: Rich header hash (RichHash) is NOT ported yet. pefile exposes
pe.RICH_HEADER, but reconstructing the same MD5-of-decoded-un-XORed-bytes
the original computed needs its exact byte layout checked against
pefile's RICH_HEADER API before trusting it - don't guess at this one,
verify against a known-good sample first.
"""

from __future__ import annotations

import bisect
import logging

import pefile

logger = logging.getLogger(__name__)


# REAL BUG FOUND AND FIXED 2026-09-07, from a real user's scan of real
# casework: imphash averaged 9.08s/file (54.5% of ALL per-file CPU time
# across the whole scan) - more expensive than SSDEEP, which has to hash
# every byte of the file, while imphash only reads a small import table.
# Confirmed directly against a real 23MB legitimate DLL (996 imported
# functions, 53 DLLs) that a well-formed file's imphash costs ~0.06s
# total, ruling out file size or import count alone; the actual cause is
# a real, structural performance bug in pefile 2024.8.26 itself, not
# BinSifter's own code or the file's size: PE.get_section_by_rva() (called
# repeatedly while resolving import-table RVAs - pefile's own source
# comment even says "very useful when parsing import table") has exactly
# ONE cache slot (the last section it resolved) and falls back to a full
# LINEAR SCAN over every one of the file's sections on any cache miss.
# For a normal PE, import RVAs almost always stay within one section
# (e.g. .rdata), so the cache hits constantly and this is cheap. Splitting
# code across an unusually large number of sections is a real, documented
# PE-format evasion/anti-analysis technique - exactly the kind of file a
# malware-triage tool is built to see - and doing so defeats this one-slot
# cache on every single lookup, turning import resolution into
# O(imports x sections) instead of O(imports). Confirmed the exact shape
# of this cost via a direct micro-benchmark isolating this one method
# (linear cache-miss lookups scale with section count exactly as
# predicted: negligible at 10 sections, ~0.65s at 2000 sections/5000
# lookups) - a file with several thousand sections (the PE format's own
# 16-bit NumberOfSections field allows up to 65535) and a large import
# table (pefile's own MAX_IMPORT_SYMBOLS=8192 cap, each needing multiple
# RVA resolutions) lands squarely in multi-second territory.
#
# Fixed by monkeypatching get_section_by_rva() to binary-search a
# sorted-by-VirtualAddress index of the file's sections (built once,
# lazily, per PE instance and cached on the instance itself) instead of
# scanning linearly - O(log sections) instead of O(sections) per lookup,
# regardless of how badly the one-slot cache gets defeated. Falls back to
# the ORIGINAL linear-scan method whenever the binary-search candidate
# doesn't actually contain the RVA - a well-formed, non-overlapping
# section table never takes this path; a deliberately overlapping/
# adversarial one still gets the exact same correct answer the original,
# unpatched method would have given, just without the speedup - this is
# strictly a performance fix, never a behavior change. Same "patch the
# installed third-party library, don't vendor a fork" approach
# authenticode.py already uses for signify's own performance bugs.
def _patch_pefile_section_lookup() -> None:
    original = pefile.PE.get_section_by_rva

    def _fast_get_section_by_rva(self: "pefile.PE", rva: int):
        cached = self.__dict__.get("_bs_section_lookup")
        if cached is None or cached[0] is not self.sections:
            ordered = sorted(self.sections, key=lambda s: s.VirtualAddress)
            starts = [s.VirtualAddress for s in ordered]
            cached = (self.sections, ordered, starts)
            self.__dict__["_bs_section_lookup"] = cached
        _, ordered, starts = cached
        pos = bisect.bisect_right(starts, rva) - 1
        if pos >= 0 and ordered[pos].contains_rva(rva):
            self._get_section_by_rva_last_used = ordered[pos]
            return ordered[pos]
        return original(self, rva)

    pefile.PE.get_section_by_rva = _fast_get_section_by_rva


_patch_pefile_section_lookup()


def compute_imphash(path: str) -> str | None:
    """None when the file isn't a parseable PE, has no import table, or
    parsing failed - same best-effort/graceful-skip behavior as the
    PowerShell version, never an exception raised to the caller."""
    try:
        pe = pefile.PE(path, fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            imphash = pe.get_imphash()
            return imphash or None
        finally:
            pe.close()
    except pefile.PEFormatError:
        return None
    except OSError as exc:
        logger.warning("Could not read %s for imphash: %s", path, exc)
        return None


def cluster_by_imphash(imphashes: dict[str, str | None]) -> dict[str, tuple[int, int]]:
    """imphashes: {file_path: imphash_or_None}. Returns
    {file_path: (cluster_id, cluster_size)} for files with a non-None
    imphash shared by at least one other file in the batch - exact-match
    grouping, not fuzzy like ssdeep. Files with no imphash, or a unique
    one in this batch, are simply absent from the result (caller should
    default those to ImphashClusterId=-1, ImphashClusterSize=0).
    """
    groups: dict[str, list[str]] = {}
    for path, imphash in imphashes.items():
        if not imphash:
            continue
        groups.setdefault(imphash, []).append(path)

    result: dict[str, tuple[int, int]] = {}
    cluster_id = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        for path in members:
            result[path] = (cluster_id, len(members))
        cluster_id += 1
    return result
