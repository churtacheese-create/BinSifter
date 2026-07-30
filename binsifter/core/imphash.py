"""Import-table hash (imphash) and exact-match clustering.

Port of the C# PeImportHasher class (BinSifter_v1.3.0-alpha.2.ps1, near
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

import logging

import pefile

logger = logging.getLogger(__name__)


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
