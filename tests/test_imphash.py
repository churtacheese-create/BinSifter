"""Tests for imphash.py - including _patch_pefile_section_lookup(), the
real pefile performance fix found and applied 2026-09-07 (see that
function's own docstring in imphash.py for the full story: pefile's own
get_section_by_rva() degrades to an O(sections) linear scan on any
one-slot-cache miss, which - multiplied by O(imports) RVA resolutions
during import-table parsing - was strongly suspected as a real
contributor to a 9.08s/file imphash average seen against real casework).
The patch is applied at module import time (importing this test module
transitively imports imphash.py), so every test below already runs
against the patched pefile.PE.get_section_by_rva.
"""

from __future__ import annotations

import pefile

from binsifter.core import imphash as imphash_mod


class _FakeSection:
    """Minimal stand-in for pefile's real SectionStructure - only
    VirtualAddress and contains_rva() are ever touched by
    get_section_by_rva(), patched or not."""

    def __init__(self, start: int, size: int) -> None:
        self.VirtualAddress = start
        self._end = start + size

    def contains_rva(self, rva: int) -> bool:
        return self.VirtualAddress <= rva < self._end


def _bare_pe(sections: list) -> "pefile.PE":
    """A pefile.PE instance with just enough state for get_section_by_rva()
    to run - __new__() bypasses the real (file-parsing) __init__ entirely,
    since these tests are only exercising this one method in isolation."""
    pe = pefile.PE.__new__(pefile.PE)
    pe.sections = sections
    pe._get_section_by_rva_last_used = None
    return pe


def test_patched_lookup_finds_correct_section_for_normal_nonoverlapping_layout():
    sections = [_FakeSection(0x1000, 0x1000), _FakeSection(0x2000, 0x1000), _FakeSection(0x5000, 0x2000)]
    pe = _bare_pe(sections)
    assert pe.get_section_by_rva(0x1500) is sections[0]
    assert pe.get_section_by_rva(0x2500) is sections[1]
    assert pe.get_section_by_rva(0x5500) is sections[2]
    assert pe.get_section_by_rva(0x1000) is sections[0]  # exact start boundary


def test_patched_lookup_returns_none_for_rva_outside_every_section():
    sections = [_FakeSection(0x1000, 0x1000)]
    pe = _bare_pe(sections)
    assert pe.get_section_by_rva(0x9000) is None
    assert pe.get_section_by_rva(0x500) is None  # before the first section too


def test_patched_lookup_falls_back_correctly_for_overlapping_sections():
    """A deliberately overlapping/adversarial section table should still
    get a correct (containing) answer via the original linear-scan
    fallback - the binary-search fast path is only ever a shortcut for
    the common, well-formed, non-overlapping case, never a behavior
    change from the original, unpatched method's own contract."""
    sections = [_FakeSection(0x1000, 0x3000), _FakeSection(0x2000, 0x500)]
    pe = _bare_pe(sections)
    result = pe.get_section_by_rva(0x2100)
    assert result is not None
    assert result.contains_rva(0x2100)


def test_patched_lookup_builds_index_once_and_reuses_it():
    """The sorted index is meant to be built once per PE instance (lazily,
    on first lookup) and reused - confirms the cache key (identity of
    pe.sections) is respected rather than rebuilding on every call."""
    sections = [_FakeSection(0x1000, 0x1000)]
    pe = _bare_pe(sections)
    pe.get_section_by_rva(0x1500)
    cached_before = pe.__dict__["_bs_section_lookup"]
    pe.get_section_by_rva(0x1600)
    cached_after = pe.__dict__["_bs_section_lookup"]
    assert cached_before is cached_after


def test_compute_imphash_returns_none_for_non_pe_file(tmp_path):
    bogus = tmp_path / "not_a_pe.bin"
    bogus.write_bytes(b"this is definitely not a PE file")
    assert imphash_mod.compute_imphash(str(bogus)) is None


def test_compute_imphash_returns_none_for_missing_file(tmp_path):
    assert imphash_mod.compute_imphash(str(tmp_path / "does_not_exist.exe")) is None


def test_cluster_by_imphash_groups_matching_hashes_only():
    imphashes = {
        "a.exe": "hash1",
        "b.exe": "hash1",
        "c.exe": "hash2",
        "d.exe": None,
    }
    clusters = imphash_mod.cluster_by_imphash(imphashes)
    assert clusters["a.exe"][1] == 2
    assert clusters["b.exe"][1] == 2
    assert clusters["a.exe"][0] == clusters["b.exe"][0]
    assert "c.exe" not in clusters  # singleton (unique imphash) - not clustered
    assert "d.exe" not in clusters  # no imphash at all
