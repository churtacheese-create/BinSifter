"""Tests for binsifter.core.nsrl's cached, memory-mapped binary index -
added 2026-08-04 alongside the rewrite itself (the original set[str]
implementation had no test coverage at all). Real files on disk (tmp_path),
not mocks - the whole point of this module is the on-disk cache format and
its staleness detection, which a mock would just assume correct.
"""

from __future__ import annotations

import hashlib
import os
import random
import time

from binsifter.core import nsrl


def _random_sha1_hex() -> str:
    return hashlib.sha1(os.urandom(16)).hexdigest()


def _write_plain_list(path, hashes: list[str]) -> None:
    path.write_text("\n".join(hashes) + "\n", encoding="utf-8")


def _write_nsrl_csv(path, hashes: list[str]) -> None:
    lines = ['"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"']
    for h in hashes:
        lines.append(f'"{h.upper()}","00000000000000000000000000000000","00000000","x.exe","1","1","1",""')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_build_and_lookup_plain_list_round_trip(tmp_path):
    known = [_random_sha1_hex() for _ in range(500)]
    unknown = [_random_sha1_hex() for _ in range(500)]

    src = tmp_path / "nsrl.txt"
    _write_plain_list(src, known)
    cache_path = nsrl.get_cache_path(str(src), str(tmp_path))

    count = nsrl.build_index(str(src), cache_path)
    assert count == len(known)

    index = nsrl.open_index(cache_path)
    assert index.count == len(known)
    for h in known:
        assert h in index
        assert h.upper() in index  # case-insensitivity is is_known_good()'s job, but __contains__ itself is exact-bytes
    for h in unknown:
        assert h not in index


def test_is_known_good_case_insensitive(tmp_path):
    known = [_random_sha1_hex() for _ in range(50)]
    src = tmp_path / "nsrl.txt"
    _write_plain_list(src, known)
    cache_path = nsrl.get_cache_path(str(src), str(tmp_path))
    nsrl.build_index(str(src), cache_path)
    index = nsrl.open_index(cache_path)

    sample = known[0]
    assert nsrl.is_known_good(sample.upper(), index)
    assert nsrl.is_known_good(sample.lower(), index)
    assert not nsrl.is_known_good(_random_sha1_hex(), index)


def test_csv_format_with_sha1_column(tmp_path):
    known = [_random_sha1_hex() for _ in range(200)]
    src = tmp_path / "NSRLFile.txt"
    _write_nsrl_csv(src, known)
    cache_path = nsrl.get_cache_path(str(src), str(tmp_path))

    count = nsrl.build_index(str(src), cache_path)
    assert count == len(known)

    index = nsrl.open_index(cache_path)
    for h in known:
        assert nsrl.is_known_good(h, index)


def test_malformed_rows_are_skipped_not_fatal(tmp_path):
    good = [_random_sha1_hex() for _ in range(10)]
    lines = list(good) + [
        "",
        "not-a-hash",
        "deadbeef",  # too short
        "g" * 40,  # right length, invalid hex
        "0" * 41,  # too long
    ]
    src = tmp_path / "nsrl.txt"
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")
    cache_path = nsrl.get_cache_path(str(src), str(tmp_path))

    count = nsrl.build_index(str(src), cache_path)
    assert count == len(good)


def test_empty_source_yields_empty_index_not_a_crash(tmp_path):
    src = tmp_path / "empty.txt"
    src.write_text("", encoding="utf-8")
    cache_path = nsrl.get_cache_path(str(src), str(tmp_path))

    count = nsrl.build_index(str(src), cache_path)
    assert count == 0

    index = nsrl.open_index(cache_path)
    assert index.count == 0
    assert _random_sha1_hex() not in index


def test_open_index_missing_cache_returns_empty_not_raises(tmp_path):
    index = nsrl.open_index(str(tmp_path / "does-not-exist.bsifter-nsrl-idx"))
    assert index.count == 0
    assert _random_sha1_hex() not in index


def test_cache_path_lives_under_report_directory_not_beside_source(tmp_path):
    # Simulates the real-world case this was explicitly designed for: the
    # NSRL source on a read-only/evidentiary drive, ReportDirectory
    # somewhere else that's actually writable.
    source_dir = tmp_path / "readonly_evidence_drive"
    source_dir.mkdir()
    report_dir = tmp_path / "reports"
    report_dir.mkdir()

    src = source_dir / "nsrl.txt"
    _write_plain_list(src, [_random_sha1_hex() for _ in range(5)])

    cache_path = nsrl.get_cache_path(str(src), str(report_dir))
    assert str(report_dir) in cache_path
    assert str(source_dir) not in cache_path

    nsrl.build_index(str(src), cache_path)
    assert os.path.isfile(cache_path)


def test_cache_is_fresh_true_immediately_after_build(tmp_path):
    src = tmp_path / "nsrl.txt"
    _write_plain_list(src, [_random_sha1_hex() for _ in range(10)])
    cache_path = nsrl.get_cache_path(str(src), str(tmp_path))

    assert not nsrl.cache_is_fresh(cache_path, str(src))  # no cache yet
    nsrl.build_index(str(src), cache_path)
    assert nsrl.cache_is_fresh(cache_path, str(src))


def test_cache_is_stale_after_source_changes(tmp_path):
    src = tmp_path / "nsrl.txt"
    _write_plain_list(src, [_random_sha1_hex() for _ in range(10)])
    cache_path = nsrl.get_cache_path(str(src), str(tmp_path))
    nsrl.build_index(str(src), cache_path)
    assert nsrl.cache_is_fresh(cache_path, str(src))

    # Real filesystem mtime resolution can be coarse (esp. on some
    # platforms/filesystems) - sleep a touch so a size-only OR mtime-only
    # change is still guaranteed detectable either way.
    time.sleep(0.05)
    _write_plain_list(src, [_random_sha1_hex() for _ in range(11)])  # different size too

    assert not nsrl.cache_is_fresh(cache_path, str(src))


def test_read_cached_count_matches_build_count_without_opening_index(tmp_path):
    known = [_random_sha1_hex() for _ in range(321)]
    src = tmp_path / "nsrl.txt"
    _write_plain_list(src, known)
    cache_path = nsrl.get_cache_path(str(src), str(tmp_path))

    built_count = nsrl.build_index(str(src), cache_path)
    assert nsrl.read_cached_count(cache_path) == built_count == len(known)


def test_prepare_nsrl_index_builds_then_reuses_cache(tmp_path, monkeypatch):
    known = [_random_sha1_hex() for _ in range(30)]
    src = tmp_path / "nsrl.txt"
    _write_plain_list(src, known)

    cache_path_1 = nsrl.prepare_nsrl_index(str(src), str(tmp_path))
    assert cache_path_1 is not None
    assert nsrl.read_cached_count(cache_path_1) == len(known)

    # Second call against the same, unchanged source should be a pure
    # cache-hit - assert build_index is NOT called again by making it raise
    # if it is.
    def _boom(*args, **kwargs):
        raise AssertionError("build_index should not run again for an unchanged source")

    monkeypatch.setattr(nsrl, "build_index", _boom)
    cache_path_2 = nsrl.prepare_nsrl_index(str(src), str(tmp_path))
    assert cache_path_2 == cache_path_1


def test_prepare_nsrl_index_blank_or_missing_path_returns_none(tmp_path):
    assert nsrl.prepare_nsrl_index("", str(tmp_path)) is None
    assert nsrl.prepare_nsrl_index(str(tmp_path / "nope.txt"), str(tmp_path)) is None


def test_lookup_correctness_at_larger_scale(tmp_path):
    """Not 72 million rows (that's what the real-world log data already
    validated timing-wise) - large enough to exercise numpy's sort/
    searchsorted path meaningfully rather than a handful of records where a
    bug could hide."""
    random.seed(1234)
    known = [_random_sha1_hex() for _ in range(20_000)]
    src = tmp_path / "nsrl.txt"
    _write_plain_list(src, known)
    cache_path = nsrl.get_cache_path(str(src), str(tmp_path))
    nsrl.build_index(str(src), cache_path)
    index = nsrl.open_index(cache_path)
    assert index.count == len(known)

    sample_known = random.sample(known, 200)
    for h in sample_known:
        assert h in index

    misses = 0
    for _ in range(200):
        candidate = _random_sha1_hex()
        if candidate in known:  # astronomically unlikely, but be exact
            continue
        if candidate in index:
            misses += 1
    assert misses == 0
