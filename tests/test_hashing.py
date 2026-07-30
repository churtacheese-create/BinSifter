"""Smoke tests for binsifter.core.hashing - run with `pytest` once the dev
extras are installed (`pip install -e ".[dev]"`).
"""

import hashlib

from binsifter.core.hashing import hash_and_score_file


def test_hash_and_score_file(tmp_path):
    content = b"BinSifter test content for hashing verification\x00\x01\x02"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(content)

    result = hash_and_score_file(str(sample))

    assert result.md5 == hashlib.md5(content).hexdigest()
    assert result.sha1 == hashlib.sha1(content).hexdigest()
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.length == len(content)
    # Not a fixed expected value (that would just re-implement the entropy
    # formula in the test) - just sanity-check it's in the valid 0-8 range
    # and isn't the "not computed" sentinel for non-empty content.
    assert 0.0 <= result.entropy <= 8.0


def test_zero_length_file_entropy_is_sentinel(tmp_path):
    sample = tmp_path / "empty.bin"
    sample.write_bytes(b"")

    result = hash_and_score_file(str(sample))

    assert result.entropy == -1.0
    assert result.length == 0
