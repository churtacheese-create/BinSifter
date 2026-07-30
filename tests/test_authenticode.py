"""Smoke tests for binsifter.core.authenticode - run with `pytest` once the
dev extras are installed (`pip install -e ".[dev]"`).

These deliberately don't assert "Valid" against any real signed binary: as
documented in authenticode.py's own TODOs, BinSifter doesn't yet populate a
real root CA trust store, and most Windows inbox binaries are catalog- not
embedded-signed - so "NotTrusted"/"NotSigned" are the expected, correct
results today, not failures. What these tests actually pin down is the
behavior that must never regress: the function never raises, and a
garbage/non-PE file degrades to a sane status rather than blowing up the
whole scan.
"""

from binsifter.core import authenticode


def test_check_signature_never_raises_on_garbage_input(tmp_path):
    sample = tmp_path / "not_a_pe.bin"
    sample.write_bytes(b"this is definitely not a PE file or PKCS#7 blob")

    result = authenticode.check_signature(str(sample))

    assert result.status in authenticode._STATUS_MAP.values() or result.status == "UnknownError"
    assert result.signer_name == ""


def test_check_signature_missing_file_degrades_to_unknown_error(tmp_path):
    missing = tmp_path / "does_not_exist.exe"

    result = authenticode.check_signature(str(missing))

    assert result.status == "UnknownError"
    assert result.signer_name == ""


def test_status_map_only_contains_documented_values():
    # Guards against a typo silently introducing a status string the rest of
    # the codebase (dashboard "Unsigned" tile predicate, CSV column, etc.)
    # doesn't recognize - see the PowerShell version's SignatureStatus enum.
    expected_values = {
        "Valid",
        "NotSigned",
        "HashMismatch",
        "NotTrusted",
        "NotSupportedFileFormat",
        "UnknownError",
    }
    assert set(authenticode._STATUS_MAP.values()) <= expected_values


def test_signify_unavailable_degrades_gracefully(monkeypatch):
    monkeypatch.setattr(authenticode, "_SIGNIFY_AVAILABLE", False)

    result = authenticode.check_signature(__file__)

    assert result.status == "UnknownError"
    assert result.signer_name == ""
