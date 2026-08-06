"""Smoke tests for binsifter.core.authenticode - run with `pytest` once the
dev extras are installed (`pip install -e ".[dev]"`).

These deliberately don't assert "Valid" against a real signed binary here -
that needs a genuinely Authenticode-embedded-signed sample, which isn't
available in this (Linux, no Windows binaries) dev sandbox. See
authenticode.py's module docstring for the 2026-08-06 correction: contrary
to what this file previously claimed, BinSifter does NOT need to wire up
its own root CA trust store - signify's AuthenticodeSignature.verify()
already defaults to a real, populated Microsoft trust store
(TRUSTED_CERTIFICATE_STORE, via the `mscerts` package), and check_signature()
never overrides that default. So "Valid" is the expected result for a
genuinely embedded-signed file with an intact chain, same as
Get-AuthenticodeSignature - "NotTrusted" should now be rare, not the norm.
"NotSigned" is still expected and correct for catalog-signed-only files
(most Windows inbox binaries) since only embedded signatures are checked -
see the separate, still-open TODO on that.

What these tests pin down is the behavior that must never regress: the
function never raises, a garbage/non-PE file degrades to a sane status
rather than blowing up the whole scan, and the trust store BinSifter is
relying on for that "Valid" behavior is actually populated.
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
    # the codebase (dashboard "Signed" tile predicate, CSV column, etc.)
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


def test_unparseable_format_is_not_supported_not_unknown_error(tmp_path):
    """2026-08-06: found via a real scan (652 files, 187 landed in
    UnknownError - see TODO.md). Most of those turned out to be file types
    signify has no parser for at all (.bat/.cmd/.ps1/.docm) - a plain-text
    batch script is the cleanest repro, since it's guaranteed not to be a
    PE/MSI/flat-signature-file signify recognizes, so AuthenticodeFile.
    from_stream() raises signify.exceptions.ParseError before explain_verify()
    is ever reached. That's now caught specifically and mapped to
    NotSupportedFileFormat (already an existing, documented status) instead
    of falling through to the generic except -> UnknownError, which used to
    make "this format literally can't carry an Authenticode signature" read
    identically to "something actually broke."
    """
    script = tmp_path / "not_a_pe.bat"
    script.write_bytes(b"@echo off\r\necho hello world\r\n")

    result = authenticode.check_signature(str(script))

    assert result.status == "NotSupportedFileFormat"
    assert result.signer_name == ""


def test_default_trust_store_is_actually_populated():
    """2026-08-06: regression guard for the trust-store correction described
    in authenticode.py's module docstring. check_signature() relies entirely
    on signify's AuthenticodeSignature.verify() default
    (`trusted_certificate_store=TRUSTED_CERTIFICATE_STORE`) to get real
    trust-chain validation - it never builds or passes its own store. This
    doesn't exercise check_signature() itself (that needs a real embedded-
    signed PE, not available in this sandbox), but it pins down the one
    thing that would silently break "Valid" results for everyone if the
    `mscerts` package ever failed to install/load correctly or signify
    changed its default: the store BinSifter is implicitly depending on
    must contain real root certificates, not be empty.
    """
    from signify.authenticode import TRUSTED_CERTIFICATE_STORE

    certs = list(TRUSTED_CERTIFICATE_STORE)
    assert len(certs) > 0
    assert any("Microsoft" in cert.subject.dn for cert in certs)
