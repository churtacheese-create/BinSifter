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


# ---------- parse_catalogs() / check_signature()'s catalogs param (2026-08-08) ----------
#
# No genuine .cat file was obtainable for this pass - no Windows machine in
# this sandbox, and GitHub's raw/API/codeload endpoints (the most likely
# source: signify's own test fixtures) are all blocked by this
# environment's network allowlist; see authenticode.py's RESOLVED
# 2026-08-08 note. These tests cover the plumbing - parse_catalogs()'s
# directory handling, and check_signature()'s add_catalog() wiring/error
# handling - against synthetic/mocked data rather than a real catalog.
# Genuinely exercising catalog verification end-to-end is still pending a
# real .cat landing in Catalogs/ (gitignored - see .gitignore and
# Catalogs/README.txt).

def test_parse_catalogs_blank_directory_returns_empty_list():
    assert authenticode.parse_catalogs("") == []


def test_parse_catalogs_missing_directory_returns_empty_list(tmp_path):
    missing = tmp_path / "does-not-exist"
    assert authenticode.parse_catalogs(str(missing)) == []


def test_parse_catalogs_empty_directory_returns_empty_list(tmp_path):
    assert authenticode.parse_catalogs(str(tmp_path)) == []


def test_parse_catalogs_ignores_non_cat_files(tmp_path):
    (tmp_path / "notes.txt").write_text("not a catalog")
    assert authenticode.parse_catalogs(str(tmp_path)) == []


def test_parse_catalogs_skips_malformed_cat_file_without_raising(tmp_path):
    # A .cat file is a PKCS#7/ASN.1 envelope - garbage bytes should be
    # logged and skipped, not crash the whole scan over one bad file.
    (tmp_path / "broken.cat").write_bytes(b"this is not a valid PKCS7 envelope")
    assert authenticode.parse_catalogs(str(tmp_path)) == []


def test_parse_catalogs_path_that_is_a_file_not_a_directory_returns_empty_list(tmp_path):
    a_file = tmp_path / "some.cat"
    a_file.write_bytes(b"irrelevant")
    # CatalogDirectory is documented as a directory, not a single file -
    # passing a file path should degrade gracefully (empty list), not raise.
    assert authenticode.parse_catalogs(str(a_file)) == []


class _FakeCatalogResult:
    def __init__(self, name):
        self.name = name


class _FakeSignedFile:
    """Stands in for a real AuthenticodeFile - just enough surface
    (add_catalog/explain_verify) for check_signature() to run its full
    control flow without needing a genuine PE/PKCS7 parse."""

    def __init__(self, explain_result="NOT_SIGNED", raise_on_catalog=None):
        self.added_catalogs = []
        self._explain_result = explain_result
        self._raise_on_catalog = raise_on_catalog
        self.signatures = []

    def add_catalog(self, catalog, check=False):
        if self._raise_on_catalog is not None and catalog is self._raise_on_catalog:
            raise RuntimeError("simulated add_catalog failure")
        self.added_catalogs.append((catalog, check))

    def explain_verify(self):
        return _FakeCatalogResult(self._explain_result), None


def test_check_signature_offers_every_provided_catalog(tmp_path, monkeypatch):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 62)

    fake_file = _FakeSignedFile(explain_result="OK")
    monkeypatch.setattr(
        authenticode.AuthenticodeFile, "from_stream", staticmethod(lambda f: fake_file)
    )

    catalog_a = object()
    catalog_b = object()
    result = authenticode.check_signature(str(target), catalogs=[catalog_a, catalog_b])

    assert result.status == "Valid"
    assert fake_file.added_catalogs == [(catalog_a, True), (catalog_b, True)]


def test_check_signature_survives_a_catalog_that_raises(tmp_path, monkeypatch):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 62)

    bad_catalog = object()
    good_catalog = object()
    fake_file = _FakeSignedFile(explain_result="NOT_SIGNED", raise_on_catalog=bad_catalog)
    monkeypatch.setattr(
        authenticode.AuthenticodeFile, "from_stream", staticmethod(lambda f: fake_file)
    )

    # Should not raise even though bad_catalog's add_catalog() blows up -
    # the good catalog should still get offered, and check_signature()
    # should still return a real result rather than folding into
    # UnknownError over one bad catalog.
    result = authenticode.check_signature(str(target), catalogs=[bad_catalog, good_catalog])

    assert result.status == "NotSigned"
    assert fake_file.added_catalogs == [(good_catalog, True)]


def test_check_signature_with_no_catalogs_argument_is_unchanged(tmp_path, monkeypatch):
    """catalogs defaults to None - existing callers (and the pre-2026-08-08
    behavior) must be unaffected."""
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 62)

    fake_file = _FakeSignedFile(explain_result="OK")
    monkeypatch.setattr(
        authenticode.AuthenticodeFile, "from_stream", staticmethod(lambda f: fake_file)
    )

    result = authenticode.check_signature(str(target))
    assert result.status == "Valid"
    assert fake_file.added_catalogs == []


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


def test_certificate_trust_list_subjects_are_cached_not_reparsed_every_call():
    """2026-08-17: regression guard for a real, severe performance bug found
    via a real 652-file FLARE VM scan's per-stage timing summary -
    authenticode averaged 61.8 SECONDS per file (92.5% of all worker CPU
    time) once CatalogDirectory pointed at a real Windows CatRoot folder
    (5730 real .cat files). Root cause traced to signify 0.9.2 itself, not
    BinSifter's own code: CertificateTrustList._subjects and
    ._subjects_by_indirect_data_hash (both used by find_subject(), which
    add_catalog(catalog, check=True) calls once per catalog per file - see
    signify/authenticode/signed_file/base.py's add_catalog()) are plain
    @property with no caching at all, so the full ASN.1 trusted_subjects
    decode was being repeated on literally every single find_subject() call,
    even though the exact same CertificateTrustList object is intentionally
    reused for every file in a worker's queue (parse_catalogs() already only
    reads each .cat file's raw bytes once per worker - this was a second,
    hidden re-parse happening one level deeper that reuse never prevented).

    authenticode.py patches both properties to functools.cached_property at
    import time - this confirms that patch is actually in effect and doing
    its job: repeated access to _subjects on the SAME instance must only
    trigger the underlying (expensive) .subjects decode once, not once per
    access. Uses a minimal CertificateTrustList subclass that skips the
    real ASN.1 __init__ entirely and replaces .subjects with a call-counting
    stub - the goal here is pinning down the caching behavior itself, not
    re-testing ASN.1 parsing (which signify's own test suite already
    covers).
    """
    from signify.authenticode.trust_list import CertificateTrustList

    call_count = {"n": 0}

    class _CountingCatalog(CertificateTrustList):
        def __init__(self):
            pass  # deliberately skip the real (ASN.1-parsing) __init__

        @property
        def subjects(self):
            call_count["n"] += 1
            return []

    catalog = _CountingCatalog()
    for _ in range(5):
        _ = catalog._subjects
        _ = catalog._subjects_by_indirect_data_hash

    # Without the fix this would be 10 (5 accesses x 2 properties, each
    # re-running .subjects's decode every time) - the whole point of the fix
    # is that a SECOND catalog instance still recomputes fresh (correctness:
    # no cross-instance leakage) while repeat access on the SAME instance
    # does not (performance: the actual bug).
    assert call_count["n"] <= 2

    call_count["n"] = 0
    second_catalog = _CountingCatalog()
    _ = second_catalog._subjects
    assert call_count["n"] == 1
