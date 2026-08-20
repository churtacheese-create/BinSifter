"""Authenticode signature verification - Python port of the PowerShell
version's Get-AuthenticodeSignature-based SignatureStatus/SignerName fields
(see BinSifter-Rowan.ps1, around line 2141 - "run unconditionally
like entropy... since 'signed' vs 'unsigned' is meaningful regardless of
hash reputation").

Uses the `signify` library (pure Python, cross-platform PE/PKCS#7
Authenticode verification) instead of a Windows-only call to
Get-AuthenticodeSignature/WinVerifyTrust, since the goal is for the Python
rewrite to eventually support Linux too. This means BinSifter now does its
own trust-chain validation rather than deferring to the Windows certificate
store - see the caveats below on why SignatureStatus values won't map 1:1
to the old .NET SignatureStatus enum.

Verified against signify 0.9.2's docs (readthedocs):
  - AuthenticodeFile.from_stream(f) / .explain_verify() returns
    (AuthenticodeVerificationResult, Exception | None) - never raises.
  - A SignedData's `.certificates` (a CertificateStore) combined with
    SignerInfo.issuer + SignerInfo.serial_number via
    CertificateStore.find_certificate(issuer=..., serial_number=...) locates
    the exact leaf signing certificate. This is NOT the same as
    SignerInfo.issuer.dn itself - that property is the name of the CA that
    *issued* the signer's certificate, not the signer's own subject. Getting
    this backwards would silently put the wrong name in SignerName.
  - Certificate.subject.dn gives an RFC2253-ish DN string (e.g.
    "CN=Some Company, O=Some Company Inc, C=US") - the closest Python
    equivalent to .NET's X509Certificate2.Subject used by the PowerShell
    version's SignerCertificate.Subject. Exact formatting can differ in
    edge cases (RDN ordering/escaping come from two different DN
    renderers), but the informational content is the same.

SignatureStatus values are chosen to read the same as the PowerShell
version's SignatureStatus enum (Valid/NotSigned/HashMismatch/NotTrusted/
NotSupportedFileFormat/UnknownError) wherever there's a reasonable
correspondence - see _STATUS_MAP - but this is a best-effort mapping, not a
guarantee of identical verdicts: signify validates against its own trust
store rather than the OS's, so edge-case verdicts can still diverge from
what Get-AuthenticodeSignature would have said on the same file.

Trust store: `AuthenticodeSignature.verify()` defaults
`trusted_certificate_store` to TRUSTED_CERTIFICATE_STORE, a real, populated
CombinedCertificateStore built from the `mscerts` package (Microsoft's
official Authenticode Certificate Trust List plus cacert.pem).
check_signature() below calls `explain_verify()` with no override, so this
default is what's actually used - BinSifter gets real trust-chain
validation for embedded signatures with no extra wiring. Not yet spot-
checked against a genuinely signed PE on real Windows hardware (only
signify's own test suite, which asserts the same zero-argument default
resolves to "Valid" against real Microsoft/vendor-signed executables).

The separate catalog-signing gap noted at the bottom of this file (system
binaries validated via .cat files rather than an embedded signature) is a
distinct, still-real limitation.
"""

from __future__ import annotations

import dataclasses
import functools
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult  # noqa: F401
    from signify.authenticode.trust_list import CertificateTrustList
    from signify.exceptions import ParseError as _SignifyParseError

    _SIGNIFY_AVAILABLE = True
except ImportError:  # signify not installed - degrade to UnknownError, don't crash the scan
    _SIGNIFY_AVAILABLE = False

if _SIGNIFY_AVAILABLE:
    # Performance fix for signify 0.9.2 itself, not BinSifter's own code.
    # A 652-file scan with CatalogDirectory pointed at a real Windows
    # CatRoot folder (5730 .cat files) showed authenticode checks eating
    # 92.5% of worker CPU time, averaging 61.8s/file - roughly 400x slower
    # than hashing or YARA on the same files.
    #
    # check_signature() below calls add_catalog(catalog, check=True) once
    # per configured catalog per file (up to 5730 times here), and each
    # call's find_subject() reads CertificateTrustList._subjects /
    # ._subjects_by_indirect_data_hash - plain @property in signify's
    # source, with no caching, that re-decodes every ASN.1 entry in the
    # catalog from scratch on every access. So the same catalog's subject
    # list was being fully re-parsed on every single find_subject() call,
    # even though parse_catalogs() only parses each .cat file's raw bytes
    # once per worker - the re-parse was happening one level deeper than
    # that reuse could prevent.
    #
    # Fixed by monkeypatching these two properties to
    # functools.cached_property, which computes once per instance and
    # reuses the result. Safe because every CertificateTrustList instance
    # here is long-lived (parsed once per worker, reused for the rest of
    # the scan - see parse_catalogs()), so a catalog's trusted-subjects
    # list cannot change out from under an already-parsed object. This
    # patches the installed library's class directly rather than vendoring
    # a fork; CertificateTrustList has no __slots__, so cached_property's
    # normal per-instance __dict__ caching works unmodified. Runs once at
    # import time in every worker process, before any file is scanned.
    def _patch_signify_trust_list_caching() -> None:
        for attr in ("_subjects", "_subjects_by_indirect_data_hash"):
            current = CertificateTrustList.__dict__.get(attr)
            if isinstance(current, property) and current.fget is not None:
                cached = functools.cached_property(current.fget)
                cached.__set_name__(CertificateTrustList, attr)
                setattr(CertificateTrustList, attr, cached)

    _patch_signify_trust_list_caching()

    # A second, distinct signify 0.9.2 performance bug: a single large PE
    # (WindowsXP-KB936929-SP3-x86-RUS.exe) took 2299.4s (38+ minutes) for its
    # authenticode check alone, blowing through the scan's 1200s stall
    # watchdog. The fix above only cached the catalog side of add_catalog();
    # this is the other half. Each add_catalog() call's find_subject() does
    # subject.get_fingerprint(self.subject_algorithm), where "subject" is
    # the same signed_file object every time. SignedPEFile.get_fingerprint()
    # (and the MSI/flat-signature equivalents) build a brand-new
    # Fingerprinter and re-hash the entire file from disk on every call -
    # unlike the neighbouring page_size property, which IS cached. So a big
    # file was being re-hashed from scratch once per catalog:
    # O(catalogs x filesize) instead of O(filesize + catalogs).
    #
    # Fixed the same way as above (monkeypatching the installed library),
    # but since the three concrete AuthenticodeFile subclasses (PE/MSI/flat)
    # each implement get_fingerprint() independently, each is wrapped with a
    # small per-instance cache keyed on the call arguments, so a genuinely
    # different digest algorithm or byte range still computes fresh - only a
    # repeat of the same request is served from cache. A single
    # AuthenticodeFile instance is created once per file in check_signature()
    # and reused for every catalog in that file's loop, so this caching is
    # scoped correctly.
    def _patch_signify_fingerprint_caching() -> None:
        from signify.authenticode.signed_file.flat import FlatFile
        from signify.authenticode.signed_file.msi import SignedMsiFile
        from signify.authenticode.signed_file.pe import SignedPEFile

        for cls in (SignedPEFile, SignedMsiFile, FlatFile):
            original = cls.__dict__.get("get_fingerprint")
            if original is None or getattr(original, "_bs_cached", False):
                continue

            @functools.wraps(original)
            def _cached_get_fingerprint(self, *args, _original=original, **kwargs):
                cache = self.__dict__.setdefault("_bs_fingerprint_cache", {})
                key = (args, tuple(sorted(kwargs.items())))
                if key not in cache:
                    cache[key] = _original(self, *args, **kwargs)
                return cache[key]

            _cached_get_fingerprint._bs_cached = True
            cls.get_fingerprint = _cached_get_fingerprint

    _patch_signify_fingerprint_caching()


@dataclasses.dataclass
class AuthenticodeResult:
    status: str  # mirrors the PowerShell version's SignatureStatus enum, as a string
    signer_name: str  # "" if unsigned, unavailable, or not resolvable


# signify's AuthenticodeVerificationResult name -> BinSifter/.NET-style status string.
# See the module docstring for why this is a best-effort mapping, not an exact one.
_STATUS_MAP = {
    "OK": "Valid",
    "NOT_SIGNED": "NotSigned",
    "PARSE_ERROR": "NotSupportedFileFormat",
    "INVALID_DIGEST": "HashMismatch",
    "CERTIFICATE_ERROR": "NotTrusted",
    "VERIFY_ERROR": "NotTrusted",
    "INCONSISTENT_DIGEST_ALGORITHM": "UnknownError",
    "UNKNOWN_ERROR": "UnknownError",
    "COUNTERSIGNER_ERROR": "NotTrusted",
    "INVALID_ADDITIONAL_HASH": "HashMismatch",
}


def parse_catalogs(catalog_directory: str) -> list["CertificateTrustList"]:
    """Parses every *.cat file directly under catalog_directory into a
    CertificateTrustList, once - see engine.py's _pool_worker_init(), which
    calls this exactly once per worker process at startup and hands the
    result to every check_signature() call that worker makes afterward,
    the same reuse-not-reparse pattern already used there for compiled YARA
    rules (a native library handle isn't safely shareable across a process
    boundary either way, so "parse once per worker" is the right unit
    regardless).

    Returns an empty list (never raises) for a blank/missing/empty
    directory - catalog checking is opt-in, matching CatalogDirectory's
    default "" in config.py. A single malformed .cat is logged and skipped
    rather than aborting the whole batch, since one bad file in what could
    be a large CatRoot-style directory shouldn't silently disable catalog
    checking for every other, valid one.

    Also checks one level of subdirectories if catalog_directory itself has
    no *.cat files directly in it. Windows' real catalog store is
    C:\\Windows\\System32\\CatRoot\\{GUID}\\*.cat - the .cat files live one
    level below CatRoot in a versioned GUID subfolder, not directly inside
    CatRoot. Pointing CatalogDirectory at the bare CatRoot folder (the more
    natural first guess) used to silently find zero catalogs with no
    warning, meaning catalog-signed system binaries landed in the wrong
    status unnoticed. Checking one subdirectory level (not a full recursive
    walk, to avoid a footgun if CatalogDirectory is pointed at something
    large) makes both the bare CatRoot folder and its GUID subfolder work.
    """
    if not _SIGNIFY_AVAILABLE or not catalog_directory:
        return []

    directory = Path(catalog_directory)
    if not directory.is_dir():
        logger.warning("CatalogDirectory does not exist or is not a directory: %s", catalog_directory)
        return []

    cat_paths = sorted(directory.glob("*.cat"))
    if not cat_paths:
        cat_paths = sorted(directory.glob("*/*.cat"))

    catalogs: list[CertificateTrustList] = []
    for cat_path in cat_paths:
        try:
            with open(cat_path, "rb") as f:
                catalogs.append(CertificateTrustList.from_envelope(f.read()))
        except Exception as exc:  # noqa: BLE001 - one bad catalog shouldn't disable the rest
            logger.warning("Could not parse catalog file %s: %s", cat_path, exc)

    logger.info("Loaded %d catalog file(s) from %s", len(catalogs), catalog_directory)
    return catalogs


def check_signature(path: str, catalogs: "list[CertificateTrustList] | None" = None) -> AuthenticodeResult:
    """Best-effort Authenticode check - never raises. Any parse/verify
    failure folds into status="UnknownError", mirroring the PowerShell
    version's own try/catch around Get-AuthenticodeSignature (see line 2153:
    `catch { $record.SignatureStatus = 'UnknownError' }`).

    catalogs: pre-parsed CertificateTrustList objects from
    parse_catalogs(), already loaded once per worker process - not
    reparsed here per file. When provided, each is offered to this file via
    add_catalog(..., check=True), which hashes the file according to the
    catalog's own digest scheme and only actually attaches the catalog if
    this file's hash is listed in it (find_subject() internally) - so
    passing every configured catalog to every file is safe and cheap; only
    matching catalogs end up contributing to the verification result.
    Wired into iter_signatures()'s default signature_types="all" for free -
    explain_verify() below needs no other changes to pick these up.
    """
    if not _SIGNIFY_AVAILABLE:
        return AuthenticodeResult(status="UnknownError", signer_name="")

    try:
        with open(path, "rb") as f:
            signed_file = AuthenticodeFile.from_stream(f)
            for catalog in catalogs or ():
                try:
                    signed_file.add_catalog(catalog, check=True)
                except Exception as exc:  # noqa: BLE001 - a catalog-matching failure shouldn't sink the whole check
                    logger.debug("add_catalog() failed for %s: %s", path, exc)
            result, _exc = signed_file.explain_verify()
            status = _STATUS_MAP.get(result.name, "UnknownError")

            signer_name = _resolve_signer_name(signed_file, path)
            return AuthenticodeResult(status=status, signer_name=signer_name)
    except _SignifyParseError as exc:
        # AuthenticodeFile.from_stream() raises this (explain_verify()'s own
        # PARSE_ERROR -> NotSupportedFileFormat path is never reached) when
        # the file isn't a format signify recognizes - e.g. plain scripts
        # (.bat/.cmd/.ps1) or Office macro docs (.docm), which aren't a
        # PE/MSI/flat-signature container signify can open. Map explicitly
        # to NotSupportedFileFormat rather than falling through to the
        # generic except below, which would read as "the tool failed"
        # instead of "this file type can't carry an Authenticode signature".
        logger.debug("Authenticode: unrecognized file format for %s: %s", path, exc)
        return AuthenticodeResult(status="NotSupportedFileFormat", signer_name="")
    except Exception as exc:  # noqa: BLE001 - matches the PowerShell catch-all -> UnknownError
        logger.debug("Authenticode check failed for %s: %s", path, exc)
        return AuthenticodeResult(status="UnknownError", signer_name="")


def _resolve_signer_name(signed_file, path: str) -> str:
    """Pulls the leaf signer certificate's subject DN out of the first
    embedded signature, if any. Kept separate from check_signature() and
    wrapped in its own try/except since a signer-name lookup failure (e.g.
    the embedded certificate list doesn't contain an exact issuer+serial
    match - has been observed in the wild for malformed/adversarial
    signatures) shouldn't blank out a SignatureStatus we already determined.
    """
    try:
        signature = next(iter(signed_file.signatures), None)
        if signature is None:
            return ""
        # AuthenticodeSignature/CertificateTrustList both expose .certificates
        # + .signer_info per signify's SignedData base class; guard with
        # getattr rather than isinstance since CertificateTrustList entries
        # (catalog-based signing) don't carry a single unambiguous signer.
        certificates = getattr(signature, "certificates", None)
        signer_info = getattr(signature, "signer_info", None)
        if certificates is None or signer_info is None:
            return ""
        cert = certificates.find_certificate(
            issuer=signer_info.issuer, serial_number=signer_info.serial_number
        )
        return cert.subject.dn
    except Exception:  # noqa: BLE001 - signer name is best-effort metadata, not the primary verdict
        logger.debug("Could not resolve signer certificate subject for %s", path, exc_info=True)
        return ""


# Catalog-based system binaries: a large fraction of Windows' own inbox
# binaries (notepad.exe, calc.exe, etc.) aren't embedded-signed - they're
# validated against a system catalog file (.cat, under
# C:\Windows\System32\CatRoot\) instead. Get-AuthenticodeSignature checks
# catalogs transparently via WinVerifyTrust, but this signify-based module
# only checks each file's embedded PE certificate table unless catalogs are
# supplied, so a validly-signed Windows binary can come back "NotSigned"
# without CatalogDirectory configured.
#
# Handled via parse_catalogs()/check_signature()'s `catalogs` parameter:
# engine.py's _pool_worker_init() parses every *.cat file under
# config.CatalogDirectory once per worker, and check_signature() offers
# each to AuthenticodeFile.add_catalog(..., check=True) before
# explain_verify(). CatalogDirectory defaults to "" (opt-in, like
# GhidraDir). Plumbing is covered by tests against synthetic data; not yet
# exercised against a real catalog end-to-end - to do that, drop a real
# .cat (e.g. copied from C:\Windows\System32\CatRoot\{GUID}\) into the
# gitignored Catalogs/ folder and point Settings' "Catalog Directory" at it.
