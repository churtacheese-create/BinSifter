"""Authenticode signature verification - Python port of the PowerShell
version's Get-AuthenticodeSignature-based SignatureStatus/SignerName fields
(see BinSifter_v1.3.0-alpha.2.ps1, around line 2141 - "run unconditionally
like entropy... since 'signed' vs 'unsigned' is meaningful regardless of
hash reputation").

Uses the `signify` library (pure Python, cross-platform PE/PKCS#7
Authenticode verification) instead of a Windows-only call to
Get-AuthenticodeSignature/WinVerifyTrust, since Steve wants the Python
rewrite to eventually support Linux too. This means BinSifter now does its
own trust-chain validation rather than deferring to the Windows certificate
store - see the caveats below on why SignatureStatus values won't map 1:1
to the old .NET SignatureStatus enum.

API verified 2026-07-30 directly against signify's own docs (readthedocs,
stable = 0.9.2) rather than guessed from memory or training-data recall,
given how easy it is to get security-relevant verification code subtly
wrong:
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
    version's SignerCertificate.Subject. The exact string formatting can
    differ in edge cases (RDN ordering/escaping come from two different DN
    renderers), but the informational content is the same.

SignatureStatus values are chosen to read the same as the PowerShell
version's SignatureStatus enum (Valid/NotSigned/HashMismatch/NotTrusted/
NotSupportedFileFormat/UnknownError) wherever there's a reasonable
correspondence - see _STATUS_MAP - but this is a best-effort mapping, not a
guarantee of identical verdicts: signify validates against its own trust
store (which BinSifter does not yet populate with a real root CA bundle -
see the TODO at the bottom of this file), while Get-AuthenticodeSignature
validated against Windows' own certificate store. Until BinSifter ships a
real trust store, expect every otherwise-valid signature to come back as
"NotTrusted" rather than "Valid" - this is a known, deliberate gap, not a
bug.
"""

from __future__ import annotations

import dataclasses
import logging

logger = logging.getLogger(__name__)

try:
    from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult  # noqa: F401

    _SIGNIFY_AVAILABLE = True
except ImportError:  # signify not installed - degrade to UnknownError, don't crash the scan
    _SIGNIFY_AVAILABLE = False


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


def check_signature(path: str) -> AuthenticodeResult:
    """Best-effort Authenticode check - never raises. Any parse/verify
    failure folds into status="UnknownError", mirroring the PowerShell
    version's own try/catch around Get-AuthenticodeSignature (see line 2153:
    `catch { $record.SignatureStatus = 'UnknownError' }`).
    """
    if not _SIGNIFY_AVAILABLE:
        return AuthenticodeResult(status="UnknownError", signer_name="")

    try:
        with open(path, "rb") as f:
            signed_file = AuthenticodeFile.from_stream(f)
            result, _exc = signed_file.explain_verify()
            status = _STATUS_MAP.get(result.name, "UnknownError")

            signer_name = _resolve_signer_name(signed_file, path)
            return AuthenticodeResult(status=status, signer_name=signer_name)
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


# TODO: BinSifter doesn't populate a real root CA trust store yet, so every
# chain currently resolves as untrusted even for genuinely Microsoft-signed
# system binaries - expect SignatureStatus="NotTrusted" across the board
# until this is addressed, not "Valid". Options once this matters for real
# triage: (1) point a FileSystemCertificateStore at the OS's own trusted-root
# bundle (platform-specific: Windows cert store export vs. Linux ca-
# certificates), or (2) ship a bundled root store similar to how browsers do.
# Deliberately not guessed at here - needs a real decision on which roots to
# trust and how they get onto disk, same "ask before assuming" pattern as
# every other open design question in this codebase.
#
# SEPARATE, likely more visible gap: a large fraction of Windows' own inbox
# system binaries (notepad.exe, calc.exe, etc.) are NOT embedded-signed at
# all - they're validated against a system catalog file (.cat, under
# C:\Windows\System32\CatRoot\) instead. Get-AuthenticodeSignature checks
# catalogs transparently via WinVerifyTrust; this module currently only
# checks each file's own embedded PE certificate table
# (AuthenticodeFile.iter_signatures(signature_types="embedded"), the
# default), so expect plenty of real, validly-signed Windows binaries to
# come back "NotSigned" here rather than "Valid" - that is a known
# difference in what's being checked, not a detection bug. signify supports
# catalog verification via AuthenticodeFile.add_catalog(), but that requires
# locating and loading the right .cat file(s) first, which has no BinSifter
# config field yet (same category of gap as capa's FLIRT sigpaths TODO in
# capa_scan.py) - flagged here rather than silently left to surprise
# whoever first notices "but Explorer says this file is signed".
