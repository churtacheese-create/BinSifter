"""Authenticode signature verification - TODO, not yet ported.

The PowerShell version got this for free from the built-in
Get-AuthenticodeSignature cmdlet - a Windows-only API with no direct
cross-platform equivalent, which is exactly the kind of thing that was
invisible as "free" functionality until the Linux support goal made it
visible as real work.

Candidate: the `signify` package (pure Python Authenticode parser/
verifier, not yet added to pyproject.toml - deliberately not pulled in
until its API is actually verified against a signed test binary, same
caution as capa/floss/speakeasy above). Do not guess at signify's method
signatures here; read its own usage docs first.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SignatureResult:
    status: str  # mirrors the PowerShell version's SignatureStatus strings:
                  # Valid/NotSigned/HashMismatch/NotTrusted/
                  # NotSupportedFileFormat/UnknownError
    signer_name: str


def verify_signature(target_path: str) -> SignatureResult:
    raise NotImplementedError(
        "Authenticode verification not yet ported - see module docstring."
    )
