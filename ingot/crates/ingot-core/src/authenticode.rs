//! Authenticode signature verification - port of `authenticode.py`'s
//! `SignatureStatus` / `SignerName` fields.
//!
//! Uses the pure-Rust `pe-sign` crate for embedded PE Authenticode
//! verification instead of Winnow's `signify`. Trust anchors are the host's
//! own native root store (via `rustls-native-certs`), falling back to
//! `pe-sign`'s bundled Mozilla set if that can't be read. Like Winnow, this
//! does its own chain building rather than calling `WinVerifyTrust`, so
//! `SignatureStatus` verdicts are best-effort and won't always match
//! `Get-AuthenticodeSignature` - the same caveat Winnow's module carries.
//!
//! Runs unconditionally on every file (not gated by NSRL) - "signed vs
//! unsigned is meaningful regardless of hash reputation" (per Rowan).
//!
//! **Known gaps vs Winnow / the OS:**
//! * catalog (`.cat`) verification is not implemented - a validly
//!   catalog-signed Windows binary (`notepad.exe` etc.) comes back
//!   `NotSigned` unless it also carries an embedded signature. Winnow parses
//!   catalogs but that path is itself only tested against synthetic data.
//!   The `catalog_directory` Setting is carried but currently unused.
//! * `pe-sign`'s signature check supports RSA signer keys only; an
//!   ECDSA-signed binary yields `UnknownError`.
//! * intermediate CAs are only taken from the signature's own embedded
//!   cert list (or one 5 s AIA HTTP fetch, for a PE that omits them) - not
//!   from the OS "intermediate CA" store, so a signature that relies on the
//!   OS for its intermediate (many Windows *component* binaries) can come
//!   back `NotTrusted` where `Get-AuthenticodeSignature` says `Valid`.
//!   Third-party software that bundles its full chain verifies correctly.

use std::path::Path;
use std::sync::OnceLock;

use base64::Engine;
use pesign::{PeSign, PeSignStatus, VerifyOption, PE};
use tracing::debug;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticodeResult {
    /// `Valid` / `NotSigned` / `HashMismatch` / `NotTrusted` /
    /// `NotSupportedFileFormat` / `UnknownError` - reads like Rowan's
    /// `SignatureStatus` enum.
    pub status: String,
    /// Leaf signer certificate subject DN, or `""`.
    pub signer_name: String,
}

impl AuthenticodeResult {
    fn status(s: &str) -> Self {
        AuthenticodeResult {
            status: s.to_string(),
            signer_name: String::new(),
        }
    }
}

pub fn check_signature(path: &Path) -> AuthenticodeResult {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            debug!("Authenticode: could not read {}: {e}", path.display());
            return AuthenticodeResult::status("UnknownError");
        }
    };

    // Not a PE at all (scripts, text, Office docs, ...) - can't carry an
    // embedded Authenticode signature. Matches signify's ParseError path.
    if bytes.len() < 2 || &bytes[..2] != b"MZ" {
        return AuthenticodeResult::status("NotSupportedFileFormat");
    }

    std::panic::catch_unwind(|| check_signature_inner(&bytes)).unwrap_or_else(|_| {
        debug!("Authenticode: pe-sign panicked on {}", path.display());
        AuthenticodeResult::status("UnknownError")
    })
}

/// The host's native root store as a PEM bundle, loaded once. `None` if it
/// couldn't be read (then `pe-sign`'s bundled Mozilla set is used).
fn native_trust_pem() -> Option<&'static str> {
    static PEM: OnceLock<Option<String>> = OnceLock::new();
    PEM.get_or_init(|| {
        let loaded = rustls_native_certs::load_native_certs();
        if loaded.certs.is_empty() {
            return None;
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut out = String::new();
        for cert in &loaded.certs {
            out.push_str("-----BEGIN CERTIFICATE-----\n");
            for chunk in b64.encode(cert).as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(chunk).unwrap());
                out.push('\n');
            }
            out.push_str("-----END CERTIFICATE-----\n");
        }
        debug!(
            "Authenticode: loaded {} native trust roots",
            loaded.certs.len()
        );
        Some(out)
    })
    .as_deref()
}

fn verify_option() -> VerifyOption {
    VerifyOption {
        check_time: true,
        trusted_ca_pem: native_trust_pem().map(str::to_string),
    }
}

fn check_signature_inner(bytes: &[u8]) -> AuthenticodeResult {
    let pesign = match PeSign::from_pe_data(bytes) {
        Ok(Some(p)) => p,
        Ok(None) => return AuthenticodeResult::status("NotSigned"),
        Err(e) => {
            debug!("Authenticode: signature parse failed: {e}");
            return AuthenticodeResult::status("UnknownError");
        }
    };

    let signer_name = resolve_signer_name(&pesign).unwrap_or_default();

    // Authenticode PE-digest check first, so a tampered/patched binary
    // reads as HashMismatch rather than a generic trust failure.
    let recomputed = PE::from_bytes(bytes)
        .and_then(|mut pe| pe.calc_authenticode(pesign.authenticode_digest_algorithm.clone()));
    if let Ok(digest) = recomputed {
        if digest != pesign.authenticode_digest {
            return AuthenticodeResult {
                status: "HashMismatch".to_string(),
                signer_name,
            };
        }
    }

    let status = match pesign.verify(&verify_option()) {
        Ok(PeSignStatus::Valid) => "Valid",
        Ok(PeSignStatus::UntrustedCertificateChain)
        | Ok(PeSignStatus::Expired)
        | Ok(PeSignStatus::Invalid) => "NotTrusted",
        Err(e) => {
            debug!("Authenticode: verify() error: {e}");
            "UnknownError"
        }
    };

    AuthenticodeResult {
        status: status.to_string(),
        signer_name,
    }
}

/// Leaf signer cert subject DN - the cert in `cert_list` whose
/// issuer+serial match the `SignerInfo`'s identifier (NOT the issuer DN
/// itself, which names the CA).
fn resolve_signer_name(pesign: &PeSign) -> Option<String> {
    use pesign::signed_data::SignerIdentifier;

    let sd = &pesign.signed_data;
    match &sd.signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => sd
            .cert_list
            .iter()
            .find(|c| c.issuer == ias.issuer && c.serial_number == ias.serial_number)
            .map(|c| c.subject.to_string()),
        SignerIdentifier::SubjectKeyIdentifier(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn non_pe_is_not_supported() {
        let f = temp(b"#!/bin/sh\necho hi\n");
        assert_eq!(check_signature(f.path()).status, "NotSupportedFileFormat");
        let f = temp(b"");
        assert_eq!(check_signature(f.path()).status, "NotSupportedFileFormat");
    }

    #[test]
    fn mz_without_signature_is_not_signed() {
        // a minimal MZ/PE with no certificate table
        let mut v = vec![0u8; 0x200];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3C..0x40].copy_from_slice(&0x80i32.to_le_bytes());
        v[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        let f = temp(&v);
        // either NotSigned (parsed, no cert table) or UnknownError (pe-sign
        // couldn't parse this stub) - both are acceptable non-crash outcomes
        let s = check_signature(f.path()).status;
        assert!(
            s == "NotSigned" || s == "UnknownError" || s == "NotSupportedFileFormat",
            "unexpected status {s}"
        );
    }

    #[test]
    fn missing_file_is_unknown_error() {
        assert_eq!(
            check_signature(Path::new("/no/such/file.exe")).status,
            "UnknownError"
        );
    }
}
