# BinSifter Ingot

Ingot is BinSifter's third variant, and the one actually intended to be cross-platform. The phased port of the detection pipeline is complete; it builds and runs today on Linux, macOS, and Windows.

## Why Ingot exists

Rowan (PowerShell/WinForms) is Windows-only by nature of its toolkit. Winnow (Python/PySide6) is now deliberately Linux-focused rather than a generic "runs everywhere" build, after real cross-platform desktop-toolkit issues (DPI scaling, dark-mode detection, a Linux-only window-resize bug) made clear that chasing true cross-platform parity through a desktop GUI toolkit is its own ongoing cost. Rather than asking either existing variant to also become the cross-platform answer, Ingot is planned from the start as the variant built to actually be cross-platform, by sidestepping desktop GUI toolkits entirely.

## Architecture

- **Rust backend service** on [axum](https://github.com/tokio-rs/axum) - runs the same detection pipeline design as Rowan/Winnow (hashing, NSRL, YARA, capa, FLOSS, etc.), exposed over a local HTTP API. Split into an `ingot-core` engine crate (no HTTP, no UI) and an `ingot-server` crate.
- **Web-based UI** instead of a desktop GUI toolkit - a browser tab is inherently cross-platform without per-OS toolkit quirks.
- Static frontend assets embedded directly into the compiled binary via `rust-embed`, so there's still just one binary to distribute, not a backend plus a separately-deployed frontend.
- Bound to `127.0.0.1` only, with no authentication - it's a local analyst tool, not a multi-user service, so there's no legitimate remote-access case to design around.
- The YARA engine is `yara-x` (pure Rust, VirusTotal's libyara successor); capa and FLOSS are Mandiant's official standalone binaries, downloaded per-user on first use. No system packages, no admin.

## Status

**Phases 1-8 complete - the phased port is finished.** The code is in [`ingot/`](../ingot/):
a Cargo workspace with an `ingot-core` scan-engine crate and an
`ingot-server` crate that runs the axum service and embeds the browser UI.
Working today: recursive file enumeration, archive expansion (zip incl.
WinZip AES / tar / gzip / 7z, nested, with a password round-trip over the
API), a single-pass MD5/SHA-1/SHA-256 + Shannon entropy read, Authenticode
signature verification (embedded PE signatures, pure-Rust, against the
host's native trust store), NSRL known-good lookup (cached and
memory-mapped, using the same on-disk cache format as Rowan/Winnow so
caches are interchangeable), the offline known-bad blocklist, the PE import
hash (imphash, reproduced byte-for-byte against pefile), an SSDEEP fuzzy
hash (byte-for-byte against ppdeep), YARA matching on `yara-x` with
severity scoring and MITRE ATT&CK technique enrichment, PE/ELF/shellcode
classification, capa capability detection on YARA-flagged binaries with a
FLOSS string + IOC-extraction fallback (Mandiant's official standalone
binaries, downloaded per-user - no admin), post-scan SSDEEP + imphash
clustering and a draft YARA rule per SSDEEP cluster, triage disposition
tracking (persisted by SHA-1, editable in the Results grid), the four
37-column CSV reports, a right-click quick-launch tool menu on the Results
grid scoped automatically to whichever OS Ingot is running on (the service
knows its own platform, so there's no install-time question), Ghidra
headless analysis, and a Markdown/JSON "export for AI analysis" - all wired
into a live-progress web UI and, at every stage, cross-checked against the
Python variant's output (or, for Authenticode, `Get-AuthenticodeSignature`).

**Released as [v0.1.0](https://github.com/churtacheese-create/BinSifter/releases/tag/ingot-v0.1.0).**
Packaging is a GitHub Actions matrix (`ingot-release.yml`) that builds the
`ingot` binary on native runners for Linux x86-64, Windows x86-64, and
macOS (Apple silicon + Intel) and attaches the archives to a GitHub Release
on an `ingot-v*` tag; a separate `ingot-ci.yml` runs fmt/clippy/tests on
Linux and Windows for every change.

Known gaps, none of them in the Python variant either: catalog (`.cat`)
signature verification, SSDEEP cluster history, and Speakeasy emulation
(which has no standalone binary). See
[`ingot/IMPLEMENTATION_PLAN.md`](../ingot/IMPLEMENTATION_PLAN.md).
