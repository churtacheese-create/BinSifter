# BinSifter Ingot

Ingot is BinSifter's planned third variant, and the one actually intended to be cross-platform - not started yet.

## Why Ingot exists

Rowan (PowerShell/WinForms) is Windows-only by nature of its toolkit. Winnow (Python/PySide6) is now deliberately Linux-focused rather than a generic "runs everywhere" build, after real cross-platform desktop-toolkit issues (DPI scaling, dark-mode detection, a Linux-only window-resize bug) made clear that chasing true cross-platform parity through a desktop GUI toolkit is its own ongoing cost. Rather than asking either existing variant to also become the cross-platform answer, Ingot is planned from the start as the variant built to actually be cross-platform, by sidestepping desktop GUI toolkits entirely.

## Planned architecture

- **Rust backend service**, likely built on [axum](https://github.com/tokio-rs/axum) - runs the same detection pipeline design as Rowan/Winnow (hashing, NSRL, YARA, capa, FLOSS, etc.), exposed over a local HTTP API.
- **Web-based UI** instead of a desktop GUI toolkit - a browser tab is inherently cross-platform without per-OS toolkit quirks.
- Static frontend assets embedded directly into the compiled binary (e.g. via `rust-embed` or `include_dir`), so there's still just one binary to distribute, not a backend plus a separately-deployed frontend.
- Bound to `127.0.0.1` only, with no authentication - it's a local analyst tool, not a multi-user service, so there's no legitimate remote-access case to design around.

## Status

**Started - Phases 1-4 complete.** The scaffold is in [`ingot/`](../ingot/):
a Cargo workspace with an `ingot-core` scan-engine crate and an
`ingot-server` crate that runs the axum service and embeds the browser UI.
Working today: recursive file enumeration, a single-pass MD5/SHA-1/SHA-256 +
Shannon entropy read, NSRL known-good lookup (cached and memory-mapped,
using the same on-disk cache format as Rowan/Winnow so caches are
interchangeable), the offline known-bad blocklist, the PE import hash
(imphash, reproduced byte-for-byte against pefile), an SSDEEP fuzzy hash
(byte-for-byte against ppdeep), YARA matching on `yara-x` with severity
scoring and MITRE ATT&CK technique enrichment (cross-checked against
Winnow's own yara-python output), PE/ELF/shellcode classification and
capa-eligibility for YARA-flagged files, post-scan SSDEEP + imphash
clustering and a draft YARA rule per SSDEEP cluster (cross-checked against
Winnow's own clustering), triage disposition tracking (persisted by SHA-1,
editable in the Results grid), and the four 37-column CSV reports - all
wired into a live-progress web UI and validated against the Python
variant's output.

Later phases, one detection stage at a time (each gated by tests and a real
scan, the same way Winnow was ported): capa + FLOSS (via the projects' own
standalone binaries, auto-downloaded per-user), Authenticode + archive
expansion, the OS-scoped quick-launch tool menu, then packaging. See
[`ingot/IMPLEMENTATION_PLAN.md`](../ingot/IMPLEMENTATION_PLAN.md).
