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

Not started. Rowan and Winnow are both being worked to completion first, one variant at a time - Ingot begins once Winnow's Linux packaging is confirmed working for real.
