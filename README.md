# BinSifter

BinSifter is a binary triage tool for forensic examiners: point it at a directory of files and it hashes, scans, and scores each one against YARA rules, CAPA capability detection, an NSRL known-good lookup, and an optional known-bad hash blocklist, then surfaces the results in a filterable dashboard for fast go/no-go triage on a batch of unknown binaries.

## Status

The current release (`BinSifter_v1.3.0-alpha.2.ps1`) is a PowerShell 7 + WinForms desktop app, and represents the end of the initial dev-prototype stage. It is functional and has been run against real casework on a FRED forensic workstation, but is still pre-1.0 and Windows-only.

A rewrite in Python (PySide6 for the UI) is planned next, primarily to add Linux support and to integrate CAPA, FLOSS, YARA, ssdeep, and Speakeasy as in-process libraries instead of external tool invocations. See `BinSifter_CHANGELOG.md` for version history.

## Core features

- Hashing (MD5/SHA-1/SHA-256), Shannon entropy, and NSRL known-good lookup for every file in a scanned directory
- YARA rule matching with MITRE ATT&CK technique enrichment
- CAPA capability detection (with a FLOSS string-extraction fallback for files CAPA can't parse)
- SSDEEP fuzzy-hash clustering and imphash exact-match clustering across a batch
- Authenticode signature verification and an optional offline known-bad hash blocklist check
- Draft YARA rule auto-generation per SSDEEP cluster
- Per-file triage disposition tracking, persisted across scans
- Results-grid quick-launch into PE Studio, DIE, CFF Explorer, Resource Hacker, Ghidra (headless), Sigcheck, x64dbg/x32dbg, and Speakeasy

## Requirements

- Windows, PowerShell 7+ (`pwsh.exe`)
- An NSRL known-good hash set (not included - see Settings)
- Whichever of the optional external tools above you want quick-launch access to (not included - point BinSifter at a single tools directory in Settings and it searches it recursively)

## Getting started

Run `Create-BinSifterShortcut.ps1` once to generate a desktop shortcut, or launch `BinSifter_v1.3.0-alpha.2.ps1` directly with `pwsh.exe -File`. Full configuration details are in the in-app Help page.

## License

BinSifter is source-available, not open source. See `LICENSE` (PolyForm Strict License 1.0.0) - noncommercial use, including by forensic examiners, government, and research institutions, is permitted, but redistribution and modified/derivative versions require permission from the licensor.
