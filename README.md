<img src="BinSifter-Logo-Horizontal-Dark.png" alt="BinSifter" width="100%">

# BinSifter

[![Latest release](https://img.shields.io/github/v/release/churtacheese-create/BinSifter?label=latest%20release&color=brightgreen)](https://github.com/churtacheese-create/BinSifter/releases/latest)
[![License](https://img.shields.io/github/license/churtacheese-create/BinSifter)](LICENSE)

BinSifter is a binary triage tool built for forensic examiners who need to make a quick go/no-go call on a pile of unknown files. Point it at a directory and it hashes everything, checks each file against YARA rules and CAPA capability detection, looks it up against an NSRL known-good set and an optional known-bad blocklist, and lays the results out in a filterable dashboard so you can triage a batch fast instead of opening files one at a time.

## Demo

<img src="BinSifter_Demo.gif" alt="BinSifter Rowan demo" width="100%">

## Variants

BinSifter ships as multiple independently-developed variants, each with its own codename and its own platform focus, sharing the same detection design and pipeline logic. Each has its own page with full requirements, install steps, and quick-launch tool details:

| Codename | Platform | Status |
| --- | --- | --- |
| **[Rowan](docs/rowan.md)** | PowerShell 7 + WinForms (Windows-only) | **Released.** Proven original, run against real casework, installers available (standard, MSI, portable) |
| **[Winnow](docs/winnow.md)** | Python + PySide6 (Linux-only) | **Released.** Full GUI and scan engine, run against real malware samples end-to-end, packages available for Debian/Ubuntu, Fedora/RHEL, and Arch |
| **[Ingot](docs/ingot.md)** | Rust (planned as a backend service + web UI - the actual cross-platform variant) | Planned, not yet started |

If you're on Windows, use Rowan. If you're on Linux, use Winnow. Ingot, once built, will be the one variant meant to run anywhere via a browser instead of a desktop GUI toolkit.

**NSRL caching (applies to both released variants):** the first scan against a given NSRL hash set builds a cached, memory-mapped index from it - a one-time cost that scales with the NSRL file's size, not the number of files being scanned (around 30 minutes for a full ~430-million-hash NSRL RDS set, measured directly). Every scan after that against the same NSRL file and Report Directory loads the cache directly (well under a second) instead of re-parsing it, so don't be alarmed if the very first scan against a new NSRL set takes noticeably longer than every scan after it. The cache lives under `<ReportDirectory>/.bsifter-nsrl-cache/` and rebuilds automatically if the source NSRL file's size or modified date changes, so switching Report Directory or NSRL file costs one more full rebuild, not a lasting slowdown.

<img src="BinSifter_Dash.png" alt="BinSifter dashboard" width="100%">

## Core features

- Hashing (MD5/SHA-1/SHA-256), Shannon entropy, and NSRL known-good lookup for every file in a scanned directory
- YARA rule matching with MITRE ATT&CK technique enrichment
- CAPA capability detection, with a FLOSS string-extraction fallback for files CAPA can't parse
- SSDEEP fuzzy-hash clustering and imphash exact-match clustering across a batch
- Authenticode signature verification and an optional offline known-bad hash blocklist check
- Draft YARA rule auto-generation per SSDEEP cluster
- Per-file triage disposition tracking, persisted across scans
- Results-grid quick-launch into external analysis tools (a different set per variant - see each variant's page for its exact list) plus Ghidra headless analysis and isolated Speakeasy emulation

## How it works

<img src="BinSifter_Flow_Diagram.svg" alt="BinSifter application and scan pipeline flow" width="100%">

## Requirements and getting started

See each variant's own page for full requirements and install steps:

- **[Rowan](docs/rowan.md)** - Windows, PowerShell 7+. Four install formats (standard installer, MSI, portable zip, or run the script directly).
- **[Winnow](docs/winnow.md)** - Linux (Debian/Ubuntu, Fedora/RHEL, Arch, and derivatives). Packaged as `.deb`/`.rpm`/`.pkg.tar.zst`, or run from source on any OS.
- **[Ingot](docs/ingot.md)** - not started yet.

Both released variants also need an NSRL known-good hash set (not included - see Settings). NSRL ships as RDSv3 hashes; BinSifter's NSRL loader expects the older RDSv2 text-file format, so you'll need to convert first - see NIST's own [RDSv3 to RDSv2 text files conversion guide](https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/RDSv3_Docs/RDSv3_to_RDSv2_text_files.pdf) (PDF).

Full configuration details for either variant are in the in-app Help page.

## License

BinSifter is source-available, not open source. See `LICENSE` (PolyForm Strict License 1.0.0) - noncommercial use, including by forensic examiners, government, and research institutions, is permitted, but redistribution and modified or derivative versions require permission from the licensor.
