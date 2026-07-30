<img src="BinSifter-Logo-Horizontal-Dark.png" alt="BinSifter" width="100%">

# BinSifter

BinSifter is a binary triage tool built for forensic examiners who need to make a quick go/no-go call on a pile of unknown files. Point it at a directory and it hashes everything, checks each file against YARA rules and CAPA capability detection, looks it up against an NSRL known-good set and an optional known-bad blocklist, and lays the results out in a filterable dashboard so you can triage a batch fast instead of opening files one at a time.

## Status

The shipped version (`BinSifter_v1.3.0-alpha.2.ps1`) is a PowerShell 7 + WinForms desktop app. It's functional and has been run against real casework on a FRED forensic workstation, but it's still pre-1.0 and Windows-only.

A full rewrite in Python and PySide6 is underway (see the `binsifter/` package), mainly to get BinSifter off Windows-only WinForms and onto something that can eventually run on Linux too. The scan engine itself is in good shape: hashing/entropy, NSRL, blocklist, YARA with MITRE ATT&CK enrichment, CAPA, FLOSS, Speakeasy emulation, Authenticode verification, IOC extraction, SSDEEP/imphash clustering, draft YARA rule generation, and CSV reporting are all real, working, and tested. The GUI is still just a placeholder shell while the real pages get built one at a time. `pip install -e ".[dev]"` then `binsifter` launches that shell, and `binsifter-scan --src-dir ... --yara-rules ... --nsrl-path ...` runs a full headless scan today. See `BinSifter_CHANGELOG.md` for the PowerShell version's history.

<img src="BinSifter_Dash.png" alt="BinSifter dashboard" width="100%">

## Core features

- Hashing (MD5/SHA-1/SHA-256), Shannon entropy, and NSRL known-good lookup for every file in a scanned directory
- YARA rule matching with MITRE ATT&CK technique enrichment
- CAPA capability detection, with a FLOSS string-extraction fallback for files CAPA can't parse
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

BinSifter is source-available, not open source. See `LICENSE` (PolyForm Strict License 1.0.0) - noncommercial use, including by forensic examiners, government, and research institutions, is permitted, but redistribution and modified or derivative versions require permission from the licensor.
