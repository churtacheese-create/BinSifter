"""BinSifter - forensic binary triage tool for bulk binary assessment.

This is Winnow, BinSifter's Python/PySide6 variant - the cross-platform
rewrite of Rowan, the original PowerShell 7 + WinForms variant
(BinSifter-Rowan.ps1, kept in the repo root for reference).
A third variant, Ingot (Rust), is planned but not yet started.
See BinSifter_CHANGELOG.md for Rowan's history, and the
"BinSifter post-prototype roadmap" project note for why this rewrite exists.

Package layout:
    binsifter.core  - the scan engine: hashing, YARA/capa/FLOSS/ssdeep/NSRL/
                       blocklist integrations, config, and the FileRecord
                       model. No GUI imports here - this half needs to run
                       standalone under the future headless/Docker CLI mode.
    binsifter.gui   - the PySide6 desktop application. Imports from
                       binsifter.core, never the other way around.
    binsifter.cli   - headless entry point (binsifter-scan), for automated/
                       pipeline use without a GUI.
"""

__version__ = "2.0.0b1"
