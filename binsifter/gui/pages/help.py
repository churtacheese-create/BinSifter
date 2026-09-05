"""Help page - port of New-HelpPage (BinSifter-Rowan.ps1, lines
~4773-4930). Read-only field guide, same role as the original's RichTextBox:
a single scrollable block of reference text, no interactive controls.

Deliberate content deviations from the PowerShell original's text, not
oversights - this port's actual behavior differs in a few real ways and the
guide would be actively misleading if it just copied the old wording:

- Settings Save no longer requires finding yara64.exe/capa.exe/ssdeep.exe
  under "Path to tools" - YARA, capa, and ssdeep are imported as in-process
  Python libraries in this port (see gui/settings_validation.py), not
  shelled out to executables. "Path to tools" now only matters for the
  smaller set of external GUI/console tools that have no Python-library
  equivalent (see core/config.py's TOOL_FILE_NAMES): PE-bear, Anya, DIE,
  Cutter, Angr, GDB, Binwalk, Malwoverview.
- FLOSS and Speakeasy are also in-process Python libraries now, not
  floss.exe/speakeasy.exe on disk - so they're no longer in the "Path to
  tools" file list either. The Results-grid quick-launch menu's Speakeasy
  entry calls core/speakeasy_scan.py's emulate_file() directly instead of
  shelling out to a speakeasy.exe, and is never disabled for "not
  configured" the way the exe-backed entries are.
- 2026-08-26: the quick-launch tool set itself was rebuilt for Winnow's
  Linux-focused direction - PE Studio/CFF Explorer/Resource Hacker/x64dbg/
  x32dbg/Sigcheck were all Windows-only with no real Linux build, so they
  were replaced with PE-bear, Anya, Rizin, and Angr (Sigcheck was dropped
  outright - no Linux substitute was identified for it). Ghidra's headless
  script is also found under its Linux name (analyzeHeadless, no .bat
  extension) now, not the Windows batch-file name.
- 2026-09-03: every quick-launch tool (plus Ghidra) is now checked and, if
  missing, auto-installed in the background on startup - "Path to tools"/
  "Path to Ghidra" are still honored first if set, but a missing tool no
  longer means a manual download; see core/tool_bootstrap.py. The same day,
  Rizin was replaced with Cutter (rizin's own GUI front-end - Rizin itself
  has no window of its own, so it did nothing when launched from a
  right-click), and GDB (paired with the GEF extension), Binwalk, and
  Malwoverview were added. GDB/Binwalk/Malwoverview are all terminal-native
  CLI tools with the same "no window" issue Rizin had, so BinSifter opens a
  real terminal emulator for those three instead of the silent failure
  Rizin used to have.
"""

from __future__ import annotations

from PySide6.QtWidgets import QTextEdit, QVBoxLayout, QWidget

from binsifter.gui.theme import ThemePalette, qcolor_to_css

_HELP_TEXT = """BIN SIFTER FIELD GUIDE

BinSifter is meant for fast, repeatable triage of a directory full of files. It does not replace reverse engineering or a full malware-analysis workflow. Its job is to reduce a large collection into smaller, useful groups: known-good files, files that matched YARA, files that capa could analyze, files with notable capabilities, and files that resemble one another through SSDEEP.

BEFORE THE FIRST SCAN

Open Settings and fill in the required paths:

- Path to binaries to scan - the folder BinSifter will walk recursively.
- NSRL text file path - an NSRL RDS hash file whose first CSV field is SHA-1.
- Path to YARA rules - the rule file YARA will apply.
- Path to capa rules - the capa rules directory.
- Path to tools - one folder containing the external GUI/console tools listed below. Optional even for those - BinSifter auto-installs anything missing in the background on startup (internet permitting); this field just lets you point at your own curated copies instead, which always win over an auto-installed one. YARA, capa, ssdeep, FLOSS, and Speakeasy all run as built-in libraries and need nothing configured here.
- Path to Ghidra - optional, your Ghidra install root. BinSifter finds analyzeHeadless inside it automatically.

Everything beyond these fields - where reports are written, MITRE ATT&CK data, the known-bad hash blocklist - is a fixed default location next to the BinSifter install itself. You don't type these in; you just place the right file in the right folder. See DEFAULT LOCATIONS below.

All Settings fields are remembered between launches: once Settings saves successfully, BinSifter writes them to a small cache file next to the install (.bsifter-settings-cache.json) and pre-fills them the next time you open BinSifter. A cached value that's no longer valid (e.g. a removable drive that isn't attached this session) just shows up as invalid on Save, same as if you'd typed it wrong - nothing breaks. Delete the cache file to reset every field to blank.

PATH TO TOOLS

Point "Path to tools" at one folder containing any of the following, by exact filename. BinSifter searches the whole folder tree under it, not just the top level. If more than one copy of a filename turns up somewhere in the tree, BinSifter picks one (logged on the Logs page) - keep only one copy of each tool under this folder if that matters for your case.

Every entry here is optional - a missing file just means that tool's path stays blank:

- PE-bear / pe-bear - static PE viewer.
- anya - PE resource editor.
- die / diec - Detect It Easy, GUI and console.
- cutter - rizin's official Qt GUI, reverse-engineering framework/debugger.
- angr - binary analysis/symbolic execution framework.
- gdb - debugger (found on PATH only - BinSifter never installs GDB itself, since that needs your distro's own package manager; it does auto-install the GEF extension for whatever gdb it finds).
- binwalk - firmware/embedded-file signature scanner and carver.
- malwoverview - VirusTotal hash/reputation lookup (sends the file's hash, never the sample itself, to VirusTotal - see its own docs before use).

BinSifter tries a couple of common filename spellings for each of these (see core/config.py's TOOL_FILE_NAMES) since none of them ship one single canonical Linux binary name the way a Windows .exe usually has - if your install uses a different filename, rename or symlink it to match, or check the Logs page to see what BinSifter actually searched for.

GDB, Binwalk, and Malwoverview are all plain command-line tools with no window of their own, so their quick-launch entries open a real terminal (whichever of x-terminal-emulator/gnome-terminal/konsole/xfce4-terminal/xterm is found on PATH) rather than doing nothing the way a bare background launch would - that terminal stays open and prints an exit status after the command finishes, so a fast crash is visible instead of the window closing before you can read it. PE-bear/DIE/Cutter are launched with --appimage-extract-and-run whenever the target is genuinely an AppImage, which works even without libfuse2 installed (several modern distros no longer ship it by default). Any quick-launch tool that exits immediately after being launched now shows an error with whatever it printed, instead of silently doing nothing.

YARA, capa, ssdeep, FLOSS, and Speakeasy are NOT on this list - they're built into BinSifter as Python libraries and always available once installed, regardless of what's in "Path to tools".

Ghidra isn't in this folder's search either - it has its own "Path to Ghidra" field instead. Point it at your Ghidra install root (e.g. ~/ghidra_11.x) and BinSifter locates the analyzeHeadless script inside it the same recursive way.

DEFAULT LOCATIONS

BinSifter creates these folders next to its own install automatically, the first time it runs, if they don't already exist. None of them are set in Settings:

- Reports\\ - where CSV reports, capa/FLOSS JSON, generated YARA rule drafts, and SSDEEP cluster reports are written.
- Attack\\ - drop enterprise-attack.json here (as Attack\\enterprise-attack.json) to enable MITRE ATT&CK technique enrichment on YARA hits. Leave the folder empty to skip that enrichment.
- Blocklist\\ - drop a known-bad hash CSV/TXT here (as Blocklist\\blocklist.csv, one SHA-1/MD5 per line or a MalwareBazaar-style export) to enable the offline reputation check. Leave the folder empty to skip that check.

STARTING A SCAN

Open Scan Queue and select Start Scan, then choose the folder to scan. BinSifter loads the NSRL hash set, walks the source directory, and creates one queue row per file.

Pause stops new files from being dispatched. Files already running are allowed to finish.

Stop cancels work still in the queue; files not yet started are marked Cancelled. A stopped run still writes the reports it can produce from the records collected so far.

Clear Completed removes finished, failed, and cancelled rows from the on-screen queue. It does not delete reports or source files.

WHAT HAPPENS TO EACH FILE

Each file is read once to calculate SHA-1 and MD5.

1. SHA-1 is checked against NSRL.
2. A known-good NSRL match skips SSDEEP, YARA, and capa.
3. An unknown file receives an SSDEEP fuzzy hash.
4. YARA runs and records matching rules, severity metadata, and ATT&CK references when available.
5. capa runs only after a YARA hit and only when the file appears suitable for capa analysis.
6. Optional FLOSS analysis can provide a fallback for suspicious files capa cannot accept, including basic IOC extraction (IPs, URLs, domains, registry paths) from the strings it finds.

An error on one file is recorded in that file's row. It does not stop the rest of the scan.

USING THE DASHBOARD

The stat tiles summarize completed files, YARA hits, capa scan attempts, capa rule detections, NSRL matches, and more.

The YARA Severity Breakdown counts each YARA-positive file once under its highest recognized severity. "Unknown" means the matched rule did not provide severity metadata BinSifter could recognize.

The SSDEEP Cluster Heat Map summarizes relationships in the current batch: similarity clusters, the largest cluster's size, singleton files, average similarity, and files above 85% similarity.

Every stat tile and the severity bars are clickable - selecting one opens Results with the corresponding filter already applied.

RESULTS AND REPORTS

Results shows the detailed record for each scanned file, including an editable Disposition column (Untriaged/Benign/Suspicious/Escalated) that's remembered by SHA-1 and carries forward into your next scan of the same files. Use the filter box to narrow by path; a dashboard selection adds its own filter on top, which you can clear to see everything again.

Right-click any row for on-demand actions, all driven by "Path to tools"/"Path to Ghidra" above:

- Quick-launch (no confirmation): PE-bear, Anya, DIE, Cutter, Angr, GDB (with GEF), Binwalk, Malwoverview, and Ghidra headless analysis. These are static/analysis tools - nothing here executes the selected file the way a live debugger would.
- Isolated Speakeasy code emulation asks for confirmation first, since emulating a live sample's code is execution-adjacent in a way the quick-launch tools above aren't - BinSifter asks you to confirm you're working in an isolated analysis environment before running it. Its output shows in a popup report window.
- Export for AI analysis writes a Markdown+JSON pair of the file's already-extracted findings for you to hand to whatever AI tool you choose - no AI is called from BinSifter itself.

Any entry showing "(not configured)" just means that tool's path wasn't found under "Path to tools" (or "Path to Ghidra" for the Ghidra entry) - place the file there and it will appear on your next right-click.

The report directory receives a full triage CSV, a suspicious/unknown CSV excluding NSRL matches, a YARA-matches CSV, a capa-compatible CSV, per-file capa JSON where capa returned output, draft YARA rules per SSDEEP cluster, and SSDEEP pair/cluster reports.

The source directory is read for analysis only. BinSifter does not quarantine, rename, repair, or delete evidence.

YARA, CAPA, NSRL, AND LOG PAGES

YARA Rules lets you inspect, reload, and edit the configured rule file. Saving changes writes directly to that file, so keep source control or a backup for production rules.

Capa Rules lists the configured rule directory and makes it easy to open that location.

NSRL shows the configured reference file and loaded hash count. Reload Now re-parses the file; a large file can take a few seconds.

Logs is the first place to look when a directory cannot be read or a report cannot be written.

PRACTICAL NOTES

Treat a YARA hit as a lead, not a verdict. Review the rule name, severity, file context, capa capabilities, strings, and cluster relationships together.

NSRL means "known to the reference set," not automatically safe in every context. Likewise, a file with no YARA hit is not automatically benign.

For repeatable case work, preserve the report directory (Reports\\ next to the BinSifter install) and note the BinSifter version shown on the About page."""


class HelpPage(QWidget):
    def __init__(self, theme: ThemePalette, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.text_view.setPlainText(_HELP_TEXT)
        self.text_view.setStyleSheet(
            f"QTextEdit {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; "
            f"color: {qcolor_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; "
            f"padding: 12px; }}"
        )
        font = self.text_view.font()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.text_view.setFont(font)

        root.addWidget(self.text_view)
