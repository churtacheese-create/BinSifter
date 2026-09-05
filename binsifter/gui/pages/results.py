"""Results page - port of New-ResultsPage's core grid (BinSifter-Rowan_v1.3.0-
beta.1.ps1, lines ~4091-4494) and its wiring (Update-ResultsGrid,
Show-FilteredResults, the Disposition CellValueChanged handler, and the
free-text filter's debounce timer - lines ~5300-5443), plus the right-click
quick-launch context menu (PS lines ~4206-4490), built now that Settings
exists to configure ToolsDir/GhidraDir.

Menu construction deviates from the PowerShell original in one deliberate,
behavior-preserving way: the original builds persistent ToolStripMenuItems
once and refreshes their Enabled/Text on every ContextMenuStrip.Opening
event. This port instead builds a fresh QMenu from scratch on every
right-click (_on_table_context_menu), reading config paths fresh each time -
functionally identical (paths are always current, disabled items are
unclickable either way), just simpler in Qt where a one-shot QMenu.exec()
is the idiomatic pattern.

Quick-launch tool set rebuilt 2026-08-26 for Winnow's Linux-focused
direction - the original PE Studio/CFF Explorer/Resource Hacker/x64dbg/
x32dbg/Sigcheck line-up was Windows-only (Sysinternals tools and Windows
PE editors/debuggers with no real Linux build), which no longer fits once
Winnow itself is Linux-only. Replaced with Linux-native substitutes named
directly by the project owner: PE-bear and Anya cover PE Studio/CFF
Explorer/Resource Hacker's static-inspection role, Cutter and Angr cover
x64dbg/x32dbg's debugging/analysis role, and DIE/Ghidra/Speakeasy/the AI
export carry over unchanged since they were already cross-platform or
already in-process libraries. Sigcheck itself is dropped outright - it's a
Sysinternals tool with no Linux build and no Linux substitute was named for
it, unlike the other four. See core/config.py's TOOL_FILE_NAMES comment for
why each new tool's config field searches a tuple of candidate filenames
instead of one fixed name.

Lineup revised again 2026-09-03, the same day core/tool_bootstrap.py's
first-run auto-installer made these tools resolvable in practice for the
first time on a real machine - a real install/scan log surfaced two
genuine bugs (see core/config.py's find_tool_path() docstring and this
module's cwd-hardening comment on _launch_quick_tool) and prompted the
project owner to reconsider the lineup itself:
- **Rizin -> Cutter.** Rizin is a terminal-native REPL with no window of
  its own - launched via a bare subprocess.Popen from a GUI app with no
  attached terminal, it produced no visible effect at all (confirmed
  directly from that log: "PE-Bear nor Rizin would work when selected").
  Cutter is rizin's own official Qt GUI front-end - same engine, but an
  actual window.
- **GDB (+ GEF), Binwalk, and Malwoverview added.** All three are equally
  terminal-native CLI tools, so all three are launched inside a real
  terminal emulator rather than repeating Rizin's exact bug three more
  times - see _find_terminal_emulator()/_QUICK_LAUNCH_TOOLS' needs_terminal
  field below. GEF is a gdb extension, not a separate program, layered
  onto whatever `gdb` is already found; Malwoverview queries VirusTotal
  with the file's hash (never the sample itself, per its own docs) - the
  same third-party-service disclosure carries through to docs/winnow.md.
- **Ghidra is now auto-installed too**, no longer manual-only, per an
  explicit request ("I want Ghidra to be installed if not installed").

Two menu actions needed real adaptation, not just a language port, because
this Python rewrite made YARA/capa/ssdeep/FLOSS/Speakeasy in-process
libraries instead of external .exe tools (see core/config.py's
TOOL_FILE_NAMES docstring):
- Speakeasy has no "speakeasy.exe" to find anymore (core/speakeasy_scan.py's
  emulate_file() already ported it as a library call) - the menu action
  calls that directly on a background QThread instead of shelling out to
  a "-t <file> -o json" CLI invocation the way the original assumed.
- The shared captured-tool-report plumbing (_start_captured_tool/
  _show_tool_report) originally served both Sigcheck and Speakeasy; now
  that Sigcheck is gone, Speakeasy is its only user, but the plumbing is
  left general rather than inlined in case a future quick-launch tool
  needs the same "run on a background thread, show output in a popup"
  pattern.
"""

from __future__ import annotations

import json
import logging
import shlex
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QObject, QThread, QTimer, QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from binsifter.core import ai_export, speakeasy_scan
from binsifter.core.config import BinSifterConfig
from binsifter.core.disposition import save_disposition_entry
from binsifter.core.models import FileRecord
from binsifter.gui.theme import ThemePalette, qcolor_to_css
from binsifter.gui.widgets import accent_to_css

logger = logging.getLogger(__name__)

# (config key, menu label, copy-path-to-clipboard-instead-of-arg,
# confirmation message, extra argv inserted between the exe and the target
# path, needs-a-terminal) - Linux tool set, see module docstring above for
# what replaced what and why. None of these need the clipboard-copy trick
# CFF Explorer used to (that was specific to CFF Explorer's command line
# being reserved for its own Lua console) or a confirmation prompt (none
# of these directly execute the sample the way a live debugger does -
# Cutter/Angr/Binwalk/Malwoverview are static/symbolic analysis and
# lookup tools, not live executors, unlike x64dbg/x32dbg were).
#
# The 5th field was added 2026-09-03 alongside core/tool_bootstrap.py,
# which made Angr resolvable for the first time in practice - that
# surfaced a real, previously-latent bug: Angr's actual CLI (confirmed
# directly against its own pyproject.toml/[project.scripts] and
# __main__.py) requires a subcommand before the binary path
# ("angr decompile <file>", not a bare "angr <file>") - a plain
# subprocess.Popen([exe, target]) would have errored out immediately every
# single time, it just never got exercised before because nothing had
# ever found a working AngrExe. Anya's CLI similarly needs "--file <path>"
# per its own README, not a bare positional. PE-bear/DIE/Cutter all
# genuinely do accept a bare "<exe> <file>" invocation, confirmed against
# each project's own docs, so their tuples stay empty.
#
# The 6th field was added the same day the lineup itself changed (Rizin ->
# Cutter, plus GDB+GEF/Binwalk/Malwoverview added): a real user's install
# log showed Rizin's menu entry doing nothing when clicked even though its
# path resolved correctly - Rizin is a terminal-native REPL with no window
# of its own, so a bare subprocess.Popen (no attached terminal, since
# Winnow itself is a GUI app) produced no visible effect at all. Cutter
# fixes this for that specific role by being a real GUI app instead, but
# GDB, Binwalk, and Malwoverview are all equally terminal-native CLI tools
# with the exact same problem - rather than repeat that bug for three more
# tools, each is launched inside a real terminal emulator instead (see
# _find_terminal_emulator()/_launch_in_terminal() below).
_QUICK_LAUNCH_TOOLS: tuple[tuple[str, str, bool, str | None, tuple[str, ...], bool], ...] = (
    ("PeBearExe", "Open in PE-bear", False, None, (), False),
    ("AnyaExe", "Open in Anya", False, None, ("--file",), False),
    ("DieExe", "Open in DIE", False, None, (), False),
    ("CutterExe", "Open in Cutter", False, None, (), False),
    ("AngrExe", "Open in Angr", False, None, ("decompile",), False),
    # GDB is launched bare (gdb <file>) - a real debugger session, meant to
    # be interacted with directly in the terminal that opens.
    ("GdbExe", "Open in GDB (with GEF)", False, None, (), True),
    # Binwalk's plain invocation (binwalk <file>) prints its signature scan
    # straight to stdout - needs a terminal to be seen at all, same as GDB.
    ("BinwalkExe", "Scan with Binwalk", False, None, (), True),
    # "-v 2 -f <path>" queries VirusTotal for this file's hash (malwoverview
    # computes and submits only the hash, never the sample itself, per its
    # own docs) and requires -f for -v 2 to work - confirmed against
    # malwoverview's own README. Same third-party-service disclosure this
    # entry carries in docs/winnow.md and _MANUAL_INSTALL_HINTS.
    ("MalwoverviewExe", "Look up hash in Malwoverview (VirusTotal)", False, None, ("-v", "2", "-f"), True),
)

# Tried in order - first one found on PATH wins. Covers Debian/Ubuntu's
# alternatives-based x-terminal-emulator, GNOME, KDE, XFCE, and a bare
# xterm as the universal last resort every distro's repos carry.
# (terminal binary name, argv prefix before the command to run)
#
# None of these carry a hold-open flag anymore (xterm's own -hold used to
# be here) - see _wrap_for_terminal_pause()'s docstring for why relying on
# each terminal's own hold-open support (inconsistent - only xterm has
# one) was replaced with a uniform wrapper applied to every terminal here.
_TERMINAL_EMULATORS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("x-terminal-emulator", ("-e",)),
    ("gnome-terminal", ("--",)),
    ("konsole", ("-e",)),
    ("xfce4-terminal", ("-x",)),
    ("xterm", ("-e",)),
)


def _find_terminal_emulator() -> tuple[str, tuple[str, ...]] | None:
    for name, prefix_args in _TERMINAL_EMULATORS:
        path = shutil.which(name)
        if path:
            return path, prefix_args
    return None


def _wrap_for_terminal_pause(argv: list[str]) -> list[str]:
    """Wraps `argv` in a small `sh -c` snippet that reports the exit status
    and waits for a keypress before the terminal's own process exits.

    Added 2026-09-04 after a real user's terminal-launched GDB did nothing
    visible when clicked - their system `gdb` turned out to be broken
    (crashes near-instantly with a `libpython`/`libexpat` symbol mismatch,
    a real problem with their machine, not something BinSifter's code
    caused or can fix), and only xterm's own `-hold` flag (see the old
    _TERMINAL_EMULATORS comment) would have kept a window open long enough
    to show that crash - whichever OTHER terminal got picked instead
    (gnome-terminal/konsole/xfce4-terminal/x-terminal-emulator, none of
    which were given a hold-open flag) would have flashed open and closed
    itself the instant the command exited, indistinguishable from nothing
    happening at all. Wrapping the command this way, uniformly, for every
    terminal, means a fast crash is now always visible - the terminal
    stays open and shows the real error - and it isn't a guess about which
    terminal happens to be installed.
    """
    command = " ".join(shlex.quote(arg) for arg in argv)
    script = f'{command}; status=$?; echo; echo "[exit status $status - press Enter to close]"; read _dummy'
    return ["sh", "-c", script]


def _is_appimage(path: str) -> bool:
    """True if `path` is an AppImage - detected via the format's own magic
    bytes (0x41 0x49 0x01/0x02, "AI" + type, at file offset 8), the same
    signature AppImage's own tooling and `file(1)` use, rather than
    guessing from the filename or which tool this is. Added 2026-09-04
    after a real user's Cutter (freshly auto-installed as an AppImage,
    confirmed via the bootstrap log) did nothing when clicked - the classic
    symptom of a missing libfuse2 on a modern distro (Ubuntu dropped it
    from the default image starting 22.04): an AppImage launched without
    FUSE available exits immediately with no window and no Python-level
    exception at all (subprocess.Popen succeeds at fork/exec; the child
    just dies a moment later), so this failure was completely invisible
    before now. PE-bear/DIE/Cutter are the only quick-launch tools ever
    delivered as AppImages when auto-installed, but a user's own manually
    supplied "Path to tools" copy might be a real native build instead
    (confirmed for PE-bear in an earlier real log) - checking the actual
    file signature, not the tool identity, means this only ever adds
    --appimage-extract-and-run when the target genuinely needs it.
    """
    try:
        with open(path, "rb") as handle:
            header = handle.read(11)
    except OSError:
        return False
    return len(header) >= 11 and header[8:10] == b"AI" and header[10] in (1, 2)


# How long to wait, in ms, before checking whether a just-launched
# quick-launch tool already died - see _popen_watched()'s own docstring.
_LIVENESS_CHECK_DELAY_MS = 400

_SPEAKEASY_CONFIRM = (
    "This emulates the selected binary's code. Emulation must be performed in an "
    "isolated analysis environment. Continue?"
)

# (attribute, header, width) - same 21 read-only columns/order as
# $resultColumns in the PowerShell version. "attribute" doubles as the
# FileRecord field name for every column except the 3 with custom
# formatting (NsrlMatch/PossibleFalseNegative -> Yes/No, blank-if-sentinel
# fields), which _row_values() below handles by name.
_COLUMNS = (
    ("Path", "File Path", 320),
    ("Status", "Status", 90),
    ("SHA1", "SHA-1", 320),
    ("NsrlMatch", "NSRL", 60),
    ("YaraHitCount", "YARA Hits", 80),
    ("YaraSeverity", "YARA Severity", 100),
    ("YaraAttackTechniques", "MITRE ATT&CK", 220),
    ("CapaDetectionCount", "Capa Detections", 110),
    ("CapaShellcodeFormat", "Capa SC Format", 90),
    ("PossibleFalseNegative", "Poss. False Neg.", 100),
    ("Entropy", "Entropy", 70),
    ("FlossStringCount", "FLOSS Strings", 90),
    ("SsdeepMatches", "SSDEEP Matches", 200),
    ("PackerDetected", "Packer (DIE)", 110),
    ("Compiler", "Compiler (DIE)", 120),
    ("Imphash", "Imphash", 110),
    ("SignatureStatus", "Signature", 90),
    ("SignerName", "Signer", 160),
    ("IocCount", "IOCs", 60),
    ("ExtractedIOCs", "Extracted IOCs", 200),
    ("ReputationStatus", "Reputation", 90),
    ("Error", "Error", 160),
    # Blank for a file found directly under SrcDir; the containing
    # archive's path for a file extracted from one - see
    # models.py's FileRecord.SourceArchive / core/archive.py's module
    # docstring for the "own rows + source-archive column" design.
    ("SourceArchive", "Source Archive", 260),
)
_DISPOSITION_COL = len(_COLUMNS)
_DISPOSITION_CHOICES = ("Untriaged", "Benign", "Suspicious", "Escalated")

_FILTER_DEBOUNCE_MS = 300


def _row_values(r: FileRecord) -> list[str]:
    """Same per-column formatting as Update-ResultsGrid: Yes/No for the two
    boolean columns, blank (not the sentinel) for Entropy/FlossStringCount/
    IocCount when they haven't been computed for this file."""
    return [
        r.Path,
        r.Status,
        r.SHA1 or "",
        "Yes" if r.NsrlMatch else "No",
        str(r.YaraHitCount),
        r.YaraSeverity,
        r.YaraAttackTechniques or "",
        str(r.CapaDetectionCount),
        r.CapaShellcodeFormat or "",
        "Yes" if r.PossibleFalseNegative else "No",
        f"{r.Entropy:.2f}" if r.Entropy >= 0 else "",
        str(r.FlossStringCount) if r.FlossStringCount >= 0 else "",
        r.SsdeepMatches or "",
        r.PackerDetected,
        r.Compiler,
        r.Imphash or "",
        r.SignatureStatus,
        r.SignerName,
        str(r.IocCount) if r.IocCount > 0 else "",
        r.ExtractedIOCs,
        r.ReputationStatus,
        r.Error or "",
        r.SourceArchive or "",
    ]


class _SpeakeasyWorker(QObject):
    """Runs core.speakeasy_scan.emulate_file() and formats the same
    summary-then-raw-dump report the PowerShell version built from its
    (differently-shaped) assumed JSON - see speakeasy_scan.py's docstring
    for why the real report shape needed a from-scratch summarizer."""

    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, target_path: str) -> None:
        super().__init__()
        self._target_path = target_path

    def run(self) -> None:
        result = speakeasy_scan.emulate_file(self._target_path)
        if result.error:
            self.failed.emit(result.error)
            return
        filename = Path(self._target_path).name
        network = ", ".join(result.network_indicators) if result.network_indicators else "(none observed)"
        summary = (
            f"Speakeasy emulation summary for {filename}\n"
            f"API calls observed: {result.api_call_count}\n"
            f"File operations observed: {result.file_operation_count}\n"
            f"Network indicators: {network}\n\n"
            "--- Raw output ---\n"
        )
        raw = json.dumps(result.raw_report, indent=2, default=str)
        self.finished.emit(summary + raw)


class ResultsPage(QWidget):
    def __init__(self, theme: ThemePalette, config: BinSifterConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        self._config = config
        self._records: list[FileRecord] = []
        self._filter_label: str | None = None
        self._filter_predicate: Callable[[FileRecord], bool] | None = None
        # Keeps background captured-tool threads (Speakeasy) alive for their
        # own lifetime - needed since nothing else holds a reference once
        # _launch_speakeasy returns.
        self._tool_threads: list[tuple[QThread, QObject]] = []

        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(_FILTER_DEBOUNCE_MS)
        self._debounce_timer.timeout.connect(self._apply_text_filter)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())
        self.filter_bar = self._build_filter_bar()
        root.addWidget(self.filter_bar)

        self.table = self._build_table()
        root.addWidget(self.table, 1)

        # Right-click quick-launch menu - port of $grid.Add_CellMouseDown +
        # $grid.ContextMenuStrip (PS lines ~4206-4490). Qt's
        # customContextMenuRequested already only fires for a right-click
        # inside the viewport, so there's no separate "select the row under
        # the cursor first" mousedown handler needed - _on_table_context_menu
        # does both (select + build menu) in one place.
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_context_menu)

    # ---------- construction ----------

    def _build_toolbar(self) -> QWidget:
        theme = self._theme
        bar = QFrame()
        bar.setFixedHeight(50)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(10)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Filter by file path...")
        self.search_box.setFixedSize(320, 32)
        self.search_box.setStyleSheet(
            f"QLineEdit {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; "
            f"color: {qcolor_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; "
            f"padding: 4px 8px; }}"
        )
        self.search_box.textChanged.connect(lambda _text: self._debounce_timer.start())

        self.open_folder_button = QPushButton("Open Report Folder")
        self.open_folder_button.setFixedSize(170, 34)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setFixedSize(100, 34)
        for btn in (self.open_folder_button, self.refresh_button):
            btn.setStyleSheet(
                f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
                f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
            )
        self.open_folder_button.clicked.connect(self._on_open_report_folder)
        self.refresh_button.clicked.connect(self._render)

        layout.addWidget(self.search_box)
        layout.addWidget(self.open_folder_button)
        layout.addWidget(self.refresh_button)
        layout.addStretch(1)
        return bar

    def _build_filter_bar(self) -> QWidget:
        theme = self._theme
        bar = QFrame()
        bar.setFixedHeight(34)
        bar.setStyleSheet(f"QFrame {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; border: none; }}")
        bar.setVisible(False)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 0, 12, 0)

        self.filter_label = QLabel("")
        font = self.filter_label.font()
        font.setPointSize(9)
        font.setBold(True)
        self.filter_label.setFont(font)
        self.filter_label.setStyleSheet(f"color: {accent_to_css(theme.Accent)}; border: none; background: transparent;")
        layout.addWidget(self.filter_label)
        layout.addStretch(1)

        clear_button = QPushButton("Clear Filter")
        clear_button.setFixedSize(100, 24)
        clear_button.setStyleSheet(
            f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
            f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
        )
        clear_button.clicked.connect(self.clear_filter)
        layout.addWidget(clear_button)

        return bar

    def _build_table(self) -> QTableWidget:
        theme = self._theme
        headers = [header for _, header, _ in _COLUMNS] + ["Disposition"]
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)  # everything but Disposition is read-only
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.verticalHeader().setVisible(False)
        table.setStyleSheet(
            f"QTableWidget {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; "
            f"color: {qcolor_to_css(theme.Fore)}; gridline-color: {qcolor_to_css(theme.Border)}; "
            f"border: none; }}"
            f"QHeaderView::section {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; "
            f"color: {accent_to_css(theme.MutedFore)}; border: none; "
            f"border-bottom: 1px solid {qcolor_to_css(theme.Border)}; "
            f"border-right: 1px solid {qcolor_to_css(theme.Border)}; padding: 8px; }}"
            f"QTableWidget::item:selected {{ background-color: {qcolor_to_css(theme.NavActive)}; "
            f"color: {qcolor_to_css(theme.Fore)}; }}"
        )
        for i, (_, _, width) in enumerate(_COLUMNS):
            table.setColumnWidth(i, width)
        table.setColumnWidth(_DISPOSITION_COL, 120)
        # Every column (File Path included) is user-resizable by dragging its
        # header border, same as the PowerShell DataGridView's default
        # AllowUserToResizeColumns behavior - File Path used to be locked to
        # Stretch mode, which blocked manual resizing on the column analysts
        # most need to widen. QHeaderView::section's border-right above also
        # gives a visible seam to grab, since the borderless header style
        # otherwise left the resize handles hard to find.
        header = table.horizontalHeader()
        for i in range(table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
        table.verticalHeader().setDefaultSectionSize(30)
        return table

    # ---------- data ----------

    def set_records(self, records: list[FileRecord]) -> None:
        self._records = records
        self._render()

    def apply_filter(self, label: str, predicate: Callable[[FileRecord], bool]) -> None:
        """Jump to Results narrowed to whatever a Dashboard tile/severity-bar
        click represents - same role as Show-FilteredResults."""
        self._filter_label = label
        self._filter_predicate = predicate
        self._render()

    def clear_filter(self) -> None:
        self._filter_label = None
        self._filter_predicate = None
        self._render()

    def _visible_records(self) -> list[FileRecord]:
        records = sorted(self._records, key=lambda r: r.Path)
        if self._filter_predicate is not None:
            records = [r for r in records if self._filter_predicate(r)]
        return records

    def _render(self) -> None:
        theme = self._theme
        visible = self._visible_records()

        if self._filter_label:
            self.filter_label.setText(f"Filtered: {self._filter_label}  -  {len(visible)} file(s)")
            self.filter_bar.setVisible(True)
        else:
            self.filter_bar.setVisible(False)

        self.table.setRowCount(0)
        self.table.setRowCount(len(visible))
        for row, record in enumerate(visible):
            for col, value in enumerate(_row_values(record)):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 4 and record.YaraHitCount > 0:  # YaraHitCount column
                    item.setForeground(theme.Warning)
                elif col == 7 and record.CapaDetectionCount > 0:  # CapaDetectionCount column
                    item.setForeground(theme.Accent)
                elif col == 3 and record.NsrlMatch:  # NsrlMatch column
                    item.setForeground(theme.Accent)
                self.table.setItem(row, col, item)

            combo = QComboBox()
            combo.addItems(_DISPOSITION_CHOICES)
            combo.setCurrentText(record.Disposition)
            combo.currentTextChanged.connect(
                lambda text, path=record.Path: self._on_disposition_changed(path, text)
            )
            self.table.setCellWidget(row, _DISPOSITION_COL, combo)

        self._apply_text_filter()

    def _on_disposition_changed(self, path: str, new_disposition: str) -> None:
        record = next((r for r in self._records if r.Path == path), None)
        if record is None or record.Disposition == new_disposition:
            return
        record.Disposition = new_disposition
        if record.SHA1:
            save_disposition_entry(self._config.ReportDirectory, record.SHA1, new_disposition)

    def _apply_text_filter(self) -> None:
        needle = self.search_box.text().strip().lower()
        for row in range(self.table.rowCount()):
            if not needle:
                self.table.setRowHidden(row, False)
                continue
            path_item = self.table.item(row, 0)
            path_text = path_item.text().lower() if path_item is not None else ""
            self.table.setRowHidden(row, needle not in path_text)

    def _on_open_report_folder(self) -> None:
        report_dir = self._config.ReportDirectory
        if not report_dir:
            return

        if Path(report_dir).is_dir():
            QDesktopServices.openUrl(QUrl.fromLocalFile(report_dir))

    # ---------- quick-launch context menu ----------

    def _on_table_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if item is None:
            return  # no row under the cursor - same as the original cancelling Opening when nothing's selected
        row = item.row()
        self.table.clearSelection()
        self.table.selectRow(row)

        path_item = self.table.item(row, 0)  # Path is always column 0
        if path_item is None:
            return
        target_path = path_item.text()

        menu = self._build_context_menu(target_path)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _build_context_menu(self, target_path: str) -> QMenu:
        """Builds the quick-launch menu for one file's path - split out from
        _on_table_context_menu so it can be constructed and inspected
        (enabled state, labels, wired handlers) without also calling
        QMenu.exec(), which blocks on a real event loop no automated test
        can drive."""
        menu = QMenu(self)
        for config_key, label, copy_path, confirm, extra_argv, needs_terminal in _QUICK_LAUNCH_TOOLS:
            exe_path = getattr(self._config, config_key, "") or ""
            configured = bool(exe_path) and Path(exe_path).is_file()
            action = menu.addAction(label if configured else f"{label} (not configured)")
            action.setEnabled(configured)
            if configured:
                action.triggered.connect(
                    lambda checked=False, exe=exe_path, target=target_path, copy=copy_path, msg=confirm, argv=extra_argv, term=needs_terminal: (  # noqa: E501
                        self._launch_quick_tool(exe, target, copy, msg, argv, term)
                    )
                )

        menu.addSeparator()

        ghidra_exe = self._config.GhidraHeadlessExe or ""
        ghidra_configured = bool(ghidra_exe) and Path(ghidra_exe).is_file()
        ghidra_label = "Send to Ghidra (headless analysis)"
        ghidra_action = menu.addAction(ghidra_label if ghidra_configured else f"{ghidra_label} (not configured)")
        ghidra_action.setEnabled(ghidra_configured)
        if ghidra_configured:
            ghidra_action.triggered.connect(lambda checked=False, target=target_path: self._launch_ghidra(target))

        # Speakeasy has no exe to find anymore - emulate_file() is always
        # available once the speakeasy library is installed, so this entry
        # is never disabled (unlike the original, which checked for
        # speakeasy.exe under ToolsDir).
        speakeasy_action = menu.addAction("Run isolated Speakeasy emulation")
        speakeasy_action.triggered.connect(lambda checked=False, target=target_path: self._launch_speakeasy(target))

        menu.addSeparator()

        # Unlike Ghidra, this has no external tool to find - it's
        # pure local formatting (see core/ai_export.py's module docstring),
        # so the only prerequisite is somewhere to write the two output
        # files, same as the "Open report folder" toolbar button already
        # requires.
        ai_export_configured = bool(self._config.ReportDirectory)
        ai_export_label = "Export for AI analysis (Markdown + JSON)"
        ai_export_action = menu.addAction(
            ai_export_label if ai_export_configured else f"{ai_export_label} (configure Report Directory first)"
        )
        ai_export_action.setEnabled(ai_export_configured)
        if ai_export_configured:
            ai_export_action.triggered.connect(
                lambda checked=False, target=target_path: self._export_for_ai_analysis(target)
            )

        return menu

    def _launch_quick_tool(
        self,
        exe_path: str,
        target_path: str,
        copy_path_instead: bool,
        confirm_message: str | None,
        extra_argv: tuple[str, ...] = (),
        needs_terminal: bool = False,
    ) -> None:
        if not Path(target_path).is_file():
            return
        if confirm_message:
            answer = QMessageBox.warning(
                self, "BinSifter", confirm_message,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        # extra_argv goes between the exe and the target path, e.g.
        # ["angr", "decompile", target] or ["anya", "--file", target] - see
        # _QUICK_LAUNCH_TOOLS' module comment for why Angr/Anya/GDB-adjacent
        # tools specifically need this and PE-bear/DIE/Cutter don't.
        #
        # --appimage-extract-and-run goes right after the exe itself (before
        # extra_argv/target) whenever exe_path genuinely is an AppImage -
        # see _is_appimage()'s own docstring for why this exists. This
        # bypasses FUSE entirely (extracting to a temp dir and running
        # directly), so it works whether or not libfuse2 happens to be
        # installed - strictly safer than the old bare invocation, never
        # narrower.
        appimage_flag = ["--appimage-extract-and-run"] if _is_appimage(exe_path) else []
        argv = (
            [exe_path, *appimage_flag, *extra_argv]
            if copy_path_instead
            else [exe_path, *appimage_flag, *extra_argv, target_path]
        )
        try:
            if needs_terminal:
                # Terminal-native CLI tools (GDB, Binwalk, Malwoverview) have
                # no window of their own - a bare subprocess.Popen with no
                # attached terminal produces no visible effect at all, the
                # exact "PE-Bear nor Rizin would work when selected" bug a
                # real user hit with the old Rizin entry. Run it inside a
                # real terminal emulator instead - see
                # _find_terminal_emulator()'s own docstring for the search
                # order.
                terminal = _find_terminal_emulator()
                if terminal is None:
                    message = (
                        "Could not launch: no terminal emulator found on PATH "
                        "(tried x-terminal-emulator, gnome-terminal, konsole, xfce4-terminal, xterm). "
                        "Install one of these, or run the command yourself:\n" + " ".join(argv)
                    )
                    logger.error("Could not launch %s - no terminal emulator on PATH", exe_path)
                    QMessageBox.critical(self, "BinSifter", message)
                    return
                terminal_path, prefix_args = terminal
                # Run through the exe's own directory as cwd (see
                # _launch_ghidra's own cwd comment below) - harmless for
                # tools that don't need it, and protects any that resolve
                # sibling files/plugins relative to their own binary the
                # way PE-bear's Qt build does.
                wrapped = _wrap_for_terminal_pause(argv)
                subprocess.Popen([terminal_path, *prefix_args, *wrapped], cwd=str(Path(exe_path).parent))
            elif copy_path_instead:
                self._popen_watched(argv, str(Path(exe_path).parent), exe_path)
                QGuiApplication.clipboard().setText(target_path)
            else:
                # HARDENED 2026-09-03: cwd defaults to wherever Winnow itself
                # was launched from, not the tool's own install directory -
                # a real user's log showed PE-bear resolving to a real,
                # executable file (a manually-built Qt binary under
                # ~/Desktop/pe-bear/build_qt6/bin/) that still did nothing
                # when clicked, with no error ever surfacing anywhere (the
                # old bare `except OSError` here never logged either - see
                # the logger.error() call below, added the same day). A Qt
                # app built to look for its own plugins/resources relative
                # to argv[0]'s directory can silently fail to find them
                # when launched from an unrelated cwd; setting cwd to the
                # exe's own directory is a cheap, safe default that removes
                # this as a possible cause without needing to know which
                # specific tool actually needs it.
                self._popen_watched(argv, str(Path(exe_path).parent), exe_path)
        except OSError as exc:
            logger.error("Could not launch %s (target %s): %s", exe_path, target_path, exc)
            QMessageBox.critical(self, "BinSifter", f"Could not launch: {exc}")

    def _popen_watched(self, argv: list[str], cwd: str, exe_path: str) -> subprocess.Popen:
        """subprocess.Popen() wrapper used by every GUI-tool quick-launch
        branch above (and Ghidra's own launch below) - captures stderr and
        schedules a short liveness check via QTimer.singleShot rather than
        blocking the GUI thread with a real sleep.

        REAL GAP FOUND AND FIXED 2026-09-04: subprocess.Popen() succeeds
        (returns a real PID) even when the spawned process crashes moments
        later at the OS level - a missing shared library, a missing FUSE
        for an AppImage (see _is_appimage()), a bad invocation - none of
        which raise a Python exception. Previously this class of failure
        produced NO log entry and NO error dialog at all, completely
        indistinguishable from nothing happening - the exact complaint a
        real user reported for a quick-launch tool that resolved to a real,
        executable file yet still appeared to do nothing when clicked. This
        doesn't guarantee a tool that survives the check is actually
        visible or fully working - only that it didn't die within the
        first fraction of a second - but that's exactly the failure mode
        this exists to catch.
        """
        process = subprocess.Popen(argv, cwd=cwd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
        QTimer.singleShot(
            _LIVENESS_CHECK_DELAY_MS, lambda: self._check_quick_launch_liveness(process, exe_path)
        )
        return process

    def _check_quick_launch_liveness(self, process: subprocess.Popen, exe_path: str) -> None:
        if process.poll() is None:
            return  # still running - looks fine, nothing to report
        if process.returncode == 0:
            return  # exited cleanly and fast - some tools legitimately do this; not our business to second-guess
        stderr_text = ""
        if process.stderr is not None:
            try:
                stderr_text = process.stderr.read().decode("utf-8", errors="replace").strip()
            except OSError:
                pass
        detail = stderr_text or f"exited immediately with status {process.returncode}"
        logger.error("%s exited immediately after launch: %s", exe_path, detail)
        QMessageBox.critical(
            self, "BinSifter", f"{Path(exe_path).name} exited immediately after launching:\n\n{detail}"
        )

    def _launch_ghidra(self, target_path: str) -> None:
        if not Path(target_path).is_file():
            return
        report_dir = self._config.ReportDirectory
        if not report_dir:
            QMessageBox.information(
                self, "BinSifter",
                "Configure a Report Directory in Settings first - Ghidra projects are stored under it.",
            )
            return
        try:
            ghidra_projects_dir = Path(report_dir) / "ghidra_projects"
            ghidra_projects_dir.mkdir(parents=True, exist_ok=True)
            # Same fallback as the original: prefer the file's SHA-1 for the
            # project name, fall back to the filename stem if this path
            # isn't in the current in-memory records for any reason.
            record = next((r for r in self._records if r.Path == target_path), None)
            project_name = (
                f"BinSifter_{record.SHA1}" if record and record.SHA1 else f"BinSifter_{Path(target_path).stem}"
            )
            # Fire-and-forget, same as the original - headless analysis can
            # run for minutes and Ghidra is purely static, so there's
            # nothing to wait on here. Still watched via _popen_watched()
            # for a fast, wrong-JAVA_HOME-style crash (previously such a
            # failure would still show the "analysis started" success
            # popup below, silently misreporting it).
            self._popen_watched(
                [
                    self._config.GhidraHeadlessExe, str(ghidra_projects_dir), project_name,
                    "-import", target_path,
                    "-overwrite", "-analysisTimeoutPerFile", "300",
                ],
                str(Path(self._config.GhidraHeadlessExe).parent),
                self._config.GhidraHeadlessExe,
            )
            # Headless analysis runs for minutes with no further UI feedback
            # by design (it's not tracked/polled), so without this a
            # right-click here looks like nothing happened. This is a
            # one-time "yes, it started" acknowledgment, not a progress
            # indicator - dismissed immediately, doesn't block anything.
            QMessageBox.information(
                self, "BinSifter",
                f"Ghidra headless analysis started for {Path(target_path).name}.\n\n"
                f"This can take several minutes. Results will be saved under:\n"
                f"{ghidra_projects_dir / project_name}",
            )
        except OSError as exc:
            logger.error("Could not launch Ghidra (target %s): %s", target_path, exc)
            QMessageBox.critical(self, "BinSifter", f"Could not launch Ghidra: {exc}")

    def _export_for_ai_analysis(self, target_path: str) -> None:
        """Writes the Markdown+JSON pair for one file's already-extracted
        findings, for the analyst to hand to whatever AI tool they choose -
        pasting the Markdown into a chat interface, or feeding the JSON to
        a script hitting a local model's API. No AI is called from here, or
        anywhere in BinSifter - see core/ai_export.py's module docstring.

        No confirmation dialog needed the way Speakeasy/X64dbg get one -
        this only reads already-in-memory scan results and writes two small
        text files, nothing that touches or executes the sample itself.
        """
        report_dir = self._config.ReportDirectory
        if not report_dir:
            QMessageBox.information(
                self, "BinSifter",
                "Configure a Report Directory in Settings first - AI exports are stored under it.",
            )
            return
        record = next((r for r in self._records if r.Path == target_path), None)
        if record is None:
            return
        try:
            export_dir = Path(report_dir) / "ai_exports"
            md_path, json_path = ai_export.export_file(record, export_dir)
            QMessageBox.information(
                self, "BinSifter",
                f"AI-ready export written for {Path(target_path).name}:\n\n"
                f"{md_path}\n{json_path}",
            )
        except OSError as exc:
            QMessageBox.critical(self, "BinSifter", f"Could not write AI export: {exc}")

    def _launch_speakeasy(self, target_path: str) -> None:
        if not Path(target_path).is_file():
            return
        answer = QMessageBox.warning(
            self, "BinSifter", _SPEAKEASY_CONFIRM,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._start_captured_tool(
            _SpeakeasyWorker(target_path),
            title=f"Speakeasy - {Path(target_path).name}",
        )

    def _start_captured_tool(self, worker: QObject, title: str) -> None:
        """Shared thread plumbing for background tool runs that report their
        result via a report popup (Show-ToolReportWindow's role) - Speakeasy
        is the only current user since Sigcheck (the other original user)
        was dropped from Winnow's Linux quick-launch set, but this stays
        general in case a future tool needs the same pattern.

        worker.finished/failed connect to bound methods of `self`, not
        lambdas: PySide6's cross-thread auto-connection only reliably
        resolves the receiver's thread through a bound-method slot, since a
        lambda isn't a QObject Qt can introspect. Connecting to a lambda
        instead falls back to a DirectConnection, so thread.wait() and
        QDialog/QMessageBox construction end up running on the background
        worker thread rather than the main thread - an explicit
        QueuedConnection type doesn't fix this either, since Qt still needs
        a real receiver to resolve the target thread. Since one pair of
        slots now serves every concurrent tool run, `self.sender()`
        recovers which worker fired, and the worker's own `title` attribute
        (set below, before the thread starts) carries what used to be
        smuggled through the lambda's closure.
        """
        self.setCursor(Qt.CursorShape.WaitCursor)
        thread = QThread(self)
        worker.title = title  # plain Python attribute - fine on a QObject, set before moveToThread/start
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_captured_tool_finished)
        worker.failed.connect(self._on_captured_tool_failed)
        self._tool_threads.append((thread, worker))
        thread.start()

    def _thread_for_worker(self, worker: QObject) -> QThread | None:
        return next((t for t, w in self._tool_threads if w is worker), None)

    def _on_captured_tool_finished(self, body: str) -> None:
        worker = self.sender()
        thread = self._thread_for_worker(worker)
        self._teardown_tool_thread(thread, worker)
        self._show_tool_report(worker.title, body)

    def _on_captured_tool_failed(self, message: str) -> None:
        worker = self.sender()
        thread = self._thread_for_worker(worker)
        self._teardown_tool_thread(thread, worker)
        tool_name = worker.title.split(" - ", 1)[0]
        QMessageBox.critical(self, "BinSifter", f"Could not run {tool_name}: {message}")

    def _teardown_tool_thread(self, thread: QThread, worker: QObject) -> None:
        self.unsetCursor()
        thread.quit()
        thread.wait()
        self._tool_threads = [(t, w) for t, w in self._tool_threads if t is not thread]

    def _show_tool_report(self, title: str, content: str) -> None:
        """Read-only report popup - port of Show-ToolReportWindow."""
        theme = self._theme
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(860, 620)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(0, 0, 0, 0)

        text_view = QPlainTextEdit()
        text_view.setReadOnly(True)
        text_view.setPlainText(content)
        text_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        font = text_view.font()
        font.setFamily("Consolas")
        font.setPointSize(9)
        text_view.setFont(font)
        text_view.setStyleSheet(
            f"QPlainTextEdit {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; "
            f"color: {qcolor_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; "
            f"padding: 8px; }}"
        )
        layout.addWidget(text_view)

        dialog.exec()
