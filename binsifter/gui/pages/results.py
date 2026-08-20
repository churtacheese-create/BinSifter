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

Two menu actions needed real adaptation, not just a language port, because
this Python rewrite made YARA/capa/ssdeep/FLOSS/Speakeasy in-process
libraries instead of external .exe tools (see core/config.py's
TOOL_FILE_NAMES docstring):
- Sigcheck still shells out to a real sigcheck.exe (no Python-library
  equivalent exists), same as the original, but runs on a background
  QThread instead of blocking the UI thread for up to 30s - an
  improvement consistent with this port's own established async pattern
  (NSRL reload, scans), not a behavior change to Sigcheck's own output.
- Speakeasy has no "speakeasy.exe" to find anymore (core/speakeasy_scan.py's
  emulate_file() already ported it as a library call) - the menu action
  calls that directly on a background QThread instead of shelling out to
  a "-t <file> -o json" CLI invocation the way the original assumed.
"""

from __future__ import annotations

import json
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

# (config key, menu label, copy-path-to-clipboard-instead-of-arg,
# confirmation message) - same order/labels/behavior as $launchTools.
# CffExplorerExe copies the path to the clipboard instead of passing it as
# a launch argument because CFF Explorer's command line is reserved for its
# own Lua scripting engine and silently ignores an arbitrary PE path (see
# the PowerShell version's own comment at $launchTools's CffExplorerExe
# entry). X64dbg/X32dbg get a
# confirmation prompt since loading a live sample into a debugger warrants
# a beat of caution a static viewer like PE Studio doesn't.
_QUICK_LAUNCH_TOOLS: tuple[tuple[str, str, bool, str | None], ...] = (
    ("PEStudioExe", "Open in PE Studio", False, None),
    ("DieExe", "Open in DIE", False, None),
    ("CffExplorerExe", "Open in CFF Explorer (copies path to clipboard)", True, None),
    ("ResourceHackerExe", "Open in Resource Hacker", False, None),
    (
        "X64dbgExe", "Open in x64dbg", False,
        "This opens the selected binary in x64dbg. Continue only in an isolated analysis environment.",
    ),
    (
        "X32dbgExe", "Open in x32dbg", False,
        "This opens the selected binary in x32dbg. Continue only in an isolated analysis environment.",
    ),
)

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


class _SigcheckWorker(QObject):
    """Runs sigcheck.exe and captures its output - port of the shared
    Invoke-CapturedTool helper's behavior for this one call site (30s
    timeout, stdout+stderr combined), on a background thread instead of
    Invoke-CapturedTool's synchronous WaitForExit."""

    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, exe_path: str, target_path: str) -> None:
        super().__init__()
        self._exe_path = exe_path
        self._target_path = target_path

    def run(self) -> None:
        try:
            proc = subprocess.run(
                [self._exe_path, "-nobanner", "-accepteula", "-a", "-h", self._target_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            body = f"{proc.stdout}\n{proc.stderr}".strip()
        except subprocess.TimeoutExpired as exc:
            stderr = (exc.stderr or "").strip()
            body = "Process timed out after 30 seconds and was terminated."
            if stderr:
                body += f"\n{stderr}"
        except OSError as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(body or "(no output)")


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
        # Keeps background captured-tool threads (Sigcheck/Speakeasy) alive
        # for their own lifetime - needed since nothing else holds a
        # reference once _launch_sigcheck/_launch_speakeasy return.
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
        for config_key, label, copy_path, confirm in _QUICK_LAUNCH_TOOLS:
            exe_path = getattr(self._config, config_key, "") or ""
            configured = bool(exe_path) and Path(exe_path).is_file()
            action = menu.addAction(label if configured else f"{label} (not configured)")
            action.setEnabled(configured)
            if configured:
                action.triggered.connect(
                    lambda checked=False, exe=exe_path, target=target_path, copy=copy_path, msg=confirm: (
                        self._launch_quick_tool(exe, target, copy, msg)
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

        sigcheck_exe = self._config.SigcheckExe or ""
        sigcheck_configured = bool(sigcheck_exe) and Path(sigcheck_exe).is_file()
        sigcheck_label = "Verify signature and provenance (Sigcheck)"
        sigcheck_action = menu.addAction(sigcheck_label if sigcheck_configured else f"{sigcheck_label} (not configured)")
        sigcheck_action.setEnabled(sigcheck_configured)
        if sigcheck_configured:
            sigcheck_action.triggered.connect(
                lambda checked=False, exe=sigcheck_exe, target=target_path: self._launch_sigcheck(exe, target)
            )

        # Speakeasy has no exe to find anymore - emulate_file() is always
        # available once the speakeasy library is installed, so this entry
        # is never disabled (unlike the original, which checked for
        # speakeasy.exe under ToolsDir).
        speakeasy_action = menu.addAction("Run isolated Speakeasy emulation")
        speakeasy_action.triggered.connect(lambda checked=False, target=target_path: self._launch_speakeasy(target))

        menu.addSeparator()

        # Unlike Ghidra/Sigcheck, this has no external tool to find - it's
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
        self, exe_path: str, target_path: str, copy_path_instead: bool, confirm_message: str | None
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
        try:
            if copy_path_instead:
                subprocess.Popen([exe_path])
                QGuiApplication.clipboard().setText(target_path)
            else:
                subprocess.Popen([exe_path, target_path])
        except OSError as exc:
            QMessageBox.critical(self, "BinSifter", f"Could not launch: {exc}")

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
            # nothing to wait on here.
            subprocess.Popen(
                [
                    self._config.GhidraHeadlessExe, str(ghidra_projects_dir), project_name,
                    "-import", target_path,
                    "-overwrite", "-analysisTimeoutPerFile", "300",
                ]
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

    def _launch_sigcheck(self, exe_path: str, target_path: str) -> None:
        if not Path(target_path).is_file():
            return
        self._start_captured_tool(
            _SigcheckWorker(exe_path, target_path),
            title=f"Sigcheck - {Path(target_path).name}",
        )

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
        """Shared thread plumbing for Sigcheck/Speakeasy - both report their
        result via a report popup (Show-ToolReportWindow's role) and share
        the same success/failure signal shapes.

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
