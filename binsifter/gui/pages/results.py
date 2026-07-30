"""Results page - port of New-ResultsPage's core grid (BinSifter_v1.3.0-
alpha.2.ps1, lines ~4091-4494) and its wiring (Update-ResultsGrid,
Show-FilteredResults, the Disposition CellValueChanged handler, and the
free-text filter's debounce timer - lines ~5300-5443).

Deliberately NOT ported in this pass: the right-click quick-launch context
menu (Open in PE Studio/DIE/CFF Explorer/Resource Hacker/x64dbg/x32dbg,
Send to Ghidra, Sigcheck, Speakeasy-via-menu - PS lines ~4206-4490). Every
one of those needs a Settings page to configure ToolsDir/GhidraDir first,
and that page doesn't exist yet in this Python port - the menu would just
always show its own "configure Settings first" dialog right now. Worth
building once Settings exists, not before.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QTimer, QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from binsifter.core.config import BinSifterConfig
from binsifter.core.disposition import save_disposition_entry
from binsifter.core.models import FileRecord
from binsifter.gui.theme import ThemePalette, qcolor_to_css
from binsifter.gui.widgets import accent_to_css

# (attribute, header, width) - same 21 read-only columns/order as
# $resultColumns in the PowerShell version. "attribute" doubles as the
# FileRecord field name for every column except the 3 with custom
# formatting (NsrlMatch/PossibleFalseNegative -> Yes/No, blank-if-sentinel
# fields), which _row_values() below handles by name.
_COLUMNS = (
    ("Path", "File Path", 260),
    ("Status", "Status", 90),
    ("SHA1", "SHA-1", 200),
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
    ]


class ResultsPage(QWidget):
    def __init__(self, theme: ThemePalette, config: BinSifterConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        self._config = config
        self._records: list[FileRecord] = []
        self._filter_label: str | None = None
        self._filter_predicate: Callable[[FileRecord], bool] | None = None

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
            f"border-bottom: 1px solid {qcolor_to_css(theme.Border)}; padding: 8px; }}"
            f"QTableWidget::item:selected {{ background-color: {qcolor_to_css(theme.NavActive)}; "
            f"color: {qcolor_to_css(theme.Fore)}; }}"
        )
        for i, (_, _, width) in enumerate(_COLUMNS):
            table.setColumnWidth(i, width)
        table.setColumnWidth(_DISPOSITION_COL, 120)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
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
        from pathlib import Path

        if Path(report_dir).is_dir():
            QDesktopServices.openUrl(QUrl.fromLocalFile(report_dir))
