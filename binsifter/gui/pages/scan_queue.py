"""Scan Queue page - port of New-ScanQueuePage (BinSifter-Rowan_v1.3.0-beta.1.ps1,
lines ~3945-4088): a toolbar (Start Scan/Pause/Stop/Clear Completed), a
summary label, and a per-file grid with a live status glyph, a real
progress bar, and color-highlighted YARA/Capa/NSRL cells.

Qt has no built-in DataGridView equivalent with the PowerShell version's
custom CellFormatting/CellPainting handlers, so this uses QTableWidget with
per-row QProgressBar cell widgets (setCellWidget) for the Progress column
instead of hand-painting a track+fill rectangle - same visual result
(a real progress bar per row), simpler than replicating GDI+ cell painting
in Qt for no visual gain.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from binsifter.core.models import FileRecord
from binsifter.gui.theme import ThemePalette, qcolor_to_css
from binsifter.gui.widgets import accent_to_css

# (name, header, width) - same 9 columns/order as $columnDefs in the
# PowerShell version, widths scaled down slightly since Qt's default table
# font/metrics run a bit narrower than WinForms' DataGridView.
_COLUMNS = (
    ("Path", "File Path", 360),
    ("Status", "Status", 120),
    ("Progress", "Progress", 130),
    ("YaraHits", "YARA Hits", 90),
    ("YaraSeverity", "YARA Severity", 110),
    ("CapaDetections", "Capa Detections", 120),
    ("PossibleFalseNegative", "Poss. False Neg.", 120),
    ("NsrlMatch", "NSRL Match", 100),
    ("Added", "Added", 140),
)

# (glyph, label) per Status value - same characters as the PowerShell
# version's CellFormatting handler (0x2714/0x25D4/0x25F7/0x2715/0x26A0).
_STATUS_GLYPHS = {
    "Completed": "✔",
    "Scanning": "◔",
    "Queued": "◷",
    "Cancelled": "✕",
    "Error": "⚠",
}


class ScanQueuePage(QWidget):
    start_clicked = Signal()
    stop_clicked = Signal()
    # Emitted with the NEW desired paused state (True = pause, False =
    # resume) - the page flips its own button label/state immediately, the
    # caller (main_window) just needs to know which way to set the
    # cooperative pause flag it hands to the scan worker.
    pause_toggled = Signal(bool)

    def __init__(self, theme: ThemePalette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        self._is_paused = False
        self._row_by_path: dict[str, int] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())
        root.addWidget(self._build_progress_row())

        self.summary_label = QLabel("No files queued.")
        self.summary_label.setContentsMargins(2, 8, 0, 8)
        self.summary_label.setStyleSheet(
            f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;"
        )
        root.addWidget(self.summary_label)

        self.table = self._build_table()
        root.addWidget(self.table, 1)

    # ---------- construction ----------

    def _build_progress_row(self) -> QWidget:
        """Overall scan progress (added 2026-08-04) - separate from the
        per-row progress bars in the table (col 2, one per file), which only
        ever show 0% or 100% for that single file and don't answer "how far
        along is the WHOLE batch". This is the first thing a user sees
        change on scan start, before the table has any rows yet - see
        set_progress()/set_indeterminate() below, called from MainWindow's
        immediate "starting scan" feedback and from every progress signal
        after that, not just file completions."""
        theme = self._theme
        row = QFrame()
        row.setFixedHeight(40)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(2, 4, 2, 4)
        layout.setSpacing(10)

        self.overall_progress = QProgressBar()
        self.overall_progress.setRange(0, 100)
        self.overall_progress.setValue(0)
        self.overall_progress.setTextVisible(True)
        self.overall_progress.setFormat("Idle")
        self.overall_progress.setStyleSheet(
            f"QProgressBar {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
            f"color: {qcolor_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; "
            f"border-radius: 3px; text-align: center; }}"
            f"QProgressBar::chunk {{ background-color: {qcolor_to_css(theme.Accent)}; }}"
        )
        layout.addWidget(self.overall_progress, 1)

        self.eta_label = QLabel("")
        self.eta_label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        self.eta_label.setFixedWidth(260)
        layout.addWidget(self.eta_label)

        return row

    def set_progress(self, done: int, total: int) -> None:
        """done/total here are SUBMITTED-or-completed counts (whatever the
        caller is currently tracking), not just terminal-status completions
        - the bar should visibly move the moment files start being
        dispatched to the worker pool, not sit at 0% until the first one
        finishes minutes later."""
        if total <= 0:
            self.overall_progress.setRange(0, 100)
            self.overall_progress.setValue(0)
            self.overall_progress.setFormat("Idle")
            return
        if self.overall_progress.maximum() == 0:
            # Coming out of set_indeterminate()'s busy/marquee mode - restore
            # a real range now that we actually know a file total.
            self.overall_progress.setRange(0, 100)
        pct = int(done / total * 100)
        self.overall_progress.setValue(pct)
        self.overall_progress.setFormat(f"{done} / {total} files ({pct}%)")

    def set_indeterminate(self, label: str) -> None:
        """Range (0, 0) makes a QProgressBar render as a busy/marquee
        indicator instead of a fixed percentage - used for the pre-scan
        setup phase (file enumeration, NSRL/blocklist/YARA/capa loading),
        where MainWindow doesn't yet know a file total to compute a real
        percentage against. Real range/value is restored by the first
        set_progress() call once the pool actually starts."""
        self.overall_progress.setRange(0, 0)
        self.overall_progress.setFormat(label)

    def set_eta(self, text: str) -> None:
        self.eta_label.setText(text)

    def _build_toolbar(self) -> QWidget:
        theme = self._theme
        bar = QFrame()
        bar.setFixedHeight(50)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(10)

        self.start_button = QPushButton("▶  Start Scan")
        self.start_button.setFixedSize(140, 34)
        self.start_button.setStyleSheet(
            f"QPushButton {{ background-color: {qcolor_to_css(theme.Accent)}; "
            f"color: {accent_to_css(theme.AccentFore)}; border: none; }}"
        )
        self.start_button.clicked.connect(self.start_clicked)

        self.pause_button = QPushButton("⏸  Pause")
        self.pause_button.setFixedSize(110, 34)
        self.pause_button.clicked.connect(self._on_pause_clicked)

        self.stop_button = QPushButton("■  Stop")
        self.stop_button.setFixedSize(110, 34)
        self.stop_button.clicked.connect(self.stop_clicked)

        self.clear_button = QPushButton("✕  Clear Completed")
        self.clear_button.setFixedSize(165, 34)
        self.clear_button.clicked.connect(self.clear_completed)

        for btn in (self.pause_button, self.stop_button, self.clear_button):
            btn.setStyleSheet(
                f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
                f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
            )

        self.set_running(False)

        layout.addWidget(self.start_button)
        layout.addWidget(self.pause_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.clear_button)
        layout.addStretch(1)
        return bar

    def _build_table(self) -> QTableWidget:
        theme = self._theme
        table = QTableWidget(0, len(_COLUMNS))
        table.setHorizontalHeaderLabels([header for _, header, _ in _COLUMNS])
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.setShowGrid(True)
        table.setAlternatingRowColors(False)
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
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setDefaultSectionSize(34)
        return table

    # ---------- toolbar behavior ----------

    def _on_pause_clicked(self) -> None:
        self._is_paused = not self._is_paused
        self.pause_button.setText("▶  Resume" if self._is_paused else "⏸  Pause")
        self.pause_toggled.emit(self._is_paused)

    def set_running(self, running: bool) -> None:
        """Toggles button enablement to match scan state. The PowerShell
        version leaves all 4 buttons always-clickable and has each handler
        silently no-op when not applicable (e.g. BtnStart.Add_Click checks
        $ScanControl.IsRunning itself); disabling here instead is a small,
        deliberate UX improvement over silently doing nothing on click, not
        a visual fidelity break - all 4 buttons are still always visible in
        the same positions."""
        self.start_button.setEnabled(not running)
        self.pause_button.setEnabled(running)
        self.stop_button.setEnabled(running)
        if not running:
            self._is_paused = False
            self.pause_button.setText("⏸  Pause")

    # ---------- grid state ----------

    def reset(self) -> None:
        self.table.setRowCount(0)
        self._row_by_path.clear()
        self.summary_label.setText("No files queued.")
        self.set_progress(0, 0)
        self.set_eta("")

    def clear_completed(self) -> None:
        """Removes rows whose Status is a terminal state - same 3-state set
        as the PowerShell version's BtnClear handler (Completed/Error/
        Cancelled), operating purely on the grid's own displayed Status
        text rather than needing a separate FileRecords lookup.

        Rows are removed bottom-to-top (not in dict-iteration order) so an
        earlier removal never invalidates the row index of another row
        still queued for removal - the mapping is then rebuilt from scratch
        off each surviving row's stored path (column 0's UserRole data),
        which is simpler and less error-prone than incrementally shifting
        indices as each row is removed.
        """
        terminal = {"Completed", "Error", "Cancelled"}
        rows_to_remove = [
            row for path, row in self._row_by_path.items()
            if (item := self.table.item(row, 1)) is not None and item.data(Qt.ItemDataRole.UserRole) in terminal
        ]
        for row in sorted(rows_to_remove, reverse=True):
            self.table.removeRow(row)

        self._row_by_path = {
            self.table.item(r, 0).data(Qt.ItemDataRole.UserRole): r
            for r in range(self.table.rowCount())
        }

    def upsert_record(self, record: FileRecord) -> None:
        """Inserts a new row for record.Path, or updates the existing one in
        place - same role as the PowerShell version's RowIndexByPath-keyed
        grid update."""
        theme = self._theme
        row = self._row_by_path.get(record.Path)
        if row is None:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self._row_by_path[record.Path] = row
            progress_bar = QProgressBar()
            progress_bar.setRange(0, 100)
            progress_bar.setTextVisible(True)
            progress_bar.setStyleSheet(
                f"QProgressBar {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
                f"color: {qcolor_to_css(theme.Fore)}; border: none; text-align: center; }}"
                f"QProgressBar::chunk {{ background-color: {qcolor_to_css(theme.Accent)}; }}"
            )
            self.table.setCellWidget(row, 2, progress_bar)

        path_item = self._set_text_cell(row, 0, f"⚙  {record.Path}", theme.Fore)
        path_item.setData(Qt.ItemDataRole.UserRole, record.Path)

        glyph = _STATUS_GLYPHS.get(record.Status, "")
        status_color = {
            "Completed": theme.Success,
            "Scanning": theme.Accent,
            "Queued": theme.MutedFore,
            "Cancelled": theme.Warning,
            "Error": theme.Danger,
        }.get(record.Status, theme.Fore)
        item = self._set_text_cell(row, 1, f"{glyph}  {record.Status}".strip(), status_color)
        item.setData(Qt.ItemDataRole.UserRole, record.Status)

        progress_bar = self.table.cellWidget(row, 2)
        if isinstance(progress_bar, QProgressBar):
            progress_bar.setValue(100 if record.Status in ("Completed", "Error", "Cancelled") else 0)

        self._set_text_cell(
            row, 3, str(record.YaraHitCount), theme.Warning if record.YaraHitCount > 0 else theme.Fore
        )
        self._set_text_cell(row, 4, record.YaraSeverity, theme.Fore)
        self._set_text_cell(
            row, 5, str(record.CapaDetectionCount), theme.Accent if record.CapaDetectionCount > 0 else theme.Fore
        )
        self._set_text_cell(row, 6, "Yes" if record.PossibleFalseNegative else "No", theme.Fore)
        nsrl_text = "Yes" if record.NsrlMatch else "No"
        self._set_text_cell(row, 7, nsrl_text, theme.Accent if record.NsrlMatch else theme.Fore)
        self._set_text_cell(row, 8, record.Added.strftime("%Y-%m-%d %H:%M:%S"), theme.Fore)

    def _set_text_cell(self, row: int, col: int, text: str, color) -> QTableWidgetItem:
        item = self.table.item(row, col)
        if item is None:
            item = QTableWidgetItem()
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, col, item)
        item.setText(text)
        item.setForeground(color)
        return item

    def set_summary(self, text: str) -> None:
        self.summary_label.setText(text)
