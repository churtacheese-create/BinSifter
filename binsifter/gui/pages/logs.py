"""Logs page - port of New-LogsPage and its wiring (BinSifter-Rowan_v1.3.0-
beta.1.ps1, lines ~4743-4770 for the page, ~5612 for BtnClear). A
read-only, auto-scrolling view of whatever binsifter's own loggers emit -
see gui/log_bridge.py for how those log records get here.
"""

from __future__ import annotations

from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import QFrame, QHBoxLayout, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from binsifter.gui.theme import ThemePalette, qcolor_to_css
from binsifter.gui.widgets import accent_to_css


class LogsPage(QWidget):
    def __init__(self, theme: ThemePalette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 10))
        # REAL BUG FOUND AND FIXED 2026-09-07: this had no cap at all, so a
        # long real scan (thousands of log lines from every worker) grew
        # this widget's backing document without bound - confirmed on a
        # real Ubuntu VM to reach 5.6GB of resident memory over a ~43
        # minute scan of real casework, at which point the kernel OOM-
        # killer terminated the app outright. engine.py's worker log-level
        # fix (see _pool_worker_init()'s own comment) addresses the biggest
        # source of that volume, but this page should never again be able
        # to grow unbounded regardless of how much a future log source
        # produces - 20,000 lines is generous for an interactively-useful
        # scrollback (old lines are dropped from the top as new ones
        # arrive) while capping worst-case memory to a small, fixed amount.
        self.log_view.setMaximumBlockCount(20000)
        self.log_view.setStyleSheet(
            f"QPlainTextEdit {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; "
            f"color: {qcolor_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
        )
        root.addWidget(self.log_view, 1)

    def _build_toolbar(self) -> QWidget:
        theme = self._theme
        bar = QFrame()
        bar.setFixedHeight(50)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 8, 0, 8)

        clear_button = QPushButton("Clear Logs")
        clear_button.setFixedSize(120, 34)
        clear_button.setStyleSheet(
            f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
            f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
        )
        clear_button.clicked.connect(self._on_clear_clicked)
        layout.addWidget(clear_button)
        layout.addStretch(1)
        return bar

    def _on_clear_clicked(self) -> None:
        self.log_view.clear()

    def append_line(self, line: str) -> None:
        self.log_view.appendPlainText(line)
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)
