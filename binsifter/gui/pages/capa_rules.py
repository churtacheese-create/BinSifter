"""Capa Rules page - port of New-CapaRulesPage and its wiring
(BinSifter_v1.3.0-alpha.2.ps1, lines ~4654-4693 for the page, ~5485-5511
for Update-CapaRulesList/BtnBrowse/BtnRefresh/BtnOpenFolder). Lists every
rule file found under config.CapaRules - no rule content preview/editing
(unlike YARA Rules, which is a single file; capa's rules are a whole
directory tree, so this page's job is locating them, not editing them).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from binsifter.core.config import BinSifterConfig
from binsifter.gui.capa_rules_listing import list_capa_rule_files
from binsifter.gui.theme import ThemePalette, qcolor_to_css
from binsifter.gui.widgets import accent_to_css

_NO_FILES_PLACEHOLDER = "(no rule files found)"


class CapaRulesPage(QWidget):
    # Emitted after Browse picks a new directory - kept in sync with
    # Settings' CapaRules field, same as the PowerShell version's BtnBrowse
    # handler poking $settings.Fields['CapaRules'].Text directly.
    rules_path_changed = Signal(str)

    def __init__(self, theme: ThemePalette, config: BinSifterConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        self._config = config

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())

        self.list_widget = QListWidget()
        self.list_widget.setFont(QFont("Consolas", 10))
        self.list_widget.setStyleSheet(
            f"QListWidget {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; "
            f"color: {qcolor_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
        )
        root.addWidget(self.list_widget, 1)

        self.reload_content()

    def _build_toolbar(self) -> QWidget:
        theme = self._theme
        bar = QFrame()
        bar.setFixedHeight(50)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(10)

        self.path_label = QLabel("No rules directory configured.")
        self.path_label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        layout.addWidget(self.path_label)
        layout.addStretch(1)

        self.browse_button = QPushButton("Browse...")
        self.open_folder_button = QPushButton("Open Folder")
        self.refresh_button = QPushButton("Refresh")
        for btn, width in (
            (self.browse_button, 110),
            (self.open_folder_button, 130),
            (self.refresh_button, 100),
        ):
            btn.setFixedSize(width, 34)
            btn.setStyleSheet(
                f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
                f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
            )

        self.browse_button.clicked.connect(self._on_browse)
        self.open_folder_button.clicked.connect(self._on_open_folder)
        self.refresh_button.clicked.connect(self.reload_content)

        layout.addWidget(self.browse_button)
        layout.addWidget(self.open_folder_button)
        layout.addWidget(self.refresh_button)
        return bar

    def reload_content(self) -> None:
        """Re-lists config.CapaRules from disk - same role as
        Update-CapaRulesList. Called on construction, on Refresh click, and
        (via main_window.py) whenever this page is shown or Settings just
        changed the path."""
        self.list_widget.clear()
        path = self._config.CapaRules
        if path and Path(path).is_dir():
            self.path_label.setText(path)
            files = list_capa_rule_files(path)
            self.list_widget.addItems(files if files else [_NO_FILES_PLACEHOLDER])
        else:
            self.path_label.setText("No rules directory configured.")

    def _on_browse(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Select capa rules folder", self._config.CapaRules)
        if not chosen:
            return
        self._config.CapaRules = chosen
        self.rules_path_changed.emit(chosen)
        self.reload_content()

    def _on_open_folder(self) -> None:
        path = self._config.CapaRules
        if path and Path(path).is_dir():
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
