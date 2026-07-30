"""YARA Rules page - port of New-YaraRulesPage and its wiring
(BinSifter_v1.3.0-alpha.2.ps1, lines ~4609-4651 for the page, ~5445-5482
for Update-YaraRulesContent/BtnBrowse/BtnReload/BtnSave). A simple raw-text
editor over whatever single file config.YaraRules points at - no rule
parsing/validation, same as the original (BinSifter never lints the rules
file itself, just hands it to the YARA engine at scan time).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from binsifter.core.config import BinSifterConfig
from binsifter.gui.theme import ThemePalette, qcolor_to_css
from binsifter.gui.widgets import accent_to_css

_YARA_FILE_FILTER = "YARA rules (*.yar *.yara);;All files (*.*)"


class YaraRulesPage(QWidget):
    # Emitted after Browse picks a new file - main_window.py connects this
    # to keep the Settings page's YaraRules field in sync, same as the
    # PowerShell version's BtnBrowse handler directly poking
    # $settings.Fields['YaraRules'].Text.
    rules_path_changed = Signal(str)

    def __init__(self, theme: ThemePalette, config: BinSifterConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        self._config = config

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())

        self.content = QPlainTextEdit()
        self.content.setFont(QFont("Consolas", 10))
        self.content.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.content.setStyleSheet(
            f"QPlainTextEdit {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; "
            f"color: {qcolor_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
        )
        root.addWidget(self.content, 1)

        self.reload_content()

    def _build_toolbar(self) -> QWidget:
        theme = self._theme
        bar = QFrame()
        bar.setFixedHeight(50)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(10)

        self.path_label = QLabel("No rules file configured.")
        self.path_label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        layout.addWidget(self.path_label)
        layout.addStretch(1)

        self.browse_button = QPushButton("Browse...")
        self.reload_button = QPushButton("Reload")
        for btn in (self.browse_button, self.reload_button):
            btn.setFixedSize(110, 34)
            btn.setStyleSheet(
                f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
                f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
            )

        self.save_button = QPushButton("Save Changes")
        self.save_button.setFixedSize(140, 34)
        self.save_button.setStyleSheet(
            f"QPushButton {{ background-color: {qcolor_to_css(theme.Accent)}; "
            f"color: {accent_to_css(theme.AccentFore)}; border: none; }}"
        )

        self.browse_button.clicked.connect(self._on_browse)
        self.reload_button.clicked.connect(self.reload_content)
        self.save_button.clicked.connect(self._on_save)

        layout.addWidget(self.browse_button)
        layout.addWidget(self.reload_button)
        layout.addWidget(self.save_button)
        return bar

    def reload_content(self) -> None:
        """Re-reads config.YaraRules from disk into the editor - same role
        as Update-YaraRulesContent. Called on construction, on Reload
        click, and (via main_window.py) whenever this page is navigated to
        or Settings just changed the path."""
        path = self._config.YaraRules
        if path and Path(path).is_file():
            self.path_label.setText(path)
            try:
                self.content.setPlainText(Path(path).read_text(encoding="utf-8"))
            except OSError as exc:
                self.content.setPlainText(f"Could not read file: {exc}")
        else:
            self.path_label.setText("No rules file configured.")
            self.content.setPlainText("")

    def _on_browse(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "Select YARA rules file", self._config.YaraRules, _YARA_FILE_FILTER)
        if not chosen:
            return
        self._config.YaraRules = chosen
        self.rules_path_changed.emit(chosen)
        self.reload_content()

    def _on_save(self) -> None:
        if not self._config.YaraRules:
            return
        try:
            Path(self._config.YaraRules).write_text(self.content.toPlainText(), encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "BinSifter", f"Save failed: {exc}")
            return
        QMessageBox.information(self, "BinSifter", "Saved.")
