"""Settings page - port of New-SettingsPage and its Save handler
(BinSifter-Rowan_v1.3.0-beta.1.ps1, lines ~4498-4606 for the page, ~5087-5218
for wiring). Same 6 fields, same 3-column (label / textbox / Browse...)
row layout, same validation-then-save flow.

See gui/settings_validation.py's module docstring for the one deliberate
deviation from the original: the ToolsDir save-check no longer requires
finding yara64.exe/capa.exe/ssdeep.exe on disk, since this port imports
those three as Python libraries instead of shelling out to executables.

Also not yet wired (both depend on pages that don't exist yet in this
port): refreshing the YARA Rules/Capa Rules pages' path labels after a
save, and Start-ToolMetadataRefresh's status-bar tool-version text.
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from binsifter.core.config import (
    BinSifterConfig,
    find_tool_path,
    save_settings_cache,
    set_tool_paths_from_directory,
)
from binsifter.gui.settings_validation import validate_settings
from binsifter.gui.theme import ThemePalette, qcolor_to_css
from binsifter.gui.widgets import accent_to_css

# (config key, label, field type, dialog filter) - same order/labels as
# $fieldDefs. "Directory"/"File" match the PowerShell version's Type values.
_FIELD_DEFS = (
    ("SrcDir", "Path to binaries to scan", "Directory", None),
    ("NsrlPath", "NSRL text file path", "File", "Text files (*.txt);;All files (*.*)"),
    ("YaraRules", "Path to YARA rules", "File", "YARA rules (*.yar *.yara);;All files (*.*)"),
    ("CapaRules", "Path to capa rules", "Directory", None),
    ("ToolsDir", "Path to tools", "Directory", None),
    ("GhidraDir", "Path to Ghidra - optional", "Directory", None),
)


class SettingsPage(QWidget):
    # Emitted after a successful Save - main_window.py doesn't need this
    # yet (no other page currently reacts to Settings changing), but it's
    # the natural hook for when YARA Rules/Capa Rules/tool-version refresh
    # get built and need to know the config just changed.
    settings_saved = Signal()

    def __init__(self, theme: ThemePalette, config: BinSifterConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        self._config = config
        self._fields: dict[str, QLineEdit] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(0)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(14)
        grid.setColumnStretch(1, 1)

        for row, (key, label_text, field_type, dialog_filter) in enumerate(_FIELD_DEFS):
            label = QLabel(label_text)
            label.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
            grid.addWidget(label, row, 0)

            line_edit = QLineEdit(getattr(config, key, "") or "")
            line_edit.setStyleSheet(
                f"QLineEdit {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; "
                f"color: {qcolor_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; "
                f"padding: 4px 8px; }}"
            )
            grid.addWidget(line_edit, row, 1)
            self._fields[key] = line_edit

            browse_button = QPushButton("Browse...")
            browse_button.setFixedWidth(100)
            browse_button.setStyleSheet(
                f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
                f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
            )
            browse_button.clicked.connect(
                lambda checked=False, e=line_edit, t=field_type, f=dialog_filter: self._on_browse(e, t, f)
            )
            grid.addWidget(browse_button, row, 2)

        root.addLayout(grid)
        root.addSpacing(20)

        self.save_button = QPushButton("Save Settings")
        self.save_button.setFixedSize(160, 36)
        self.save_button.setStyleSheet(
            f"QPushButton {{ background-color: {qcolor_to_css(theme.Accent)}; "
            f"color: {accent_to_css(theme.AccentFore)}; border: none; }}"
        )
        self.save_button.clicked.connect(self._on_save_clicked)
        root.addWidget(self.save_button)

        root.addSpacing(12)
        self.status_label = QLabel("")
        root.addWidget(self.status_label)

        root.addStretch(1)

    def _on_browse(self, line_edit: QLineEdit, field_type: str, dialog_filter: str | None) -> None:
        current = line_edit.text().strip()
        if field_type == "Directory":
            start_dir = current if current else ""
            chosen = QFileDialog.getExistingDirectory(self, "Select folder", start_dir)
            if chosen:
                line_edit.setText(chosen)
        else:
            chosen, _ = QFileDialog.getOpenFileName(self, "Select file", current, dialog_filter or "All files (*.*)")
            if chosen:
                line_edit.setText(chosen)

    def _on_save_clicked(self) -> None:
        theme = self._theme
        values = {key: field.text() for key, field in self._fields.items()}
        result = validate_settings(values, self._config.ReportDirectory)

        if not result.ok:
            self.status_label.setStyleSheet(f"color: {accent_to_css(theme.Danger)}; border: none; background: transparent;")
            self.status_label.setText(result.error_message or "Invalid settings.")
            return

        for key, value in result.candidate.items():
            setattr(self._config, key, value)
            self._fields[key].setText(value)

        set_tool_paths_from_directory(self._config, self._config.ToolsDir)
        self._config.GhidraHeadlessExe = find_tool_path(self._config.GhidraDir, "analyzeHeadless.bat")

        try:
            save_settings_cache(self._config)
        except OSError:
            pass  # best-effort, same as the PowerShell version - a read-only install dir just means no caching

        self.status_label.setStyleSheet(f"color: {accent_to_css(theme.Success)}; border: none; background: transparent;")
        self.status_label.setText("Settings saved.")
        self.settings_saved.emit()
