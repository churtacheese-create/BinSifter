"""Settings page - port of New-SettingsPage and its Save handler
(BinSifter-Rowan.ps1, lines ~4498-4606 for the page, ~5087-5218
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
    QApplication,
    QFileDialog,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from binsifter import __version__ as _BINSIFTER_VERSION
from binsifter.core import av_detect, update_check
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
    # Optional, like GhidraDir - a folder of .cat catalog files for
    # Authenticode catalog verification (see authenticode.py). Blank means
    # catalog checks are skipped, not an error.
    ("CatalogDirectory", "Catalog (.cat) directory - optional", "Directory", None),
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

        # Detects whatever AV/EDR product is actually installed (via
        # av_detect.py's curated table of known Linux systemd
        # units/processes/install paths) and points the analyst at that
        # vendor's own exclusion settings - there's no automated exclusion
        # action here (that was a Windows Defender-specific feature, removed
        # 2026-09-07 since Winnow is Linux-only and it could never work).
        root.addSpacing(24)
        av_label = QLabel("Antivirus")
        av_label.setStyleSheet(
            f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent; font-weight: bold;"
        )
        root.addWidget(av_label)

        av_explainer = QLabel(
            "Detects known antivirus/EDR product(s) installed on this machine via known Linux "
            "services/processes, and points you at where to add a scan exclusion for that product "
            "if extracted archive contents are being flagged/quarantined during a scan."
        )
        av_explainer.setWordWrap(True)
        av_explainer.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        root.addWidget(av_explainer)

        root.addSpacing(8)
        self.av_detect_button = QPushButton("Detect installed antivirus")
        self.av_detect_button.setFixedHeight(32)
        self.av_detect_button.setStyleSheet(
            f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
            f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
        )
        self.av_detect_button.clicked.connect(self._on_detect_av_clicked)
        root.addWidget(self.av_detect_button)

        self.av_detect_status_label = QLabel("")
        self.av_detect_status_label.setWordWrap(True)
        root.addWidget(self.av_detect_status_label)

        # Checks GitHub's releases for a newer v* tag (Rowan's and Winnow's
        # shared line). Never installs anything itself - Winnow is a
        # root-owned system package (.deb/.rpm/.pkg.tar.zst), so rewriting
        # its files outside dpkg/rpm/pacman would corrupt their own
        # integrity tracking. This downloads the matching package to an
        # ordinary per-user folder and shows the exact command to run.
        self._pending_update: update_check.UpdateCheckResult | None = None
        root.addSpacing(24)
        update_label = QLabel("Update")
        update_label.setStyleSheet(
            f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent; font-weight: bold;"
        )
        root.addWidget(update_label)

        update_explainer = QLabel(
            "Checks this repository's GitHub releases for a newer version. Winnow never installs "
            "an update itself - packages you get through your distro's package manager should be "
            "updated through it, not overwritten by the app - so this downloads the matching "
            "package and shows you the exact command to run."
        )
        update_explainer.setWordWrap(True)
        update_explainer.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        root.addWidget(update_explainer)

        root.addSpacing(8)
        self.check_update_button = QPushButton("Check for updates")
        self.check_update_button.setFixedHeight(32)
        self.check_update_button.setStyleSheet(
            f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
            f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
        )
        self.check_update_button.clicked.connect(self._on_check_update_clicked)
        root.addWidget(self.check_update_button)

        self.download_update_button = QPushButton("Download update")
        self.download_update_button.setFixedHeight(32)
        self.download_update_button.setStyleSheet(
            f"QPushButton {{ background-color: {qcolor_to_css(theme.Accent)}; "
            f"color: {accent_to_css(theme.AccentFore)}; border: none; }}"
        )
        self.download_update_button.clicked.connect(self._on_download_update_clicked)
        self.download_update_button.hide()
        root.addWidget(self.download_update_button)

        self.update_status_label = QLabel("")
        self.update_status_label.setWordWrap(True)
        root.addWidget(self.update_status_label)

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
        # "analyzeHeadless" with no extension - Ghidra's Linux/macOS headless
        # launcher is a shell script, not the "analyzeHeadless.bat" batch
        # file Rowan (Windows) looks for. Winnow is Linux-only now, so this
        # only ever needs the one name, unlike the multi-candidate tuples in
        # TOOL_FILE_NAMES above for tools with no single canonical filename.
        self._config.GhidraHeadlessExe = find_tool_path(self._config.GhidraDir, "analyzeHeadless")

        try:
            save_settings_cache(self._config)
        except OSError:
            pass  # best-effort, same as the PowerShell version - a read-only install dir just means no caching

        self.status_label.setStyleSheet(f"color: {accent_to_css(theme.Success)}; border: none; background: transparent;")
        self.status_label.setText("Settings saved.")
        self.settings_saved.emit()

    def _on_detect_av_clicked(self) -> None:
        theme = self._theme
        self.av_detect_button.setEnabled(False)
        self.av_detect_status_label.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
        self.av_detect_status_label.setText("Checking...")
        QApplication.processEvents()

        try:
            products = av_detect.detect_av_products()
        except av_detect.AvDetectionError as exc:
            self.av_detect_status_label.setStyleSheet(f"color: {accent_to_css(theme.Danger)}; border: none; background: transparent;")
            self.av_detect_status_label.setText(str(exc))
            self.av_detect_button.setEnabled(True)
            return

        if not products:
            self.av_detect_status_label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
            self.av_detect_status_label.setText(
                "No known antivirus/EDR product found. On Windows this can mean Security Center "
                "isn't available (e.g. Windows Server) or genuinely nothing is registered; on Linux "
                "it means nothing on BinSifter's known-product list was detected - a product not on "
                "that list, or one running under an unrecognized service/process name, won't show up."
            )
            self.av_detect_button.setEnabled(True)
            return

        names = ", ".join(p.name for p in products)
        lines = [f"Detected: {names}"]
        for product in products:
            lines.append(f"- {product.name}: {av_detect.guidance_for(product.name)}")
        self.av_detect_status_label.setStyleSheet(f"color: {accent_to_css(theme.Success)}; border: none; background: transparent;")
        self.av_detect_status_label.setText("\n".join(lines))
        self.av_detect_button.setEnabled(True)

    def _on_check_update_clicked(self) -> None:
        theme = self._theme
        self.check_update_button.setEnabled(False)
        self.download_update_button.hide()
        self._pending_update = None
        self.update_status_label.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
        self.update_status_label.setText("Checking...")
        QApplication.processEvents()

        try:
            result = update_check.check_for_update(_BINSIFTER_VERSION)
        except update_check.UpdateCheckError as exc:
            self.update_status_label.setStyleSheet(f"color: {accent_to_css(theme.Danger)}; border: none; background: transparent;")
            self.update_status_label.setText(str(exc))
            self.check_update_button.setEnabled(True)
            return

        if not result.update_available:
            self.update_status_label.setStyleSheet(f"color: {accent_to_css(theme.Success)}; border: none; background: transparent;")
            self.update_status_label.setText(f"You're running the latest version ({result.current_version}).")
            self.check_update_button.setEnabled(True)
            return

        self._pending_update = result
        self.update_status_label.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
        self.update_status_label.setText(
            f"Version {result.latest_version} is available (you have {result.current_version})."
        )
        self.download_update_button.show()
        self.check_update_button.setEnabled(True)

    def _on_download_update_clicked(self) -> None:
        theme = self._theme
        result = self._pending_update
        if result is None:
            return

        manager = update_check.detect_package_manager()
        self.download_update_button.setEnabled(False)
        self.update_status_label.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
        self.update_status_label.setText("Downloading...")
        QApplication.processEvents()

        if manager is None:
            self.update_status_label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
            self.update_status_label.setText(
                "Could not tell which package manager owns this install (are you running from "
                f"source?) - download the update yourself from {result.release_url}"
            )
            self.download_update_button.setEnabled(True)
            return

        try:
            path = update_check.download_update_asset(result, manager)
        except update_check.UpdateCheckError as exc:
            self.update_status_label.setStyleSheet(f"color: {accent_to_css(theme.Danger)}; border: none; background: transparent;")
            self.update_status_label.setText(str(exc))
            self.download_update_button.setEnabled(True)
            return

        command = update_check.install_command_for(manager, path)
        lines = [f"Downloaded to {path}.", "", "To install, run:", "", f"  {command}"]
        if update_check.is_winnow_running():
            lines.insert(0, "BinSifter Winnow is currently running - close it before running the command below.")
            lines.insert(1, "")
        self.update_status_label.setStyleSheet(f"color: {accent_to_css(theme.Success)}; border: none; background: transparent;")
        self.update_status_label.setText("\n".join(lines))
        self.download_update_button.setEnabled(True)
