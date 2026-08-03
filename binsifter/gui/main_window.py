"""Main window shell - port of the PowerShell version's top-level WinForms
layout (BinSifter_v1.3.0-alpha.2.ps1: sidebar construction ~5018-5075, top
bar ~4970-5017, status bar ~5080-5099, overall form assembly ~5100-5140).
Sidebar width/nav order, top bar height/button widths, and status bar height
are copied 1:1 from that source rather than re-derived, same fidelity goal
as theme.py/icons.py/widgets.py.

The scan trigger (folder picker + background thread) now lives on the Scan
Queue page's Start/Pause/Stop buttons, matching the PowerShell version's own
design (BtnStart.Add_Click, lines ~5221-5263) - an earlier pass had a
stopgap "Run Scan" button on the Dashboard's top bar since Scan Queue was
still a placeholder; that's been removed now that Scan Queue is real.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from binsifter import __version__
from binsifter.core.config import build_default_config
from binsifter.core.engine import ScanResult, scan_directory
from binsifter.core.models import FileRecord
from binsifter.core.tool_metadata import format_status_line, refresh_tool_metadata
from binsifter.gui.log_bridge import QtLogHandler
from binsifter.gui.pages.about import AboutPage
from binsifter.gui.pages.capa_rules import CapaRulesPage
from binsifter.gui.pages.dashboard import DashboardPage
from binsifter.gui.pages.help import HelpPage
from binsifter.gui.pages.logs import LogsPage
from binsifter.gui.pages.nsrl import NsrlPage
from binsifter.gui.pages.results import ResultsPage
from binsifter.gui.pages.scan_queue import ScanQueuePage
from binsifter.gui.pages.settings import SettingsPage
from binsifter.gui.pages.yara_rules import YaraRulesPage
from binsifter.gui.theme import DARK, ThemePalette, qcolor_to_css
from binsifter.gui.widgets import NavButton, accent_to_css

# (label, icon_name) - order and icon choice match the sidebar's 7 entries
# in the reference screenshot exactly.
_NAV_ITEMS = (
    ("Dashboard", "gauge"),
    ("Scan Queue", "list"),
    ("Results", "chart"),
    ("YARA Rules", "document"),
    ("Capa Rules", "layers"),
    ("NSRL", "database"),
    ("Logs", "document"),
)

_SIDEBAR_WIDTH = 300
_TOPBAR_HEIGHT = 72
_STATUSBAR_HEIGHT = 40
_LOGO_FILENAME = "BinSifter-Logo-Horizontal-Dark.png"

_TERMINAL_STATUSES = ("Completed", "Error", "Cancelled")


def _format_elapsed(seconds: float) -> str:
    total = int(seconds)
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


class _ScanControl:
    """Cooperative pause/stop flags shared between the UI thread and the
    scan worker thread - same role as the PowerShell version's $ScanControl
    hashtable (IsPaused/StopRequested), just as plain attributes instead of
    a hashtable. Reading/writing a bool attribute across threads without a
    lock is safe enough here under the GIL for this polling use (the worker
    only ever reads these between files, never mid-file), matching the
    original's own lock-free access pattern on the same fields."""

    def __init__(self) -> None:
        self.is_paused = False
        self.stop_requested = False


class _ScanWorker(QObject):
    """Runs engine.scan_directory() off the UI thread - a real scan can take
    long enough on a large source tree that running it inline would freeze
    the window, which the PowerShell version avoided via its own background
    runspace. progress/finished/failed mirror that runspace's event
    callbacks. progress now carries the FileRecord itself (Scanning, then
    Completed/Error) so the Scan Queue grid can show live per-file state."""

    progress = Signal(int, int, str, object)  # done, total, path, FileRecord
    finished = Signal(object)  # ScanResult
    failed = Signal(str)

    def __init__(self, config, scan_control: _ScanControl) -> None:
        super().__init__()
        self._config = config
        self._scan_control = scan_control

    def run(self) -> None:
        try:
            result: ScanResult = scan_directory(
                self._config,
                progress_callback=self._on_progress,
                should_pause=lambda: self._scan_control.is_paused,
                should_stop=lambda: self._scan_control.stop_requested,
            )
        except Exception as exc:  # noqa: BLE001 - report to the UI instead of crashing the thread
            self.failed.emit(str(exc))
            return
        self.finished.emit(result)

    def _on_progress(self, done: int, total: int, current_path: str, record: FileRecord) -> None:
        self.progress.emit(done, total, current_path, record)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.theme: ThemePalette = DARK
        self.setWindowTitle(f"BinSifter {__version__}")
        self.resize(1400, 900)
        self.setStyleSheet(f"QMainWindow {{ background-color: {qcolor_to_css(self.theme.WindowBack)}; }}")

        self.config = build_default_config()
        self._scan_thread: QThread | None = None
        self._scan_worker: _ScanWorker | None = None
        self._scan_control: _ScanControl | None = None
        self._scan_start_time: float | None = None
        self._scan_total_files = 0

        central = QWidget()
        central_layout = QHBoxLayout(central)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)

        central_layout.addWidget(self._build_sidebar())

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        right_layout.addWidget(self._build_topbar())
        right_layout.addWidget(self._build_content())
        right_layout.addWidget(self._build_statusbar())
        central_layout.addWidget(right, 1)

        self.setCentralWidget(central)

        self._nav_buttons[0].set_active(True)

    # ---------- sidebar ----------

    def _build_sidebar(self) -> QWidget:
        theme = self.theme
        sidebar = QFrame()
        sidebar.setFixedWidth(_SIDEBAR_WIDTH)
        sidebar.setStyleSheet(f"QFrame {{ background-color: {qcolor_to_css(theme.SidebarBack)}; border: none; }}")

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 18, 0, 0)
        layout.setSpacing(0)

        logo_path = Path(__file__).resolve().parent.parent.parent / _LOGO_FILENAME
        logo_label = QLabel()
        logo_label.setContentsMargins(12, 0, 12, 0)
        if logo_path.is_file():
            pixmap = QPixmap(str(logo_path))
            scaled = pixmap.scaledToWidth(275, Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(scaled)
        layout.addWidget(logo_label)

        layout.addSpacing(150 - 18 - logo_label.sizeHint().height())

        self._nav_buttons: list[NavButton] = []
        for label, icon_name in _NAV_ITEMS:
            btn = NavButton(theme, icon_name, label)
            btn.clicked.connect(lambda checked=False, b=btn: self._on_nav_clicked(b))
            layout.addWidget(btn)
            self._nav_buttons.append(btn)

        layout.addStretch(1)
        return sidebar

    def _on_nav_clicked(self, clicked: NavButton) -> None:
        for i, btn in enumerate(self._nav_buttons):
            active = btn is clicked
            btn.set_active(active)
            if active:
                self.pages.setCurrentIndex(i)
                self.page_title.setText("" if i == 0 else _NAV_ITEMS[i][0])
                if i == 3:  # YARA Rules - re-read the file fresh every time it's shown, same as Show-Page's Update-YaraRulesContent call
                    self.yara_rules_page.reload_content()
                elif i == 4:  # Capa Rules - same "re-list on every visit" behavior as Show-Page's Update-CapaRulesList call
                    self.capa_rules_page.reload_content()

    def _on_settings_clicked(self) -> None:
        """Settings (like Help/About) is reachable only from the top bar,
        not the sidebar - same as the PowerShell version's Show-Page, which
        only recolors $navButtons entries and leaves Settings/Help/About
        with no sidebar highlight of their own."""
        for btn in self._nav_buttons:
            btn.set_active(False)
        self.page_title.setText("Settings")
        self.pages.setCurrentWidget(self.settings_page)

    def _on_help_clicked(self) -> None:
        for btn in self._nav_buttons:
            btn.set_active(False)
        self.page_title.setText("Help")
        self.pages.setCurrentWidget(self.help_page)

    def _on_about_clicked(self) -> None:
        for btn in self._nav_buttons:
            btn.set_active(False)
        self.page_title.setText("About")
        self.pages.setCurrentWidget(self.about_page)

    # ---------- top bar ----------

    def _build_topbar(self) -> QWidget:
        theme = self.theme
        bar = QFrame()
        bar.setFixedHeight(_TOPBAR_HEIGHT)
        bar.setStyleSheet(f"QFrame {{ background-color: {qcolor_to_css(theme.HeaderBack)}; border: none; }}")

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(28, 0, 24, 0)
        layout.setSpacing(12)

        self.page_title = QLabel("")  # blank on Dashboard, matching the reference screenshot
        self.page_title.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
        font = self.page_title.font()
        font.setPointSize(16)
        font.setBold(True)
        self.page_title.setFont(font)
        layout.addWidget(self.page_title)
        layout.addStretch(1)

        self._topbar_buttons: dict[str, QPushButton] = {}
        # Flat, borderless text-plus-glyph buttons - matches the PowerShell
        # version's New-TopBarButton exactly (BinSifter_v1.3.0-alpha.2.ps1
        # lines ~3456-3473): FlatStyle.Flat, FlatAppearance.BorderSize = 0,
        # BackColor == the bar's own HeaderBack (so there's no visible
        # "chip" behind the label, just colored text), same three glyphs
        # (gear / question mark / circled i) prefixed onto the label text.
        for label, glyph, width in (
            ("Settings", "⚙", 142),  # GEAR
            ("Help", "?", 110),  # plain question mark, same as the original
            ("About", "ⓘ", 122),  # CIRCLED LATIN CAPITAL LETTER I
        ):
            btn = QPushButton(f"{glyph}  {label}")
            btn.setFixedSize(width, 50)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            font = btn.font()
            font.setPointSizeF(12.5)
            btn.setFont(font)
            btn.setStyleSheet(
                f"QPushButton {{ background-color: {qcolor_to_css(theme.HeaderBack)}; "
                f"color: {accent_to_css(theme.Fore)}; border: none; }}"
                f"QPushButton:hover {{ color: {accent_to_css(theme.Accent)}; }}"
            )
            layout.addWidget(btn)
            self._topbar_buttons[label] = btn

        self._topbar_buttons["Settings"].clicked.connect(self._on_settings_clicked)
        self._topbar_buttons["Help"].clicked.connect(self._on_help_clicked)
        self._topbar_buttons["About"].clicked.connect(self._on_about_clicked)

        layout.addSpacing(16)

        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(f"color: {accent_to_css(theme.Success)}; border: none; background: transparent;")
        dot_font = self.status_dot.font()
        dot_font.setPointSizeF(12.5)
        self.status_dot.setFont(dot_font)
        layout.addWidget(self.status_dot)

        self.status_text = QLabel("Ready")
        self.status_text.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
        status_font = self.status_text.font()
        status_font.setPointSizeF(12.5)
        self.status_text.setFont(status_font)
        layout.addWidget(self.status_text)

        return bar

    def _set_status(self, text: str, color) -> None:
        self.status_dot.setStyleSheet(f"color: {accent_to_css(color)}; border: none; background: transparent;")
        self.status_text.setText(text)

    # ---------- scan lifecycle ----------

    def _on_start_scan_clicked(self) -> None:
        if self._scan_thread is not None:
            return  # a scan is already running

        # No folder picker here - SrcDir is a Settings-page field, already
        # on self.config once Settings has been saved. Same required-fields
        # gate as the PowerShell version's BtnStart.Add_Click
        # (BinSifter_v1.3.0-alpha.2.ps1 lines ~5221-5239): warn and jump to
        # Settings if anything required is still blank, instead of silently
        # prompting for (and overwriting SrcDir with) a directory inline.
        required = ("SrcDir", "NsrlPath", "YaraRules", "CapaRules", "ToolsDir")
        missing = [key for key in required if not (getattr(self.config, key, "") or "").strip()]
        if missing:
            QMessageBox.warning(self, "BinSifter", "Configure Settings before starting a scan.")
            self._on_settings_clicked()
            return

        self.scan_queue_page.reset()
        self.scan_queue_page.set_running(True)
        self._set_status("Scanning...", self.theme.Warning)
        self._scan_start_time = time.monotonic()
        self._scan_total_files = 0

        self._scan_control = _ScanControl()
        self._scan_thread = QThread(self)
        self._scan_worker = _ScanWorker(self.config, self._scan_control)
        self._scan_worker.moveToThread(self._scan_thread)
        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.failed.connect(self._on_scan_failed)
        self._scan_thread.start()

    def _on_pause_toggled(self, paused: bool) -> None:
        if self._scan_control is not None:
            self._scan_control.is_paused = paused
        if paused:
            self._set_status("Paused", self.theme.Warning)
        elif self._scan_thread is not None:
            self._set_status("Scanning...", self.theme.Warning)

    def _on_stop_clicked(self) -> None:
        if self._scan_control is not None:
            self._scan_control.stop_requested = True
        self._set_status("Stopping...", self.theme.Warning)

    def _on_scan_progress(self, done: int, total: int, current_path: str, record: FileRecord) -> None:
        self._scan_total_files = total
        self.scan_queue_page.upsert_record(record)

        if record.Status not in _TERMINAL_STATUSES:
            return  # the mid-file "Scanning" callback only needs the grid row above

        elapsed = _format_elapsed(time.monotonic() - self._scan_start_time) if self._scan_start_time else "00:00:00"
        self.dashboard_page.summary_label.setText(f"Scanning: {done} / {total} files - elapsed {elapsed}")
        self.scan_queue_page.set_summary(f"{total} files total - {done} completed - elapsed {elapsed}")

    def _on_scan_finished(self, result: ScanResult) -> None:
        self.dashboard_page.update_from_records(result.records)
        self.results_page.set_records(result.records)
        completed = sum(1 for r in result.records if r.Status == "Completed")
        self.scan_queue_page.set_summary(f"Scan finished. {completed} / {len(result.records)} files completed.")
        self._set_status("Ready", self.theme.Success)
        self.scan_queue_page.set_running(False)
        self._teardown_scan_thread()

    def _on_scan_failed(self, message: str) -> None:
        self._set_status("Error", self.theme.Danger)
        self.scan_queue_page.set_running(False)
        self._teardown_scan_thread()
        QMessageBox.critical(self, "Scan failed", message)

    def _teardown_scan_thread(self) -> None:
        if self._scan_thread is not None:
            self._scan_thread.quit()
            self._scan_thread.wait()
        self._scan_thread = None
        self._scan_worker = None
        self._scan_control = None

    # ---------- content ----------

    def _build_content(self) -> QWidget:
        theme = self.theme
        wrap = QFrame()
        wrap.setStyleSheet(f"QFrame {{ background-color: {qcolor_to_css(theme.WindowBack)}; border: none; }}")
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)

        self.pages = QStackedWidget()
        self.dashboard_page = DashboardPage(theme)
        self.dashboard_page.filter_requested.connect(self._on_dashboard_filter_requested)
        self.pages.addWidget(self.dashboard_page)

        self.scan_queue_page = ScanQueuePage(theme)
        self.scan_queue_page.start_clicked.connect(self._on_start_scan_clicked)
        self.scan_queue_page.pause_toggled.connect(self._on_pause_toggled)
        self.scan_queue_page.stop_clicked.connect(self._on_stop_clicked)
        self.pages.addWidget(self.scan_queue_page)

        self.results_page = ResultsPage(theme, self.config)
        self.pages.addWidget(self.results_page)

        self.yara_rules_page = YaraRulesPage(theme, self.config)
        self.pages.addWidget(self.yara_rules_page)

        self.capa_rules_page = CapaRulesPage(theme, self.config)
        self.pages.addWidget(self.capa_rules_page)

        self.nsrl_page = NsrlPage(theme, self.config)
        self.pages.addWidget(self.nsrl_page)

        self.logs_page = LogsPage(theme)
        self.pages.addWidget(self.logs_page)

        # Every sidebar nav page is real as of this pass - no more
        # "page - not yet built" placeholders in the QStackedWidget.

        # Settings, like Help/About, is a top-bar-only destination - added
        # to the same QStackedWidget but not part of the sidebar's
        # _NAV_ITEMS loop above (see _on_settings_clicked).
        self.settings_page = SettingsPage(theme, self.config)
        self.pages.addWidget(self.settings_page)

        # Help/About, like Settings, are top-bar-only destinations - added
        # to the same QStackedWidget but not part of the sidebar's
        # _NAV_ITEMS loop (see _on_help_clicked/_on_about_clicked).
        self.help_page = HelpPage(theme)
        self.pages.addWidget(self.help_page)

        self.about_page = AboutPage(theme)
        self.pages.addWidget(self.about_page)

        # Cross-page sync, matching the PowerShell version's direct field
        # pokes: browsing to a new path from YARA Rules/Capa Rules/NSRL
        # updates Settings' matching textbox too. Saving Settings refreshes
        # YARA Rules' content and Capa Rules' list (same as the original's
        # Update-YaraRulesContent/Update-CapaRulesList calls after a save);
        # NSRL only gets its label text resynced, not an automatic reload -
        # the original doesn't auto-reload the hash count on Settings save
        # either (BinSifter_v1.3.0-alpha.2.ps1 lines ~5212-5217), since a
        # reload can be a real multi-second parse the analyst should ask
        # for explicitly via Reload Now.
        self.yara_rules_page.rules_path_changed.connect(
            lambda path: self.settings_page._fields["YaraRules"].setText(path)
        )
        self.capa_rules_page.rules_path_changed.connect(
            lambda path: self.settings_page._fields["CapaRules"].setText(path)
        )
        self.nsrl_page.path_changed.connect(lambda path: self.settings_page._fields["NsrlPath"].setText(path))

        self.settings_page.settings_saved.connect(self.yara_rules_page.reload_content)
        self.settings_page.settings_saved.connect(self.capa_rules_page.reload_content)
        self.settings_page.settings_saved.connect(
            lambda: self.nsrl_page.path_label.setText(self.config.NsrlPath or "No NSRL file configured.")
        )

        # Bridges binsifter's own logging into the Logs page - the first
        # thing that makes engine.py's log calls (ATT&CK load status,
        # draft rule-gen skips, etc.) visible anywhere in the GUI.
        self._log_handler = QtLogHandler(level=logging.INFO)
        self._log_handler.log_line.connect(self.logs_page.append_line)
        logging.getLogger("binsifter").addHandler(self._log_handler)
        logging.getLogger("binsifter").setLevel(logging.INFO)

        layout.addWidget(self.pages)
        return wrap

    def _on_dashboard_filter_requested(self, label: str, predicate) -> None:
        """A Dashboard tile or severity bar was clicked - jump to Results
        pre-narrowed to that subset, same as Show-FilteredResults."""
        self.results_page.apply_filter(label, predicate)
        self._on_nav_clicked(self._nav_buttons[2])  # Results is nav index 2

    # ---------- status bar ----------

    def _build_statusbar(self) -> QWidget:
        theme = self.theme
        bar = QFrame()
        bar.setFixedHeight(_STATUSBAR_HEIGHT)
        bar.setStyleSheet(f"QFrame {{ background-color: {qcolor_to_css(theme.HeaderBack)}; border: none; }}")

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24, 0, 24, 0)

        self.footer_label = QLabel(f"BinSifter {__version__}")
        self.footer_label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        font = self.footer_label.font()
        font.setPointSize(9)
        self.footer_label.setFont(font)
        layout.addWidget(self.footer_label)
        layout.addStretch(1)

        # Populate immediately - Start-ToolMetadataRefresh's role, but
        # synchronous here (see core/tool_metadata.py's docstring for why no
        # background thread is needed anymore). Covers the "cached ToolsDir/
        # NsrlPath already filled in at startup" case the original called
        # out explicitly, since build_default_config() already loaded the
        # settings cache before this runs.
        self._refresh_footer()
        # Re-run after every Settings save, same as the original's
        # Start-ToolMetadataRefresh call at the end of the Save handler.
        self.settings_page.settings_saved.connect(self._refresh_footer)

        return bar

    def _refresh_footer(self) -> None:
        metadata = refresh_tool_metadata(self.config.NsrlPath)
        self.footer_label.setText(format_status_line(__version__, metadata))
