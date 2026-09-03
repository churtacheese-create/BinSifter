"""Main window shell - port of the PowerShell version's top-level WinForms
layout (BinSifter-Rowan.ps1: sidebar construction ~5018-5075, top
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
import threading
import time
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from binsifter import __version__
from binsifter.core.config import build_default_config, get_bundled_asset_path, set_tool_paths_from_directory
from binsifter.core.engine import ScanResult, scan_directory
from binsifter.core.models import FileRecord
from binsifter.core.tool_bootstrap import ToolBootstrapResult, run_tool_bootstrap
from binsifter.core.tool_metadata import format_status_line, refresh_tool_metadata
from binsifter.gui.archive_password_dialog import ArchivePasswordDialog
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
from binsifter.gui.theme import ThemePalette, detect_os_dark_mode, get_theme_palette, logo_horizontal_filename, qcolor_to_css
from binsifter.gui.widgets import NavButton, accent_to_css

logger = logging.getLogger(__name__)

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
# Logo filename is theme-dependent - see theme.logo_horizontal_filename()
# (BinSifter detects OS dark/light mode rather than always rendering dark).

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
    # Emitted at most once per scan, from inside scan_directory()'s
    # archive-expansion step (engine.py) if archive.py's pre-scan pass found
    # password-protected archives - carries the locked archive paths. run()
    # blocks on _password_event right after emitting this, until
    # provide_passwords() is called back from the GUI thread (see
    # MainWindow._on_password_needed(), which shows ArchivePasswordDialog).
    # Same "block a background thread, let the GUI thread answer" pattern
    # _scan_control uses for pause/stop, but a one-shot answer instead of a
    # polled flag - safe because this worker is a QThread in the same
    # process as the GUI, not a separate multiprocessing.Pool worker.
    password_needed = Signal(list)

    def __init__(self, config, scan_control: _ScanControl) -> None:
        super().__init__()
        self._config = config
        self._scan_control = scan_control
        self._password_event = threading.Event()
        self._password_map: dict[str, str] = {}

    def run(self) -> None:
        try:
            result: ScanResult = scan_directory(
                self._config,
                progress_callback=self._on_progress,
                should_pause=lambda: self._scan_control.is_paused,
                should_stop=lambda: self._scan_control.stop_requested,
                password_prompt_callback=self._prompt_for_passwords,
            )
        except Exception as exc:  # noqa: BLE001 - report to the UI instead of crashing the thread
            self.failed.emit(str(exc))
            return
        self.finished.emit(result)

    def _on_progress(self, done: int, total: int, current_path: str, record: FileRecord) -> None:
        self.progress.emit(done, total, current_path, record)

    def _prompt_for_passwords(self, locked_archives: list[str]) -> dict[str, str]:
        """Runs on this worker's background QThread, called synchronously
        from inside scan_directory()'s archive-expansion step (handed to it
        as password_prompt_callback above). Blocks until
        MainWindow._on_password_needed() (GUI thread) shows
        ArchivePasswordDialog and calls provide_passwords() back on this
        object. Uses a threading.Event rather than just the signal emit,
        since Signal.emit() doesn't block for a receiver's return value.
        """
        self._password_event.clear()
        self.password_needed.emit(list(locked_archives))
        self._password_event.wait()
        return self._password_map

    def provide_passwords(self, password_map: dict[str, str]) -> None:
        """Called from the GUI thread (MainWindow._on_password_needed(),
        right after ArchivePasswordDialog closes) - hands the answer back
        and unblocks _prompt_for_passwords() above. Safe to touch
        _password_map/_password_event here: the worker thread is parked in
        _password_event.wait() until .set() below runs.
        """
        self._password_map = password_map
        self._password_event.set()


class _ToolBootstrapWorker(QObject):
    """Runs tool_bootstrap.run_tool_bootstrap() off the UI thread - added
    2026-09-03 per the project owner's direct request: on startup, missing
    quick-launch tools (PE-bear/Anya/DIE/Rizin/Angr) should be found or
    auto-installed, but this can mean real network downloads (Angr's pip
    install pulls a whole dependency chain) that must never block the
    window from appearing or a scan from starting - same "don't freeze the
    GUI for a potentially-slow operation" rationale as _ScanWorker above,
    just for startup instead of a scan.
    """

    finished = Signal(list)  # list[ToolBootstrapResult]

    def __init__(self, config) -> None:
        super().__init__()
        self._config = config

    def run(self) -> None:
        try:
            results = run_tool_bootstrap(self._config)
        except Exception:  # noqa: BLE001 - run_tool_bootstrap is itself written to never raise; this is a last-resort net so a genuinely unexpected failure here still can't take the app down
            logger.exception("Unexpected error during tool bootstrap")
            results = []
        self.finished.emit(results)


class MainWindow(QMainWindow):
    def __init__(self, theme: ThemePalette | None = None) -> None:
        super().__init__()
        # `theme` is an optional constructor param (rather than always
        # detecting internally) so __main__.py can detect the OS dark/light
        # setting once and share the result with the app-wide QMessageBox
        # stylesheet too, instead of detecting separately in two places.
        self.theme: ThemePalette = theme if theme is not None else get_theme_palette(detect_os_dark_mode())
        self.setWindowTitle(f"BinSifter Winnow {__version__}")
        # winnow.spec embeds an icon into the exe's PE resources for the
        # taskbar entry, but Qt doesn't reuse that for the window's own
        # title-bar icon - needs an explicit setWindowIcon() call. Uses the
        # PNG (not the .ico winnow.spec embeds) since PNG decoding is built
        # into Qt on every platform; .ico needs a separate imageformats
        # plugin that may not be bundled.
        icon_path = get_bundled_asset_path("BinSifter-WindowIcon.png")
        if icon_path.is_file():
            self.setWindowIcon(QIcon(str(icon_path)))
        self.resize(1400, 900)
        self.setStyleSheet(f"QMainWindow {{ background-color: {qcolor_to_css(self.theme.WindowBack)}; }}")

        self.config = build_default_config()
        self._scan_thread: QThread | None = None
        self._scan_worker: _ScanWorker | None = None
        self._scan_control: _ScanControl | None = None
        self._scan_start_time: float | None = None
        self._scan_total_files = 0
        self._scan_done_count = 0

        # Ticks every second for the whole scan, independent of
        # progress_callback - pre-scan setup (file enumeration, NSRL/
        # blocklist/YARA/capa loading) and slow individual files (capa can
        # take up to its 120s timeout) can produce long gaps with no
        # progress signal, during which a static status text is
        # indistinguishable from a frozen app. This keeps the elapsed-time
        # display counting up regardless of what stage is running.
        self._scan_timer = QTimer(self)
        self._scan_timer.setInterval(1000)
        self._scan_timer.timeout.connect(self._on_scan_tick)

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

        self._tool_bootstrap_thread: QThread | None = None
        self._tool_bootstrap_worker: _ToolBootstrapWorker | None = None
        self._start_tool_bootstrap()

    def _start_tool_bootstrap(self) -> None:
        """Kicks off the first-run (and every-run-until-successful, see
        tool_bootstrap.py's module docstring) quick-launch tool check on a
        background thread, right after the window is otherwise fully
        constructed. Deliberately NOT awaited or blocking anything below it
        - the whole point is that a missing tool (and any network time
        spent trying to auto-install it) can never delay the window
        appearing or a scan starting, per the project owner's explicit
        requirement.
        """
        self._tool_bootstrap_thread = QThread(self)
        self._tool_bootstrap_worker = _ToolBootstrapWorker(self.config)
        self._tool_bootstrap_worker.moveToThread(self._tool_bootstrap_thread)
        self._tool_bootstrap_thread.started.connect(self._tool_bootstrap_worker.run)
        self._tool_bootstrap_worker.finished.connect(self._on_tool_bootstrap_finished)
        self._tool_bootstrap_thread.start()

    def _on_tool_bootstrap_finished(self, results: list[ToolBootstrapResult]) -> None:
        thread = self._tool_bootstrap_thread
        if thread is not None:
            thread.quit()
            thread.wait()
        self._tool_bootstrap_thread = None
        self._tool_bootstrap_worker = None

        if not results:
            return  # nothing ran (e.g. every tool was already present) or bootstrap itself failed unexpectedly - either way, nothing to refresh or tell the user

        # Re-resolve every tool path from config's own ToolsDir/PATH/
        # AutoInstalledTools search, now that the bootstrap pass may have
        # populated AutoInstalledTools - cheap (no network), and is what
        # actually makes a freshly-installed tool's menu item enable
        # without waiting for the next full app restart.
        set_tool_paths_from_directory(self.config, self.config.ToolsDir)

        installed = [r for r in results if r.status == "installed"]
        failed = [r for r in results if r.status == "failed"]
        no_internet = [r for r in results if r.status == "no_internet"]
        if not installed and not failed and not no_internet:
            return  # every tool was already present - stay silent, no popup on every ordinary launch

        lines = []
        if installed:
            lines.append("Installed: " + ", ".join(r.tool_label for r in installed))
        if failed:
            lines.append("Could not auto-install: " + ", ".join(r.tool_label for r in failed))
        if no_internet:
            lines.append(
                "No internet connection, so these couldn't be auto-installed. Reconnect and relaunch "
                "Winnow to retry, or install them yourself:\n"
                + "\n".join(f"  - {r.tool_label}" for r in no_internet)
            )
        QMessageBox.information(self, "BinSifter - quick-launch tools", "\n\n".join(lines))

    # ---------- sidebar ----------

    def _build_sidebar(self) -> QWidget:
        theme = self.theme
        sidebar = QFrame()
        sidebar.setFixedWidth(_SIDEBAR_WIDTH)
        sidebar.setStyleSheet(f"QFrame {{ background-color: {qcolor_to_css(theme.SidebarBack)}; border: none; }}")

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 18, 0, 0)
        layout.setSpacing(0)

        # get_bundled_asset_path(), not a __file__-relative path - a frozen
        # exe's bundled assets don't reliably sit next to the exe depending
        # on the PyInstaller version that built it.
        logo_path = get_bundled_asset_path(logo_horizontal_filename(theme))
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
        # version's New-TopBarButton exactly (BinSifter-Rowan.ps1
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
        # (BinSifter-Rowan.ps1 lines ~5221-5239): warn and jump to
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
        # Runs immediately on click, before the background thread starts -
        # closes the gap between "Start clicked" and visible feedback,
        # which previously spanned however long file enumeration +
        # NSRL/blocklist/YARA/capa loading took (several minutes observed
        # on a large NSRL set) with nothing on screen changing.
        self._set_status("Scanning... (00:00:00)", self.theme.Warning)
        self.scan_queue_page.set_indeterminate("Starting scan - enumerating files...")
        self.scan_queue_page.set_summary("Starting scan...")
        self.scan_queue_page.set_eta("")
        self._scan_start_time = time.monotonic()
        self._scan_total_files = 0
        self._scan_done_count = 0
        self._scan_timer.start()

        self._scan_control = _ScanControl()
        self._scan_thread = QThread(self)
        self._scan_worker = _ScanWorker(self.config, self._scan_control)
        self._scan_worker.moveToThread(self._scan_thread)
        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.failed.connect(self._on_scan_failed)
        # Connected to a bound method of `self`, not a lambda - Qt's
        # cross-thread signal delivery only reliably resolves the
        # receiver's thread through a bound-method slot (see results.py's
        # Speakeasy/Sigcheck thread-safety fix for the same issue).
        self._scan_worker.password_needed.connect(self._on_password_needed)
        self._scan_thread.start()

    def _on_scan_tick(self) -> None:
        """Fires every second for the whole scan (see the QTimer setup in
        __init__). Only owns the top-bar elapsed-time text; deliberately
        doesn't touch scan_queue_page's summary/progress bar, which reflect
        real file-level progress from _on_scan_progress().

        Real-world bug found 2026-08-23: clicking Stop showed "Stopping..."
        for an instant, then the label flipped right back to "Scanning...",
        repeatedly, making Stop look completely broken. This tick handler
        is why - it unconditionally overwrote the status label with
        "Scanning..." (or "Paused...") every second, with no idea a stop
        had been requested, so it clobbered _on_stop_clicked()'s
        "Stopping..." text within a second of the click. Purely cosmetic -
        the underlying stop_requested flag was set correctly the whole
        time and the scan did eventually stop - but there was no way to
        tell from the screen. stop_requested is now checked first, ahead
        of is_paused, since a stop click should always win over a stale
        paused state.
        """
        if self._scan_start_time is None:
            return
        elapsed = _format_elapsed(time.monotonic() - self._scan_start_time)
        if self._scan_control is not None and self._scan_control.stop_requested:
            self._set_status(f"Stopping... ({elapsed})", self.theme.Warning)
        elif self._scan_control is not None and self._scan_control.is_paused:
            self._set_status(f"Paused ({elapsed})", self.theme.Warning)
        else:
            self._set_status(f"Scanning... ({elapsed})", self.theme.Warning)

    def _on_pause_toggled(self, paused: bool) -> None:
        if self._scan_control is not None:
            self._scan_control.is_paused = paused
        # _on_scan_tick() already keeps the Paused/Scanning text in sync
        # every second - this gives instant feedback on the click instead
        # of waiting for the next tick.
        self._on_scan_tick()

    def _on_stop_clicked(self) -> None:
        if self._scan_control is not None:
            self._scan_control.stop_requested = True
        self._set_status("Stopping...", self.theme.Warning)

    def _on_password_needed(self, locked_archives: list[str]) -> None:
        """Slot for _ScanWorker.password_needed - runs on the GUI thread.
        Shows one batch dialog for every password-protected archive found,
        then hands the answer back to the worker, which is parked in
        _prompt_for_passwords()'s .wait()."""
        self._set_status("Waiting for archive password(s)...", self.theme.Warning)
        dialog = ArchivePasswordDialog(self.theme, locked_archives, self)
        dialog.exec()
        if self._scan_worker is not None:
            self._scan_worker.provide_passwords(dialog.password_map())

    def _on_scan_progress(self, done: int, total: int, current_path: str, record: FileRecord) -> None:
        self._scan_total_files = total
        self.scan_queue_page.upsert_record(record)

        if record.Status not in _TERMINAL_STATUSES:
            # Submission-phase callback: `done` counts files dispatched to
            # the worker pool, not completed - still useful since the file
            # total becomes visible here for the first time. Not fed into
            # the overall progress bar, since submission happens in one
            # fast burst and would jump the bar to ~100% then drop back to
            # 0% once completions start, which reads as a glitch.
            self.scan_queue_page.set_progress(0, total)
            self.scan_queue_page.set_summary(f"{total} file(s) queued - dispatching to worker pool...")
            return

        self._scan_done_count = done
        elapsed_seconds = time.monotonic() - self._scan_start_time if self._scan_start_time else 0.0
        elapsed = _format_elapsed(elapsed_seconds)
        self.scan_queue_page.set_progress(done, total)
        self.dashboard_page.summary_label.setText(f"Scanning: {done} / {total} files - elapsed {elapsed}")
        self.scan_queue_page.set_summary(f"{total} files total - {done} completed - elapsed {elapsed}")
        self._update_eta(elapsed_seconds, done, total)

    def _update_eta(self, elapsed_seconds: float, done: int, total: int) -> None:
        """Average time-per-completed-file, recomputed on every completion
        so it adapts as the mix of fast (NSRL-known) and slow (full
        capa/vivisect) files changes over the batch. Deliberately simple -
        capa's per-file cost varies too much for a tight estimate to be
        honest."""
        if done <= 0 or total <= 0:
            self.scan_queue_page.set_eta("ETA: calculating...")
            return
        remaining = total - done
        if remaining <= 0:
            self.scan_queue_page.set_eta("")
            return
        eta_seconds = (elapsed_seconds / done) * remaining
        self.scan_queue_page.set_eta(f"ETA: ~{_format_elapsed(eta_seconds)} remaining")

    def _on_scan_finished(self, result: ScanResult) -> None:
        self.dashboard_page.update_from_records(result.records)
        self.results_page.set_records(result.records)
        completed = sum(1 for r in result.records if r.Status == "Completed")
        self.scan_queue_page.set_summary(f"Scan finished. {completed} / {len(result.records)} files completed.")
        self.scan_queue_page.set_eta("")
        self._set_status("Ready", self.theme.Success)
        self.scan_queue_page.set_running(False)
        self._scan_timer.stop()
        self._teardown_scan_thread()

    def _on_scan_failed(self, message: str) -> None:
        self._set_status("Error", self.theme.Danger)
        self.scan_queue_page.set_running(False)
        self._scan_timer.stop()
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
        # Wrapped in a QScrollArea rather than added directly - Dashboard's
        # three tile rows + severity chart + summary line add up to more
        # combined content than any other page, and on Linux (confirmed via
        # a real Ubuntu-VM bug report, 2026-08-26) that combination made the
        # whole MAIN WINDOW itself refuse to resize vertically at all - not
        # just Dashboard - because QStackedWidget's own effective size
        # hint/constraint is derived from the largest content among ALL of
        # its pages, not just whichever one is currently visible. Isolated
        # via a long real-machine bisection (StatTile alone: fine,
        # SeverityBarChart alone: fine, up to 3 tile rows + chart: fine,
        # only the FULL combination including the section-title labels and
        # the word-wrapping summary label together actually reproduced the
        # lock) without ever finding one single offending line - this is
        # the standard, correct Qt fix for "a page has more natural content
        # than reliably fits" regardless of the exact underlying layout
        # interaction, since a QScrollArea's own size hint is independent
        # of its inner content's size, so it can no longer propagate a
        # rigid height constraint up to the window at all. setWidgetResizable(True)
        # is required - without it the scroll area sizes itself to the
        # page's sizeHint instead of letting the page fill/scroll within
        # whatever space it's given, which would silently reintroduce the
        # exact same problem.
        dashboard_scroll = QScrollArea()
        dashboard_scroll.setWidget(self.dashboard_page)
        dashboard_scroll.setWidgetResizable(True)
        dashboard_scroll.setFrameShape(QFrame.Shape.NoFrame)
        dashboard_scroll.setStyleSheet(
            f"QScrollArea {{ background-color: {qcolor_to_css(theme.WindowBack)}; border: none; }}"
        )
        self.pages.addWidget(dashboard_scroll)

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

        # Cross-page sync: browsing to a new path from YARA Rules/Capa
        # Rules/NSRL updates Settings' matching textbox. Saving Settings
        # refreshes YARA Rules' content and Capa Rules' list; NSRL only
        # resyncs its label text, not an automatic reload - a reload can be
        # a multi-second parse, left to the analyst via Reload Now.
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

        # Populate immediately - synchronous, since build_default_config()
        # already loaded the settings cache before this runs (see
        # core/tool_metadata.py for why no background thread is needed).
        self._refresh_footer()
        # Re-run after every Settings save.
        self.settings_page.settings_saved.connect(self._refresh_footer)

        return bar

    def _refresh_footer(self) -> None:
        metadata = refresh_tool_metadata(self.config.NsrlPath)
        self.footer_label.setText(format_status_line(f"{__version__}", metadata))
