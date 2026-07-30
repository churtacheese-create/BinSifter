"""Main window shell - port of the PowerShell version's top-level WinForms
layout (BinSifter_v1.3.0-alpha.2.ps1: sidebar construction ~5018-5075, top
bar ~4970-5017, status bar ~5080-5099, overall form assembly ~5100-5140).
Sidebar width/nav order, top bar height/button widths, and status bar height
are copied 1:1 from that source rather than re-derived, same fidelity goal
as theme.py/icons.py/widgets.py.

This replaces the earlier scaffold (nav QListWidget + plain QLabel
placeholders) now that the real themed pieces exist.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFileDialog,
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
from binsifter.gui.pages.dashboard import DashboardPage
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


class _ScanWorker(QObject):
    """Runs engine.scan_directory() off the UI thread - a real scan can take
    long enough on a large source tree that running it inline would freeze
    the window, which the PowerShell version avoided via its own background
    runspace. progress/finished/failed mirror that runspace's event
    callbacks."""

    progress = Signal(int, int, str)
    finished = Signal(object)  # ScanResult
    failed = Signal(str)

    def __init__(self, config) -> None:
        super().__init__()
        self._config = config

    def run(self) -> None:
        try:
            result: ScanResult = scan_directory(self._config, progress_callback=self._on_progress)
        except Exception as exc:  # noqa: BLE001 - report to the UI instead of crashing the thread
            self.failed.emit(str(exc))
            return
        self.finished.emit(result)

    def _on_progress(self, done: int, total: int, current_path: str) -> None:
        self.progress.emit(done, total, current_path)


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
        self._pages_by_nav: dict[int, QWidget] = {}
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

        # Run Scan has no equivalent button in the reference screenshot -
        # the PowerShell version triggers scans from the Scan Queue page,
        # which is still a placeholder here. Kept as a distinct, visually
        # separated control (not mixed into the Settings/Help/About group)
        # since it's a deliberate scope addition for wiring the Dashboard to
        # real data, not part of the ported chrome.
        self.run_scan_button = QPushButton("Run Scan")
        self.run_scan_button.setFixedSize(110, 44)
        self.run_scan_button.setStyleSheet(
            f"QPushButton {{ background-color: {qcolor_to_css(theme.Accent)}; "
            f"color: {accent_to_css(theme.AccentFore)}; border: none; }}"
        )
        self.run_scan_button.clicked.connect(self._on_run_scan_clicked)
        layout.addWidget(self.run_scan_button)

        layout.addSpacing(16)

        for label, width in (("Settings", 126), ("Help", 96), ("About", 106)):
            btn = QPushButton(label)
            btn.setFixedSize(width, 44)
            btn.setStyleSheet(
                f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
                f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
            )
            layout.addWidget(btn)

        layout.addSpacing(16)

        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(f"color: {accent_to_css(theme.Success)}; border: none; background: transparent;")
        layout.addWidget(self.status_dot)

        self.status_text = QLabel("Ready")
        self.status_text.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
        layout.addWidget(self.status_text)

        return bar

    def _on_run_scan_clicked(self) -> None:
        if self._scan_thread is not None:
            return  # a scan is already running

        src_dir = QFileDialog.getExistingDirectory(self, "Select folder to scan")
        if not src_dir:
            return
        self.config.SrcDir = src_dir

        self.status_dot.setStyleSheet(
            f"color: {accent_to_css(self.theme.Warning)}; border: none; background: transparent;"
        )
        self.status_text.setText("Scanning...")
        self.run_scan_button.setEnabled(False)

        self._scan_thread = QThread(self)
        self._scan_worker = _ScanWorker(self.config)
        self._scan_worker.moveToThread(self._scan_thread)
        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.failed.connect(self._on_scan_failed)
        self._scan_thread.start()

    def _on_scan_progress(self, done: int, total: int, current_path: str) -> None:
        self.status_text.setText(f"Scanning... {done}/{total}")

    def _on_scan_finished(self, result: ScanResult) -> None:
        self.dashboard_page.update_from_records(result.records)
        self.status_dot.setStyleSheet(
            f"color: {accent_to_css(self.theme.Success)}; border: none; background: transparent;"
        )
        self.status_text.setText("Ready")
        self.run_scan_button.setEnabled(True)
        self._teardown_scan_thread()

    def _on_scan_failed(self, message: str) -> None:
        self.status_dot.setStyleSheet(
            f"color: {accent_to_css(self.theme.Danger)}; border: none; background: transparent;"
        )
        self.status_text.setText("Error")
        self.run_scan_button.setEnabled(True)
        self._teardown_scan_thread()
        QMessageBox.critical(self, "Scan failed", message)

    def _teardown_scan_thread(self) -> None:
        if self._scan_thread is not None:
            self._scan_thread.quit()
            self._scan_thread.wait()
        self._scan_thread = None
        self._scan_worker = None

    # ---------- content ----------

    def _build_content(self) -> QWidget:
        theme = self.theme
        wrap = QFrame()
        wrap.setStyleSheet(f"QFrame {{ background-color: {qcolor_to_css(theme.WindowBack)}; border: none; }}")
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)

        self.pages = QStackedWidget()
        self.dashboard_page = DashboardPage(theme)
        self.pages.addWidget(self.dashboard_page)
        for label, _ in _NAV_ITEMS[1:]:
            placeholder = QLabel(f"{label} page - not yet built.")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)};")
            self.pages.addWidget(placeholder)

        layout.addWidget(self.pages)
        return wrap

    # ---------- status bar ----------

    def _build_statusbar(self) -> QWidget:
        theme = self.theme
        bar = QFrame()
        bar.setFixedHeight(_STATUSBAR_HEIGHT)
        bar.setStyleSheet(f"QFrame {{ background-color: {qcolor_to_css(theme.HeaderBack)}; border: none; }}")

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24, 0, 24, 0)

        label = QLabel(f"BinSifter {__version__}")
        label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        font = label.font()
        font.setPointSize(9)
        label.setFont(font)
        layout.addWidget(label)
        layout.addStretch(1)

        return bar
