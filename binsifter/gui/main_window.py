"""Main window shell - a minimal, launchable skeleton, not a feature port
yet. Purpose right now is just to confirm PySide6 and the environment are
wired up correctly before real pages (Dashboard/Results/Settings/Help/Logs,
mirroring the PowerShell version's WinForms pages) get built out one at a
time.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QLabel,
    QListWidget,
    QMainWindow,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from binsifter import __version__
from binsifter.core.config import build_default_config

_NAV_PAGES = ["Dashboard", "Results", "Settings", "Help", "Logs"]


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"BinSifter {__version__} (scaffold)")
        self.resize(1200, 800)

        # Loads config.py's default-location logic (Reports/Attack/Blocklist
        # auto-created next to the install, settings cache loaded) - proves
        # that path out end-to-end, same as the rest of this scaffold.
        self.config = build_default_config()

        nav_list = QListWidget()
        nav_list.addItems(_NAV_PAGES)
        nav_list.setFixedWidth(160)

        self.pages = QStackedWidget()
        for name in _NAV_PAGES:
            placeholder = QLabel(f"{name} page - not yet built.")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.pages.addWidget(placeholder)

        nav_list.currentRowChanged.connect(self.pages.setCurrentIndex)
        nav_list.setCurrentRow(0)

        splitter = QSplitter()
        splitter.addWidget(nav_list)
        splitter.addWidget(self.pages)
        splitter.setStretchFactor(1, 1)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)
        self.setCentralWidget(container)

        self.statusBar().showMessage(
            f"Report directory: {self.config.ReportDirectory}"
        )
