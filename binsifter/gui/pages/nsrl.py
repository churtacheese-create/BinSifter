"""NSRL page - port of New-NsrlPage and its wiring (BinSifter-Rowan_v1.3.0-
beta.1.ps1, lines ~4696-4740 for the page, ~5513-5609 for BtnBrowse/
BtnReloadPreview). Path label, Browse, Reload Now, and a big known-good
hash count.

Updated 2026-08-04: core.nsrl now has the cache this module's docstring
used to flag as missing (a real 72-million-row NSRL file made "parses
fresh every time" cost 24.5 minutes on its own, not a theoretical gap
anymore - see nsrl.py's module docstring for the full story). Reload Now
uses the same get_cache_path/cache_is_fresh/build_index/read_cached_count
functions scan_directory() does, so a repeat reload of an unchanged file is
a fast cache-hit here too, not a second full reparse. Still runs on a
background QThread - even a cache-hit mmap open plus header read shouldn't
block the window, and a genuine cache MISS (first load of a new/changed
file) still needs the real build.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from binsifter.core import nsrl as nsrl_mod
from binsifter.core.config import BinSifterConfig
from binsifter.gui.theme import ThemePalette, qcolor_to_css
from binsifter.gui.widgets import accent_to_css

_NSRL_FILE_FILTER = "Text files (*.txt);;All files (*.*)"


class _NsrlLoadWorker(QObject):
    finished = Signal(int)  # hash count
    failed = Signal(str)

    def __init__(self, path: str, report_directory: str) -> None:
        super().__init__()
        self._path = path
        self._report_directory = report_directory

    def run(self) -> None:
        try:
            cache_path = nsrl_mod.get_cache_path(self._path, self._report_directory)
            if nsrl_mod.cache_is_fresh(cache_path, self._path):
                count = nsrl_mod.read_cached_count(cache_path)
            else:
                count = nsrl_mod.build_index(self._path, cache_path)
        except Exception as exc:  # noqa: BLE001 - report to the UI instead of crashing the thread
            self.failed.emit(str(exc))
            return
        self.finished.emit(count)


class NsrlPage(QWidget):
    # Emitted after Browse picks a new file - kept in sync with Settings'
    # NsrlPath field, same as the PowerShell version's BtnBrowse handler
    # poking $settings.Fields['NsrlPath'].Text directly.
    path_changed = Signal(str)

    def __init__(self, theme: ThemePalette, config: BinSifterConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        self._config = config
        self._thread: QThread | None = None
        self._worker: _NsrlLoadWorker | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 24)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())
        root.addSpacing(20)

        self.count_label = QLabel("0")
        self.count_label.setContentsMargins(28, 0, 0, 0)
        count_font = QFont("Segoe UI", 28)
        count_font.setBold(True)
        self.count_label.setFont(count_font)
        self.count_label.setStyleSheet(f"color: {accent_to_css(theme.Accent)}; border: none; background: transparent;")
        root.addWidget(self.count_label)

        caption = QLabel("known-good hashes loaded")
        caption.setContentsMargins(28, 4, 0, 0)
        caption.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        root.addWidget(caption)

        root.addStretch(1)

        if config.NsrlPath:
            self.path_label.setText(config.NsrlPath)

    def _build_toolbar(self) -> QWidget:
        theme = self._theme
        bar = QFrame()
        bar.setFixedHeight(50)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(10)

        self.path_label = QLabel("No NSRL file configured.")
        self.path_label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        layout.addWidget(self.path_label)
        layout.addStretch(1)

        self.browse_button = QPushButton("Browse...")
        self.browse_button.setFixedSize(110, 34)
        self.reload_button = QPushButton("Reload Now")
        self.reload_button.setFixedSize(130, 34)
        for btn in (self.browse_button, self.reload_button):
            btn.setStyleSheet(
                f"QPushButton {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
                f"color: {accent_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}"
            )

        self.browse_button.clicked.connect(self._on_browse)
        self.reload_button.clicked.connect(self._on_reload_clicked)

        layout.addWidget(self.browse_button)
        layout.addWidget(self.reload_button)
        return bar

    def _on_browse(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "Select NSRL file", self._config.NsrlPath, _NSRL_FILE_FILTER)
        if not chosen:
            return
        self._config.NsrlPath = chosen
        self.path_label.setText(chosen)
        self.path_changed.emit(chosen)

    def _on_reload_clicked(self) -> None:
        path = self._config.NsrlPath
        if not path or not Path(path).is_file():
            QMessageBox.information(self, "BinSifter", "Configure a valid NSRL file first.")
            return
        if self._thread is not None:
            return  # a reload is already in flight

        self.reload_button.setEnabled(False)
        self.reload_button.setText("Loading...")

        self._thread = QThread(self)
        self._worker = _NsrlLoadWorker(path, self._config.ReportDirectory)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_load_finished)
        self._worker.failed.connect(self._on_load_failed)
        self._thread.start()

    def _on_load_finished(self, count: int) -> None:
        self.count_label.setText(str(count))
        self._teardown_thread()

    def _on_load_failed(self, message: str) -> None:
        QMessageBox.critical(self, "BinSifter", f"NSRL preview failed: {message}")
        self._teardown_thread()

    def _teardown_thread(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait()
        self._thread = None
        self._worker = None
        self.reload_button.setEnabled(True)
        self.reload_button.setText("Reload Now")
