"""NSRL page - port of New-NsrlPage and its wiring (BinSifter_v1.3.0-
alpha.2.ps1, lines ~4696-4740 for the page, ~5513-5609 for BtnBrowse/
BtnReloadPreview). Path label, Browse, Reload Now, and a big known-good
hash count.

Deliberate simplification from the original, not a missing feature: the
PowerShell version's Reload Now maintains its own on-disk binary cache
(length + mtime ticks header, one 20-byte record per hash) so repeat
reloads of the same unchanged file skip re-parsing the whole CSV. This
port's core.nsrl.load_nsrl_hashes() has no such cache - it parses fresh
every time, same as the PowerShell version's own cache-miss path. Still
runs on a background QThread (not inline) since a large NSRL file's parse
can take real time and shouldn't freeze the window - just without the
original's persistent speed-up for repeat loads. Worth adding a real cache
to core/nsrl.py later if reload latency on a large file turns out to
matter in practice; not invented speculatively here.
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

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path

    def run(self) -> None:
        try:
            hashes = nsrl_mod.load_nsrl_hashes(self._path)
        except Exception as exc:  # noqa: BLE001 - report to the UI instead of crashing the thread
            self.failed.emit(str(exc))
            return
        self.finished.emit(len(hashes))


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
        self._worker = _NsrlLoadWorker(path)
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
