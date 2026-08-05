"""Bridges Python's `logging` module into the GUI's Logs page - the Python
port's equivalent of the PowerShell version's $LogQueue/Add-Log/750ms drain
timer (BinSifter-Rowan_v1.3.0-beta.1.ps1 lines ~1881-1885 for Add-Log, ~5611-5628
for the drain). Same "[HH:MM:SS] message" line format.

Real, not cosmetic: engine.py and its collaborators already log through
Python's `logging` module (e.g. "MITRE ATT&CK data loaded: N techniques
indexed", "Draft YARA rule generation skipped due to error: ..."), but
nothing in the GUI has ever attached a handler to see them - this is the
first thing that makes those messages visible in the app at all, same
purpose the PowerShell version's Logs page served.

QtLogHandler is a QObject+logging.Handler hybrid so log records emitted
from ANY thread (the background scan worker included) get delivered
GUI-thread-safely via Qt's signal/slot mechanism (queued connections cross
threads correctly; touching a QPlainTextEdit directly from a non-GUI
thread would not).
"""

from __future__ import annotations

import logging
from datetime import datetime

from PySide6.QtCore import QObject, Signal


class QtLogHandler(QObject, logging.Handler):
    log_line = Signal(str)

    def __init__(self, level: int = logging.INFO) -> None:
        QObject.__init__(self)
        logging.Handler.__init__(self, level=level)

    def emit(self, record: logging.LogRecord) -> None:
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a bad log call shouldn't crash the handler
            message = record.msg
        self.log_line.emit(f"[{timestamp}] {message}")
