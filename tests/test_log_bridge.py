"""Tests for binsifter.gui.log_bridge.QtLogHandler - the logging.Handler
that surfaces Python log records in the GUI's Logs page. Needs a
QCoreApplication (not a full QApplication/display) since QtLogHandler is a
QObject for its signal, but never creates a widget."""

import logging

from PySide6.QtCore import QCoreApplication

from binsifter.gui.log_bridge import QtLogHandler

_app = QCoreApplication.instance() or QCoreApplication([])


def test_emit_formats_hh_mm_ss_prefix_and_message():
    handler = QtLogHandler()
    captured = []
    handler.log_line.connect(captured.append)

    logger = logging.getLogger("test.log_bridge.one")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        logger.info("hello world")
    finally:
        logger.removeHandler(handler)

    assert len(captured) == 1
    line = captured[0]
    assert line.endswith("] hello world")
    assert line.startswith("[")
    # "[HH:MM:SS] " - 10 chars between the brackets plus the trailing space
    assert line[9] == "]"


def test_emit_formats_percent_style_args():
    handler = QtLogHandler()
    captured = []
    handler.log_line.connect(captured.append)

    logger = logging.getLogger("test.log_bridge.two")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        logger.info("loaded %d rule(s) from %s", 3, "rules.yar")
    finally:
        logger.removeHandler(handler)

    assert captured[0].endswith("] loaded 3 rule(s) from rules.yar")


def test_handler_respects_level_threshold():
    handler = QtLogHandler(level=logging.WARNING)
    captured = []
    handler.log_line.connect(captured.append)

    logger = logging.getLogger("test.log_bridge.three")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        logger.info("should not appear")
        logger.warning("should appear")
    finally:
        logger.removeHandler(handler)

    assert len(captured) == 1
    assert "should appear" in captured[0]
