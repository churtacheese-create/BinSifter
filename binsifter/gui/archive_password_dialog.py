"""Batch password-prompt dialog for archive expansion - shown at most once
per scan, when core/archive.py's pass 1 (expand_archives(), called from
engine.py's scan_directory()) finds one or more password-protected
archives under SrcDir.

By design, all locked archives found are prompted for at once, in a
single batch dialog, rather than interrupting the scan once per archive.
See main_window.py's
_ScanWorker.password_needed signal / MainWindow._on_password_needed() for
how this gets shown safely from the scan's background QThread - Qt dialogs
can only be shown on the GUI thread, so the worker thread blocks on a
threading.Event while this dialog runs there instead.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QLabel,
    QLineEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from binsifter.gui.theme import ThemePalette, qcolor_to_css
from binsifter.gui.widgets import accent_to_css


class ArchivePasswordDialog(QDialog):
    def __init__(self, theme: ThemePalette, locked_archives: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("BinSifter - Password-Protected Archives")
        self.setMinimumWidth(560)
        self.setMinimumHeight(320)
        self.setStyleSheet(f"QDialog {{ background-color: {qcolor_to_css(theme.WindowBack)}; }}")
        self._fields: dict[str, QLineEdit] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        intro = QLabel(
            f"{len(locked_archives)} archive(s) under the scan source are password-protected. "
            "Enter a password for any you know - anything left blank will be saved to "
            "password_protected/ under Reports for you to try with an external cracking tool "
            "(John, hashcat, etc.) instead."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
        root.addWidget(intro)

        # When a batch of archives (e.g. a Malware Bazaar download) all
        # share one password, typing it once here is faster than filling in
        # the same value per row below. An archive's own field wins if
        # filled in (lets an analyst override one oddball archive without
        # clearing this field); otherwise this shared value is used. See
        # password_map().
        shared_label = QLabel("Shared password (optional) - used for any archive left blank below:")
        shared_label.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
        root.addWidget(shared_label)

        self._shared_field = QLineEdit()
        self._shared_field.setEchoMode(QLineEdit.EchoMode.Password)
        self._shared_field.setPlaceholderText("(applies to every archive below that's left blank)")
        self._shared_field.setStyleSheet(
            f"QLineEdit {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
            f"color: {qcolor_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; "
            f"padding: 4px; }}"
        )
        root.addWidget(self._shared_field)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; border: 1px solid {qcolor_to_css(theme.Border)}; }}")
        inner = QWidget()
        inner.setStyleSheet(f"background-color: {qcolor_to_css(theme.SurfaceBack)};")
        grid = QGridLayout(inner)
        grid.setColumnStretch(0, 2)
        grid.setColumnStretch(1, 1)
        for row, path in enumerate(locked_archives):
            label = QLabel(path)
            label.setWordWrap(True)
            label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
            field = QLineEdit()
            field.setEchoMode(QLineEdit.EchoMode.Password)
            field.setPlaceholderText("(leave blank if unknown)")
            field.setStyleSheet(
                f"QLineEdit {{ background-color: {qcolor_to_css(theme.ButtonBack)}; "
                f"color: {qcolor_to_css(theme.Fore)}; border: 1px solid {qcolor_to_css(theme.Border)}; "
                f"padding: 4px; }}"
            )
            grid.addWidget(label, row, 0)
            grid.addWidget(field, row, 1)
            self._fields[path] = field
        scroll.setWidget(inner)
        root.addWidget(scroll, 1)

        # Deliberately no Cancel button - there's no real "cancel" concept
        # here. By the time this dialog can appear, pre-scan setup and
        # every non-locked-archive file are already queued/underway; this
        # step is purely additive (which locked archives get a password
        # attempt vs. saved for external cracking), not a gate on whether
        # the scan proceeds at all. Closing via the window's own X button
        # behaves the same as clicking Continue - password_map() reads
        # whatever's currently in the fields regardless of how the dialog
        # closed.
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Continue Scan")
        buttons.accepted.connect(self.accept)
        root.addWidget(buttons)

    def password_map(self) -> dict[str, str]:
        """Whatever's currently in each field, non-blank entries only - an
        archive's own field wins if filled in; otherwise falls back to the
        shared password field, if that's filled in either. An archive with
        neither stays unresolved."""
        shared = self._shared_field.text()
        result: dict[str, str] = {}
        for path, field in self._fields.items():
            value = field.text() or shared
            if value:
                result[path] = value
        return result
