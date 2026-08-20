"""GUI entry point - `binsifter` console script (see pyproject.toml)."""

from __future__ import annotations

import multiprocessing
import sys

from PySide6.QtWidgets import QApplication

from binsifter.gui.main_window import MainWindow
from binsifter.gui.theme import ThemePalette, detect_os_dark_mode, get_theme_palette, qcolor_to_css


def _apply_message_box_stylesheet(app: QApplication, theme: ThemePalette) -> None:
    """Every other widget in this app gets its colors from an explicit
    per-widget setStyleSheet() call using theme.py's palette - there's no
    app-wide QApplication.setStyleSheet()/setPalette() call anywhere else.
    QMessageBox is the exception: every call site uses the static
    QMessageBox.information/warning/critical() convenience methods, which
    build a plain, unstyled dialog with no BinSifter theming applied.

    On Windows 11 with the OS "dark mode" setting on, Qt6 auto-applies a
    dark palette to native-style dialogs like QMessageBox, but text-color
    roles don't get correspondingly lightened, producing near-black text
    on a near-black background. This isn't a BinSifter bug - it's a gap in
    Qt's OS-derived palette for a dialog nobody explicitly styled.

    Applied once, globally, here rather than at each QMessageBox call
    site, so a single stylesheet covers every current and future one.
    `theme` is passed in from main() (detected once via
    detect_os_dark_mode(), shared with MainWindow) so message boxes match
    whichever palette the rest of the app is using.
    """
    app.setStyleSheet(
        f"QMessageBox {{ background-color: {qcolor_to_css(theme.SurfaceBack)}; }}"
        f"QMessageBox QLabel {{ color: {qcolor_to_css(theme.Fore)}; background: transparent; }}"
    )


def main() -> int:
    app = QApplication(sys.argv)
    # Detected once, here, and shared with both consumers below - see
    # MainWindow.__init__'s comment on why detecting separately in two
    # places would risk them disagreeing.
    theme = get_theme_palette(detect_os_dark_mode())
    _apply_message_box_stylesheet(app, theme)
    window = MainWindow(theme)
    window.show()
    return app.exec()


if __name__ == "__main__":
    # REQUIRED for a frozen (PyInstaller) build - without this, every
    # multiprocessing worker engine.py's scan_directory() spawns opens a
    # brand new full GUI window instead of running as a background worker.
    #
    # Root cause: on Windows, multiprocessing has no fork() and must
    # "spawn" - relaunch a fresh interpreter that imports the main module.
    # For a normal script that relaunch runs `python.exe -c <bootstrap>`,
    # which never re-executes this file's `if __name__ == "__main__":`
    # block, so unfrozen this needs no special handling. Once frozen there
    # is no separate python.exe, so multiprocessing.spawn instead
    # relaunches the same exe with a hidden sentinel flag. freeze_support()
    # recognizes that sentinel and runs the worker's target function
    # instead of re-running this whole script (QApplication and MainWindow
    # included). winnow.spec's "multiprocessing.popen_spawn_win32"
    # hiddenimport only bundles the module - it doesn't call
    # freeze_support() for you. Must run before QApplication is created,
    # since a spawned worker needs to exit before reaching that. Harmless
    # no-op on Linux/macOS and on an unfrozen run, so left unconditional.
    multiprocessing.freeze_support()
    sys.exit(main())
