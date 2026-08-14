"""GUI entry point - `binsifter` console script (see pyproject.toml)."""

from __future__ import annotations

import multiprocessing
import sys

from PySide6.QtWidgets import QApplication

from binsifter.gui.main_window import MainWindow
from binsifter.gui.theme import ThemePalette, detect_os_dark_mode, get_theme_palette, qcolor_to_css


def _apply_message_box_stylesheet(app: QApplication, theme: ThemePalette) -> None:
    """2026-08-06: every other widget in this app gets its colors from an
    explicit per-widget setStyleSheet() call using theme.py's palette (see
    e.g. main_window.py, results.py) - there is not, and never has been,
    any app-wide QApplication.setStyleSheet()/setPalette() call anywhere in
    this codebase (confirmed by grep before writing this). QMessageBox is
    the one exception: every call site (main_window.py's "Configure
    Settings"/scan-failed dialogs, results.py's Ghidra/Sigcheck/Speakeasy
    dialogs, settings.py's validation errors, etc.) uses the static
    QMessageBox.information/warning/critical() convenience methods, which
    build a plain, unstyled dialog with no BinSifter theming applied at
    all - it renders however Qt's own default/OS-derived styling says to.

    On a Windows 11 machine with the OS-level "dark mode" setting on, Qt6
    auto-detects that preference and applies a dark palette to native-style
    top-level dialogs like QMessageBox - but that auto-derivation has a
    well-documented gap where the background gets darkened correctly while
    text-color roles (WindowText/Text) don't get correspondingly lightened,
    producing exactly the "text is there but unreadable, near-black on
    near-black" symptom hit on both the Ghidra confirmation dialog
    (plain synchronous QMessageBox.information() call, no threading
    involved at all - rules out the QThread fix as a cause) and the
    Speakeasy confirmation dialog. This isn't something BinSifter's own
    code got wrong - it's Qt/Windows failing to correctly derive readable
    text colors for a dialog nobody explicitly styled.

    Applied once, globally, here rather than at each of the ~10+
    QMessageBox call sites: a single app-wide stylesheet targeting the
    QMessageBox class name overrides Qt's OS-derived palette for every
    current AND future call site, the same "one true place" pattern
    theme.py already establishes for everything else.

    2026-08-06: `theme` is now passed in from main() (detected once via
    detect_os_dark_mode(), shared with MainWindow) instead of being
    hardcoded to DARK - message boxes now match whichever palette the rest
    of the app is actually using, light or dark, instead of always looking
    dark regardless of the OS setting or what MainWindow picked.
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
    # 2026-08-13: REQUIRED for a frozen (PyInstaller) build - without this,
    # a real installer test showed every multiprocessing worker
    # engine.py's scan_directory() spawns (up to 16, one per CPU) opening
    # a brand new full BinSifter-Winnow.exe GUI window instead of running
    # as a background worker, mid-scan, right after NSRL caching finished.
    #
    # Root cause: on Windows, multiprocessing has no fork() and must
    # "spawn" - relaunch a fresh interpreter and have it import the main
    # module. For a normal (non-frozen) script that relaunch runs
    # `python.exe -c <bootstrap code>`, which never re-executes this
    # file's own `if __name__ == "__main__":` block at all - so unfrozen,
    # this codebase's engine.py/capa_scan.py/subprocess_timeout.py's
    # existing multiprocessing.get_context("spawn") calls (dev sandbox and
    # `pip install -e .` usage) always worked correctly with no special
    # handling needed. There is no separate python.exe once frozen,
    # though - the frozen exe IS the only executable, so Python's own
    # multiprocessing.spawn module relaunches THAT SAME exe with a hidden
    # sentinel flag instead. freeze_support() is what recognizes that
    # sentinel and, in the child, runs the worker's target function then
    # exits immediately - WITHOUT that check, PyInstaller's bootloader has
    # no way to know this launch is a spawned worker and not a fresh
    # double-click, so it just ran this whole script again top to bottom,
    # QApplication and MainWindow included. winnow.spec's existing
    # "multiprocessing.popen_spawn_win32" hiddenimport only makes sure the
    # module bundles into the build - it doesn't call freeze_support() for
    # you, which is a separate, required, one-line step per Python's own
    # multiprocessing docs. Must be the very first thing done here, before
    # QApplication is ever created, since a spawned worker needs to exit
    # before reaching any of that. A harmless no-op on Linux/macOS and on
    # an unfrozen run either way, so left unconditional rather than
    # gated behind `sys.frozen`.
    multiprocessing.freeze_support()
    sys.exit(main())
