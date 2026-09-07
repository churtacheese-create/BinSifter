"""Environment sanitization for subprocess calls that launch EXTERNAL,
non-bundled executables (a real system python3, pip, gdb, an AppImage,
Ghidra's own launch scripts, a terminal emulator, gsettings/xdg-desktop-
portal, etc.) - see external_subprocess_env()'s own docstring for the
real bug this module exists to fix.
"""

from __future__ import annotations

import os


def external_subprocess_env() -> dict[str, str]:
    """Returns a copy of the current process's environment suitable for
    launching an EXTERNAL program BinSifter did not itself compile or
    bundle - use as the `env=` argument to every subprocess.run()/Popen()
    call that does so.

    REAL BUG FOUND AND FIXED 2026-09-07, confirmed directly via `strace`
    against a real frozen `.deb` install, not guessed: PyInstaller's Linux
    bootloader sets LD_LIBRARY_PATH to its own bundled library directory
    (.../_internal, which contains BinSifter's own bundled libssl.so.3/
    libcrypto.so.3 among many others) so the frozen app's OWN Python can
    find its bundled native libraries at runtime - necessary and correct
    for the frozen app itself. But subprocess.run()/Popen() inherit the
    parent's environment by default, so every EXTERNAL tool this app
    spawns (a real system python3 for a private venv, pip installing a
    real package, gdb, an AppImage, Ghidra's own launch scripts, a
    terminal emulator) was ALSO getting BinSifter's bundled
    LD_LIBRARY_PATH - meaning the dynamic linker preferred BinSifter's
    bundled .so files over the system's own for any shared library name
    that happened to collide, silently swapping in a different,
    potentially ABI-incompatible library underneath a completely
    unrelated, independently-compiled program.

    Confirmed exact failure mode via strace against a real launch: a
    private venv's `python3 -m venv --without-pip` itself succeeded (needs
    no network/SSL), but the very next pip-bootstrap step (ensurepip, then
    this project's own get-pip.py fallback - see tool_bootstrap.py's
    _create_private_venv()) failed with pip's own "WARNING: Disabling
    truststore since ssl support is missing" / "ERROR: Could not find a
    version that satisfies the requirement pip (from versions: none)" -
    textbook symptoms of a Python process whose `_ssl` C extension linked
    against the wrong OpenSSL build. The identical mechanism explains real
    quick-launch tools (Anya/DIE/Cutter AppImages, Ghidra, GDB) doing
    nothing or erroring after a successful auto-install: they're launched
    via subprocess.Popen() from this same frozen process (see
    gui/pages/results.py's _popen_watched()), so they inherit the exact
    same polluted LD_LIBRARY_PATH BinSifter's own bundle needs for itself.

    PyInstaller's own documented convention for exactly this class of
    problem is to check LD_LIBRARY_PATH_ORIG (a bootloader-saved,
    pre-injection value) and restore it before invoking an external
    program - checked for here in case a future PyInstaller/bootloader
    version sets it, but this project's actual installed bootloader was
    directly confirmed via strace to NOT set any such variable, so
    removing LD_LIBRARY_PATH outright is the correct fallback here, not
    just a defensive extra branch nothing will ever take.
    """
    env = os.environ.copy()
    original = env.pop("LD_LIBRARY_PATH_ORIG", None)
    if original:
        env["LD_LIBRARY_PATH"] = original
    else:
        env.pop("LD_LIBRARY_PATH", None)
    return env
