# PyInstaller spec for Winnow (BinSifter's Python/PySide6 variant) - added
# 2026-08-08 per a direct request for a real, installable beta release.
#
# HONEST CAVEAT, stated plainly rather than glossed over: this spec was
# written and reasoned through in a Linux-only dev sandbox with no Windows
# environment to actually run PyInstaller against - there is no way to
# compile or test a Windows .exe from here. Everything below reflects real
# knowledge of PyInstaller's known trouble spots for this specific
# dependency stack (capa/vivisect's dynamic imports, signify's mscerts
# trust-store DATA files, speakeasy's own data files), not guesses, but a
# first real Windows build should be expected to need at least one or two
# iterations - PyInstaller failures for a stack this size (PySide6 + capa +
# vivisect + speakeasy/unicorn + signify + numpy) are almost never clean on
# the very first attempt for anyone, not just from this sandbox's
# constraints. Run installer/build_winnow.ps1, see what (if anything)
# fails at runtime, and extend the collect_all()/hiddenimports lists below
# to match - the comments on each explain WHY it's there so extending them
# is a "same reasoning, one more package" exercise, not a fresh
# investigation each time.
#
# Build with: pyinstaller installer/winnow.spec --distpath installer/dist
# (see build_winnow.ps1, which also runs Inno Setup afterward)

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

block_cipher = None
repo_root = Path(SPECPATH).resolve().parent

# ---------------------------------------------------------------------------
# Data files BinSifter's OWN code reads by path at runtime (see
# binsifter/core/config.py's get_binsifter_root(), 2026-08-08 addition -
# when frozen, that function returns sys.executable's own directory, which
# is exactly where --onedir puts these, matching the layout below).
# ---------------------------------------------------------------------------
own_datas = [
    (str(repo_root / "BinSifter-Logo-Horizontal-Dark.png"), "."),
    (str(repo_root / "BinSifter-Logo-Horizontal.png"), "."),
]

# ---------------------------------------------------------------------------
# Third-party packages that bundle their own non-code DATA files, which
# PyInstaller's static import-following analysis cannot discover on its
# own - each of these would freeze "successfully" (no import error) but
# then produce silently WRONG results at runtime without its data:
#
#   - mscerts: signify's real, populated Microsoft root-certificate trust
#     store (see authenticode.py's module docstring on why this matters -
#     "Valid" vs "NotTrusted" for genuinely signed files depends on this
#     data being present, not just the signify Python code). Missing this
#     wouldn't crash the build - it would just make every embedded
#     signature check come back untrusted, exactly the bug this project
#     already spent real effort finding and fixing once already this
#     project (2026-08-06 correction in authenticode.py) - not something
#     to accidentally reintroduce via a packaging gap.
#   - speakeasy (speakeasy-emulator on PyPI, imported as `speakeasy`):
#     ships JSON/data describing Windows API behavior that its emulation
#     core reads at runtime, not just Python bytecode.
# ---------------------------------------------------------------------------
mscerts_datas, mscerts_binaries, mscerts_hidden = collect_all("mscerts")
speakeasy_datas, speakeasy_binaries, speakeasy_hidden = collect_all("speakeasy")

# ---------------------------------------------------------------------------
# capa's own dependency, vivisect (plus its sister package envi), is a
# well-known PyInstaller pain point in the wider capa/vivisect community -
# both use import-machinery tricks (dynamic architecture/format-specific
# module loading) that PyInstaller's static analysis can miss entirely,
# producing a "works until you analyze an x86 vs x64 file specifically"
# class of runtime failure rather than an obvious build-time error.
# collect_submodules() forces every submodule in, not just the ones a
# static scan happens to find reachable.
# ---------------------------------------------------------------------------
vivisect_hidden = collect_submodules("vivisect")
envi_hidden = collect_submodules("envi")
capa_hidden = collect_submodules("capa")

# capa-rules are NOT bundled here on purpose - matches BinSifter's existing
# design (both Rowan and Winnow expect the analyst to point Settings'
# "Path to capa rules" field at a separately-downloaded capa-rules
# checkout/release, e.g. F:\Tools\capa-rules-9.4.0 - see
# TODO.md/README.md). Bundling a specific capa-rules version inside the
# installer would silently pin analysts to whatever ruleset existed at
# build time instead of letting them update independently.

a = Analysis(
    [str(repo_root / "binsifter" / "gui" / "__main__.py")],
    pathex=[str(repo_root)],
    binaries=[*mscerts_binaries, *speakeasy_binaries],
    datas=[*own_datas, *mscerts_datas, *speakeasy_datas],
    hiddenimports=[
        *mscerts_hidden, *speakeasy_hidden,
        *vivisect_hidden, *envi_hidden, *capa_hidden,
        # multiprocessing.Pool workers (engine.py's scan_directory()) need
        # their own entry point resolvable when frozen - PyInstaller's
        # multiprocessing support handles the spawn bootstrap itself, but
        # explicitly listing this submodule is cheap insurance against a
        # "frozen support" edge case biting only under --onedir + Windows'
        # spawn-only multiprocessing start method (Windows has no fork()).
        "multiprocessing.popen_spawn_win32",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="BinSifter-Winnow",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    # upx=False deliberately - UPX-compressed executables are a well-known
    # antivirus false-positive trigger (the exact category of problem
    # motivating the Defender-exclusion feature added alongside this
    # spec), and this is a security-analysis tool that will routinely run
    # on machines with real-time AV active. Not worth the smaller binary.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(repo_root / "BinSifter-WindowIcon.ico"),
)

# --onedir, not --onefile, deliberately - see get_binsifter_root()'s
# 2026-08-08 docstring note in binsifter/core/config.py: a --onefile build
# self-extracts to a FRESH temp directory on every single launch
# (sys._MEIPASS), which would silently break Settings-cache persistence
# and force an NSRL cache rebuild every run. --onedir keeps every bundled
# file as a real, stable file next to BinSifter-Winnow.exe, matching the
# "next to the installed exe" convention Rowan's own $BinSifterRoot already
# uses. It also avoids the self-extracting-exe antivirus false-positive
# risk noted above.
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="BinSifter-Winnow",
)
