# BinSifter installers

Added 2026-08-08, per a direct request for real, installable beta releases
of both Rowan and Winnow. Read this before running either build script.

## Honest caveat, stated plainly

**Update, 2026-08-26: Winnow's Windows installer (`Winnow.iss`/`build_winnow.ps1`, producing `BinSifter-Winnow-Setup.exe`) is no longer built or offered.** Winnow's platform focus moved to Linux-only the same day (see the repo root's `TODO.md`, "BinSifter variant platform focus" section) - Windows users should use Rowan instead. `Winnow.iss` and `build_winnow.ps1` are left in the repo for reference, unused by the release workflow. Everything below that still mentions them describes history, not something you need to run.

**Update, 2026-08-24: the caveat below described the state of this folder on 2026-08-08, before either build script had ever been run for real.** Since then, both installers have been built repeatedly via the GitHub Actions workflow and tested end-to-end on real Windows hardware (host PC and a FLARE VM) across many rounds - see the repo root's `TODO.md` for the full history of real bugs found and fixed along the way (missing bundled assets, PyInstaller layout changes, frozen-exe path resolution, multiprocessing under freeze, and more). Both builds are stable and have run real malware-sample scans to completion cleanly. Left the original wording below intact as a record of where this started, not because it still describes today's reality.

Everything in this folder was written and reasoned through in a Linux-only
dev sandbox with **no Windows environment available to actually compile or
run either build**. The PyInstaller spec and both Inno Setup scripts
reflect real, specific knowledge of this dependency stack's known
PyInstaller trouble spots (see `winnow.spec`'s comments - capa/vivisect's
dynamic imports, signify's `mscerts` trust-store data files, speakeasy's
own data files) rather than guesses, but a stack this size (PySide6 + capa
+ vivisect + speakeasy/unicorn + signify + numpy) essentially never
freezes clean on the very first attempt for anyone, sandbox constraints or
not. Expect to iterate - each failure should point at a specific missing
hidden import or data file, which is a "same reasoning, one more package"
fix, not a fresh investigation, per that spec file's comments.

Neither `Winnow.iss` nor `Rowan.iss` has been compiled by `ISCC.exe`
either - review them before running, especially the two `AppId` GUIDs
(fine to keep as generated, just don't regenerate them on a future
version - Inno Setup uses that GUID to recognize "this is an upgrade of
the same app," not a new AppId every version). The same caveat applies to
`Rowan.wxs` and `build_rowan_exe.ps1` - real, specific drafts, refined
against actual build/runtime failures reported back from a real Windows
machine (see the portable .exe's PS2EXE.Core switch below, made after
the original `ps2exe`-based build produced an exe that crashed on
launch), but still not guaranteed clean on the very next attempt.

## What's here

| File | Purpose |
| --- | --- |
| `winnow.spec` | PyInstaller spec - freezes Winnow (`binsifter/gui/__main__.py`) into a self-contained `--onedir` build, used by the `build-winnow-linux` job. Its Windows-only `.ico` embedding and `multiprocessing.popen_spawn_win32` hidden import are still guarded behind `sys.platform == "win32"` (harmless dead code now that nothing builds this on Windows, kept in case someone runs PyInstaller from source on Windows for local testing). See its comments for why `--onedir` and not `--onefile`. |
| `build_winnow.ps1` | **Deprecated 2026-08-26** - built the old Windows installer (PyInstaller + Inno Setup). No longer run by anything; see the caveat at the top of this file. |
| `Winnow.iss` | **Deprecated 2026-08-26** - Inno Setup script that packaged PyInstaller's output into `BinSifter-Winnow-Setup.exe`. No longer run by anything; see the caveat at the top of this file. |
| `linux/binsifter-winnow.desktop` | Freedesktop `.desktop` entry, so the installed Linux packages show up in a normal application menu instead of being terminal-only. Copied into each package's staging tree by the release workflow's Linux job. |
| `Rowan.iss` | Inno Setup script - packages `BinSifter-Rowan.ps1` + its image assets directly (no freeze step needed) into `BinSifter-Rowan-Setup.exe`. |
| `build_rowan.ps1` | Runs Inno Setup against `Rowan.iss`. |
| `Rowan.wxs` | WiX Toolset v5 source - packages the same files as `Rowan.iss` into `BinSifter-Rowan.msi`, for deployment paths that specifically need an MSI. |
| `build_rowan_msi.ps1` | Installs the WiX dotnet tool if needed, then builds `Rowan.wxs` into `BinSifter-Rowan.msi`. |
| `build_rowan_exe.ps1` | Wraps `BinSifter-Rowan.ps1` into a portable `BinSifter-Rowan-Portable.zip` (extract-and-run folder, not a single file - see its own comments for why) via the PS2EXE.Core module - no install/uninstall, still needs PowerShell 7 present on the machine that runs it. |
| `../.github/workflows/release-installers.yml` | GitHub Actions workflow that runs Rowan's Windows build scripts on a Windows runner, builds Winnow's three Linux packages on an Ubuntu runner, and publishes a GitHub Release with everything attached. See "Publishing a real GitHub Release" below - this is the recommended way to build these, not running scripts by hand, since neither a Windows machine nor a real Linux desktop is available in this project's dev sandbox. |

## Publishing a real GitHub Release (recommended path)

Added 2026-08-08. Neither a Windows environment nor push/release
credentials are available in the dev sandbox this project is built from,
so installers can't be compiled or a release published from there
directly - a GitHub Actions workflow
(`.github/workflows/release-installers.yml`) handles both instead, using
GitHub's own infrastructure. It needs to be pushed once; after that it's
self-serve for every future release.

**One-time setup:** commit and push everything (the workflow file, the
`installer/` folder, and any other pending changes):

```
git add -A
git commit -m "..."
git push
```

**To test the build without cutting a release:** go to the repo's Actions
tab on GitHub -> "Build and release installers" -> "Run workflow". This
builds Rowan's installers on a real Windows runner AND Winnow's three
Linux packages on an Ubuntu runner, attaching all of them as downloadable
Actions artifacts, without creating a Release. Rowan's Windows builds have
since been tested for real, repeatedly, across several rounds of
real-hardware bug fixes (see the repo root's `TODO.md`) - the "expect at
least one round of fixes" caveat above described the very first attempt,
not the current state. **The Linux packaging job (added 2026-08-26) has
NOT been run for real yet** - run it via workflow_dispatch first and check
the Actions log before ever pushing a tag, same as every other build
script here got its first real test.

**To cut a real release:** push a version tag from your machine, matching
whatever `pyproject.toml`/`binsifter/__init__.py`currently say (kept in
sync by hand, not derived from the git tag):

```
git tag v2.0.0
git push origin v2.0.0
```

That triggers the same build, then publishes a real GitHub Release titled
"BinSifter v2.0.0" (not marked pre-release - that flag was dropped once
Winnow's own beta label came off for real, see `TODO.md`'s "Winnow
promoted out of Beta" section) with `binsifter-winnow.deb`,
`binsifter-winnow.rpm`, `binsifter-winnow.pkg.tar.zst`,
`BinSifter-Rowan-Setup.exe`, `BinSifter-Rowan.msi`, and
`BinSifter-Rowan-Portable.zip` attached as downloadable assets. No further
action needed on your end once it's green - the release notes are
generated by the workflow itself.

If a build fails, the Actions run's log will show exactly which
PyInstaller/Inno Setup step failed - paste it back to me and I'll fix the
spec/script, same as any other bug report.

## Prerequisites (on the Windows machine doing the actual build)

These are all for Rowan now - Winnow's build runs on Linux; see "Winnow's
Linux packages" below for its own prerequisites.

- **Rowan's standard installer:** [Inno Setup](https://jrsoftware.org/isdl.php) 6.x, installed so `ISCC.exe` is either on `PATH` or at its default install location.
- **Rowan's MSI:** the [.NET SDK](https://dotnet.microsoft.com/download) (for `dotnet tool install --global wix`) - `build_rowan_msi.ps1` installs the WiX tool itself and its UI extension automatically the first time it runs, pinned to the 5.x line specifically. WiX v6+ added an Open Source Maintenance Fee EULA that `wix build` refuses to run without accepting (error WIX7015) - pinning to 5.x sidesteps that entirely rather than scripting an unattended EULA acceptance into CI.
- **Rowan's portable zip:** the [.NET SDK](https://dotnet.microsoft.com/download), same as the MSI - `build_rowan_exe.ps1` uses the `PS2EXE.Core` module (not the older `ps2exe` module, which turned out to still compile against a classic .NET Framework host regardless of which pwsh.exe version ran it - confirmed by real runtime failures on the first portable build: Add-Type couldn't find `System.Text.Json`, and `[System.Windows.Forms.HighDpiMode]` didn't resolve). `PS2EXE.Core`'s `-Core` switch genuinely targets PowerShell Core/.NET, which is what this needs `dotnet` for. The script installs the module for the current user automatically if it isn't already present. Not built with `-PublishSingleFile` - that hits an open upstream PowerShell SDK bug under single-file hosting (confirmed by a second real runtime failure: `Add-Type` itself failed to initialize) - so the output is a folder zipped up into one asset, not a literal single `.exe`.
- **Rowan needs no compile step of its own for any format** - it's the same `.ps1` file and PNG/ICO assets, just packaged differently by each build script.

## Building

```powershell
# From the repo root (Rowan only - Winnow builds via the Linux CI job, see below):
pwsh -File installer\build_rowan.ps1
pwsh -File installer\build_rowan_msi.ps1
pwsh -File installer\build_rowan_exe.ps1
```

Each produces its output under `installer\Output\`. None of the scripts
touch each other's output - build any subset independently.

## What the installers do (Rowan's standard .exe/.msi)

- License page (`LICENSE` - BinSifter is source-available, not open
  source, so this is a real accept-to-continue page like any commercial
  Windows installer), Start Menu shortcut, an **unchecked-by-default
  "Create a desktop icon" option** (per the "create desktop icons, or ask
  the user if they want one" requirement - this is the asking), and an
  uninstaller.
- Installable without administrator rights for every format (Inno Setup's
  `PrivilegesRequired=lowest` with the modern per-user/all-users override
  dialog; the MSI's per-user `MSIINSTALLPERUSER` property does the same
  job for `msiexec`).
- Deliberately does **not** delete `Reports/`, the settings cache, or any
  other runtime/case data on uninstall - only BinSifter's own program
  files are removed. Same "never silently destroy case data" caution this
  project already applies elsewhere (e.g. `archive.py` copying, never
  moving, locked archives).
- The MSI's desktop icon is opt-in at install time rather than a wizard
  checkbox (a bare `msiexec` run has no interactive UI the way Inno's
  wizard does): `msiexec /i BinSifter-Rowan.msi ADDLOCAL=Main,DesktopIcon`.

Rowan's portable zip (`build_rowan_exe.ps1`) is different in kind, not
just packaging - there's no install/uninstall at all, no Start Menu
shortcut, no license page. Extract it and run `BinSifter-Rowan.exe` from
inside the extracted folder - the DLLs sitting alongside it are required,
don't move the exe out on its own. Meant for anyone who'd rather not go
through an install flow. It still needs PowerShell 7 present on the
machine, same as every other Rowan package.

## Winnow's Linux packages (.deb/.rpm/.pkg.tar.zst)

Added 2026-08-26, once Winnow's platform focus moved to Linux (see the
main README's Variants table). All three formats come from the exact same
PyInstaller `--onedir` build the Windows installer uses - `winnow.spec` is
one shared, cross-platform spec, not a separate Linux-only copy - packaged
via [`fpm`](https://github.com/jordansissel/fpm), which builds `.deb`,
`.rpm`, and Arch's `.pkg.tar.zst` from one staged directory tree instead of
needing three separate packaging toolchains (`dpkg-deb`+`debhelper`,
`rpmbuild`+a `.spec` file, `makepkg`+a `PKGBUILD`) for identical content.

The release workflow's `build-winnow-linux` job stages the on-disk layout
itself before handing it to `fpm`:

```
/opt/binsifter-winnow/                                    <- PyInstaller's onedir output, as-is
/usr/bin/binsifter-winnow                                 <- symlink to the exe above, so it's on PATH
/usr/share/applications/binsifter-winnow.desktop           <- app-menu entry (see linux/binsifter-winnow.desktop)
/usr/share/icons/hicolor/256x256/apps/binsifter-winnow.png <- app-menu icon
```

`fpm -s dir -C <staged tree> -t <deb|rpm|pacman> .` packages that layout
as-is - `-t pacman` is what actually produces the `.pkg.tar.zst` Arch
wants, `fpm` just names the target after the package manager, not the file
extension. Version comes from `binsifter/__init__.py`'s `__version__` at
build time (same source `pyproject.toml`/`Winnow.iss` are hand-kept in
sync with), not a fourth place to bump by hand.

**This job needs a Linux build toolchain that isn't obvious from
Winnow's own `pyproject.toml`** - confirmed the hard way via real Ubuntu-
VM testing, 2026-08-26: `yara-python` and `flare-floss`'s `binary2strings`
dependency both compile native extensions from source on Linux (neither
publishes a prebuilt Linux wheel), so a bare `pip install -e .` fails
outright without `build-essential`/`python3-dev` present, and
`yara-python`'s own bundled `libyara` additionally needs the autotools
chain (`automake`/`libtool`) to configure itself, not just a C compiler.
The GitHub Actions job installs all of this itself on the Ubuntu runner -
nothing extra needed on your end to trigger a build, this is just
documenting why that step exists rather than a plain `pip install`.

**Not yet run for real** - test via `workflow_dispatch` (see "Publishing a
real GitHub Release" above) before ever cutting a tag with these included.

## What's different between the variants

- **Winnow** bundles everything (Python interpreter, PySide6, capa,
  vivisect, signify, speakeasy, numpy, etc.) into one self-contained
  `--onedir` folder via PyInstaller first - nothing needs to be
  separately installed on the target machine to run it, per the
  confirmed "bundle everything" choice.
- **Rowan** does NOT bundle PowerShell 7 or 7-Zip (also per the
  confirmed choice) in any of its three package formats. The standard
  installer (`Rowan.iss`) checks for `pwsh.exe`/`7z.exe` on `PATH` after
  install and shows a plain, non-blocking message linking to the official
  installer for whichever is missing - the MSI and portable zip don't
  have an equivalent built-in check (see `Rowan.wxs`'s and
  `build_rowan_exe.ps1`'s own comments for why), so the same prerequisite
  is just documented here and in the main README instead.
