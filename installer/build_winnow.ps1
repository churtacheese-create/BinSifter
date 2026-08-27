<#
  DEPRECATED as of 2026-08-26 - Winnow's platform focus moved to Linux-only,
  and its Windows installer (BinSifter-Winnow-Setup.exe) was dropped from
  release-installers.yml the same day. Left in the repo for reference
  rather than deleted outright; safe to delete for real once that's
  confirmed to be wanted. Winnow's actual Linux packages are now built by
  that workflow's build-winnow-linux job (fpm, not this script).

  Builds the Winnow installer end to end: PyInstaller freeze (--onedir,
  see winnow.spec's comments on why) followed by Inno Setup packaging.
  Added 2026-08-08 - see installer/README.md for prerequisites and the
  honest caveat that this has not been run for real from this project's
  Linux-only dev sandbox.

  Run from the repo root on a real Windows machine with Python (matching
  BinSifter's own requires-python >=3.10) and Inno Setup both installed:

      pwsh -File installer\build_winnow.ps1

  Produces installer\Output\BinSifter-Winnow-Setup.exe on success.
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$installerDir = $PSScriptRoot

Write-Host "=== Step 1: install BinSifter + PyInstaller into the current Python environment ===" -ForegroundColor Cyan
Push-Location $repoRoot
try {
    # Installs Winnow itself (editable) plus every runtime dependency from
    # pyproject.toml - PyInstaller's static analysis below needs these
    # actually importable, not just declared, to find them at all.
    python -m pip install -e . --quiet
    # 2026-08-14: floor-pinned, not left fully unconstrained - a real
    # installer build with no pin at all silently picked up PyInstaller
    # 6.0's onedir layout change (bundled datas moved from flat-next-to-
    # the-exe into a new _internal\ subdirectory), which broke every
    # bundled logo PNG's resolution (get_bundled_asset_path() in
    # binsifter/core/config.py now handles either layout, but there's no
    # reason to keep inviting the same class of silent, version-triggered
    # behavior change for some future PyInstaller release too - matches
    # every other real dependency in pyproject.toml, which are all pinned
    # with at least a floor).
    python -m pip install "pyinstaller>=6.0" --quiet
}
finally {
    Pop-Location
}

Write-Host "=== Step 2: PyInstaller freeze (--onedir) ===" -ForegroundColor Cyan
Push-Location $repoRoot
try {
    # winnow.spec already encodes --onedir/--windowed/icon/datas/hiddenimports
    # itself - running with a .spec file directly (not re-passing those
    # flags on the command line) is PyInstaller's own documented way to
    # keep the real build configuration in one reviewable, version-
    # controlled file instead of a build script's command-line arguments.
    pyinstaller installer\winnow.spec --distpath installer\dist --workpath installer\build --noconfirm
}
finally {
    Pop-Location
}

$exePath = Join-Path $installerDir 'dist\BinSifter-Winnow\BinSifter-Winnow.exe'
if (-not (Test-Path -LiteralPath $exePath)) {
    throw "PyInstaller did not produce $exePath - check the output above for the actual failure before re-running. See winnow.spec's comments for the known-fragile packages (capa/vivisect, signify/mscerts, speakeasy) most likely to need an extra hiddenimport/collect_all entry."
}
Write-Host "PyInstaller build OK: $exePath" -ForegroundColor Green

Write-Host "=== Step 3: Inno Setup compile ===" -ForegroundColor Cyan
$iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
if (-not $iscc) {
    # Inno Setup's default install location, in case it's not on PATH -
    # its own installer doesn't add itself to PATH by default.
    $candidate = "$Env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe"
    if (Test-Path -LiteralPath $candidate) { $iscc = Get-Item -LiteralPath $candidate }
}
if (-not $iscc) {
    throw "ISCC.exe (Inno Setup's compiler) was not found on PATH or at its default install location. Install Inno Setup first: https://jrsoftware.org/isdl.php"
}

& $iscc.Source (Join-Path $installerDir 'Winnow.iss')

$setupExe = Join-Path $installerDir 'Output\BinSifter-Winnow-Setup.exe'
if (Test-Path -LiteralPath $setupExe) {
    Write-Host "Done: $setupExe" -ForegroundColor Green
}
else {
    throw "Inno Setup did not produce $setupExe - check the ISCC output above."
}
