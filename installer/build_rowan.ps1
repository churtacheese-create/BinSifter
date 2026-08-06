<#
  Builds the Rowan installer. Added 2026-08-08 - see installer/README.md
  for prerequisites and the honest caveat that this has not been run for
  real from this project's Linux-only dev sandbox.

  Unlike build_winnow.ps1, there's no freeze step - Rowan.iss packages the
  .ps1 script and its image assets directly from the repo root. Only
  Inno Setup itself needs to be installed first.

  Run from anywhere on a real Windows machine:

      pwsh -File installer\build_rowan.ps1

  Produces installer\Output\BinSifter-Rowan-Setup.exe on success.
#>

$ErrorActionPreference = 'Stop'
$installerDir = $PSScriptRoot

$iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
if (-not $iscc) {
    $candidate = "$Env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe"
    if (Test-Path -LiteralPath $candidate) { $iscc = Get-Item -LiteralPath $candidate }
}
if (-not $iscc) {
    throw "ISCC.exe (Inno Setup's compiler) was not found on PATH or at its default install location. Install Inno Setup first: https://jrsoftware.org/isdl.php"
}

& $iscc.Source (Join-Path $installerDir 'Rowan.iss')

$setupExe = Join-Path $installerDir 'Output\BinSifter-Rowan-Setup.exe'
if (Test-Path -LiteralPath $setupExe) {
    Write-Host "Done: $setupExe" -ForegroundColor Green
}
else {
    throw "Inno Setup did not produce $setupExe - check the ISCC output above."
}
