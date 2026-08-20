<#
  Wraps BinSifter-Rowan.ps1 into a standalone BinSifter-Rowan.exe using the
  PS2EXE module. This is an alternative to the Inno Setup installer
  (build_rowan.ps1) for anyone who'd rather run one .exe directly than go
  through a full install/uninstall flow - a portable option, not a
  replacement for the installer.

  Important: this does NOT bundle the PowerShell 7 engine itself. PS2EXE
  produces a small native launcher stub that starts a PowerShell host and
  runs the wrapped script inside it - pwsh.exe (PowerShell 7) still needs
  to be present on the machine this runs on, same prerequisite as the
  installer's own Rowan.iss already documents. What this buys you is a
  double-clickable .exe with no console window and no visible script
  source, not a fully self-contained binary.

  Run from anywhere on a real Windows machine with PowerShell 7:

      pwsh -File installer\build_rowan_exe.ps1

  Produces installer\Output\BinSifter-Rowan.exe on success.
#>

$ErrorActionPreference = 'Stop'
$installerDir = $PSScriptRoot
$repoRoot = Split-Path -Parent $installerDir
$outputDir = Join-Path $installerDir 'Output'

# Machines with the default Restricted/AllSigned execution policy block
# Import-Module from loading ps2exe's .psm1 at all (PSSecurityException),
# even though this script itself was allowed to run via `pwsh -File`.
# -Scope Process only affects this one pwsh.exe instance for its
# lifetime - it doesn't touch the machine's or user's persistent policy,
# so it's safe to set unconditionally here rather than asking the user
# to change a system-wide setting just to build an installer.
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'ps2exe module not found - installing for the current user...' -ForegroundColor Yellow
    Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
}
Import-Module ps2exe

if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$sourceScript = Join-Path $repoRoot 'BinSifter-Rowan.ps1'
$targetExe = Join-Path $outputDir 'BinSifter-Rowan.exe'
$iconFile = Join-Path $repoRoot 'BinSifter-WindowIcon.ico'

# No -Core flag here: that belongs to a different, newer module
# (PS2EXE.Core by Fabien Tschanz), not the one this script installs
# (MScholtes/ps2exe from the PowerShell Gallery), whose Invoke-ps2exe
# has no such parameter at all. That module instead compiles against
# whichever PowerShell host actually runs Invoke-ps2exe - since this
# script requires pwsh.exe (PowerShell 7) per its own prerequisite
# above, the resulting exe already targets PS7's engine, which is what
# Rowan needs for its .NET 5+ HashData/ToHexString APIs (see TODO.md's
# cross-machine PS7.0 fix). -STA is required for WinForms. -NoConsole
# hides the console window a plain pwsh.exe launch would otherwise
# show. -DPIAware/-WinFormsDPIAware match the DPI-scaling work already
# done inside the script itself.
Invoke-ps2exe `
    -InputFile $sourceScript `
    -OutputFile $targetExe `
    -IconFile $iconFile `
    -Title 'BinSifter Rowan' `
    -Product 'BinSifter' `
    -Company 'BinSifter Project' `
    -Version '1.0.0.0' `
    -STA `
    -NoConsole `
    -DPIAware `
    -WinFormsDPIAware

if (Test-Path -LiteralPath $targetExe) {
    Write-Host "Done: $targetExe" -ForegroundColor Green
    Write-Host 'Reminder: this still needs PowerShell 7 (pwsh.exe) installed on the machine that runs it.' -ForegroundColor Yellow
}
else {
    throw "PS2EXE did not produce $targetExe - check the Invoke-ps2exe output above."
}
