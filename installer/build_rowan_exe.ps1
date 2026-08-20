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

# -Core targets pwsh.exe (PowerShell 7+) rather than legacy Windows
# PowerShell 5.1 - Rowan needs .NET 5+'s HashData/ToHexString APIs (see
# TODO.md's cross-machine PS7.0 fix), so this has to match. -STA is
# required for WinForms. -NoConsole hides the console window a plain
# pwsh.exe launch would otherwise show. -DPIAware/-WinFormsDPIAware match
# the DPI-scaling work already done inside the script itself.
Invoke-ps2exe `
    -InputFile $sourceScript `
    -OutputFile $targetExe `
    -IconFile $iconFile `
    -Title 'BinSifter Rowan' `
    -Product 'BinSifter' `
    -Company 'BinSifter Project' `
    -Version '1.0.0.0' `
    -Core `
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
