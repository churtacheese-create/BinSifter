<#
  Wraps BinSifter-Rowan.ps1 into a standalone BinSifter-Rowan.exe using the
  PS2EXE.Core module. This is an alternative to the Inno Setup installer
  (build_rowan.ps1) for anyone who'd rather run one .exe directly than go
  through a full install/uninstall flow - a portable option, not a
  replacement for the installer.

  Uses PS2EXE.Core (FabienTschanz/PS2EXE.Core), not the older MScholtes/
  ps2exe module this script started with. The two are not interchangeable:
  MScholtes/ps2exe's compiled output turned out to still run the wrapped
  script under a classic .NET Framework host regardless of which pwsh.exe
  version built it (confirmed by two real runtime failures - Add-Type
  couldn't find System.Text.Json, and [System.Windows.Forms.HighDpiMode]
  didn't resolve, both hallmarks of .NET Framework rather than real
  PowerShell 7/.NET). PS2EXE.Core's -Core switch genuinely compiles a
  PowerShell-Core/.NET-hosted executable instead, which is what Rowan
  actually needs (it already requires PS7/.NET 5+ elsewhere, e.g. its
  HashData/ToHexString hashing calls - see TODO.md's cross-machine PS7.0
  fix).

  Important: this does NOT bundle the PowerShell/.NET runtime itself
  (no -SelfContained). It's a small launcher that hosts a PowerShell
  Core engine at runtime - pwsh.exe (PowerShell 7) still needs to be
  present on the machine this runs on, same prerequisite as the
  installer's own Rowan.iss already documents. What this buys you is a
  double-clickable .exe with no console window and no visible script
  source, not a fully self-contained binary.

  Prerequisite: the .NET SDK (PS2EXE.Core needs the .NET CLI to compile
  a Core-targeted executable) - same prerequisite build_rowan_msi.ps1
  already has for WiX. GitHub's windows-latest runners already have it.

  Run from anywhere on a real Windows machine with PowerShell 7:

      pwsh -File installer\build_rowan_exe.ps1

  Produces installer\Output\BinSifter-Rowan.exe on success.
#>

$ErrorActionPreference = 'Stop'
$installerDir = $PSScriptRoot
$repoRoot = Split-Path -Parent $installerDir
$outputDir = Join-Path $installerDir 'Output'

# Machines with the default Restricted/AllSigned execution policy block
# Import-Module from loading PS2EXE.Core's .psm1 at all (PSSecurityException),
# even though this script itself was allowed to run via `pwsh -File`.
# -Scope Process only affects this one pwsh.exe instance for its
# lifetime - it doesn't touch the machine's or user's persistent policy,
# so it's safe to set unconditionally here rather than asking the user
# to change a system-wide setting just to build an installer.
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet (.NET SDK) was not found on PATH - required by PS2EXE.Core to compile a PowerShell-Core-targeted executable. Install from https://dotnet.microsoft.com/download"
}

if (Get-Module -ListAvailable -Name ps2exe) {
    # The old module this script used to use - if it's still on this
    # machine, it isn't a problem (Import-Module below only loads
    # PS2EXE.Core by exact name), just noted here since it's a possible
    # source of confusion if someone's diagnosing which module actually
    # built a given BinSifter-Rowan.exe.
    Write-Host 'Note: the older ps2exe module is also installed on this machine - not used by this script, PS2EXE.Core is.' -ForegroundColor DarkGray
}

if (-not (Get-Module -ListAvailable -Name PS2EXE.Core)) {
    Write-Host 'PS2EXE.Core module not found - installing for the current user...' -ForegroundColor Yellow
    Install-Module -Name PS2EXE.Core -Scope CurrentUser -Force -AllowClobber
}
Import-Module PS2EXE.Core

if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$sourceScript = Join-Path $repoRoot 'BinSifter-Rowan.ps1'
$targetExe = Join-Path $outputDir 'BinSifter-Rowan.exe'
$iconFile = Join-Path $repoRoot 'BinSifter-WindowIcon.ico'

# -Core is the whole point of using this module instead of MScholtes/
# ps2exe - see the file header comment above. No -TargetFramework/
# -PowerShellVersion override: PS2EXE.Core auto-detects the installed
# PowerShell Core/.NET SDK version and picks the matching target itself,
# which is the right behavior for a CI runner or dev machine we don't
# control the exact PS7 patch version on. -STA is required for WinForms.
# -NoConsole hides the console window a plain pwsh.exe launch would
# otherwise show. -DPIAware gets the per-monitor-v2 DPI manifest entry
# (matches the DPI-scaling work already done inside the script itself).
# No -WinFormsDPIAware: that parameter only exists in this module's
# 'WinPS' parameter set (the old .NET-Framework-app.config-based DPI
# mechanism) - combining it with -Core is a parameter-set conflict
# PowerShell rejects outright ("Parameter set cannot be resolved"),
# and it wouldn't apply to a Core build anyway. -PublishSingleFile
# keeps the "single portable .exe" promise - without it, -Core produces
# a folder of loose files instead of one file (framework-dependent, not
# -SelfContained, so it still doesn't bundle the .NET/PowerShell
# runtime - just bundles this app's own files into one launcher).
Invoke-PS2EXE `
    -InputFile $sourceScript `
    -OutputFile $targetExe `
    -IconFile $iconFile `
    -Title 'BinSifter Rowan' `
    -Product 'BinSifter' `
    -Company 'BinSifter Project' `
    -Version '1.0.1.0' `
    -Core `
    -STA `
    -NoConsole `
    -DPIAware `
    -PublishSingleFile

# -Core always publishes into a "Release" subfolder under the output
# directory (per PS2EXE.Core's own design - see Invoke-PS2EXE.ps1's
# comments), not directly to $targetExe, even with -PublishSingleFile.
# Copy the real output up to the flat path the rest of this project
# (the GitHub Actions workflow's upload-artifact step, the main README)
# expects a single BinSifter-Rowan.exe to live at.
$publishedExe = Join-Path (Join-Path $outputDir 'Release') 'BinSifter-Rowan.exe'
if (Test-Path -LiteralPath $publishedExe -PathType Leaf) {
    Copy-Item -LiteralPath $publishedExe -Destination $targetExe -Force
}

if (Test-Path -LiteralPath $targetExe) {
    Write-Host "Done: $targetExe" -ForegroundColor Green
    Write-Host 'Reminder: this still needs PowerShell 7 (pwsh.exe) installed on the machine that runs it.' -ForegroundColor Yellow
}
else {
    throw "PS2EXE.Core did not produce $targetExe (checked $publishedExe too) - check the Invoke-PS2EXE output above."
}
