<#
  Builds an MSI package for Rowan from Rowan.wxs, using WiX Toolset v5 (the
  current .NET-tool-based WiX, not the older candle.exe/light.exe v3
  toolchain). An alternative to the Inno Setup .exe installer
  (build_rowan.ps1) for environments that specifically need an .msi -
  both formats install the same files side by side, pick whichever your
  deployment process needs.

  Prerequisite: the .NET SDK (for `dotnet tool install`). GitHub's
  windows-latest runners already have this; a local machine may need it
  from https://dotnet.microsoft.com/download first.

  Run from anywhere on a real Windows machine:

      pwsh -File installer\build_rowan_msi.ps1

  Produces installer\Output\BinSifter-Rowan.msi on success.
#>

$ErrorActionPreference = 'Stop'
$installerDir = $PSScriptRoot
$outputDir = Join-Path $installerDir 'Output'

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet (.NET SDK) was not found on PATH - required to install/run the wix tool. Install from https://dotnet.microsoft.com/download"
}

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host 'wix tool not found - installing as a global dotnet tool...' -ForegroundColor Yellow
    dotnet tool install --global wix
}

# Needed for the Shortcut/Icon elements Rowan.wxs uses - not installed by
# default with the base wix tool.
$installedExtensions = wix extension list --global 2>$null
if (-not ($installedExtensions -match 'WixToolset\.UI\.wixext')) {
    wix extension add --global WixToolset.UI.wixext
}

if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$wxsFile = Join-Path $installerDir 'Rowan.wxs'
$msiFile = Join-Path $outputDir 'BinSifter-Rowan.msi'

wix build $wxsFile -ext WixToolset.UI.wixext -o $msiFile

if (Test-Path -LiteralPath $msiFile) {
    Write-Host "Done: $msiFile" -ForegroundColor Green
    Write-Host 'Desktop shortcut is opt-in (matches the Inno installer''s unchecked-by-default checkbox):' -ForegroundColor Yellow
    Write-Host '  msiexec /i BinSifter-Rowan.msi ADDLOCAL=Main,DesktopIcon' -ForegroundColor Yellow
}
else {
    throw "wix build did not produce $msiFile - check the output above."
}
