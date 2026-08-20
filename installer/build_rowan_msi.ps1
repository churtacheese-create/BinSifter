<#
  Builds an MSI package for Rowan from Rowan.wxs, using WiX Toolset v5 (the
  current .NET-tool-based WiX, not the older candle.exe/light.exe v3
  toolchain). An alternative to the Inno Setup .exe installer
  (build_rowan.ps1) for environments that specifically need an .msi -
  both formats install the same files side by side, pick whichever your
  deployment process needs.

  Pinned to the 5.x line on purpose: starting with WiX v7, `wix build`
  refuses to run at all until its Open Source Maintenance Fee EULA is
  accepted (error WIX7015) - see https://wixtoolset.org/osmf/. Rather than
  scripting an unattended EULA acceptance into CI, this just installs the
  older 5.x tool, which has no such requirement and is fully sufficient
  for what Rowan.wxs needs.

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
$wixVersion = '5.0.1'

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet (.NET SDK) was not found on PATH - required to install/run the wix tool. Install from https://dotnet.microsoft.com/download"
}

$existingWix = Get-Command wix -ErrorAction SilentlyContinue
if ($existingWix) {
    $installedVersion = (wix --version) 2>$null
    if ($installedVersion -notmatch '^5\.') {
        Write-Host "wix tool is installed at version $installedVersion, not the 5.x line this script needs - reinstalling as $wixVersion to avoid WiX v6+'s Open Source Maintenance Fee EULA gate..." -ForegroundColor Yellow
        dotnet tool uninstall --global wix | Out-Null
        $existingWix = $null
    }
}
if (-not $existingWix) {
    Write-Host "wix tool not found - installing $wixVersion as a global dotnet tool..." -ForegroundColor Yellow
    dotnet tool install --global wix --version $wixVersion

    # A first-ever `dotnet tool install --global` adds %USERPROFILE%\.dotnet\tools
    # to the user PATH, but only the registry copy - the current process's
    # $env:PATH doesn't see it until a new shell is opened. Add it here too so
    # the rest of this script can call `wix` without making the user restart
    # their terminal and re-run.
    $dotnetToolsDir = Join-Path $env:USERPROFILE '.dotnet\tools'
    if (($env:PATH -split ';') -notcontains $dotnetToolsDir) {
        $env:PATH = "$env:PATH;$dotnetToolsDir"
    }
    if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
        throw "wix was installed but still isn't resolvable on PATH - expected it under $dotnetToolsDir. Open a new terminal and re-run this script."
    }
}

# Needed for the Shortcut/Icon elements Rowan.wxs uses - not installed by
# default with the base wix tool. Pinned to the same version as the wix
# tool itself to keep the two in step.
$installedExtensions = wix extension list --global 2>$null
if (-not ($installedExtensions -match 'WixToolset\.UI\.wixext')) {
    wix extension add --global "WixToolset.UI.wixext/$wixVersion"
}

if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$wxsFile = Join-Path $installerDir 'Rowan.wxs'
$msiFile = Join-Path $outputDir 'BinSifter-Rowan.msi'

# Rowan.wxs's File/Icon Source paths (..\BinSifter-Rowan.ps1, etc.) are
# written relative to Rowan.wxs's own location, one level up to the repo
# root where those assets actually live. wix build resolves relative
# Source paths against the current working directory, not the .wxs
# file's directory, so this has to actually be running from installer\
# for those "..\" paths to land in the right place - hence the
# Push-Location rather than just passing $wxsFile as an absolute path.
Push-Location $installerDir
try {
    wix build 'Rowan.wxs' -ext WixToolset.UI.wixext -o $msiFile
}
finally {
    Pop-Location
}

if (Test-Path -LiteralPath $msiFile) {
    Write-Host "Done: $msiFile" -ForegroundColor Green
    Write-Host 'Desktop shortcut is opt-in (matches the Inno installer''s unchecked-by-default checkbox):' -ForegroundColor Yellow
    Write-Host '  msiexec /i BinSifter-Rowan.msi ADDLOCAL=Main,DesktopIcon' -ForegroundColor Yellow
}
else {
    throw "wix build did not produce $msiFile - check the output above."
}
