<#
Creates a Desktop shortcut that launches BinSifter-Rowan_v1.3.0-beta.1.ps1 under PowerShell 7 (pwsh.exe).

Run this ONCE, on whichever machine you want the icon on (e.g. your FRED workstation),
from the same folder you copied BinSifter-Rowan_v1.3.0-beta.1.ps1 into. It does not need admin rights.

    pwsh.exe -ExecutionPolicy Bypass -File .\Create-BinSifterShortcut.ps1
#>

$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot 'BinSifter-Rowan_v1.3.0-beta.1.ps1'
if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    throw "BinSifter-Rowan_v1.3.0-beta.1.ps1 was not found next to this script ($PSScriptRoot). Copy them into the same folder, or edit `$scriptPath below."
}

# BinSifter uses .NET 5+ APIs (Convert.ToHexString, etc.), so it needs PowerShell 7+
# (pwsh.exe) - Windows PowerShell 5.1 (powershell.exe) will not run it.
$pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if (-not $pwsh) {
    Write-Warning "pwsh.exe (PowerShell 7+) was not found on PATH. Install it first: https://aka.ms/powershell-release?tag=stable - the shortcut will still be created, pointing at 'pwsh.exe', but won't launch until it's installed."
}

$desktop = [Environment]::GetFolderPath('Desktop')
$shortcutPath = Join-Path $desktop 'BinSifter.lnk'

$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut($shortcutPath)
$shortcut.TargetPath = if ($pwsh) { $pwsh.Source } else { 'pwsh.exe' }
# -ExecutionPolicy Bypass here only affects this one launched process, not the
# machine's default policy - it does not change any other script's ability to run.
$shortcut.Arguments = "-NoLogo -ExecutionPolicy Bypass -File `"$scriptPath`""
$shortcut.WorkingDirectory = $PSScriptRoot
$shortcut.Description = 'BinSifter Rowan (PowerShell variant) binary triage tool'

# Optional custom icon. Windows shortcuts need a .ico file, not a .png, so this only
# applies if you've converted one of the BinSifter-Logo PNGs to .ico and placed it
# here as BinSifter-Logo-Full.ico - otherwise this is skipped and the shortcut just
# uses pwsh.exe's default icon.
$logoIco = Join-Path $PSScriptRoot 'BinSifter-Logo-Full.ico'
if (Test-Path -LiteralPath $logoIco -PathType Leaf) {
    $shortcut.IconLocation = $logoIco
}

$shortcut.Save()
Write-Host "Desktop shortcut created: $shortcutPath" -ForegroundColor Green
Write-Host "Target: $($shortcut.TargetPath) $($shortcut.Arguments)"
