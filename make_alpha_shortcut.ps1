# Creates a desktop shortcut for the PowerShell/beta.1 variant, separate
# from the Python variant's existing shortcut - named "BinSifter_Power" per
# Steve's request, so both apps can be launched independently while both
# are being kept working.
#
# WorkingDirectory is set explicitly to the script's own folder - this
# isn't just cosmetic: alpha.2's $BinSifterRoot resolution falls back to
# whatever the process's working directory happens to be if $PSScriptRoot
# comes back empty (see BinSifter_v1.3.0-beta.1.ps1 lines ~1694-1718), and
# a shortcut with no "Start in" set is a plausible reason that ever landed
# on C:\Windows\System32 in the first place. Setting it here directly may
# fix that at the root, on top of the write-test/fallback safety net
# already added in the script itself.
#
# Targets pwsh.exe (PowerShell 7+), NOT powershell.exe (legacy Windows
# PowerShell 5.1) - confirmed necessary, not a style preference: the script
# calls [System.Security.Cryptography.SHA256]::HashData(...) (lines ~2663
# and ~5589), a static method that only exists under .NET 5+ / PowerShell
# 7+. Running it under legacy powershell.exe's .NET Framework runtime fails
# with "does not contain a method named 'HashData'" - reproduced directly
# 2026-08-03 against a first version of this script that resolved plain
# powershell.exe instead.

$repoDir = "C:\Users\TALINO\Documents\GitHub\BinSifter"
$scriptPath = Join-Path $repoDir "BinSifter_v1.3.0-beta.1.ps1"
$iconPath = Join-Path $repoDir "BinSifter-WindowIcon.ico"
$desktopDir = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopDir "BinSifter_Power.lnk"

if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "Could not find $scriptPath - is the repo path correct?"
}

$pwshCommand = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if (-not $pwshCommand) {
    throw "Could not find pwsh.exe (PowerShell 7+) on PATH - beta.1 requires it (uses SHA256.HashData, a .NET 5+ API not available under legacy powershell.exe). Install PowerShell 7 or locate pwsh.exe manually."
}

$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $pwshCommand.Source
$shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`""
$shortcut.WorkingDirectory = $repoDir
if (Test-Path -LiteralPath $iconPath) {
    $shortcut.IconLocation = $iconPath
}
$shortcut.Description = "BinSifter (PowerShell / beta.1)"
$shortcut.Save()

Write-Host "Created shortcut: $shortcutPath"
Write-Host "Target: $($shortcut.TargetPath) $($shortcut.Arguments)"
Write-Host "Start in: $($shortcut.WorkingDirectory)"
