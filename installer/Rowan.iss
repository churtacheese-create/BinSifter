; Inno Setup script for Rowan (BinSifter's PowerShell 7 + WinForms variant).
; Added 2026-08-08 - see installer/README.md for the full build sequence
; and honest caveats (not compiled/tested from this dev sandbox - no
; Windows environment here to run ISCC.exe against).
;
; Unlike Winnow, there's no freeze/PyInstaller step first - Rowan is a
; single .ps1 file plus a handful of image assets, run directly by pwsh.exe.
; Per the confirmed choice (2026-08-08): this installer does NOT bundle
; PowerShell 7 or 7-Zip themselves - it checks for pwsh.exe/7z.exe and
; links to their official installers if either is missing, same
; "check-and-link, don't silently fail" pattern the rest of this codebase
; already uses for optional/external tools (Sigcheck, Ghidra, etc.).
;
; Compile with Inno Setup's ISCC.exe:
;     iscc installer\Rowan.iss
; (or open in the Inno Setup IDE and press Compile) - produces
; installer\Output\BinSifter-Rowan-Setup.exe

#define MyAppName "BinSifter Rowan"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "BinSifter Project"
#define MyScriptName "BinSifter-Rowan.ps1"

[Setup]
; Generated once, fixed forever after - see Winnow.iss's identical note on
; why this must never be regenerated on a future build.
AppId={{7C3A9E7D-6B0D-4B9E-9E77-2B7B7B0B0B0B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\BinSifter Rowan
DefaultGroupName=BinSifter
; Same reasoning as Winnow.iss - installable without admin rights.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=Output
OutputBaseFilename=BinSifter-Rowan-Setup
SetupIconFile=..\BinSifter-WindowIcon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Unchecked by default, exactly per the "create desktop icons (or ask
; the user if they want one)" requirement - same as Winnow.iss.
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "..\{#MyScriptName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\BinSifter-Logo-Horizontal-Dark.png"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\BinSifter-Logo-Horizontal.png"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\BinSifter-Logo-Full.png"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\BinSifter-WindowIcon.png"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\BinSifter-WindowIcon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\BinSifter-Desktop.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Filename is deliberately the bare "pwsh.exe", not a resolved full path -
; ShellExecute performs a PATH search at LAUNCH time for a bare exe name,
; so this keeps working even if PowerShell 7 gets installed AFTER
; BinSifter (unlike resolving a fixed path once at install time, which
; Create-BinSifterShortcut.ps1's older approach does for the same reason -
; this installer's version is a small improvement on that, not a
; behavior regression).
Name: "{group}\BinSifter Rowan"; Filename: "pwsh.exe"; Parameters: "-NoLogo -ExecutionPolicy Bypass -File ""{app}\{#MyScriptName}"""; WorkingDir: "{app}"; IconFilename: "{app}\BinSifter-WindowIcon.ico"
Name: "{group}\Uninstall BinSifter Rowan"; Filename: "{uninstallexe}"
Name: "{autodesktop}\BinSifter Rowan"; Filename: "pwsh.exe"; Parameters: "-NoLogo -ExecutionPolicy Bypass -File ""{app}\{#MyScriptName}"""; WorkingDir: "{app}"; IconFilename: "{app}\BinSifter-WindowIcon.ico"; Tasks: desktopicon

[UninstallDelete]
; Rowan writes its own runtime data (Reports/, Attack/, Blocklist/, the
; settings cache) under {app} by default - same "never silently destroy
; case data" reasoning as Winnow.iss, deliberately left behind on
; uninstall for the analyst to keep or remove themselves.

[Code]
function IsToolOnPath(const ExeName: string): Boolean;
var
  ResultCode: Integer;
begin
  // `where` is a built-in cmd.exe command available on every supported
  // Windows version - simplest reliable way to ask "is this on PATH" from
  // Pascal Script, which has no direct PATH-search primitive of its own.
  Result := Exec('cmd.exe', '/C where ' + ExeName + ' >nul 2>nul', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Non-blocking - matches this project's established pattern for every
    // other optional/external tool (Sigcheck, Ghidra, 7z.exe under
    // ToolsDir, etc.): tell the analyst plainly, let install finish
    // either way, rather than hard-failing Setup over a tool BinSifter
    // itself doesn't install or bundle.
    if not IsToolOnPath('pwsh.exe') then
      MsgBox('PowerShell 7 (pwsh.exe) was not found on PATH. BinSifter Rowan needs it to run - '
        + 'install it from https://aka.ms/powershell-release?tag=stable, then use the shortcuts '
        + 'this installer created (they will find pwsh.exe once it is installed).',
        mbInformation, MB_OK);

    if not IsToolOnPath('7z.exe') then
      MsgBox('7-Zip''s command-line tool (7z.exe) was not found on PATH. It is needed for '
        + 'BinSifter Rowan''s archive/compressed-file scanning feature (zip/tar/gzip/7z) - '
        + 'install 7-Zip from https://www.7-zip.org/, then point Settings'' "Path to tools" '
        + 'field at a folder containing 7z.exe. Everything else in BinSifter works without it.',
        mbInformation, MB_OK);
  end;
end;
