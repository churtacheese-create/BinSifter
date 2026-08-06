; Inno Setup script for Winnow (BinSifter's Python/PySide6 variant).
; Added 2026-08-08 - see installer/README.md for the full build sequence
; and honest caveats (not compiled/tested from this dev sandbox - no
; Windows environment here to run ISCC.exe against).
;
; Prerequisite: installer/build_winnow.ps1 has already run PyInstaller and
; produced installer/dist/BinSifter-Winnow/ (a --onedir build - see
; winnow.spec's comments on why onedir, not onefile). This script just
; packages THAT folder; it does not invoke PyInstaller itself.
;
; Compile with Inno Setup's ISCC.exe:
;     iscc installer\Winnow.iss
; (or open in the Inno Setup IDE and press Compile) - produces
; installer\Output\BinSifter-Winnow-Setup.exe

#define MyAppName "BinSifter Winnow"
#define MyAppVersion "2.0.0-beta.1"
#define MyAppPublisher "Steven C. Lauterbach"
#define MyAppExeName "BinSifter-Winnow.exe"
#define MyDistDir "dist\BinSifter-Winnow"

[Setup]
; Generated once, fixed forever after - re-running this generator would
; make Inno Setup treat future versions as a different, unrelated app for
; upgrade/uninstall purposes. Do not regenerate this on future builds.
AppId={{B15F17E2-1A1E-4A2E-9C1D-57494E4E4F57}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\BinSifter Winnow
DefaultGroupName=BinSifter
; Modern Inno Setup (6.1+) per-user-vs-all-users install choice - lets an
; analyst without admin rights on their own workstation still install
; (matches Create-BinSifterShortcut.ps1's existing "does not need admin
; rights" convention for Rowan), while still supporting a normal
; all-users/Program Files install when run elevated.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=Output
OutputBaseFilename=BinSifter-Winnow-Setup
SetupIconFile=..\BinSifter-WindowIcon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE
; BinSifter is source-available (PolyForm Strict), not open source - see
; the repo's own README/LICENSE. Shown as a standard Inno Setup license
; page the installer requires accepting before Install, same as any other
; commercial/non-OSS Windows installer.
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Unchecked by default, exactly per Steve's "create desktop icons (or ask
; the user if they want one)" - this IS the asking: a normal wizard
; checkbox page, off by default, on if the analyst opts in.
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; Everything PyInstaller's --onedir COLLECT step produced - the exe plus
; every bundled dependency (PySide6, capa/vivisect, signify+mscerts,
; speakeasy, numpy, etc. - see winnow.spec) as real files, recursively.
Source: "{#MyDistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\BinSifter Winnow"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall BinSifter Winnow"; Filename: "{uninstallexe}"
Name: "{autodesktop}\BinSifter Winnow"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Standard "launch after install" checkbox, unchecked by default so a
; silent/unattended install doesn't unexpectedly pop the GUI.
Filename: "{app}\{#MyAppExeName}"; Description: "Launch BinSifter Winnow"; Flags: nowait postinstall skipifsilent unchecked

[UninstallDelete]
; BinSifter writes its own runtime data (Reports/, Attack/, Blocklist/,
; the settings cache, the NSRL mmap cache) under {app} by default (see
; core/config.py's build_default_config()) - explicitly NOT deleted on
; uninstall, matching the same "never silently destroy case data" caution
; already established elsewhere in this project (archive.py copies rather
; than moves locked archives, for the same reason). Uninstalling only
; removes BinSifter's own program files; case data under Reports/ is left
; for the analyst to keep or remove themselves.
