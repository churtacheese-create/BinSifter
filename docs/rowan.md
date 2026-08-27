# BinSifter Rowan

Rowan is BinSifter's original variant: a single PowerShell 7 + WinForms script (`BinSifter-Rowan.ps1`). It's Windows-only and is the variant to use if you're triaging on Windows - proven against real casework, with installers available in four formats.

## Requirements

- Windows, with PowerShell 7+ (`pwsh.exe`) installed.
- An NSRL known-good hash set (not included - see Settings). NSRL ships as RDSv3 hashes; BinSifter's NSRL loader expects the older RDSv2 text-file format, so you'll need to convert first - see NIST's own [RDSv3 to RDSv2 text files conversion guide](https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/RDSv3_Docs/RDSv3_to_RDSv2_text_files.pdf) (PDF).
- Whichever of the optional external quick-launch tools below you want right-click access to (not included - point BinSifter at a single tools directory in Settings and it searches it recursively).

## Getting started

Four ways to get Rowan running, pick whichever fits:

- **Standard installer** (`BinSifter-Rowan-Setup.exe`) - the usual install/uninstall flow, Start Menu shortcut, optional desktop icon.
- **MSI** (`BinSifter-Rowan.msi`) - the same install, packaged for managed/enterprise deployment (Group Policy, SCCM, Intune) instead of a standard installer.
- **Portable** (`BinSifter-Rowan-Portable.zip`) - no install/uninstall, extract and run `BinSifter-Rowan.exe` from inside the extracted folder (the DLLs alongside it are required, don't move the exe out on its own).
- Or skip packaging entirely and launch `BinSifter-Rowan.ps1` directly with `pwsh.exe -File`.

All four need PowerShell 7 (`pwsh.exe`) already installed. See `installer/README.md` for how each package is built.

## Quick-launch tools

Right-click any row in Results for on-demand actions, driven by "Path to tools"/"Path to Ghidra" in Settings:

- **No confirmation needed** (read-only inspection): PE Studio, DIE, CFF Explorer (copies the path to your clipboard instead of opening the file directly - CFF Explorer's own command line is reserved for its Lua scripting engine), Resource Hacker, Ghidra headless analysis, and Sigcheck (signature/provenance check).
- **Confirmation required** (execution-adjacent): x64dbg, x32dbg, and an isolated Speakeasy code emulation.
- **Export for AI analysis** writes a Markdown+JSON pair of the file's already-extracted findings for you to hand to whatever AI tool you choose - no AI is called from BinSifter itself.

Any entry showing "(not configured)" means that tool's path wasn't found under "Path to tools" (or "Path to Ghidra" for the Ghidra entry).

## License

BinSifter is source-available, not open source. See the repo root's `LICENSE` (PolyForm Strict License 1.0.0).
