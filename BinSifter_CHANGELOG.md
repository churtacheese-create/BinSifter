# BinSifter Changelog

This changelog covers Rowan, BinSifter's PowerShell + WinForms variant. Entries below predate the codename (adopted 2026-08-05) and were written against the plain version numbers current at the time - left as-is rather than rewritten, same as every other historical entry here.

## v1.2.2 (prototype additions)
- Shannon entropy scored for every file (free byproduct of the existing hash read loop) - a structural signal that survives even when a file can't be parsed as PE/ELF.
- Capa's shellcode path now passes `-f sc32/sc64` explicitly instead of relying on format auto-detection, which can't work on headerless input.
- Optional FLOSS fallback for YARA-flagged files that fail capa's PE/ELF eligibility check (PossibleFalseNegative), recovering strings/IOCs when capa can't run at all.
- Post-scan SSDEEP fuzzy-hash clustering across the batch, surfacing related/near-duplicate files instead of leaving ssdeep hashes as report-only data.

## v1.2.3
- Dashboard stat tiles and severity-bar-graph bars are now clickable, jumping to Results pre-filtered to the matching rows.
- Real SSDEEP connected-component clustering (union-find), not just pairwise match lists - gives actual cluster IDs/sizes.
- SSDEEP heat map panel on the dashboard (cluster count, largest cluster, singletons, average similarity, files above 85%, previously-seen clusters via a persisted cross-run history), each cell clickable like the tiles.
- On-screen version string is now driven by a single `$AppVersion` value instead of being hardcoded in three places - update it at the bootstrap call at the bottom of the script on every future version bump.

## v1.2.4
- Hand-drawn line-icon system (`New-LineIconBitmap`) replacing the old Segoe MDL2 font-glyph icons, used on the sidebar nav, dashboard tiles, and heat map tiles.
- New Help page ("BIN SIFTER FIELD GUIDE") reachable from a rebuilt top bar.
- Top bar restructured: Settings/Help/About moved out of the sidebar into dedicated top-bar buttons; status indicator split into a dot + text label.
- Severity bar chart gained a measured Y-axis (grid lines + tick labels).
- Optional custom window/taskbar icon (WindowIconPath), loaded once at startup and disposed on close.

## v1.2.5
- Refresh-timer dashboard updates switched from a full O(all files) rescan every 750ms to a dirty-queue diff model: workers enqueue their path on each state change, the tick drains only changed paths, and each file's prior contribution to the running totals is subtracted before its new one is added - keeps the UI thread's per-tick cost proportional to files that actually changed, not total file count.
- Tool-version checks (yara/capa/ssdeep `--version`) moved off the UI thread into a background runspace (`Start-ToolMetadataRefresh`) instead of blocking Settings Save / Scan Start for several seconds.
- Worker-pool ThrottleLimit capped at 16 regardless of core count.
- Fixed a "Clear Completed" row-removal bug (rows now removed by descending index so earlier removals don't invalidate later ones).

## v1.3-proto1 (prototype - not run against real files before being folded into v1.3.0-alpha.2)
- Quick-launch: right-click any Results row to open the file directly in an optionally configured external tool (PE Studio, DIE, CFF Explorer, Resource Hacker).
- DIE console-mode packer/compiler detection, gated to ambiguous files (high entropy or capa-ineligible) rather than run on every file.
- Imphash (import-table hash) computed for every PE file, plus exact-match clustering across the batch - a second, non-fuzzy clustering signal alongside SSDEEP that survives recompiles/repacks SSDEEP can miss.
- Authenticode signature verification (status + signer) for every file.
- IOC extraction (IPs, domains, URLs, registry paths) mined from FLOSS output already being generated, instead of leaving it unread in JSON.
- Optional offline known-bad hash blocklist check, mirroring the existing NSRL known-good lookup.
- Draft YARA rule auto-generation per SSDEEP cluster (common-string based, written to a `generated_rules` folder for manual review).
- Per-file triage disposition (Untriaged/Benign/Suspicious/Escalated), editable in the Results grid and persisted across scans by SHA-1.

## v1.3.0-beta.1 (promoted from alpha.2, 2026-08-04)
- No functional changes from alpha.2 - promoted after real-casework validation on a FRED forensic workstation and confirmation it's working as intended. The "still unvalidated, first real run pending" caveat on the alpha.2 entry below no longer applies.
- File renamed `BinSifter_v1.3.0-alpha.2.ps1` -> `BinSifter_v1.3.0-beta.1.ps1`; `$AppVersion` bumped to match. All shortcut scripts and README references updated accordingly.

## Codename: Rowan (2026-08-05)
- This variant (the PowerShell + WinForms one, versioned above as v1.3.0-beta.1) is now codenamed **Rowan**, distinguishing it from Winnow (the Python/PySide6 rewrite) and Ingot (a planned future Rust variant) now that BinSifter is heading toward multiple public variants. No functional changes - file renamed again, `BinSifter_v1.3.0-beta.1.ps1` -> `BinSifter-Rowan_v1.3.0-beta.1.ps1`, with in-app status bar/About/window-title text updated to show "Rowan" alongside the version number.

## v1.3.0-alpha.2 (merge of proto1 + selected proto2 features - still unvalidated, first real run pending)

### Deep-analysis actions ported from a second v1.3 prototype branch (proto2)
- 5 new on-demand "deep analysis" actions added to the Results-grid right-click menu: Ghidra headless analysis (project auto-named by SHA-1 under `Reports\ghidra_projects`), Sigcheck (captured signature/provenance dump), x64dbg and x32dbg (separate launch entries so the analyst picks the right bitness), and Speakeasy (captured emulation output with a best-effort JSON summary layered on top of the raw dump).
- x64dbg/x32dbg and Speakeasy prompt for confirmation before launching ("isolated analysis environment" warning) since they're execution-adjacent; Ghidra and Sigcheck don't, since both are read-only/static.
- New generic on-demand tool runner (`Invoke-CapturedTool`) and report viewer (`Show-ToolReportWindow`) for Sigcheck/Speakeasy's captured output - a UI-thread-only counterpart to the scan engine's own `Invoke-ExternalTool`, since that one lives inside the worker/dispatcher runspaces and isn't reachable from Results-grid click handlers.
- All 5 are single-file, analyst-initiated actions with no FileRecord fields, CSV columns, or dashboard aggregates - deliberately not added as bulk-scan steps or dashboard tiles (assessed and intentionally skipped; see project memory for the full reasoning).

### Settings consolidation
- Settings consolidated from ~21 fields down to a handful: Source Directory, NSRL Path, YARA Rules, CAPA Rules, Path to tools, and Path to Ghidra.
- "Path to tools" is one directory holding every tool exe except Ghidra's, searched **recursively** (`Find-ToolPath` / `Set-ToolPathsFromDirectory`) rather than assumed flat, since FRED-style tool directories are routinely hierarchical. If a filename turns up more than once, the first match in sorted-path order wins and the ambiguity is logged.
- "Path to Ghidra" is a directory field pointing at a Ghidra install root; `analyzeHeadless.bat` is located automatically inside it (also via recursive search) rather than requiring the analyst to browse to the `.bat` file directly - this also sidesteps the original problem where a relocated/symlinked copy of just that file wouldn't reliably resolve the rest of the Ghidra install.
- Report Directory, MITRE ATT&CK data, and the known-bad hash blocklist are no longer Settings fields at all - they default to `Reports\`, `Attack\enterprise-attack.json`, and `Blocklist\blocklist.csv` next to the BinSifter script itself, auto-created on first launch. Same blank-tolerant/graceful-skip behavior throughout - a missing tool or missing Attack/Blocklist file just quietly disables that one feature.
- All Settings field values are cached to `.bsifter-settings-cache.json` next to the script on a successful Save, and pre-fill the fields on the next launch - these paths tend not to change assessment to assessment on a given workstation. A cached "Path to tools" or "Path to Ghidra" directory is re-resolved once, after the main window is first shown (not before, so a large/hierarchical tree can't delay the window from appearing at all).
- Full field list, default locations, and Results-grid quick-action details are documented in the in-app Help page.

## Release cleanup and MSI/portable packaging (2026-08-19)
- File renamed again, `BinSifter-Rowan_v1.3.0-beta.1.ps1` -> `BinSifter-Rowan.ps1`, dropping the version identifier from the filename for good going forward. The in-app `$AppVersion` display (status bar, About page) is retired along with it - Rowan no longer shows a version string in its own UI.
- Two new release formats added alongside the existing standard installer: `BinSifter-Rowan.msi` (WiX Toolset v5) for managed/enterprise deployment, and a portable `BinSifter-Rowan.exe` (PS2EXE) for a single-file, no-install option. All three still require PowerShell 7 present on the machine.
- Diagnostic/one-off scripts from the DPI-scaling and authenticode-performance investigations removed from the repo root (`diagnose_*`, `make_icon.ps1`, `make_rowan_shortcut.ps1`, `prototype_ollama_triage.py`) now that the bugs they were built to chase are fixed and confirmed - see TODO.md for what each one found. `Create-BinSifterShortcut.ps1` also removed, superseded by the new installers.
- A real name was found baked into `pyproject.toml`'s author field and both Inno Setup scripts' `AppPublisher` - replaced with "BinSifter Project" in all three places.
- General comment cleanup across `binsifter/`, `BinSifter-Rowan.ps1`, and the installer scripts - trimmed narrative debugging-journal-style comments down to plain root-cause-plus-fix documentation. No behavior changes.
