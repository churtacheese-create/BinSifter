# BinSifter v1.2.1: A Guided Code Tutorial

This tutorial explains how `BinSifter_v1.2.1.ps1` works from startup to shutdown. It covers every named PowerShell function, every compiled C# helper, the major UI sections, event handlers, shared state, scan pipeline, reports, and important design decisions.

> **Scope:** This is a code-reading tutorial, not an operator manual. It explains what the program does internally and why the implementation is structured this way.

## 1. What BinSifter Does

BinSifter is a Windows PowerShell 7+ WinForms application for bulk binary triage. For every file in a selected directory tree, it:

1. Calculates SHA-1 and MD5 in a single read pass.
2. Checks the SHA-1 against an NSRL known-good set.
3. Skips deeper analysis when the file is known-good.
4. Calculates an ssdeep fuzzy hash for an unknown file.
5. Scans the unknown file with YARA metadata enabled.
6. Derives the worst matched-rule severity and optionally resolves MITRE ATT&CK techniques.
7. If YARA matches, determines whether the file is suitable for capa.
8. Runs capa on eligible PE, ELF, or probable shellcode files.
9. Updates the UI and writes several CSV reports plus per-file capa JSON.

The high-level data flow is:

```text
Directory tree
    |
    v
Native file enumeration
    |
    v
Bounded worker pool
    |
    +--> SHA-1 + MD5 + header capture
            |
            v
         NSRL match? ---- yes ---> mark known-good and finish
            |
            no
            v
          ssdeep
            |
            v
           YARA -------- no match ---> finish
            |
          match
            v
     PE / ELF / shellcode eligibility
            |
            +--> not eligible ---> flag possible false negative when appropriate
            |
            v
           capa
            |
            v
     CSV reports + capa JSON
```

## 2. Runtime Architecture

The script uses multiple execution layers so that a long scan does not freeze the GUI:

| Layer | Purpose |
|---|---|
| Bootstrap thread | Detects the theme, selects a logo, and starts the application. |
| STA UI runspace | Owns every WinForms control and processes UI events. |
| Dispatcher runspace | Loads NSRL data, enumerates files, feeds work to the pool, handles pause/stop, and exports reports. |
| Worker runspace pool | Processes several files concurrently, up to the throttle limit. |
| External processes | Runs `ssdeep.exe`, `yara64.exe`, and `capa.exe`. |
| Compiled C# helpers | Accelerate NSRL parsing, file enumeration, record storage, and CSV output. |

This separation is essential: WinForms controls must stay on their owning STA thread, while scanning and external tools can run in the background.

## 3. Script Header and Error Policy

The opening comment describes the application’s intended properties. Immediately afterward, two global policies are enabled:

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
```

`Set-StrictMode` catches common mistakes such as using uninitialized variables or nonexistent properties. Setting `$ErrorActionPreference` to `Stop` turns normally non-terminating PowerShell errors into exceptions, allowing the script’s `try`/`catch` blocks to handle them consistently.

## 4. Top-Level Functions

### 4.1 `Test-SystemDarkMode`

```powershell
function Test-SystemDarkMode
```

This function reads the current user’s Windows application-theme preference from:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize
```

The `AppsUseLightTheme` registry value is `0` for dark mode and `1` for light mode. The function returns `$true` only when the value equals `0`.

The registry read is wrapped in `try`/`catch`. If the value is absent, inaccessible, or malformed, the function safely defaults to light mode by returning `$false`.

### 4.2 `New-STARunspace`

```powershell
function New-STARunspace
```

This function constructs a PowerShell runspace configured as a single-threaded apartment:

```powershell
$runspace.ApartmentState = [System.Threading.ApartmentState]::STA
$runspace.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
```

STA is important for Windows desktop UI technologies. `ReuseThread` ensures that the runspace continues using the same thread, preserving the apartment and UI ownership model.

The function opens the runspace before returning it, so callers receive a ready-to-use execution environment.

### 4.3 `Show-MainWindow`

```powershell
function Show-MainWindow
```

This is the main application function. It accepts:

| Parameter | Meaning |
|---|---|
| `IsDarkMode` | Selects the dark or light color palette. |
| `LogoHorizontalPath` | Points to the matching logo image. |
| `ThrottleLimit` | Maximum number of file workers allowed at once. |

The function:

1. Creates an STA runspace.
2. injects the three parameters into that runspace.
3. Creates a `PowerShell` instance attached to the runspace.
4. Adds one large script block containing the application.
5. Invokes it synchronously.
6. Disposes the PowerShell instance and runspace after the window closes.

Although the call blocks the bootstrap thread, the GUI itself stays responsive because it runs in its own STA runspace and delegates scans elsewhere.

## 5. Application Initialization Inside `Show-MainWindow`

The application script block loads:

```powershell
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
```

`System.Windows.Forms` provides the controls and event loop. `System.Drawing` supplies fonts, colors, sizes, points, bitmaps, and images. `EnableVisualStyles()` asks Windows to render standard controls using the current visual style.

## 6. Compiled C# “Native Hot Paths”

The script compiles a C# block with `Add-Type`. These helpers replace PowerShell loops in performance-sensitive paths. Compilation is guarded by:

```powershell
if (-not ('BinSifter.NsrlLoader' -as [type]))
```

This prevents “type already exists” failures if the script is rerun in a PowerShell process that retains loaded types.

### 6.1 `HashKey`

`HashKey` is a value type representing one 20-byte SHA-1 digest as:

- two 64-bit unsigned integers, `A` and `B`;
- one 32-bit unsigned integer, `C`.

Its two constructors read either the first 20 bytes of an array or 20 bytes at a supplied offset.

#### `Equals(HashKey other)`

Compares all three numeric fields. Two keys are equal only when all 20 original hash bytes match.

#### `Equals(object obj)`

Implements the standard object equality override. It first checks that the object is a `HashKey`, then calls the typed equality method.

#### `GetHashCode()`

Combines the three fields into a hash code for efficient use in `HashSet<HashKey>`. The `unchecked` block permits normal integer overflow during hash-code arithmetic.

This representation avoids storing millions of SHA-1 hashes as comparatively expensive .NET strings.

### 6.2 `NsrlLoader`

`NsrlLoader` is a static class that parses and caches NSRL SHA-1 data.

#### `BuildFromCsv(string csvPath, string cacheBuildPath)`

This is the slow, first-load path:

1. Opens the NSRL CSV using a 1 MiB stream buffer.
2. Reads it one line at a time.
3. Selects the first comma-delimited field.
4. Removes surrounding quotation marks when present.
5. Requires exactly 40 hexadecimal characters.
6. Parses the characters into 20 raw bytes.
7. Writes the 20 bytes to a flat temporary cache file.
8. Adds the hash to a `HashSet<HashKey>`.

Malformed rows are skipped. Because the file is streamed, the entire CSV is never loaded into memory at once.

#### `LoadFromCache(string cachePath, long headerBytes)`

This is the fast repeat-load path. It seeks past the cache metadata header, reads blocks containing up to 65,536 SHA-1 records, and reconstructs the `HashSet<HashKey>`.

The cache uses fixed 20-byte records, eliminating CSV parsing and hexadecimal conversion on later scans.

#### `CountRows(string csvPath)`

This method supports the NSRL page’s “Reload Now” preview. It counts rows whose first field has the expected 40-character SHA-1 length without retaining hashes.

It validates length but does not fully validate every hexadecimal character, so it is best understood as a quick preview count rather than the authoritative loaded-set count.

#### `TryParseHex40(ReadOnlySpan<char> hex, byte[] output)`

This private helper converts 40 hex characters into 20 bytes. Each output byte is formed from a high and low nibble. It returns `false` immediately if either character is invalid.

#### `HexVal(char c)`

Converts one hexadecimal character into the numeric range 0–15. It supports digits, lowercase A–F, and uppercase A–F; all other characters return `-1`.

### 6.3 `FileRecord`

`FileRecord` is the shared result model for one scanned file. It uses public fields so PowerShell can read and write values directly with `$record.Field`.

| Field | Meaning |
|---|---|
| `Path` | Full file path. |
| `Status` | `Queued`, `Scanning`, `Completed`, `Error`, or `Cancelled`. |
| `Progress` | Coarse per-file percentage. |
| `MD5`, `SHA1`, `SSDEEP` | Calculated hashes. |
| `NsrlMatch` | Whether SHA-1 is in the known-good set. |
| `YaraMatches` | Matched YARA rule names, one per line. |
| `YaraHitCount` | Number of parsed YARA matches. |
| `YaraSeverity` | Highest recognized severity among matched rules. |
| `YaraSeverityScore` | Normalized 0–100 score, or `-1` for a word-only/unknown severity. |
| `YaraAttackTechniques` | Semicolon-delimited ATT&CK techniques resolved from matched-rule metadata. |
| `CapaEligible` | Whether capa was invoked for the file. |
| `PossibleFalseNegative` | Flags an executable-like extension with invalid native magic that was not sent to capa. |
| `CAPAOutput` | Raw capa JSON output. |
| `CapaDetectionCount` | Number of rule properties in capa’s JSON `rules` object. |
| `Error` | Per-file exception message. |
| `Added` | Time the record entered the queue. |

### 6.4 `EnumerationResult`

This small result class contains:

- `Files`: all successfully discovered file paths;
- `ErrorCount`: the number of directories or file enumerations that failed.

Returning both values lets enumeration continue through accessible areas while still reporting partial-access problems.

### 6.5 `FileScanner.EnumerateFiles(string rootPath)`

This method performs iterative depth-first traversal with a `Stack<string>`.

For each directory, it separately attempts to:

1. retrieve subdirectories and push them onto the stack;
2. enumerate files and append them to the result.

Each operation has its own `try`/`catch`, so one inaccessible folder does not abort the entire scan. Using a stack instead of recursive method calls also avoids call-stack overflow on deeply nested trees.

### 6.6 `CsvWriter`

The compiled CSV writer avoids the reflection and pipeline overhead of `Export-Csv`.

#### `WriteReport(string path, List<FileRecord> records, string mode)`

Writes a UTF-8-with-BOM CSV using a 1 MiB buffer. The mode determines row filtering:

| Mode | Included rows |
|---|---|
| `full` | Every record. |
| `suspicious` | Records not matched by NSRL. |
| `yara` | Records with one or more YARA hits. |
| `capa` | Records marked capa-eligible. |

#### `WriteRow(StreamWriter writer, params string[] fields)`

Writes one comma-separated row, calling `WriteField` for safe escaping.

#### `WriteField(StreamWriter writer, string field)`

Empty fields remain empty. A field containing a comma, quotation mark, carriage return, or newline is enclosed in quotes, and embedded quotes are doubled according to CSV conventions.

### 6.7 `YaraMetaParser`

This compiled helper parses `yara -m` output. `MatchInfo` holds a rule name and a case-insensitive metadata dictionary.

- `Parse` splits output into lines, extracts the rule name, and parses an optional bracketed metadata block. Plain output without metadata is accepted.
- `FindMatchingBracket` locates the closing bracket while ignoring brackets inside quoted strings.
- `ParseMetaBlob` parses comma-delimited `key=value` entries, including quoted values and escaped quotes.

### 6.8 `SeverityScorer`

This class converts recognized YARA metadata to a common scale.

- `BucketScore` maps 90+ to Critical, 70–89 to High, 40–69 to Medium, 1–39 to Low, and zero or below to Unknown.
- `Resolve` checks numeric `score`, then `tc_detection_factor` multiplied by 20, then word-valued `severity`, `tc_policy_severity`, or `importance`.
- `NormalizeWord` recognizes low, medium/moderate, high, and critical/severe.

The returned tuple contains the bucket and normalized score. Word-only severities use `-1` because the code does not invent a numeric value.

### 6.9 ATT&CK data classes

`AttackTechniqueInfo` stores a technique ID, name, and primary tactic.

`AttackDb.Load` reads a MITRE ATT&CK STIX JSON bundle in two passes. The first indexes non-revoked, non-deprecated techniques and entities. The second indexes `uses` relationships from malware, tools, and groups to techniques.

`AttackDb.Resolve` searches matched-rule metadata values for ATT&CK URLs. Direct technique URLs resolve immediately; software and group URLs resolve through indexed `uses` relationships. Results are deduplicated and capped at ten techniques per rule match.

Its private helpers are:

- `IsTrue`, which safely checks a Boolean JSON property;
- `GetAttackExternalId`, which selects the `mitre-attack` external ID;
- `GetPrimaryTactic`, which collects MITRE kill-chain phase names;
- `TitleCase`, which converts kebab-case phase names to display text.

## 7. Theme Section

### 7.1 `Get-ThemePalette`

Returns a hashtable of semantic colors. Both palettes define the same keys—such as `WindowBack`, `SurfaceBack`, `Fore`, `Accent`, `Success`, `Warning`, and `Danger`—so the rest of the UI does not need separate dark- and light-mode branches.

### 7.2 `New-ThemedButton`

Creates a consistently sized flat WinForms button. A normal button uses the neutral surface colors; `-Primary` uses the accent background and contrasting text.

Centralizing button styling prevents each page builder from duplicating visual setup.

### 7.3 `Import-ThemedLogo`

This function:

1. validates that the image path exists;
2. loads the source image;
3. clones it into a `Bitmap`;
4. disposes the original file-backed image;
5. calculates an aspect-ratio-preserving height;
6. returns a configured `PictureBox`.

Cloning and disposing the original image releases the source file lock.

## 8. Shared State

### 8.1 `$Config`

The configuration hashtable stores the source directory, report directory, NSRL source, YARA executable and rules, capa executable and rules, ssdeep executable, and optional `AttackDataPath`.

It begins with empty strings and is populated through the Settings page.

### 8.2 `$FileRecords`

This is a `ConcurrentDictionary<string, object>` keyed by file path. Workers update records while the UI timer reads them. A concurrent collection prevents unsafe structural access across threads.

Individual `FileRecord` fields are mutable. The design tolerates eventually consistent UI snapshots: a timer may briefly see some old and some new field values, but the next tick corrects the display.

### 8.3 `$ScanControl`

This synchronized hashtable coordinates the UI and dispatcher:

| Key | Purpose |
|---|---|
| `IsRunning`, `IsPaused`, `StopRequested`, `Completed` | Scan lifecycle flags. |
| `TotalFiles`, `FilesDiscovered`, `OrderedPaths` | Queue discovery state. |
| `NsrlHashCount` | Loaded or previewed hash count. |
| `NsrlPreviewBusy` | Prevents duplicate preview jobs. |
| `Timer` | Scan stopwatch. |
| `ReportPath` | Most recent full CSV report. |
| `ProcessRegistry` | Currently running external processes. |
| `NsrlPreviewHandle` | Resources for the preview runspace. |

### 8.4 `$LogQueue` and `Add-Log`

`$LogQueue` is a `ConcurrentQueue<string>`. `Add-Log` adds a timestamp and enqueues a message. Background code can produce log entries safely; only the UI timer touches the log textbox.

### 8.5 `$EngineState`

This hashtable holds the dispatcher job handle and associated resources so the UI timer can dispose them once the background work finishes.

## 9. Per-File Worker

`$workerScriptBlock` is not a named function, but it is the core per-file unit of work. The dispatcher binds its parameters and runs one copy per active file in the runspace pool.

### 9.1 `Invoke-ExternalTool`

This nested worker function safely runs an executable.

It builds a `ProcessStartInfo`, adds every argument through `ArgumentList` rather than constructing a shell command, disables shell execution, hides the console window, and redirects both output streams.

After starting the process, it registers the `Process` under the file path so stop and shutdown handlers can kill it.

Standard output and error are read concurrently with `ReadToEndAsync()`. This avoids:

- losing output from fast processes;
- deadlocking when one redirected stream fills while the other is being read.

If the process exceeds the default 600-second timeout, it is killed with its descendants and the function returns:

```text
ExitCode = -1
TimedOut = true
```

The `finally` block removes the process from the registry and disposes it regardless of success or failure.

### 9.2 `Get-SeverityRank`

This worker-local function ranks Critical, High, Medium, Low, and all other values as 4 through 0. The worker uses it to retain the worst severity across every YARA rule that matched a file.

### 9.3 Worker Pipeline

The worker updates progress at meaningful stages:

| Progress | Meaning |
|---|---|
| 10% | Worker started. |
| 40% | SHA-1 and MD5 complete. |
| 55% | ssdeep complete. |
| 70% | YARA complete. |
| 90% | capa complete. |
| 100% | Completed or error. |

#### Single-pass hashing and header capture

The worker opens the file with `FileShare.ReadWrite`, allowing analysis of files that another process has open. A rented 1 MiB buffer feeds both `IncrementalHash` objects.

At the same time, the first 4 KiB is copied into `$header`. This avoids a second file read for format detection and allows for unusually large DOS stubs before a PE header.

The stream, pooled buffer, and hashers are always released in `finally`.

#### NSRL gate

The raw SHA-1 bytes become a `HashKey` and are tested against the in-memory NSRL set. A match marks the file known-good and skips ssdeep, YARA, and capa.

#### ssdeep and YARA

Unknown files are passed first to ssdeep and then to `yara -m`. A nonzero exit code from either tool becomes a per-file exception. The compiled parser determines the match count and stores only rule names in `YaraMatches`.

For every parsed match, the worker resolves severity, keeps the highest bucket, and—when an ATT&CK database is loaded—resolves and deduplicates technique references.

#### PE detection

The worker first requires `MZ`. It then reads the signed 32-bit `e_lfanew` value at offset `0x3C`, verifies that the target is within the captured header, and checks for `PE\0\0`.

Requiring both signatures is stronger than classifying every `MZ` file as a valid PE.

#### ELF detection

The worker checks for the four-byte ELF magic:

```text
7F 45 4C 46
```

#### Shellcode heuristic

A YARA-matched file is considered probable shellcode when it is neither PE nor ELF and either:

- has a `.raw` or `.bin` extension and is smaller than 200,000 bytes; or
- has no listed native/data extension and is smaller than 100,000 bytes.

This is a heuristic, not a parser. It intentionally limits capa invocations while allowing small raw samples.

#### Possible false-negative flag

If a YARA-matched file has an executable-like extension (`.exe`, `.dll`, `.so`, or `.elf`) but fails PE/ELF validation, it is not sent through the shellcode fallback. `PossibleFalseNegative` highlights that analysis gap.

Examples include a corrupt executable, truncated collection, misleading extension, or deliberately damaged header.

#### capa execution

Eligible files run:

```text
capa.exe -j -r <rules-directory> <file>
```

The raw JSON is saved in the record. If JSON parsing succeeds and a `rules` object exists, its property count becomes `CapaDetectionCount`.

A best-effort copy is also written as:

```text
<report-directory>\capa_reports\<SHA1>.json
```

Failure to write this secondary JSON file does not fail the file scan.

#### Per-file exception boundary

The outer worker `try`/`catch` converts any failure into:

```text
Status = Error
Progress = 100
Error = <exception message>
```

One unreadable file or failed tool invocation therefore does not crash the scan engine.

## 10. Scan Engine Section

### 10.1 `Start-ScanEngine`

This function creates a separate dispatcher runspace and starts it asynchronously. Its returned object contains:

- the dispatcher `PowerShell` instance;
- its async handle;
- its runspace;
- a `Disposed` flag.

The UI stores this object in `$EngineState.Handle`.

### 10.2 `Add-Log2`

The dispatcher cannot rely on the UI runspace’s local `Add-Log` function, so it defines its own small logger. It writes to the same concurrent queue using the same timestamp format.

### 10.3 Process Registry

The dispatcher creates a concurrent dictionary of active external `Process` objects and exposes it through `$ScanControl.ProcessRegistry`.

This allows both the Stop path and the form-closing handler to terminate ssdeep, YARA, or capa processes that are still running.

### 10.4 NSRL Cache Loading

The engine hashes the lowercase NSRL source path with SHA-256 and uses the first 16 hexadecimal characters in the cache name. This prevents same-named NSRL files in different locations from colliding.

The cache lives under:

```text
<report-directory>\.bsifter-nsrl-cache
```

Its first 16 bytes contain:

| Bytes | Value |
|---|---|
| 0–7 | Original source-file length as `Int64`. |
| 8–15 | Original UTC last-write ticks as `Int64`. |
| 16 onward | Consecutive raw 20-byte SHA-1 records. |

If source length and timestamp still match, the engine uses `LoadFromCache`. Otherwise it parses the CSV into a temporary cache body, writes a new metadata header and body, and removes the temporary file.

The source directory is never used for the cache, which supports read-only NSRL media.

### 10.5 File Enumeration and Record Creation

`FileScanner.EnumerateFiles` discovers the target tree. The engine logs partial enumeration errors but continues with discovered files.

It creates a `FileRecord` for each path, sets a common added time, and publishes `TotalFiles`, `OrderedPaths`, and `FilesDiscovered` to the UI.

Before enumeration, the dispatcher optionally loads `AttackDataPath`. A missing path or parse failure disables TTP mapping without failing the scan. A successfully loaded `AttackDb` is shared read-only with the worker pool.

### 10.6 Runspace Pool and Dispatch Loop

The pool is created with a minimum of one worker and a maximum of `$ThrottleLimit`.

The dispatcher maintains:

- `$queue`: paths waiting to start;
- `$inFlight`: active PowerShell worker invocations;
- `$completedCount`: finished async jobs;
- `$nextMilestone`: next multiple-of-50 log threshold.

Each loop iteration:

1. handles a stop request;
2. reaps completed workers with `EndInvoke`;
3. starts one new worker if not paused and capacity is available;
4. otherwise sleeps for 100 milliseconds.

Pause affects only new dispatches. Already running workers continue to completion.

### 10.7 Stop Behavior

When stopping:

1. Active external processes are killed.
2. Queued records become `Cancelled`.
3. The dispatcher waits up to five seconds for in-flight workers.
4. Remaining worker PowerShell instances are stopped and disposed.
5. Records still marked `Scanning` become `Cancelled`.

The worker pool is closed and disposed in `finally`, including after unexpected dispatcher errors.

### 10.8 Report Export

After processing, records are sorted by path and four timestamped CSVs are written:

| Filename pattern | Contents |
|---|---|
| `BinSifter_Triage_<timestamp>.csv` | All records. |
| `suspicious_unknown_<timestamp>.csv` | Non-NSRL records. |
| `yara_matches_<timestamp>.csv` | Records with YARA hits. |
| `capa_compatible_<timestamp>.csv` | Records for which capa was eligible. |

The full report path is stored in `$ScanControl.ReportPath`. capa JSON documents are kept separately in `capa_reports`.

### 10.9 Dispatcher Completion

Expected sentinel exceptions—`stopped-before-enumeration` and `nothing-to-scan`—are suppressed from error logging. Other exceptions become scan-engine log entries.

The final block always sets:

```powershell
$ScanControl.IsRunning = $false
$ScanControl.Completed = $true
```

This guarantees the UI can return to its ready state and clean up resources.

## 11. Main Form Shell

The shell creates:

- a resizable 1400×900 main form;
- a fixed-width left sidebar;
- an optional logo;
- a vertical navigation panel;
- a top bar with page title and status;
- a bottom status bar;
- a fill-docked content panel.

Docking order matters in WinForms. The content panel fills the remaining area after the sidebar, top bar, and status bar claim their space.

### `Move-TopBarControls`

This function recalculates the right-aligned status label’s location based on the current top-bar width and label width. It runs when the top bar resizes and when the form is first shown.

## 12. Dashboard Page

### 12.1 `New-DashboardPage`

Builds five statistic cards:

- files completed;
- YARA hits;
- capa scans;
- capa rule detections;
- NSRL matches.

A second row contains Critical, High, Medium, Low, and Unknown YARA-severity tiles. Each file is intended to count once under its worst matched-rule severity.

It also creates a summary panel for scan status and elapsed time. The function returns a custom object containing the page and references to labels that must be updated later.

Returning references is a useful WinForms pattern: the builder owns construction, while the refresh timer can still update specific controls.

### 12.2 `New-StatTile`

This nested factory creates one card, caption, and large numeric label. It returns both the card to place in the layout and the value label to update.

## 13. Scan Queue Page

### `New-ScanQueuePage`

Builds:

- Start, Pause, Stop, and Clear Completed buttons;
- a text summary;
- a read-only `DataGridView`;
- columns for file status, progress, YARA and capa counts, false-negative warning, NSRL state, and added time.

The queue also displays the file’s worst YARA severity. The returned `RowIndexByPath` hashtable maps file paths to UI row indexes, avoiding a whole-grid search every refresh tick.

## 14. Results Page

### `New-ResultsPage`

Builds a filter box, report-folder button, refresh button, and results grid. The results grid includes hashes, YARA severity, resolved MITRE ATT&CK techniques, and error details rather than live progress.

The page is refreshed on demand and when navigated to, rather than being updated continuously.

## 15. Settings Page

### `New-SettingsPage`

Creates a table-driven editor for all configuration fields. Each field definition specifies:

- configuration key;
- user-facing label;
- file or directory picker;
- optional file filter.

The MITRE ATT&CK enterprise JSON path is optional; the scanner and tool paths are required.

Each Browse button stores its own field definition and textbox inside `.Tag`. This is important because event handlers run later, after the builder function has returned; the handler does not have to depend on a loop variable or local lookup remaining in scope.

The function returns the page, a key-to-textbox map, the Save button, and a status label.

## 16. YARA Rules Page

### `New-YaraRulesPage`

Creates:

- the active rule-path label;
- Browse, Reload, and Save Changes buttons;
- a multiline, monospaced text editor.

This page edits the selected YARA file directly. It does not validate YARA syntax before saving.

## 17. Capa Rules Page

### `New-CapaRulesPage`

Creates a directory label, Browse/Open Folder/Refresh buttons, and a list box showing `.yml`, `.yaml`, and `.json` files found recursively in the selected rule directory.

The page is a browser, not a capa rule editor.

## 18. NSRL Page

### `New-NsrlPage`

Creates a file label, Browse button, Reload Now button, and large known-good hash count.

The preview operation runs in a background runspace so a large NSRL CSV does not freeze the UI.

## 19. Logs Page

### `New-LogsPage`

Creates a clear button and a read-only, monospaced, vertically scrolling textbox. The textbox is populated only by the UI refresh timer after it drains `$LogQueue`.

## 20. About Page

### `New-AboutPage`

Creates an optional logo, version label, application description, and integration list.

The script filename is `v1.2.1`, but the About and status labels currently display `BinSifter 1.0.0`. This is a presentation inconsistency, not a scan-engine behavior.

## 21. Page Assembly and Navigation

Each page builder is called once. The returned panels are placed in an ordered `$pageMap`, added to the content panel, and initially hidden.

A matching sidebar button is created for every page. The page name is stored in the button’s `.Tag`, and its click handler calls `Show-Page`.

### `Show-Page`

This function:

1. makes the requested page visible and hides the others;
2. highlights the active navigation button;
3. updates the top-bar page title;
4. refreshes Results, capa rules, or YARA content when those pages open.

## 22. Settings Wiring

The Save handler validates every configured path with the expected file-system type. Valid paths are normalized with `Resolve-Path`.

Before accepting the report directory, the handler creates and deletes a uniquely named probe file. This catches read-only or permission-restricted output locations before a scan begins.

After validation, it updates `$Config`, refreshes the relevant page labels and content, and logs the save.

The current Save handler does not copy the optional `AttackDataPath` textbox into `$Config`. Consequently, selecting that file in Settings does not activate ATT&CK loading unless the configuration assignment is extended. This is an implementation gap in the current source.

The settings exist only in memory. The script does not persist them across application launches.

## 23. Scan Queue Wiring

### Start button

The handler:

1. refuses to start a second concurrent scan;
2. checks that every configuration value is nonempty;
3. redirects the user to Settings if configuration is missing;
4. clears records and grid state from the previous scan;
5. resets lifecycle flags;
6. starts a stopwatch;
7. calls `Start-ScanEngine`.

The engine performs the authoritative path validation only indirectly through its operations; the Save handler is expected to have validated paths first.

### Pause button

Toggles `IsPaused`, changes its text between Pause and Resume, and logs the transition. Active workers are not suspended; only new worker dispatch is paused.

### Stop button

Sets `StopRequested`. The dispatcher observes this flag on its next loop and performs coordinated cancellation.

### Clear Completed button

Removes grid rows for records in `Completed`, `Error`, or `Cancelled` state. It does not remove those records from `$FileRecords`, so dashboard totals and exported data remain intact.

After row removal, it rebuilds the path-to-index map because `DataGridView` row indexes have shifted.

## 24. Results Wiring

### `Update-ResultsGrid`

Clears the results grid, sorts records by path, and repopulates every row. Boolean values are displayed as `Yes` or `No`.

### Open Report Folder

Uses `Start-Process` on the configured report directory, which asks Windows to open it in the default file manager.

### Debounced filtering

The filter timer waits 300 milliseconds after the latest text change. It then shows only rows whose Path cell contains the entered wildcard substring.

Debouncing prevents a large grid from being rescanned after every keystroke during rapid typing.

## 25. YARA Rules Wiring

### `Update-YaraRulesContent`

If the selected rules file exists, it loads the full text into the editor. Read failures are shown inside the editor. With no valid file, the label and editor are reset.

The Browse handler updates both `$Config` and the matching Settings textbox. Reload discards unsaved editor changes by rereading the file. Save writes the current editor contents directly to disk and reports success or failure in a message box.

## 26. Capa Rules Wiring

### `Update-CapaRulesList`

Clears the list, recursively discovers `.yml`, `.yaml`, and `.json` files, and adds their full paths. It displays a placeholder if the directory contains no matching files.

The Browse handler updates both configuration and the Settings textbox. Open Folder launches the configured directory in the default file manager.

## 27. NSRL Wiring

The Browse handler updates the NSRL path in configuration, Settings, and the page label.

The Reload Now handler prevents duplicate reloads with `NsrlPreviewBusy`, then starts a one-off background runspace.

The preview runspace uses the same cache naming and validation rules as a real scan:

- if a valid cache exists, it calculates the count from cache length;
- otherwise it calls `NsrlLoader.CountRows`.

Results and failures are placed in the shared log queue. A `finally` block always clears the busy flag.

The preview handle is stored so the refresh timer can later call `EndInvoke` and dispose its PowerShell and runspace objects.

## 28. Logs Wiring

The Clear Logs button clears only the textbox. It does not cancel work or alter records, and any queued log lines not yet drained can appear on the next timer tick.

## 29. Refresh Timer

The WinForms timer ticks every 750 milliseconds on the UI thread. It is the synchronization bridge between background state and controls.

Each tick performs the following work.

### 29.1 Drain logs

It repeatedly calls `TryDequeue`, appends lines to the log box, and scrolls to the end if anything was added.

### 29.2 Initially populate the scan grid

Once the dispatcher publishes `FilesDiscovered` and `OrderedPaths`, the timer creates rows for every file.

`SuspendLayout()` and `ResumeLayout()` prevent an expensive redraw and layout pass for every inserted row.

### 29.3 Update records and aggregate counters

For every `FileRecord`, the timer:

- counts completed files;
- sums YARA matches;
- sums capa rule detections;
- counts capa-eligible files;
- counts NSRL matches;
- updates the corresponding live queue row.

“Capa Scans” and “Capa Rule Detections” intentionally measure different things. One file can cause one capa scan but produce many rule detections.

Files with YARA hits are counted once in the dashboard severity row under their worst bucket. Clean and NSRL-skipped files do not inflate the Unknown count.

### 29.4 Update summaries

While running, the dashboard and queue show completed count, total count, and stopwatch elapsed time. After completion, they show the final completed count.

Cancelled and errored files are not included in the “completed” count because the code counts only records whose status equals `Completed`.

### 29.5 Dispose finished runspaces

When the dispatcher completes, the timer calls `EndInvoke`, disposes its `PowerShell` instance, closes and disposes its runspace, and marks the handle disposed.

It performs equivalent cleanup for the NSRL preview runspace.

### 29.6 Update status and controls

The top-right indicator changes among Ready, Scanning, and Paused. Start is disabled while running; Pause and Stop are enabled only while running.

The status bar includes the displayed application version, NSRL count, and most recent full report filename when available.

## 30. Form Closing

The `FormClosing` handler performs a controlled shutdown:

1. sets `StopRequested` if a scan is active;
2. kills every registered external process that is still running;
3. pumps UI events and waits up to five seconds for dispatcher completion;
4. stops the refresh timer.

Directly killing registered processes reduces the risk of leaving orphaned ssdeep, YARA, or capa processes when the PowerShell host exits.

## 31. Starting the UI Event Loop

After wiring is complete:

```powershell
Show-Page -Name 'Dashboard'
$refreshTimer.Start()
[System.Windows.Forms.Application]::Run($form)
```

`Application.Run` owns the message loop and blocks until the main form closes. Control then returns through `Show-MainWindow`’s cleanup blocks.

## 32. Bootstrap Section

The final section runs after all functions have been defined:

1. `Test-SystemDarkMode` selects the theme.
2. The throttle limit becomes twice the logical processor count, with a minimum of two.
3. The dark or light horizontal logo path is built relative to `$PSScriptRoot`.
4. `Show-MainWindow` launches the application.
5. A green console message is written after the application closes.

Using `$PSScriptRoot` makes logo discovery independent of the caller’s current working directory.

The throttle calculation favors concurrency because each worker performs a mix of disk I/O and external-process waiting. On very fast storage or systems with expensive capa scans, a lower configurable limit may be more appropriate.

## 33. End-to-End Example

Suppose the target contains `sample.exe`:

1. Native enumeration discovers the path.
2. The dispatcher creates a queued `FileRecord`.
3. A worker changes it to `Scanning`.
4. The file is read once; SHA-1, MD5, and the 4 KiB header are collected.
5. The SHA-1 is absent from NSRL.
6. ssdeep produces a fuzzy-hash line.
7. YARA emits two metadata-bearing matches, so `YaraHitCount = 2`.
8. The worker retains the worse severity and resolves any ATT&CK references.
9. `MZ`, `e_lfanew`, and `PE\0\0` validate the file as PE.
10. `CapaEligible = true`; capa runs with JSON output.
11. If capa’s `rules` object has seven properties, `CapaDetectionCount = 7`.
12. The record becomes `Completed`.
13. The UI timer shows the updated core counts.
14. The file appears in the full, suspicious/unknown, YARA, and capa-compatible CSVs.
15. Its capa output is saved as `capa_reports\<SHA1>.json`.

If the same file’s SHA-1 were present in NSRL, processing would stop after step 5 and it would appear only in the full report.

## 34. Important Implementation Notes

- **Windows-only UI:** WinForms and the Windows theme registry make the interface Windows-specific.
- **PowerShell requirement:** The script identifies itself as PowerShell 7+ and uses APIs such as `ProcessStartInfo.ArgumentList` and `Convert.ToHexString`.
- **NSRL assumption:** Matching uses the first CSV column as SHA-1 and expects the NSRL RDS-style layout described in the code.
- **Known-good means skipped:** An NSRL match bypasses ssdeep, YARA, and capa. This improves throughput but trusts the selected NSRL data and SHA-1 identity.
- **YARA controls capa:** A file reaches capa only after at least one YARA output line and eligibility classification.
- **Severity is metadata-dependent:** Missing or unrecognized rule metadata remains `Unknown`; BinSifter does not guess.
- **ATT&CK mapping is optional:** It requires local ATT&CK STIX JSON and references in YARA metadata; the present Settings Save handler also needs an assignment fix before the selected path is retained.
- **Pause is non-preemptive:** It stops new dispatches, not already running tools.
- **Tool timeout:** Each external invocation has a ten-minute default timeout.
- **No settings persistence:** Paths must be configured again after restarting the program.
- **Version labels:** Several UI strings say `1.0.0` even though the script is named `v1.2.1`.
- **Raw output retention:** Full YARA text is stored in memory; full capa JSON is stored in memory and normally written per eligible file.

## 35. Function Index

### PowerShell functions

| Function | Role |
|---|---|
| `Test-SystemDarkMode` | Reads the Windows application-theme preference. |
| `New-STARunspace` | Creates an open STA PowerShell runspace. |
| `Show-MainWindow` | Builds, runs, and cleans up the application. |
| `Get-ThemePalette` | Returns semantic dark/light colors. |
| `New-ThemedButton` | Creates a consistently styled button. |
| `Import-ThemedLogo` | Loads and sizes a logo without retaining a file lock. |
| `Add-Log` | Enqueues a timestamped UI-side log entry. |
| `Get-SeverityRank` | Orders severity buckets so the worst match wins. |
| `Invoke-ExternalTool` | Runs and supervises ssdeep, YARA, or capa. |
| `Start-ScanEngine` | Starts the dispatcher and returns its async resources. |
| `Add-Log2` | Enqueues dispatcher-side log entries. |
| `Move-TopBarControls` | Right-aligns the status indicator. |
| `New-DashboardPage` | Builds the dashboard. |
| `New-StatTile` | Builds one dashboard counter card. |
| `New-ScanQueuePage` | Builds live scan controls and queue grid. |
| `New-ResultsPage` | Builds the results browser and filter. |
| `New-SettingsPage` | Builds path configuration controls. |
| `New-YaraRulesPage` | Builds the YARA text editor. |
| `New-CapaRulesPage` | Builds the capa rule browser. |
| `New-NsrlPage` | Builds the NSRL status page. |
| `New-LogsPage` | Builds the log viewer. |
| `New-AboutPage` | Builds application information. |
| `Show-Page` | Switches the visible page. |
| `Update-ResultsGrid` | Rebuilds the results grid from records. |
| `Update-YaraRulesContent` | Loads the active YARA file into the editor. |
| `Update-CapaRulesList` | Enumerates capa rule files. |

### C# methods

| Method | Role |
|---|---|
| `HashKey.Equals(HashKey)` | Performs typed SHA-1-key equality. |
| `HashKey.Equals(object)` | Implements object equality. |
| `HashKey.GetHashCode()` | Supports hash-set lookup. |
| `NsrlLoader.BuildFromCsv` | Parses NSRL CSV and builds a cache. |
| `NsrlLoader.LoadFromCache` | Loads raw SHA-1 records from cache. |
| `NsrlLoader.CountRows` | Counts preview rows without retaining hashes. |
| `NsrlLoader.TryParseHex40` | Converts 40 hex characters to 20 bytes. |
| `NsrlLoader.HexVal` | Converts one hex character to a nibble. |
| `FileScanner.EnumerateFiles` | Walks a directory tree while tolerating access errors. |
| `CsvWriter.WriteReport` | Filters and writes a report. |
| `CsvWriter.WriteRow` | Writes one CSV row. |
| `CsvWriter.WriteField` | Escapes and writes one CSV field. |
| `YaraMetaParser.Parse` | Parses `yara -m` lines into rule names and metadata. |
| `YaraMetaParser.FindMatchingBracket` | Finds a metadata block’s closing bracket. |
| `YaraMetaParser.ParseMetaBlob` | Parses YARA metadata key/value pairs. |
| `SeverityScorer.BucketScore` | Maps a normalized score to a severity bucket. |
| `SeverityScorer.Resolve` | Derives severity from recognized metadata fields. |
| `SeverityScorer.NormalizeWord` | Normalizes word-valued severities. |
| `AttackDb.Load` | Loads and indexes ATT&CK STIX data. |
| `AttackDb.Resolve` | Resolves ATT&CK URLs in rule metadata. |
| `AttackDb.IsTrue` | Reads a Boolean JSON flag safely. |
| `AttackDb.GetAttackExternalId` | Finds an object’s ATT&CK external ID. |
| `AttackDb.GetPrimaryTactic` | Formats a technique’s MITRE tactics. |
| `AttackDb.TitleCase` | Converts kebab-case phase text. |

## 36. Suggested Reading Order in the Source

For a first code walkthrough, read in this order:

1. Bootstrap and the three top-level functions.
2. `FileRecord` to understand the data model.
3. `$workerScriptBlock` to understand what happens to one file.
4. `Start-ScanEngine` to understand concurrency and reports.
5. Shared state and the refresh timer to understand cross-thread coordination.
6. Page builders and event wiring to understand the UI.
7. Compiled C# helpers for the performance details.

That order follows the application’s behavior rather than the exact source-file order, which makes the design easier to learn.
