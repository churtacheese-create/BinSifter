# Ingot implementation plan

Ingot is BinSifter's third variant: a Rust backend service + browser UI, the
one variant meant to run on any Linux/macOS/Windows without a per-OS desktop
GUI toolkit. See `docs/ingot.md` for the public-facing summary.

This document is the internal build plan. It mirrors how Winnow (the Python
variant) was ported: **one pipeline stage at a time, each hard-gated by tests
and a real scan before the next is started** - not a big-bang rewrite.

## Decisions locked in (2026-09-09)

| Question | Decision |
| --- | --- |
| First block of work | Phased scaffold first (Phase 1 below) |
| capa / FLOSS / Speakeasy | Auto-download the official standalone binaries per-user on first run (same pattern as Winnow's `tool_bootstrap.py`) and shell out to them. Speakeasy has no standalone binary - deferred / optional-Python. |
| YARA engine | `yara-x` (pure-Rust, VirusTotal's official successor - no libyara C dependency, static cross builds) |
| Frontend | Hand-written HTML/CSS/vanilla JS, no Node build step, embedded via `rust-embed` |
| NSRL cache format | Reuse Winnow/Rowan's exact on-disk format (`BSNL` magic, version 1) so caches are interchangeable between variants |
| Repo location | New top-level `ingot/` Cargo workspace |

## Prerequisite

Rust is installed on the dev machine (rustup). If setting up fresh:

```
winget install --id Rustlang.Rustup -e --source winget
```

then restart the shell so `~/.cargo/bin` is on PATH. The workspace MSRV is
**1.93** (`rust-version` in `ingot/Cargo.toml`) - `yara-x` and its bundled
`wasmtime`/`cranelift` set the floor and raise it over time, so this tracks
upward with dependency updates rather than staying pinned low.

## Target architecture

```
ingot/
  Cargo.toml                 # workspace
  IMPLEMENTATION_PLAN.md      # this file
  crates/
    ingot-core/              # scan engine library - NO http, NO ui
      src/
        lib.rs
        config.rs            # IngotConfig  <- port of core/config.py
        model.rs             # FileRecord   <- port of core/models.py
        hashing.rs           # MD5/SHA-1/SHA-256 + Shannon entropy, one pass
        nsrl.rs              # BSNL cached mmap index  <- port of core/nsrl.py
        blocklist.rs         # known-bad hash lookup   <- port of core/blocklist.py
        report.rs            # 37-column CSV writer     <- port of core/report.py
        engine.rs            # scan_directory() orchestration + progress events
        (later) yara.rs file_type.rs imphash.rs ssdeep.rs capa.rs floss.rs
                authenticode.rs archive.rs attack.rs yara_rule_gen.rs
                disposition.rs tool_bootstrap.rs
    ingot-server/            # axum HTTP service + embedded frontend + binary
      src/
        main.rs              # bind 127.0.0.1:<port>, serve, optional browser open
        api.rs               # REST + SSE handlers
        assets.rs            # rust-embed of ../../frontend
      build.rs (if needed)
  frontend/
    index.html app.css app.js   # tabbed SPA: Scan / Results / Dashboard / Settings / Logs / About
  tests/ (per crate)
```

`ingot-core` never depends on `ingot-server`. A headless `ingot-cli` (parity
with `binsifter-scan`) is trivial to add later on top of `ingot-core`.

### Key crates

- `axum`, `tokio`, `tower-http` - HTTP + static serving + tracing
- `serde`, `serde_json`
- `rust-embed` - frontend assets (reads from disk in debug, embeds in release)
- `md-5`, `sha1`, `sha2` (RustCrypto) - hashing
- `csv` - report writing (BOM + CRLF handled explicitly for Excel parity)
- `walkdir` - recursive file enumeration
- `memmap2` - NSRL index mmap
- `rayon` - data-parallel per-file scanning (no GIL, so far simpler than
  Winnow's multiprocessing pool; thread pool capped at 16 = Winnow's
  `MAX_SCAN_WORKERS`)
- `tracing`, `tracing-subscriber` - logging, forwarded to the Logs tab over SSE
- `directories` - per-user data dir (XDG / `%LOCALAPPDATA%` / macOS equivalent)
- later: `yara-x`, `zip`/`sevenz-rust`, `goblin` (PE/ELF parse for imphash/file-type)

## Behaviour parity notes (must match Winnow exactly)

- **CSV**: 37 columns, exact order/names from `core/report.py::COLUMNS`. UTF-8
  **with BOM**, CRLF line endings. Bool fields render `True`/`False`
  (Python-style capitalisation). `Entropy` to 3 decimals, blank when `< 0`.
  Sentinel int columns (`-1`/`0`) render blank, not the number. 4 files per
  scan: `BinSifter_Triage_`, `suspicious_unknown_`, `yara_matches_`,
  `capa_compatible_` + `<timestamp>.csv`, timestamp `%Y-%m-%d_%H%M%S`.
- **NSRL cache**: header `struct <4sIQqQ` = magic `BSNL`, u32 version `1`,
  u64 record_count, i64 source_mtime_ns, u64 source_size; then
  `record_count` * 20-byte SHA-1 digests sorted ascending. Cache lives in
  `<ReportDirectory>/.bsifter-nsrl-cache/<stem>_<sha256(normcase path)[:16]>.bsifter-nsrl-idx`.
  Staleness = source mtime_ns + size match. Build streams records to a temp
  file, sorts in place over an mmap, `rename()`s into place (atomic).
  Source parse accepts an RDSv2 CSV (`SHA-1` column) or a plain
  one-hash-per-line list.
- **Blocklist**: plain list or MalwareBazaar-style CSV (`#` comments), collects
  any 32/40/64-hex token, uppercased. `check_reputation` tests SHA-256 then
  SHA-1 then MD5 -> `("KnownBad", "<kind>")` or `("Clean", "")`.
- **NSRL-known-good gate**: a file NSRL vouches for skips imphash / ssdeep /
  YARA / capa / FLOSS entirely (matches `engine.py` and Rowan).
- **Entropy**: bits/byte over a 256-bucket histogram from the same streaming
  read as the hashes; `-1.0` for a zero-length file.
- **File enumeration**: recursive, one bad subdir skipped not fatal.
- **Disposition**: persisted by SHA-1 in
  `<ReportDirectory>/.bsifter-disposition-history.txt`, `sha1|disposition`
  per line, case-insensitive key. (Phase 2.)

## Phase 1 - scaffold + pure-Rust pipeline - COMPLETE (2026-09-09)

Goal: a runnable `ingot` binary that serves the UI, runs a real scan over the
stages that need no external engine, streams progress, and writes
byte-parity CSV reports.

**Status:** done and validated. `cargo test --workspace` (20 tests),
`cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo fmt --check` all pass. A real scan over a smoke-test tree produced
hashes/entropy identical to Python's `hashlib`, the NSRL known-good gate and
known-bad blocklist both fired correctly, the NSRL cache is byte-compatible
with the shared `BSNL` v1 format (32-byte header, sorted 20-byte records)
and is reused on rescan, and the four CSV reports carry the UTF-8 BOM, CRLF
endings, the exact 37-column header, `True`/`False` bools, 3-dp entropy, and
blank sentinels. The HTTP API (health/config/scan/SSE/reports), progress and
log SSE streams, static asset serving, and CSV downloads all verified over
`curl`.

Run it: `cd ingot && cargo run` (opens `http://127.0.0.1:8477` in a browser;
`--no-open` to skip, `--port N` / `INGOT_PORT` to change the port,
`INGOT_DATA_ROOT` to relocate `Reports/`+settings+NSRL cache).

Original checklist:

1. **Workspace + `ingot-core` skeleton**: `Cargo.toml`, `lib.rs`, module
   stubs, `.gitignore` entry for `ingot/target/`.
2. **`model.rs`**: `FileRecord` (serde) - every field from `core/models.py`
   with the same defaults/sentinels.
3. **`config.rs`**: `IngotConfig` + data-root resolution + JSON settings
   cache (`.bsifter-settings-cache.json`) + default `Reports/`, `Attack/`,
   `Blocklist/` layout.
4. **`hashing.rs`** + unit tests (known vectors, empty file -> entropy -1).
5. **`blocklist.rs`** + unit tests (list + CSV inputs, all three hash kinds).
6. **`nsrl.rs`**: build / freshness / mmap-open / binary-search lookup +
   tests, including a round-trip test and a fixture-cache read test. Verify a
   cache built here is byte-identical to one Winnow builds from the same
   source (diff against `Reports/.bsifter-nsrl-cache/` sample).
7. **`report.rs`**: 37-column writer + tests asserting column list, BOM,
   CRLF, `True`/`False`, blank-sentinel formatting. Golden-file diff against
   a Winnow-produced CSV on the same records.
8. **`engine.rs`**: `scan_directory(config, progress_sink)` - enumerate,
   load NSRL/blocklist, rayon parallel per-file (hash+entropy, NSRL,
   blocklist), write the 4 CSVs, return `ScanResult`.
9. **`ingot-server`**: axum on `127.0.0.1` (default port `8477`, `--port` /
   `INGOT_PORT` override), `rust-embed` assets, endpoints:
   - `GET /` + assets
   - `GET /api/health` -> version
   - `GET /api/config`, `PUT /api/config`
   - `POST /api/scan` (one at a time; 409 if running) -> scan id
   - `GET /api/scan/:id/events` -> SSE `{done,total,path,record}`
   - `GET /api/scan/:id` -> status + records
   - `GET /api/scan/:id/report/:kind` -> CSV download
   - `GET /api/reports` -> list CSVs already in `ReportDirectory`
   - `GET /api/logs/events` -> SSE tracing stream
10. **`frontend`**: tabbed SPA - Scan (dir path + Start, live progress +
    per-file log), Results (sortable/filterable table of records), Dashboard
    (stat tiles from `dashboard_stats.py` logic that Phase 1 fields support),
    Settings (the `IngotConfig` fields), Logs, About. Dark/light via
    `prefers-color-scheme`.
11. **Validation** (see below). Then stop - Phase 1 is a hard gate.

## Phase 2 - file-type / imphash / disposition - COMPLETE (2026-09-10)

- `file_type.rs` - PE/ELF/shellcode magic + capa-eligibility +
  `PossibleFalseNegative`, byte-for-byte port of `file_type.py`. Tested,
  **not yet wired into the scan** - the other variants only compute
  capa-eligibility behind a YARA-hit gate, so it plugs in with YARA (P3).
- `imphash.rs` - reproduces pefile's `get_imphash()` exactly, via `goblin`
  for PE parsing plus a generated copy of `ordlookup`'s ordinal tables
  (`imphash_ordinals.rs`, from oleaut32/ws2_32/wsock32). Verified
  **byte-identical to pefile across 35 real PEs** (20 by-name, 15
  by-ordinal). Wired into the scan behind the NSRL-known-good gate.
- `disposition.rs` - `.bsifter-disposition-history.txt` read/write
  (`sha1|disposition`, case-insensitive key), port of `disposition.py`.
  Prior dispositions are loaded once per scan and applied to every file.
- `PUT /api/disposition` `{sha1, disposition}` - persists to history and
  updates matching in-memory scan rows; Results grid gained an Imphash
  column and a per-row disposition `<select>`; Dashboard gained
  "Have imphash" / "Escalated" tiles.

Validated: `cargo test --workspace` (33), clippy `-D warnings`, fmt all
clean; a real scan showed imphashes matching pefile, NSRL-known PEs
correctly skipping imphash, the disposition endpoint persisting and a
rescan picking the value back up, and the CSV `Imphash`/`Disposition`
columns populated. Release build still one binary with assets embedded.

A dev-only pefile venv was used for validation (scratch dir, since
removed); `crates/ingot-core/examples/imphash.rs` prints Ingot's imphash
for given paths for future diffing.

## Phase 3 - YARA + severity + MITRE ATT&CK - COMPLETE (2026-09-10)

- `yara_scan.rs` - YARA matching on `yara-x` (pure-Rust, `relaxed_re_syntax`
  on so classic rule sets compile; `include` resolves relative to the
  rules file). Severity bucketing (`score` band -> `tc_detection_factor`
  x20 -> severity word -> `Unknown`) and the worst-case-wins selection are
  faithful ports of `yara_scan.py`. Metadata is collapsed first-insertion,
  last-value-wins, matching how yara-python builds a dict.
- `attack.rs` - MITRE ATT&CK enrichment, port of `attack_db.py`. Loads the
  STIX `enterprise-attack.json` bundle (the fixed `Attack/` location), the
  two-pass technique / entity / `uses` index, and `resolve()` including both
  documented parity quirks (per-URL 10-cap check, `trim('/.)')`).
- `file_type.rs` is now wired: for a file with >=1 YARA hit, `engine.rs`
  computes `CapaEligible` + `PossibleFalseNegative` (capa/FLOSS themselves
  are Phase 5). Per-thread `yara_x::Scanner` reuse via `rayon::map_init`.
- YARA compile failure disables YARA for the scan (logged at ERROR) rather
  than aborting - a deviation from `engine.py` (which raises); the Logs tab
  surfaces it.
- Results grid gained YARA / Severity / ATT&CK columns; Dashboard gained
  YARA-hits + per-severity + capa-eligible + ATT&CK-mapped tiles.

Validated: `cargo test --workspace` (45), clippy `-D warnings`, fmt clean.
Cross-checked against **Winnow's own `binsifter.core.yara_scan`** (imported
directly, real yara-python + real `enterprise-attack.json`) on a mixed
fixture set - hit counts, severity, score, rule names, and the full
73-technique ATT&CK resolution all identical. capa-eligibility gate,
filtered `yara_matches_*.csv`, and all YARA CSV columns verified.

Cost note: the release binary grew ~3.9 MB -> ~27 MB (yara-x pulls
wasmtime + cranelift for its rule VM). Acceptable for a self-contained
"bundles a YARA engine" binary; revisit if a JIT-off feature appears.

## Phase 4 - SSDEEP + imphash clustering + draft rules - COMPLETE (2026-09-10)

- `ssdeep.rs` - fuzzy hashing via the `fuzzyhash` crate (pure-Rust
  spamsum, hash output **byte-identical to ppdeep**). The **comparison** is
  a hand port of `ppdeep.compare` - `fuzzyhash`'s own `compare` scores
  lower, and the thresholds (40 / 85) are calibrated to ppdeep, which is
  also what Winnow uses (ppdeep's standard-Levenshtein sub-cost-1, not
  libfuzzy's 2). Verified **0/1769 pairs differ** from `ppdeep.compare`.
- `cluster_by_ssdeep` - transitive union-find, port of
  `ssdeep_cluster.cluster_by_ssdeep`. `cluster_by_imphash` added to
  `imphash.rs`, port of `imphash.cluster_by_imphash`.
- `yara_rule_gen.rs` - port of `yara_rule_gen.py`, including the `(3 of
  them)` quirk and the skeleton fallback. FLOSS strings aren't ported yet
  so every rule currently takes the filesize-skeleton path (same as
  Winnow today).
- `engine.rs` post-scan pass: build path-ordered `imphashes` /
  `ssdeep_hashes` maps, cluster, write the cluster fields back, then draft
  a rule per size>=2 SSDEEP cluster. Cluster ids are numbered in ascending
  path order so a rescan is reproducible (Winnow numbers them in
  completion order, which isn't) - a deliberate small improvement.
- **Cluster history (`SsdeepPreviouslySeen`) is not implemented** - Winnow
  doesn't implement it either (still PowerShell-only); left `false`,
  matching Winnow, to be added to both together later.
- Results grid gained a Cluster column; Dashboard gained
  SSDEEP-clusters / >=85%-similarity / imphash-clustered tiles.

Validated: `cargo test --workspace` (56), clippy `-D warnings`, fmt clean.
End-to-end scan cross-checked against **Winnow's own
`binsifter.core.ssdeep_cluster` + `imphash`** (real ppdeep) - ssdeep
hashes identical, SSDEEP + imphash cluster **membership identical**,
`SsdeepMatches` / high-similarity / sizes identical, CSV cluster columns
and draft-rule output verified. Release binary unchanged at ~27 MB.

`fuzzyhash` release throughput measured at ~26 MB/s - roughly 22x faster
than ppdeep's documented ~1.16 MB/s, so Ingot's fuzzy hashing is much
faster than Winnow's (debug builds are ~3 MB/s, which is why the engine
tests use small fixtures, not the 65 MB debug binary).

## Phase 5 - capa + FLOSS + IOC extraction - COMPLETE (2026-09-10)

- `tool_bootstrap.rs` - resolves `capa` / `floss` from `<data_root>/tools/`
  then `PATH`; `install_capa()` / `install_floss()` fetch Mandiant's
  standalone release zip for the host (GitHub API, exact `-<platform>.zip`
  suffix match so `-linux.zip` never grabs `-linux-arm64`/`-linux-py312`),
  extract it flat, `chmod +x` on unix. Plain per-user download, never
  `sudo`. `ureq` (rustls) + `zip`.
- `capa.rs` - shells out to the standalone `capa -j` (it bundles its own
  rules + FLIRT sigs, so unlike Winnow's pip `flare-capa` no rules dir is
  required; `capa_rules` in Settings passes `-r` to override). stdout goes
  to a temp file so a full pipe can't deadlock the timeout wait; `-f sc32`
  then `-f sc64` for shellcode. Output parsing mirrors
  `capa_scan.py::_summarize`. Timeout 300s (`INGOT_CAPA_TIMEOUT_SECONDS`).
- `floss.rs` - shells out to standalone `floss --json --quiet --only
  static stack tight decoded`, port of `floss_scan.py`. Empty result on
  any failure, never errors. Feeds `static_strings` into draft-rule
  generation.
- `iocs.rs` - pure-Rust port of `iocs.py`, all four regexes 1:1 including
  the case-sensitivity quirks. **Byte-identical to `binsifter.core.iocs`**
  across a 200-line sweep.
- `engine.rs` - the YARA-hit gate now runs capa (if the binary resolves +
  capa-eligible) or FLOSS + IOC extraction (if `PossibleFalseNegative`),
  matching `engine.py`'s `if CapaRules and CapaEligible / elif
  PossibleFalseNegative`. capa failure/timeout is noted on `record.error`
  but the file still completes (engine.py does the same).
- `config.rs` gains derived `capa_exe` / `floss_exe` (+ `refresh_tool_paths`).
  Server: `GET /api/tools`, `POST /api/tools/install/{tool}` (background
  download). Settings page shows status + a Download button; Results grid
  gains capa / IOCs columns; Dashboard gains capa-hits / capa-detections /
  files-with-IOCs tiles.

Validated: `cargo test --workspace` (70), clippy `-D warnings`, fmt clean.
Real scan: capa reported **16 detections, output text identical** to a
direct `capa -j` run on the same PE; FLOSS invoked for a
`PossibleFalseNegative` file and degraded gracefully; IOC extraction
byte-identical to Winnow's; the install endpoint downloaded capa (34 MB)
and refreshed config in ~3 s; CSV still 37 columns with `CAPAOutput`
correctly absent. Release binary ~27 -> ~29 MB (ureq/rustls/zip).

Known edge: a `capa` on `PATH` from `pip install flare-capa` resolves but
lacks bundled rules/sigs and fails per-file with a graceful error - the
Download button installs the standalone, which then wins (tools dir first).

## Phase 6 - Authenticode + archive expansion - COMPLETE (2026-09-10)

- `authenticode.rs` - embedded PE signature verification via the pure-Rust
  `pe-sign` crate (CMS/PKCS#7 + Authenticode PE digest), port of
  `authenticode.py`'s `SignatureStatus` / `SignerName`. Trust anchors are
  the host's native root store (`rustls-native-certs`), falling back to
  `pe-sign`'s bundled Mozilla set. Runs unconditionally per file (not
  NSRL-gated). Digest check first -> `HashMismatch`; then chain/time/CMS ->
  `Valid` / `NotTrusted`; `NotSigned` for a PE with no cert table;
  `NotSupportedFileFormat` for a non-MZ file. `catch_unwind` around
  `pe-sign` (it's a 0.1.x crate).
- `archive.rs` - zip (incl. WinZip AES) / tar (+ `.tar.gz|tgz|tar.xz|txz|
  tar.bz2|tbz2` via `flate2`/`lzma-rs`/`bzip2-rs`) / gzip / 7z
  (`sevenz-rust2`), all pure-Rust. Port of `archive.py`: extension-based
  `classify`, `needs_password`, recursive expansion (`MAX_NESTED_DEPTH=3`),
  the two-pass `expand_archives` / `resolve_locked_archives` flow. Extracted
  files become ordinary Results rows tagged with `SourceArchive`.
- `engine.rs` - archives expand in a serial pre-scan pass before the pool;
  `scan_directory_with(config, archive_passwords, on_progress)` threads a
  password map through, wrapped by the unchanged `scan_directory`.
- Server: `POST /api/scan` accepts `{ archivePasswords: {path: pw} }`;
  unmatched locked archives are copied to `<report>/password_protected/`.
- UI: Results grid gains Signature + Source columns; Dashboard gains
  valid-signature / signature-problem / from-an-archive tiles. The
  `catalog_directory` Setting is relabelled "not yet used".

**Known gaps (documented in `authenticode.rs`):**
* No catalog (`.cat`) verification - a catalog-signed Windows binary
  (`notepad.exe`) reads as `NotSigned`. (Winnow's catalog path is itself
  only synthetic-tested.)
* Intermediates come only from the signature's own cert list (or one AIA
  fetch), not the OS "CA" store - so many Windows *component* binaries read
  `NotTrusted` where the OS says `Valid`. Third-party software that bundles
  its full chain verifies correctly (checked: pwsh.exe, VS Code -> `Valid`).
* `pe-sign` verifies RSA signer keys only; ECDSA-signed -> `UnknownError`
  (checked: python.exe, node.exe).

Validated: `cargo test --workspace` (78), clippy `-D warnings`, fmt clean.
Authenticode cross-checked against `Get-AuthenticodeSignature`: tampered PE
-> `HashMismatch` (match), unsigned -> `NotSigned` (match), pwsh/VS Code ->
`Valid` (match); the gaps above account for the rest. Archive expansion
end-to-end: zip/tar.gz/gzip extracted with correct `SourceArchive`, AES zip
saved for cracking with no password then extracted with the right one,
nested archives recursed, CSV `SourceArchive` column populated.

Release binary ~29 -> ~32 MB (pe-sign pulls cms/x509/rsa + a http-only
reqwest for AIA).

## Phase 7 - quick-launch tool menu + Ghidra + AI export - COMPLETE (2026-09-10)

- `tools.rs` - the OS-scoped quick-launch tool set (port of
  `gui/pages/results.py::_QUICK_LAUNCH_TOOLS` + its launch helpers).
  `tools_for_os()` returns the Windows set (PE Studio / DIE / CFF Explorer /
  Resource Hacker / x64dbg / x32dbg / Sigcheck), the Linux set (PE-bear /
  Anya / DIE / Cutter / angr / GDB / unblob), or the macOS set (DIE / Cutter /
  radare2) at runtime from `std::env::consts::OS` - **no install-time OS
  question is needed** (the plan's original P7 sketch assumed a desktop
  installer; the service knows its own OS). `find_tool` resolves each by a
  case-insensitive recursive walk of the configured tools directory, then
  `PATH` (with a `.exe` fallback on Windows). `launch_tool` spawns GUI tools
  detached with null stdio; terminal tools (`needs_terminal`) are wrapped per
  OS (`cmd /k` / `osascript` Terminal / `x-terminal-emulator … ; read _`);
  `needs_confirm` tools (debuggers) get a frontend confirm. Linux AppImages
  are detected by magic and run with `--appimage-extract-and-run`.
- `resolve_ghidra_headless` / `launch_ghidra` - port of `_launch_ghidra`:
  finds `analyzeHeadless[.bat]` under the configured Ghidra directory and
  spawns `<headless> <report>/ghidra_projects BinSifter_<sha1> -import
  <target> -overwrite -analysisTimeoutPerFile 300` detached.
- `ai_export.rs` - port of `binsifter.core.ai_export`. `build_markdown`
  output is **near-byte-identical to Winnow's** (cross-checked: same section
  order/titles, `ssdeep / imphash clustering` header, same disclaimer; the
  only diff is the "BinSifter Ingot" byline vs "BinSifter"). `build_json`
  and the on-disk `_meta`/`findings` keys are camelCase to match the rest of
  Ingot's JSON API rather than Winnow's PascalCase dataclass keys.
  `export_file` writes `BinSifter_<sha1>.{md,json}` (Winnow's naming) into
  `<report>/ai_exports/`. Entropy is rounded to 3 dp for display
  (consistent with the CSV and Results grid; Winnow prints full precision).
- Server: `GET /api/launch-tools` (resolved tool set + Ghidra status),
  `POST /api/launch` `{toolId, filePath}`, `POST /api/ghidra` `{filePath}`,
  `POST /api/ai-export` `{filePath}` (returns markdown + written paths).
  Ghidra/AI-export look the file up in the current scan session for its
  SHA-1 / record.
- UI: Results rows carry `data-path`; right-click opens `#ctxmenu` built
  from `/api/launch-tools` (missing tools greyed out), plus Ghidra (when
  found) and "Export for AI analysis…", which opens a `<dialog>` with the
  rendered Markdown and a Copy button. About page "working now" list
  updated; the install-time OS question note is dropped.

**Known gaps (carried forward):** Speakeasy (no standalone binary, deferred
since P0); `SsdeepPreviouslySeen` cluster history (not in Winnow either).

Validated: `cargo test --workspace` (84), clippy `-D warnings`, fmt clean.
Runtime: `GET /api/launch-tools` returns the Windows set; a real scan then
`POST /api/ai-export` produced Markdown byte-matching Winnow's
`binsifter.core.ai_export.build_markdown` on the same record (byline aside)
and wrote both files under `Reports/ai_exports/`; `POST /api/launch`
launched a resolved tool and returned the right 400s for an unknown id and
a not-installed tool; `POST /api/ghidra` returned the expected 400 with no
Ghidra configured. Release binary ~32 -> 30.5 MB (no new heavy deps; the
figure moves with toolchain/deps between measurements).

## Phase 8 - packaging + CI - COMPLETE (2026-09-10)

The phased port is finished; this phase makes it shippable and adds the CI
that was missing for the Rust code.

- `.github/workflows/ingot-ci.yml` - runs on every push to `main` and every
  PR that touches `ingot/`. Jobs: `fmt` (`cargo fmt --check`), `test` (both
  `ubuntu-latest` and `windows-latest`: `cargo clippy --workspace
  --all-targets --locked -- -D warnings` then `cargo test --workspace
  --locked`), and `msrv` (`cargo check` on the exact declared MSRV). Windows
  is in the matrix because `tools.rs` / `archive.rs` / `authenticode.rs`
  carry real `cfg`/`std::env::consts::OS` branches.
- `.github/workflows/ingot-release.yml` - `ingot-v*` tag (or
  `workflow_dispatch`) builds the `ingot` binary on GitHub-hosted runners
  for four targets - `x86_64-unknown-linux-gnu` (ubuntu-latest),
  `x86_64-pc-windows-msvc` (windows-latest), `aarch64-apple-darwin`
  (macos-latest, native), `x86_64-apple-darwin` (macos-latest,
  cross-compiled - Xcode's SDK is universal, and free Intel runners are now
  too scarce to queue on). Each is packaged as
  `ingot-<version>-<target>.{tar.gz,zip}` containing the
  binary + `LICENSE` + `README.md`. A tag push additionally publishes a
  GitHub Release with all four archives and a `SHA256SUMS` file.
  `workflow_dispatch` builds + uploads artifacts only (no Release) - run
  that first. **Deliberately no `.deb`/`.msi`/`.pkg`**: Ingot is one
  self-contained binary with no runtime deps to install (capa/FLOSS
  download per-user, the frontend and YARA engine are in the binary), so an
  installer would be untested surface for no gain. Independent of
  `release-installers.yml` (Rowan/Winnow, `v*` tags, BinSifter's 2.x line).
- **MSRV corrected**: `ingot/Cargo.toml` `rust-version` was a stale `1.80`;
  the real floor is **1.93** (`yara-x` 1.20 + `wasmtime` 45 / `cranelift`
  0.132 require it - `cranelift` needs edition 2024, i.e. Cargo ≥ 1.85, and
  the wasmtime/yara-x crates declare `rust-version = 1.93`). Verified: a
  full `cargo +1.93.0 check` + `cargo +1.93.0 test --workspace` pass. This
  floor tracks upward with those deps by design; the `msrv` CI job pins it
  so the declared value stays honest.

Locally verified: both workflow YAMLs parse; `cargo build --release
--locked --target x86_64-pc-windows-msvc -p ingot-server` succeeds and the
packaging shell script produces the expected archive layout; MSRV 1.93.0
builds and tests clean; `cargo test --workspace` (84), clippy `-D
warnings`, `cargo fmt --check` all green.

**GitHub-verified 2026-09-10** - two `workflow_dispatch` runs of
`ingot-release.yml`: all four targets build green and upload their archive
artifacts (11-13 MB each), the `release` job correctly skips on a non-tag
run. The wasmtime/ring/pe-sign/yara-x stack compiles on ubuntu-latest,
windows-latest, and macos-latest (Apple silicon). `x86_64-apple-darwin`
was moved off the scarce `macos-13` Intel runner to a cross-compile on
`macos-latest` after the first run's Intel job sat unscheduled for 30+ min;
the cross-build (including `ring`'s x86_64 asm on an arm64 host) passes.

## Post-test-scan fixes - 2026-09-10

First real end-to-end run by the project owner (652 files, real NSRL / YARA
sets) surfaced five gaps, all fixed together:

1. **Branding** - the frontend had none. Added `BinSifter-Logo-Horizontal[-Dark].png`
   + `BinSifter-WindowIcon.ico` to `frontend/`, a `<picture>` (light/dark via
   `prefers-color-scheme`) in the sidebar and on the About page, and a favicon.
   Release binary ~30.5 -> ~31.3 MB (the two logo PNGs).
2. **No activity feedback during the long pre-scan stages** - `scan_directory_with`
   gained an `on_phase(&str)` callback; the engine reports each stage
   (Enumerating / Building NSRL index / Compiling YARA rules / Scanning /
   Clustering / Writing reports). The server broadcasts these as a
   `{kind:"phase"}` SSE event and stores the current phase on the session
   snapshot; the Scan page shows the phase, a live elapsed-time clock, and an
   indeterminate progress sweep until per-file counts start. A 3s status poll
   backstops the SSE (each scan opens a fresh channel, so an early event can
   be missed on connect).
3. **Dashboard tiles weren't clickable** - every tile is now a button backed
   by a `DASHBOARD_FACETS` predicate; clicking one jumps to Results filtered
   to those files with a clearable chip. Zero-count tiles are disabled.
4. **Right-click menu resolved nothing** - three bugs in `tools.rs`:
   (a) `resolve_tools`/the frontend only fetched once at boot, so setting the
   tools dir *after* page load left every entry "not installed" until a
   reload - now re-fetched on settings save and lazily on first right-click;
   (b) `find_tool` matched any file by stem, so `x64dbg`/`x32dbg` resolved to
   `x64dbg.lib` and Ghidra to the extensionless Unix `analyzeHeadless` -
   added `looks_launchable()` (Windows: `.exe/.bat/.cmd/.com` only) and made
   name lists priority-ordered instead of merge-then-path-sort;
   (c) the directory walk ran once per tool on the async runtime thread -
   now one shared walk, off-thread via `spawn_blocking`.
   Verified against the owner's `F:\Tools`: all 7 tools + Ghidra now resolve
   to the right executable.
5. **No AV detection / exclusion** - new `av_detect.rs` (port of
   `binsifter.core.av_detect` + the removed-from-Winnow `defender.py`):
   `detect_av_products()` (Windows `root/SecurityCenter2` WMI via powershell;
   Linux systemd-unit / `/proc` / install-path signals), `guidance_for()`
   (Linux-first then generic vendor table), and `add_defender_exclusion()`
   (Windows only - spawns an elevated `Add-MpPreference` via
   `Start-Process -Verb RunAs`, so UAC does the elevation and Ingot never
   runs as admin). Endpoints `GET /api/av`, `POST /api/av/exclude`; Settings
   grew an "Antivirus" section. Detection verified (finds Windows Defender);
   `add_defender_exclusion` is **runtime-unverified** - it triggers a real
   UAC prompt and a real Defender config change, so it needs the owner's own
   test, same caveat `defender.py` always carried.

6. **Scan stall on a wedged file** - during the same testing, a `System32`
   scan hung at 651/652: one file wedged an in-process stage (hashing /
   Authenticode / imphash / SSDEEP have no timeout of their own), and rayon's
   `.collect()` never returned. Fixed: the per-file pipeline is split into
   `scan_core` (the in-process read/parse stages) and the rest. `scan_core`
   now runs via `with_deadline()` - a throwaway thread with an
   `mpsc::recv_timeout` - under a per-file deadline (`per_file_timeout()`,
   default 180 s, `INGOT_FILE_TIMEOUT_SECONDS`). A file that blows the
   deadline is recorded `status = "Error"` / `error = "timed out after Ns"`
   and the scan moves on (the stuck thread is abandoned - unkillable in Rust,
   but idle and rare). YARA gets `Scanner::set_timeout(deadline)` (yara-x
   native); capa/FLOSS keep their own subprocess timeouts and run outside the
   deadline (their legitimate runtime is minutes). Cost: YARA/capa moved off
   `scan_core` onto the rayon worker, so the per-thread `Scanner` reuse is
   kept.

Validated: `cargo test --workspace` (91 - `with_deadline_abandons_a_hung_worker`,
`per_file_timeout_env_is_clamped` added), clippy `-D warnings`, fmt clean;
`node --check frontend/app.js`; a live scan showed the phase/elapsed UI and
the phase SSE events (`Scanning files` -> `Clustering...` -> `Writing
reports` -> complete); `GET /api/av` returns Windows Defender in camelCase;
a 10 GB file scanned with `INGOT_FILE_TIMEOUT_SECONDS=25` timed out at 25 s
as an errored record and the scan **completed** instead of hanging; the
652-file `System32` scan that previously stalled now finishes.

## Quick-launch menu fixes + Ghidra GUI preload - 2026-09-10

Manual testing after the fixes above surfaced three more `tools.rs` issues,
plus a feature port from Winnow, extended to Rowan too:

- **DIE and Sigcheck "didn't open"** - `["diec", "die"]` resolved DIE's
  *console* build first (runs, prints to a discarded stdout, exits); reordered
  to `["die", "diec"]` on every OS so "Open in DIE" gets the GUI. Sigcheck
  is a Sysinternals tool - without `-accepteula` it blocks on a first-run EULA
  dialog from a service context, invisibly; added `-accepteula -nobanner`.
  Also reworked the Windows terminal-tool launch: the old `cmd /c start ""
  cmd /k "<joined>"` nested-quoting couldn't round-trip through Rust's
  `Command` arg escaping (cmd.exe's quote rules aren't the ones `Command`
  targets) - now writes a temp `.bat` (self-deleting after `pause`) and
  `start`s that instead.
- **Tools opened behind the browser** - Ingot is a headless service, so
  Windows' foreground-activation lock stops a spawned GUI tool from taking
  focus. Added `win_foreground.rs` (`#[cfg(windows)]`, new `windows-sys`
  dependency): after spawning a GUI tool, a short-lived watcher polls
  (`EnumWindows`) for its top-level window and lifts it with a
  `HWND_TOPMOST` -> `HWND_NOTOPMOST` Z-order toggle. **Deliberately not**
  `AttachThreadInput` + forced `SetForegroundWindow` - that first
  implementation attached to the window's input queue mid-startup and
  crashed DIE (a Qt app) ~4 s after launch, caught by watching the spawned
  process rather than trusting a green HTTP response. The Z-order-only
  version is gentler: the window surfaces on top, the user clicks it to
  focus, nothing has its input queue touched.
- **Ghidra GUI preload** - ported Winnow's `_watch_ghidra_completion`
  behavior (open `ghidraRun <project>.gpr` once headless analysis finishes,
  so the analyzed program is loaded for review) to both Ingot and Rowan.
  Ingot's `launch_ghidra` and Rowan's Ghidra quick-launch both now chain
  `analyzeHeadless ... && ghidraRun <gpr>` as one detached unit (a temp
  `.bat` on Windows, `sh -c` on Unix for Ingot) rather than a watched
  process + a second launch - simpler for a stateless server, and the chain
  survives a restart. `ghidraRun <gpr>` opening the project is Ghidra's own
  documented behavior; not independently GUI-verified end-to-end here (same
  caveat Winnow's own port carries) - `-import`/`-overwrite` and the chain
  wiring are verified (a live Ghidra headless run against a real 43 KB
  sample produced the expected `.gpr`/`.lock`, killed before it reached the
  GUI-boot step to avoid leaving Ghidra running unattended).

Validated: `cargo test --workspace` (93 - `die_prefers_the_gui_over_the_
console_build`, `sigcheck_accepts_the_eula_non_interactively` added),
clippy `-D warnings`, fmt clean, `Cargo.lock` diff minimal (`windows-sys`
0.59 already in the tree transitively). Live on Windows: DIE now resolves
to `die.exe` and stays running (previously died ~4 s after launch under the
`AttachThreadInput` version); Sigcheck opens a titled console window
running `-accepteula -nobanner` and pauses for the analyst to read it;
pestudio/CFF Explorer/Resource Hacker still launch clean under the new
foreground code; the Ghidra chain script was inspected and the headless
half runs and produces real output. Rowan's Ghidra block re-parses clean
(`Parser.ParseFile`); not yet run against a real Ghidra install.

## Two more real bugs from that same manual pass - 2026-09-10

1. **CFF Explorer never had the Rowan/Winnow clipboard-copy special case.**
   CFF Explorer's own command line is reserved for its Lua scripting engine,
   so a target-path argument is silently ignored - the app opens but never
   loads the flagged file. Ingot's `tools.rs` never ported the
   `copy_path_instead` behavior Rowan/Winnow have. Added: `ToolDef` gained
   `copy_path_instead`, `cff`'s definition sets it (relabelled "Open in CFF
   Explorer (copies path to clipboard)"), `launch_tool` skips the target
   argv when it's set and copies the path to the clipboard after launch via
   new `win_clipboard.rs` (`#[cfg(windows)]`, raw `OpenClipboard` /
   `GlobalAlloc` / `SetClipboardData` - Ingot and the browser are always the
   same machine, so setting the OS clipboard from the server is exactly
   "the analyst's clipboard").
2. **Ghidra GUI never opened, confirmed with a real headless run watched to
   completion (not just inspected).** Root cause: the chain bat invoked
   `analyzeHeadless.bat` (and `ghidraRun.bat`) **without `call`** - in batch
   scripting, running a nested `.bat`/`.cmd` without `call` transfers
   control into it permanently, so when `analyzeHeadless.bat` finished, the
   whole script terminated right there and never reached the `ghidraRun`
   line. Confirmed directly: the real `.gpr`/`.rep` output existed (analysis
   genuinely completed) but the chain's temp `.bat` never self-deleted (it
   never reached `:done`). Fixed by prefixing both nested invocations with
   `call`, in both Ingot's `launch_ghidra` and Rowan's Ghidra quick-launch
   block (same bug, same fix, both never `call`ed either).

Validated: `cargo test --workspace` (93, unchanged - these were runtime
logic bugs, not something a unit test would catch without spinning up a
real Ghidra install), clippy `-D warnings`, fmt clean. **Live end-to-end,
watched to completion, not just inspected:** triggered `/api/ghidra`
against a real file, watched `analyzeHeadless` run and exit, confirmed the
chain `.bat` self-deleted (reached `:done`), and confirmed a `javaw.exe`
process came up with window title **"Ghidra: BinSifter_<name>"** - the
project loaded, exactly the ported behavior. Rowan's fix re-parses clean;
not independently run against Rowan itself (no live Rowan session in this
pass) - same fix, same root cause, high confidence but flagging the gap
honestly.

**Known minor gap, not fixed here:** the Ghidra GUI process itself isn't
foreground-raised the way quick-launch tools are (`win_foreground.rs`) -
identifying the right `javaw` PID out of the detached chain is more work
than the other tools' direct-spawn case, and wasn't asked for. It may still
open behind the browser.

## Ghidra GUI still didn't open - two more real bugs, found by re-testing against the actual reported file - 2026-09-10/11

The `call` fix above was verified only against `where.exe` (no special
characters) - it genuinely fixed what it targeted, but the owner's re-test
against the real file that started this (a filename containing `"(2)"`)
still failed. Re-diagnosed the same way as before - watch a real run to
completion, not just inspect the script - and found two further, *separate*
failure modes, both triggered by the parens, neither fixable by anything on
Ingot's/Rowan's own command-line-construction side alone:

1. **cmd.exe's batch parser treats `(`/`)` as command-grouping syntax even
   inside a double-quoted argument on the same line.** A direct repro
   (`analyzeHeadless.bat ... -import "...(2).exe" ...` with the path
   inlined) exited 255, `"X.exe was unexpected at this time"`. Standard fix:
   `set "VAR=value"` each path on its own line (cmd does not re-tokenize
   inside a `set` assignment), then reference `%VAR%` in the actual
   command - **but this alone was not enough**, see #2.
2. **Ghidra's own bundled `analyzeHeadless.bat` (not Ingot's/Rowan's script)
   independently re-breaks on the same parens**, in two of its own code
   paths, each confirmed separately by watching a real run to completion:
   - Its `-import` handling does `for %%f in ("%~2") do (...)` for wildcard
     expansion - cmd's `for ... in (set)` clause has the identical
     "parens break parsing" problem even for a value that arrived safely via
     `set`. Confirmed directly: a byte-identical copy of the real file under
     a paren-free name analyzed clean in 15s (`analyzeHeadless`'s own log:
     "Analysis succeeded", "Import succeeded"); the original path produced
     silently zero output.
   - Independently, the **project name** argument (the `BinSifter_<stem>`
     fallback used when no SHA1 record exists yet) also broke Ghidra's own
     Java argument parser - `Exception in thread "main"
     ghidra.util.exception.InvalidInputException: Bad argument: <path>` -
     even with an already-safe import path. Isolated by testing a safe
     target with a still-parens-containing project name alone.

   Since both live inside Ghidra's bundled script/parser, not Ingot's or
   Rowan's own code, there's nothing to `set`-var around - the fix is to
   never hand Ghidra a risky value at all:
   - **Target path**: stage a byte-identical copy under a generated,
     special-character-free name (`tempfile`-style random suffix, original
     extension kept) before importing, and delete it right after
     `analyzeHeadless` reads it (Ghidra copies the bytes into its own
     project storage, so the staged copy isn't needed past that point).
     New `stage_safe_import_copy()` in `tools.rs`; Rowan stages the same way
     with `Copy-Item` + a GUID-based name.
   - **Project name**: sanitize the filename-stem fallback (new
     `sanitize_for_ghidra()` - replace anything but `[A-Za-z0-9_-]` with
     `_`) before using it as Ghidra's project name. The SHA1 branch was
     already safe (plain hex) and is untouched.
   - The `errorlevel` check also had to move: `del`-ing the staged copy
     right after the analyze call would otherwise clobber `%errorlevel%`
     before the `if errorlevel 1 goto done` line ever read it - now captured
     into `%INGOT_RC%`/`%RW_RC%` immediately after the `call`, before any
     other command runs.

Validated: `cargo test --workspace` (94 - added
`sanitize_for_ghidra_strips_spaces_and_parens`), clippy `-D warnings`, fmt
clean; Rowan re-parses clean. **Live, watched to actual completion, against
the exact real file that started this** (not `where.exe`): triggered
`/api/ghidra` on `General_Player_V1.7.0.0.T.20150929 (2).exe`, watched the
chain run and self-delete at t+30s, and confirmed a `javaw.exe` window
titled **"Ghidra: BinSifter_General_Player_V1_7_0_0_T_20150929__2_"** -
the analyzed project loaded. This is the same file, same failure, the owner
hit twice in manual testing before this fix.

## Ghidra GUI foreground raise - 2026-09-11

Closed the "known minor gap" flagged above: after the parens/staging fixes,
Ghidra's GUI genuinely opened with the analyzed project loaded, but the
owner's next report was "opened this test scan but opened in the
background" - same foreground-activation-lock problem `win_foreground.rs`
already solves for directly-spawned quick-launch tools, just not extended
to Ghidra.

The blocker: Ghidra's GUI process (`javaw.exe`) comes up at the end of a
fully detached shell chain (`analyzeHeadless` -> `ghidraRun`) minutes after
Ingot's own `launch_ghidra` call returns, so there's no PID on the Rust side
to hand to the existing PID-based `raise_when_ready`. Fixed by generalizing
`win_foreground.rs`:

- New `Match` enum (`Pid(u32)` / `TitleContains(String)`) behind a shared
  `find_window`/`watch_and_lift` core - `raise_when_ready(pid)` is now a
  thin wrapper over the `Pid` path, unchanged in behavior.
- New `raise_when_titled(title_substring, timeout)` polls every 2s (this
  runs for minutes, not seconds) for a visible top-level window whose title
  contains the substring, and lifts it the same Z-order-toggle way.
- `launch_ghidra`'s Windows branch calls
  `raise_when_titled(format!("Ghidra: {project_name}"), Duration::from_secs(480))`
  right after the chain spawns - 480s comfortably covers the
  `-analysisTimeoutPerFile 300` ceiling plus JVM/analysis startup slack. The
  title format was empirically confirmed against a real run in the prior
  fix round.
- Not ported to Rowan: Rowan's Ghidra quick-launch runs from a foreground
  WinForms app the analyst just clicked into, not a headless service, so it
  isn't subject to the same foreground-activation lock - not requested,
  not added speculatively.

Validated: `cargo test --workspace` (94, unchanged - no new unit-testable
logic, this is a live-window-manager behavior), clippy `-D warnings`, fmt
clean, release build. **Live, watched to actual completion, against the
exact real file**: triggered `/api/ghidra` on
`General_Player_V1.7.0.0.T.20150929 (2).exe` with no scan session active
(project-name fallback path, the harder of the two), watched the chain run
to completion, and confirmed via `GetForegroundWindow()` that Ghidra's
CodeBrowser window came up as the actual foreground window. Separately
confirmed by the project owner's own manual test run at the same time
(coincidental overlap - the owner was independently exercising the rest of
the right-click menu against the same instance): "Ghidra came up in front
this time too."

## Verification (Phase 1)

1. `cargo test --workspace` - all green.
2. `cargo clippy --workspace -- -D warnings`, `cargo fmt --check`.
3. `cargo run -p ingot-server` -> `curl 127.0.0.1:8477/api/health` returns the version.
4. Point a scan at `smoketest/` and at a small real sample dir:
   - hashes + entropy for a known file match Python
     (`python -c "import hashlib,pathlib; ..."`) exactly.
   - with an NSRL text set configured: cache builds, second scan loads from
     cache (sub-second), a known NSRL SHA-1 reports `IsKnownGood=True`.
   - with a blocklist configured: a planted known-bad hash reports `KnownBad`.
   - the 4 CSVs diff clean against Winnow's output on the same inputs
     (allowing for path + timestamp differences only).
5. Browser: open `http://127.0.0.1:8477`, run a scan, watch live progress,
   filter the Results table, view Dashboard tiles, edit + persist Settings.
6. Cross-platform smoke: `cargo build` on Windows now; Linux/macOS + Windows
   clippy/test via `ingot-ci.yml`, per-target release builds via
   `ingot-release.yml` (P8).

## Non-goals for now

- No auth, no non-loopback binding, ever (local analyst tool).
- No live-updating dashboard math beyond what Winnow does (recompute once
  after the scan) until there's a reason.
- Speakeasy until a workable cross-platform story exists.
