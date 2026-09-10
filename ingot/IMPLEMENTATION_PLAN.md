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

## Prerequisite (blocker)

Rust is **not installed** on this machine. Nothing can be built or tested
until it is. Install via rustup (recommended) - from the repo the user runs:

```
winget install --id Rustlang.Rustup -e --source winget
```

then restart the shell so `~/.cargo/bin` is on PATH. `rustc --version` should
report 1.80+.

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

## Later phases (one stage per block, each gated)

- **P7**: quick-launch context menu in the Results grid, **OS-scoped at
  install time** - installer asks Windows vs Linux vs macOS and the UI loads
  that platform's tool set (Windows: PE-Studio / x64dbg / CFF Explorer /
  Resource Hacker / Sigcheck; Linux: PE-bear / Anya / Cutter / angr / GDB+GEF
  / unblob / malwoverview; macOS: TBD). Ghidra headless + Speakeasy +
  "export for AI analysis" are cross-platform. Tools launched via the OS
  from the local service (it's `127.0.0.1`, single-user).
- **P8**: packaging - single binary per OS (GitHub Actions matrix), optional
  installers, `docs/ingot.md` rewrite, README status bump.

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
6. Cross-platform smoke: `cargo build` on Windows now; Linux/macOS via CI in P8
   (note any `cfg!` OS branches as they're added).

## Non-goals for now

- No auth, no non-loopback binding, ever (local analyst tool).
- No live-updating dashboard math beyond what Winnow does (recompute once
  after the scan) until there's a reason.
- Speakeasy until a workable cross-platform story exists.
