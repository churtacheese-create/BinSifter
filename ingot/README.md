# BinSifter Ingot

The Rust variant of BinSifter: a local backend service plus a browser UI,
built to run on any Linux, macOS, or Windows machine without a desktop GUI
toolkit. Bound to `127.0.0.1` only, no authentication - a single-analyst
local tool.

See [`../docs/ingot.md`](../docs/ingot.md) for the project rationale and
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for the phased build plan
and current status.

## Status

**Phases 1-8 complete - the phased port is finished.** Working today:
recursive file enumeration, archive
expansion (zip incl. WinZip AES / tar / gzip / 7z, nested, with a
password round-trip), a single-pass MD5/SHA-1/SHA-256 + Shannon entropy
read, Authenticode signature verification, NSRL known-good lookup (cached,
memory-mapped, format-shared with the other variants), the offline
known-bad blocklist, the PE import hash (imphash, byte-identical to
pefile), an SSDEEP fuzzy hash (byte-identical to ppdeep), YARA matching on
`yara-x` with severity scoring and MITRE ATT&CK technique enrichment,
PE/ELF/shellcode classification, capa capability detection on YARA-flagged
binaries with a FLOSS string + IOC-extraction fallback (Mandiant's
standalone binaries, downloaded per-user from the Settings page), post-scan
SSDEEP + imphash clustering and a draft YARA rule per SSDEEP cluster,
triage disposition tracking (persisted by SHA-1, editable in the Results
grid), the 37-column CSV reports (all four filtered views), a right-click
quick-launch menu on the Results grid scoped to the OS Ingot is running on
(PE Studio / x64dbg / DIE / … on Windows; PE-bear / Cutter / angr / … on
Linux; DIE / Cutter / radare2 on macOS), Ghidra headless analysis, a
Markdown/JSON "export for AI analysis", a live-progress browser UI, and the
HTTP API behind it. Every stage is cross-checked against the Python (Winnow)
variant's output.

Known gaps: catalog (`.cat`) signature verification, SSDEEP cluster history,
and Speakeasy emulation (no standalone binary) - none are in the Python
variant either.

## Build & run

Needs a Rust toolchain (1.93+; install from <https://rustup.rs>). The MSRV
floor comes from `yara-x` and its bundled `wasmtime`/`cranelift` and moves
up as those update.

```sh
cd ingot
cargo run                 # builds, starts the service, opens the UI in a browser
cargo run -- --no-open    # don't open a browser
cargo run -- --port 9000  # or set INGOT_PORT
cargo test --workspace    # unit + integration tests
```

The UI defaults to <http://127.0.0.1:8477>.

## Releases

Tagged builds (`ingot-v*`) publish a GitHub Release with a self-contained
`ingot` binary for Linux x86-64, Windows x86-64, and macOS (Apple silicon
and Intel), each as `ingot-<version>-<target>.{tar.gz,zip}` alongside a
`SHA256SUMS` file - see
[`../.github/workflows/ingot-release.yml`](../.github/workflows/ingot-release.yml).
Extract and run `ingot`; nothing else to install. There is no OS installer
(`.deb`/`.msi`/`.pkg`) - it's a single binary with no runtime dependencies.

CI ([`ingot-ci.yml`](../.github/workflows/ingot-ci.yml)) runs `fmt`,
`clippy -D warnings`, and the test suite on Linux and Windows for every push
to `main` and every PR touching `ingot/`.

Runtime data (the `Reports/` directory, the settings cache, and the NSRL
cache) lives under the per-user data directory
(`%LOCALAPPDATA%\BinSifter Ingot` on Windows,
`~/.local/share/binsifter-ingot` on Linux,
`~/Library/Application Support/BinSifter Ingot` on macOS). Set
`INGOT_DATA_ROOT` to override it.

## Layout

| Path | What |
| --- | --- |
| `crates/ingot-core` | scan engine library - no HTTP, no UI |
| `crates/ingot-server` | axum HTTP service, embedded frontend, the `ingot` binary |
| `frontend/` | the browser UI (plain HTML/CSS/JS, embedded at build time) |

capa and FLOSS run as Mandiant's official standalone binaries; Ingot
downloads them per-user into `<data-root>/tools/` from the Settings page
(no admin needed), or picks up a `capa`/`floss` already on `PATH`.

## License

Source-available under the PolyForm Strict License 1.0.0 - see the
repository root `LICENSE`.
