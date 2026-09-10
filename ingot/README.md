# BinSifter Ingot

The Rust variant of BinSifter: a local backend service plus a browser UI,
built to run on any Linux, macOS, or Windows machine without a desktop GUI
toolkit. Bound to `127.0.0.1` only, no authentication - a single-analyst
local tool.

See [`../docs/ingot.md`](../docs/ingot.md) for the project rationale and
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for the phased build plan
and current status.

## Status

**Phases 1-6 complete.** Working today: recursive file enumeration, archive
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
grid), the 37-column CSV reports (all four filtered views), a live-progress
browser UI, and the HTTP API behind it. Every stage is cross-checked
against the Python (Winnow) variant's output.

Not yet ported (later phases): catalog (`.cat`) signature verification, and
the OS-scoped quick-launch tool menu.

## Build & run

Needs a Rust toolchain (1.80+; install from <https://rustup.rs>).

```sh
cd ingot
cargo run                 # builds, starts the service, opens the UI in a browser
cargo run -- --no-open    # don't open a browser
cargo run -- --port 9000  # or set INGOT_PORT
cargo test --workspace    # unit + integration tests
```

The UI defaults to <http://127.0.0.1:8477>.

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
