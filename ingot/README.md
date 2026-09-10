# BinSifter Ingot

The Rust variant of BinSifter: a local backend service plus a browser UI,
built to run on any Linux, macOS, or Windows machine without a desktop GUI
toolkit. Bound to `127.0.0.1` only, no authentication - a single-analyst
local tool.

See [`../docs/ingot.md`](../docs/ingot.md) for the project rationale and
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for the phased build plan
and current status.

## Status

**Phases 1-4 complete.** Working today: recursive file enumeration, a
single-pass MD5/SHA-1/SHA-256 + Shannon entropy read, NSRL known-good
lookup (cached, memory-mapped, format-shared with the other variants), the
offline known-bad blocklist, the PE import hash (imphash, byte-identical to
pefile), an SSDEEP fuzzy hash (byte-identical to ppdeep), YARA matching on
`yara-x` with severity scoring and MITRE ATT&CK technique enrichment
(cross-checked against Winnow's yara-python output), PE/ELF/shellcode
classification and capa-eligibility for YARA-flagged files, post-scan
SSDEEP + imphash clustering and a draft YARA rule per SSDEEP cluster
(cross-checked against Winnow's own clustering), triage disposition
tracking (persisted by SHA-1, editable in the Results grid), the 37-column
CSV reports (all four filtered views), a live-progress browser UI, and the
HTTP API behind it.

Not yet ported (later phases): capa, FLOSS, Authenticode, archive
expansion, and the OS-scoped quick-launch tool menu.

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

## License

Source-available under the PolyForm Strict License 1.0.0 - see the
repository root `LICENSE`.
