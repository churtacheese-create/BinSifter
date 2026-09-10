//! BinSifter Ingot - scan engine.
//!
//! Ingot is BinSifter's Rust variant: a local backend service + browser UI,
//! the variant meant to run on any Linux / macOS / Windows without a
//! per-OS desktop GUI toolkit. This crate is the engine half - no HTTP, no
//! UI - so it stays usable from a future headless CLI. The detection design
//! is shared with the PowerShell (Rowan) and Python (Winnow) variants; the
//! parity notes live in each module.
//!
//! Ported so far: [`hashing`], [`nsrl`], [`blocklist`], [`report`],
//! [`imphash`] (+ clustering), [`ssdeep`] (fuzzy hash + clustering),
//! [`file_type`], [`disposition`], [`yara_scan`] (with severity bucketing),
//! [`attack`] (MITRE ATT&CK enrichment), [`yara_rule_gen`] (draft rules),
//! [`capa`] + [`floss`] (shell-outs to the standalone binaries resolved /
//! downloaded by [`tool_bootstrap`]), [`iocs`], [`authenticode`] (PE
//! signature verification), [`archive`] (zip/tar/gzip/7z expansion), and
//! the [`engine::scan_directory`] orchestration. The OS-scoped quick-launch
//! tool menu lands in a later phase.

pub mod archive;
pub mod attack;
pub mod authenticode;
pub mod blocklist;
pub mod capa;
pub mod config;
pub mod disposition;
pub mod engine;
pub mod file_type;
pub mod floss;
pub mod hashing;
pub mod imphash;
mod imphash_ordinals;
pub mod iocs;
pub mod model;
pub mod nsrl;
pub mod report;
pub mod ssdeep;
pub mod tool_bootstrap;
pub mod yara_rule_gen;
pub mod yara_scan;

pub use config::{build_default_config, IngotConfig, SettingsFields};
pub use engine::{scan_directory, Progress, ScanResult};
pub use model::FileRecord;
pub use report::{ReportMode, ReportPaths, COLUMNS};

/// Product name + version, surfaced by the server's `/api/health`.
pub const PRODUCT_NAME: &str = "BinSifter Ingot";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
