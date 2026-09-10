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
//! [`imphash`], [`file_type`], [`disposition`], and the
//! [`engine::scan_directory`] orchestration. YARA / ssdeep / capa / FLOSS /
//! Authenticode / archives / ATT&CK / clustering land in later phases.
//!
//! [`file_type`] classification is a ready, tested module but is not wired
//! into the scan yet - the other variants only compute capa-eligibility
//! behind a YARA-hit gate, so it plugs in with YARA (Phase 3).

pub mod blocklist;
pub mod config;
pub mod disposition;
pub mod engine;
pub mod file_type;
pub mod hashing;
pub mod imphash;
mod imphash_ordinals;
pub mod model;
pub mod nsrl;
pub mod report;

pub use config::{build_default_config, IngotConfig, SettingsFields};
pub use engine::{scan_directory, Progress, ScanResult};
pub use model::FileRecord;
pub use report::{ReportMode, ReportPaths, COLUMNS};

/// Product name + version, surfaced by the server's `/api/health`.
pub const PRODUCT_NAME: &str = "BinSifter Ingot";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
