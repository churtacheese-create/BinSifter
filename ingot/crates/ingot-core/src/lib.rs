//! BinSifter Ingot - scan engine.
//!
//! Ingot is BinSifter's Rust variant: a local backend service + browser UI,
//! the variant meant to run on any Linux / macOS / Windows without a
//! per-OS desktop GUI toolkit. This crate is the engine half - no HTTP, no
//! UI - so it stays usable from a future headless CLI. The detection design
//! is shared with the PowerShell (Rowan) and Python (Winnow) variants; the
//! parity notes live in each module.
//!
//! Phase 1 scope: [`hashing`], [`nsrl`], [`blocklist`], [`report`], and the
//! [`engine::scan_directory`] orchestration. YARA / imphash / ssdeep / capa
//! / FLOSS / Authenticode / archives / ATT&CK land in later phases.

pub mod blocklist;
pub mod config;
pub mod engine;
pub mod hashing;
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
