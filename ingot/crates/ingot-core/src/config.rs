//! Settings/config model - port of `binsifter.core.config`.
//!
//! `IngotConfig` mirrors the `BinSifterConfig` dataclass: the seven
//! user-facing Settings fields, plus the derived tool paths (resolved
//! later - Phase 2+), plus the fixed default `Reports`/`Attack`/`Blocklist`
//! locations. Only the seven Settings fields are round-tripped to the JSON
//! settings cache; the rest are recomputed each launch.
//!
//! Unlike the desktop variants, Ingot is a per-user local service, so its
//! data root is the platform's per-user data directory
//! (`%LOCALAPPDATA%\BinSifter Ingot` / `~/.local/share/binsifter-ingot` /
//! `~/Library/Application Support/BinSifter Ingot`) rather than "next to the
//! installed exe".

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use tracing::warn;

const SETTINGS_CACHE_FILENAME: &str = ".bsifter-settings-cache.json";

/// Per-user data root - `Reports/`, `Attack/`, `Blocklist/`, the settings
/// cache and the NSRL cache all live under here. Resolved once.
pub fn data_root() -> PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        if let Ok(explicit) = std::env::var("INGOT_DATA_ROOT") {
            if !explicit.is_empty() {
                return PathBuf::from(explicit);
            }
        }
        let dir = ProjectDirs::from("", "BinSifter", "Ingot")
            .map(|p| p.data_local_dir().to_path_buf())
            .unwrap_or_else(|| std::env::temp_dir().join("binsifter-ingot"));
        if let Err(e) = fs::create_dir_all(&dir) {
            warn!("Could not create data root {}: {e}", dir.display());
        }
        dir
    })
    .clone()
}

/// The seven fields the Settings page owns and that get cached to disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsFields {
    pub src_dir: String,
    pub nsrl_path: String,
    pub yara_rules: String,
    pub capa_rules: String,
    pub tools_dir: String,
    pub ghidra_dir: String,
    pub catalog_directory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngotConfig {
    // Settings-page fields
    pub src_dir: String,
    pub nsrl_path: String,
    pub yara_rules: String,
    pub capa_rules: String,
    pub tools_dir: String,
    pub ghidra_dir: String,
    pub catalog_directory: String,

    // Fixed default locations (not Settings fields)
    pub report_directory: String,
    pub attack_data_path: String,
    pub blocklist_path: String,

    // Derived - resolved from `<data_root>/tools/` or PATH, refreshed after
    // a tools install. Never user-entered. Empty = not available.
    pub capa_exe: String,
    pub floss_exe: String,
}

impl IngotConfig {
    /// Re-resolve the derived capa / FLOSS binary paths (call after a
    /// download, or at startup).
    pub fn refresh_tool_paths(&mut self) {
        self.capa_exe = crate::tool_bootstrap::resolve_capa()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.floss_exe = crate::tool_bootstrap::resolve_floss()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
    }

    pub fn settings_fields(&self) -> SettingsFields {
        SettingsFields {
            src_dir: self.src_dir.clone(),
            nsrl_path: self.nsrl_path.clone(),
            yara_rules: self.yara_rules.clone(),
            capa_rules: self.capa_rules.clone(),
            tools_dir: self.tools_dir.clone(),
            ghidra_dir: self.ghidra_dir.clone(),
            catalog_directory: self.catalog_directory.clone(),
        }
    }

    /// Apply the seven Settings fields from a client update.
    pub fn apply_settings(&mut self, f: SettingsFields) {
        self.src_dir = f.src_dir;
        self.nsrl_path = f.nsrl_path;
        self.yara_rules = f.yara_rules;
        self.capa_rules = f.capa_rules;
        self.tools_dir = f.tools_dir;
        self.ghidra_dir = f.ghidra_dir;
        self.catalog_directory = f.catalog_directory;
    }
}

fn settings_cache_path() -> PathBuf {
    data_root().join(SETTINGS_CACHE_FILENAME)
}

/// Build a config with the default `Reports`/`Attack`/`Blocklist` layout
/// (directories auto-created) and any cached Settings values overlaid.
pub fn build_default_config() -> IngotConfig {
    let root = data_root();
    let reports_dir = root.join("Reports");
    let attack_path = root.join("Attack").join("enterprise-attack.json");
    let blocklist_path = root.join("Blocklist").join("blocklist.csv");

    for dir in [
        &reports_dir,
        attack_path.parent().unwrap(),
        blocklist_path.parent().unwrap(),
    ] {
        if let Err(e) = fs::create_dir_all(dir) {
            warn!("Could not create {}: {e}", dir.display());
        }
    }

    let mut config = IngotConfig {
        src_dir: String::new(),
        nsrl_path: String::new(),
        yara_rules: String::new(),
        capa_rules: String::new(),
        tools_dir: String::new(),
        ghidra_dir: String::new(),
        catalog_directory: String::new(),
        report_directory: reports_dir.to_string_lossy().into_owned(),
        attack_data_path: attack_path.to_string_lossy().into_owned(),
        blocklist_path: blocklist_path.to_string_lossy().into_owned(),
        capa_exe: String::new(),
        floss_exe: String::new(),
    };

    if let Some(cached) = load_settings_cache() {
        config.apply_settings(cached);
    }
    config.refresh_tool_paths();
    config
}

fn load_settings_cache() -> Option<SettingsFields> {
    let path = settings_cache_path();
    if !path.is_file() {
        return None;
    }
    match fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<SettingsFields>(&text) {
            Ok(f) => Some(f),
            Err(e) => {
                warn!("Could not parse settings cache {}: {e}", path.display());
                None
            }
        },
        Err(e) => {
            warn!("Could not read settings cache {}: {e}", path.display());
            None
        }
    }
}

/// Persist the seven Settings fields. Called after a successful Settings save.
pub fn save_settings_cache(config: &IngotConfig) -> std::io::Result<()> {
    let path = settings_cache_path();
    let json = serde_json::to_string_pretty(&config.settings_fields())
        .expect("SettingsFields always serialises");
    fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_roundtrip() {
        let mut c = IngotConfig {
            src_dir: "a".into(),
            nsrl_path: "b".into(),
            yara_rules: "c".into(),
            capa_rules: "d".into(),
            tools_dir: "e".into(),
            ghidra_dir: "f".into(),
            catalog_directory: "g".into(),
            report_directory: "r".into(),
            attack_data_path: "at".into(),
            blocklist_path: "bl".into(),
            capa_exe: String::new(),
            floss_exe: String::new(),
        };
        let f = c.settings_fields();
        let json = serde_json::to_string(&f).unwrap();
        let back: SettingsFields = serde_json::from_str(&json).unwrap();
        c.apply_settings(back);
        assert_eq!(c.src_dir, "a");
        assert_eq!(c.catalog_directory, "g");
        // fixed fields untouched by apply_settings
        assert_eq!(c.report_directory, "r");
    }
}
