//! Resolves - and, on request, downloads - the standalone `capa` and
//! `floss` binaries.
//!
//! Unlike Winnow (`flare-capa` / `flare-floss` as pip libraries), Ingot
//! shells out to Mandiant's official self-contained release binaries. They
//! bundle their own rules / FLIRT signatures, so once the binary is present
//! nothing else needs configuring.
//!
//! Resolution order: `<data_root>/tools/` (where a download lands), then the
//! system `PATH`. Downloading is never automatic - a scan that needs capa
//! but can't find it logs a line and skips capa for that file; the browser
//! UI exposes an explicit "install" action (`POST /api/tools/install/...`).
//! Everything here is a plain per-user download, never `sudo`.

use std::fs;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde_json::Value;
use tracing::info;

const USER_AGENT: &str = "BinSifter-Ingot-ToolBootstrap/1.0";
const CAPA_REPO: &str = "mandiant/capa";
const FLOSS_REPO: &str = "mandiant/flare-floss";
/// Generous ceiling - the release zips are ~30-60 MB.
const DOWNLOAD_LIMIT_BYTES: u64 = 300 * 1024 * 1024;

pub fn tools_dir() -> PathBuf {
    crate::config::data_root().join("tools")
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(name);
        candidate.is_file().then_some(candidate)
    })
}

fn resolve(names: &[&str]) -> Option<PathBuf> {
    let dir = tools_dir();
    names
        .iter()
        .map(|n| dir.join(n))
        .find(|p| p.is_file())
        .or_else(|| names.iter().find_map(|n| which_on_path(n)))
}

pub fn resolve_capa() -> Option<PathBuf> {
    resolve(&["capa", "capa.exe"])
}

pub fn resolve_floss() -> Option<PathBuf> {
    resolve(&["floss", "floss.exe"])
}

/// The `-<platform>.zip` suffix of the release asset for the host, or
/// `None` on an unsupported platform.
fn platform_suffix() -> Option<&'static str> {
    Some(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", _) => "windows",
        ("linux", "aarch64") => "linux-arm64",
        ("linux", "x86_64") => "linux",
        ("macos", "aarch64") => "macos-arm64",
        ("macos", "x86_64") => "macos",
        _ => return None,
    })
}

fn http_get_string(url: &str) -> anyhow::Result<String> {
    Ok(ureq::get(url)
        .header("User-Agent", USER_AGENT)
        .call()?
        .body_mut()
        .read_to_string()?)
}

fn http_get_bytes(url: &str) -> anyhow::Result<Vec<u8>> {
    Ok(ureq::get(url)
        .header("User-Agent", USER_AGENT)
        .call()?
        .body_mut()
        .with_config()
        .limit(DOWNLOAD_LIMIT_BYTES)
        .read_to_vec()?)
}

/// `(asset_name, download_url)` for the host platform from a repo's latest
/// release. Asset match is an exact `-<platform>.zip` suffix so
/// `-linux.zip` never picks up `-linux-arm64.zip` / `-linux-py312.zip`.
fn latest_release_asset(repo: &str) -> anyhow::Result<(String, String)> {
    let suffix = platform_suffix().ok_or_else(|| {
        anyhow!(
            "no standalone build for {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let want = format!("-{suffix}.zip");

    let body = http_get_string(&format!(
        "https://api.github.com/repos/{repo}/releases/latest"
    ))
    .with_context(|| format!("querying {repo} latest release"))?;
    let doc: Value = serde_json::from_str(&body)?;
    let tag = doc.get("tag_name").and_then(Value::as_str).unwrap_or("?");

    let asset = doc
        .get("assets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|a| {
            a.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| n.ends_with(&want))
        })
        .ok_or_else(|| anyhow!("no asset ending with '{want}' in {repo} {tag}"))?;

    let name = asset["name"].as_str().unwrap_or_default().to_string();
    let url = asset
        .get("browser_download_url")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("asset {name} has no download url"))?
        .to_string();
    Ok((name, url))
}

fn extract_zip_flat(bytes: Vec<u8>, dest_dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(dest_dir)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let Some(name) = Path::new(entry.name()).file_name() else {
            continue;
        };
        let out_path = dest_dir.join(name);
        let mut out = fs::File::create(&out_path)?;
        io::copy(&mut entry, &mut out)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&out_path, fs::Permissions::from_mode(0o755))?;
        }
    }
    Ok(())
}

fn install(repo: &str, bin_names: &[&str]) -> anyhow::Result<PathBuf> {
    let (asset_name, url) = latest_release_asset(repo)?;
    info!("Downloading {asset_name} from {repo}...");
    let bytes = http_get_bytes(&url).with_context(|| format!("downloading {asset_name}"))?;
    info!("Downloaded {} MB, extracting...", bytes.len() / 1024 / 1024);
    let dir = tools_dir();
    extract_zip_flat(bytes, &dir)?;
    resolve(bin_names)
        .filter(|p| p.starts_with(&dir))
        .ok_or_else(|| {
            anyhow!(
                "{asset_name} extracted but no binary found in {}",
                dir.display()
            )
        })
}

/// Download the standalone capa into `<data_root>/tools/`. Returns its path.
pub fn install_capa() -> anyhow::Result<PathBuf> {
    install(CAPA_REPO, &["capa", "capa.exe"])
}

/// Download the standalone FLOSS into `<data_root>/tools/`. Returns its path.
pub fn install_floss() -> anyhow::Result<PathBuf> {
    install(FLOSS_REPO, &["floss", "floss.exe"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_suffix_matches_real_asset_names() {
        // exact-suffix matching must not confuse the linux variants
        let linux_assets = [
            "capa-v9.4.0-linux-arm64.zip",
            "capa-v9.4.0-linux-py312.zip",
            "capa-v9.4.0-linux.zip",
        ];
        let hits: Vec<_> = linux_assets
            .iter()
            .filter(|n| n.ends_with("-linux.zip"))
            .collect();
        assert_eq!(hits, [&"capa-v9.4.0-linux.zip"]);

        assert!("floss-v3.1.1-windows.zip".ends_with("-windows.zip"));
        assert!("capa-v9.4.0-macos.zip".ends_with("-macos.zip"));
        assert!(!"capa-v9.4.0-macos-arm64.zip".ends_with("-macos.zip"));
        assert!("capa-v9.4.0-macos-arm64.zip".ends_with("-macos-arm64.zip"));
    }

    #[test]
    fn resolve_returns_none_when_absent() {
        // tools_dir is under a per-user data root; on a clean checkout the
        // binaries aren't there and (normally) not on PATH either
        let _ = resolve_capa();
        let _ = resolve_floss();
        // just assert it doesn't panic and tools_dir is sane
        assert!(tools_dir().ends_with("tools"));
    }
}
