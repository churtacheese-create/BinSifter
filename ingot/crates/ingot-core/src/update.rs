//! On-request self-update: checks GitHub for a newer Ingot release and, on
//! request, downloads and installs it in place - added per a direct
//! request for a "Check for updates" button on the Settings page, mirrored
//! (with very different mechanics) across all three BinSifter variants.
//!
//! Ingot is the one variant where a real, safe, fully-automatic self-update
//! makes sense: it's a single portable binary with no installer and no
//! root requirement (unlike Winnow, a root-owned Linux package that must
//! never be rewritten outside `dpkg`/`rpm`, or Rowan's portable compiled
//! exe, which needs a fundamentally different locked-binary dance not
//! built here - see `ingot/IMPLEMENTATION_PLAN.md` for the full
//! cross-variant design notes).
//!
//! The tricky part - replacing a binary while it's the currently *running*
//! executable - is handled by the `self-replace` crate rather than
//! hand-rolled here: on Unix it's a plain atomic rename (already-open file
//! handles keep working against the old, now-unlinked inode); on Windows
//! it renames the running exe aside and marks it `FILE_FLAG_DELETE_ON_CLOSE`,
//! so the OS itself cleans up the leftover file the moment this process
//! actually exits - no separate helper process, no manual cleanup step.
//!
//! Ingot shares one GitHub repo with Rowan/Winnow but has its own,
//! disjoint tag line - `ingot-v*` (0.x) vs their shared `v*` (2.x) - so
//! this never queries `/releases/latest` (which would return whichever tag
//! is newest by publish time, regardless of prefix): it fetches the
//! releases list and filters by tag prefix itself.

use std::fs;
use std::io::Cursor;
use std::path::Path;

use anyhow::{anyhow, Context};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

const USER_AGENT: &str = "BinSifter-Ingot-Update/1.0";
const REPO: &str = "churtacheese-create/BinSifter";
/// Generous ceiling - release archives are ~10-35 MB.
const DOWNLOAD_LIMIT_BYTES: u64 = 200 * 1024 * 1024;

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

fn releases_list() -> anyhow::Result<Vec<Value>> {
    let body = http_get_string(&format!(
        "https://api.github.com/repos/{REPO}/releases?per_page=30"
    ))
    .context("querying BinSifter's releases")?;
    let doc: Value = serde_json::from_str(&body)?;
    Ok(doc.as_array().cloned().unwrap_or_default())
}

type SemVer = (u64, u64, u64);

fn parse_semver(v: &str) -> Option<SemVer> {
    let mut parts = v.split('.');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ))
}

fn current_version() -> SemVer {
    parse_semver(crate::VERSION).unwrap_or((0, 0, 0))
}

/// The newest release whose tag matches `ingot-vX.Y.Z` - never
/// `/releases/latest`, which doesn't know Rowan/Winnow's `v*` tags from
/// Ingot's own `ingot-v*` line and would happily return either.
fn latest_ingot_release(releases: &[Value]) -> Option<(SemVer, Value)> {
    releases
        .iter()
        .filter_map(|r| {
            let tag = r.get("tag_name").and_then(Value::as_str)?;
            let version = parse_semver(tag.strip_prefix("ingot-v")?)?;
            Some((version, r.clone()))
        })
        .max_by_key(|(version, _)| *version)
}

fn format_version(v: SemVer) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub release_url: String,
}

/// Checks GitHub for a newer `ingot-v*` release. Never installs anything -
/// see [`download_and_replace`] for that.
pub fn check_for_update() -> anyhow::Result<UpdateInfo> {
    let releases = releases_list()?;
    let current = current_version();
    Ok(match latest_ingot_release(&releases) {
        Some((latest, release)) => UpdateInfo {
            current_version: crate::VERSION.to_string(),
            latest_version: format_version(latest),
            update_available: latest > current,
            release_url: release
                .get("html_url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        },
        None => UpdateInfo {
            current_version: crate::VERSION.to_string(),
            latest_version: crate::VERSION.to_string(),
            update_available: false,
            release_url: format!("https://github.com/{REPO}/releases"),
        },
    })
}

/// This host's `ingot-release.yml` target triple, or `None` on a platform
/// that workflow doesn't build for (only 4 targets are published).
fn release_target_triple() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        _ => None,
    }
}

fn asset_url<'a>(assets: &'a [Value], name: &str) -> Option<&'a str> {
    assets
        .iter()
        .find(|a| a.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|a| a.get("browser_download_url"))
        .and_then(Value::as_str)
}

/// Extracts the `ingot`/`ingot.exe` binary from a downloaded release
/// archive into `dest_dir`, returning its path.
fn extract_binary(bytes: Vec<u8>, dest_dir: &Path) -> anyhow::Result<std::path::PathBuf> {
    let bin_name = if cfg!(windows) { "ingot.exe" } else { "ingot" };
    if cfg!(windows) {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            if entry.is_dir() {
                continue;
            }
            let Some(name) = Path::new(entry.name()).file_name() else {
                continue;
            };
            if name.to_str() != Some(bin_name) {
                continue;
            }
            let out_path = dest_dir.join(bin_name);
            let mut out = fs::File::create(&out_path)?;
            std::io::copy(&mut entry, &mut out)?;
            return Ok(out_path);
        }
    } else {
        let gz = flate2::read::GzDecoder::new(Cursor::new(bytes));
        tar::Archive::new(gz).unpack(dest_dir)?;
        if let Some(found) = walkdir::WalkDir::new(dest_dir)
            .into_iter()
            .filter_map(Result::ok)
            .find(|e| e.file_type().is_file() && e.file_name().to_str() == Some(bin_name))
            .map(walkdir::DirEntry::into_path)
        {
            return Ok(found);
        }
    }
    Err(anyhow!(
        "extracted the release archive but couldn't find {bin_name} inside"
    ))
}

/// Downloads the newest `ingot-v*` release for this OS/architecture,
/// verifies it against the release's own `SHA256SUMS`, and replaces the
/// running executable with it via `self_replace` - the caller is
/// responsible for spawning the new binary and shutting this process down
/// afterward (see `ingot-server`'s `install_update` handler); this
/// function only makes sure the file on disk is the new version.
pub fn download_and_replace() -> anyhow::Result<()> {
    let releases = releases_list()?;
    let (latest, release) =
        latest_ingot_release(&releases).ok_or_else(|| anyhow!("no ingot-v* release found"))?;
    if latest <= current_version() {
        return Err(anyhow!("already on the latest version"));
    }

    let triple = release_target_triple().ok_or_else(|| {
        anyhow!(
            "no self-update build for this platform ({} {}) - download manually from https://github.com/{REPO}/releases",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let version_str = format_version(latest);
    let ext = if cfg!(windows) { "zip" } else { "tar.gz" };
    let asset_name = format!("ingot-{version_str}-{triple}.{ext}");

    let assets = release
        .get("assets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let download_url = asset_url(&assets, &asset_name)
        .ok_or_else(|| anyhow!("release {version_str} has no asset named {asset_name}"))?
        .to_string();

    info!("Downloading {asset_name} for the self-update...");
    let bytes =
        http_get_bytes(&download_url).with_context(|| format!("downloading {asset_name}"))?;

    match asset_url(&assets, "SHA256SUMS") {
        Some(sums_url) => {
            let sums_text = http_get_string(sums_url).context("downloading SHA256SUMS")?;
            let expected = sums_text
                .lines()
                .find_map(|line| {
                    let mut parts = line.split_whitespace();
                    let hash = parts.next()?;
                    let name = parts.next()?.trim_start_matches('*');
                    (name == asset_name).then(|| hash.to_ascii_lowercase())
                })
                .ok_or_else(|| anyhow!("SHA256SUMS has no entry for {asset_name}"))?;
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let actual = hex::encode(hasher.finalize());
            if actual != expected {
                return Err(anyhow!(
                    "checksum mismatch for {asset_name}: expected {expected}, got {actual} - not installing"
                ));
            }
        }
        None => warn!(
            "SHA256SUMS not found in release {version_str} - installing {asset_name} unverified"
        ),
    }

    let extract_dir = tempfile::Builder::new()
        .prefix("ingot-update-")
        .tempdir()
        .context("could not create a temp directory to extract the update into")?;
    let new_binary = extract_binary(bytes, extract_dir.path())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(&new_binary)?.permissions();
        perm.set_mode(perm.mode() | 0o755);
        fs::set_permissions(&new_binary, perm)?;
    }

    self_replace::self_replace(&new_binary).context("could not replace the running executable")?;
    info!("Ingot updated to {version_str}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_release(tag: &str, assets: Vec<&str>) -> Value {
        serde_json::json!({
            "tag_name": tag,
            "html_url": format!("https://github.com/{REPO}/releases/tag/{tag}"),
            "assets": assets.iter().map(|name| serde_json::json!({
                "name": name,
                "browser_download_url": format!("https://example.invalid/{name}"),
            })).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn parses_semver() {
        assert_eq!(parse_semver("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver("0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_semver("not-a-version"), None);
    }

    #[test]
    fn ignores_non_ingot_tags_and_picks_the_max() {
        let releases = vec![
            fake_release("v2.0.9", vec![]), // Rowan/Winnow's line - must never match
            fake_release("ingot-v0.1.0", vec![]),
            fake_release("ingot-v0.2.0", vec![]),
            fake_release("ingot-v0.1.5", vec![]),
        ];
        let (best, release) = latest_ingot_release(&releases).unwrap();
        assert_eq!(best, (0, 2, 0));
        assert_eq!(release["tag_name"], "ingot-v0.2.0");
    }

    #[test]
    fn no_matching_tag_is_none() {
        let releases = vec![fake_release("v2.0.9", vec![])];
        assert!(latest_ingot_release(&releases).is_none());
    }

    #[test]
    fn release_target_triple_matches_ingot_release_yml_matrix() {
        // one of these must resolve on any CI/dev box this actually runs on
        let known = [
            ("windows", "x86_64"),
            ("linux", "x86_64"),
            ("macos", "aarch64"),
            ("macos", "x86_64"),
        ];
        assert!(
            known.contains(&(std::env::consts::OS, std::env::consts::ARCH))
                == release_target_triple().is_some()
        );
    }

    #[test]
    fn asset_url_finds_exact_name_only() {
        let assets = vec![
            serde_json::json!({"name": "ingot-0.2.0-x86_64-unknown-linux-gnu.tar.gz", "browser_download_url": "https://x/1"}),
            serde_json::json!({"name": "SHA256SUMS", "browser_download_url": "https://x/2"}),
        ];
        assert_eq!(
            asset_url(&assets, "ingot-0.2.0-x86_64-unknown-linux-gnu.tar.gz"),
            Some("https://x/1")
        );
        assert_eq!(asset_url(&assets, "SHA256SUMS"), Some("https://x/2"));
        assert_eq!(asset_url(&assets, "nope"), None);
    }
}
