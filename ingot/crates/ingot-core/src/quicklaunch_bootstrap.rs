//! On-request installer for the Results right-click quick-launch tools
//! ([`crate::tools`]) - added in response to a real gap found testing
//! Ingot: a missing tool was just greyed out with no way to get it, unlike
//! Winnow's `tool_bootstrap.py`, which downloads several of these
//! automatically. Ported here for the tools Winnow already verified a
//! real, no-root, per-user download source for (all Linux-only): PE-bear,
//! DIE, Cutter, and Anya publish self-contained GitHub-release AppImages/
//! tarballs; angr and unblob are plain PyPI packages installed into a
//! private virtualenv the same way Winnow does it.
//!
//! Deliberately Linux-only. Ingot's Windows tool set (PE Studio, CFF
//! Explorer, Resource Hacker, x64dbg/x32dbg, Sigcheck) and macOS/Windows
//! copies of DIE/Cutter/radare2 have no equivalent verified-safe per-user
//! download source anywhere in this codebase - Rowan (the Windows variant)
//! has never auto-installed any of its own quick-launch tools either, it
//! only ever resolves them from the configured tools directory or `PATH`.
//! Rather than hard-code a guessed download URL for those, [`manual_hint`]
//! gives the same kind of "here's where to get it, here's where to put it"
//! guidance Rowan's own missing-tool dialogs already use (see
//! `BinSifter-Rowan.ps1`'s Speakeasy-missing message).
//!
//! Every installer here is a plain per-user download/pip-install - no
//! `sudo`, matching `tool_bootstrap.rs`'s existing capa/FLOSS installers.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context};
use serde_json::Value;
use tracing::info;

const USER_AGENT: &str = "BinSifter-Ingot-QuickLaunchBootstrap/1.0";
/// AppImages/tarballs here run larger than capa/FLOSS's release zips.
const DOWNLOAD_LIMIT_BYTES: u64 = 500 * 1024 * 1024;

/// Same fixed per-user directory `tool_bootstrap`'s capa/FLOSS installers
/// use - one place Ingot always searches automatically, regardless of the
/// user's own "Tools directory" Settings field. See `tools.rs::resolve_tools`.
pub fn tools_dir() -> PathBuf {
    crate::tool_bootstrap::tools_dir()
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(name);
        candidate.is_file().then_some(candidate)
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

fn latest_release_assets(owner: &str, repo: &str) -> anyhow::Result<Vec<Value>> {
    let body = http_get_string(&format!(
        "https://api.github.com/repos/{owner}/{repo}/releases/latest"
    ))
    .with_context(|| format!("querying {owner}/{repo}'s latest release"))?;
    let doc: Value = serde_json::from_str(&body)?;
    Ok(doc
        .get("assets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

/// First asset whose (lowercased) name contains every token in
/// `must_contain` and none of `must_not_contain` - same matching rule
/// `tool_bootstrap.py::_pick_asset` already used successfully for these
/// exact repos.
fn pick_asset<'a>(
    assets: &'a [Value],
    must_contain: &[&str],
    must_not_contain: &[&str],
) -> Option<&'a Value> {
    assets.iter().find(|a| {
        let name = a
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        must_contain.iter().all(|t| name.contains(t))
            && !must_not_contain.iter().any(|t| name.contains(t))
    })
}

fn asset_download_url(asset: &Value) -> anyhow::Result<(&str, &str)> {
    let name = asset.get("name").and_then(Value::as_str).unwrap_or("?");
    let url = asset
        .get("browser_download_url")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("asset {name} has no download url"))?;
    Ok((name, url))
}

fn make_executable(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(path)?.permissions();
        perm.set_mode(perm.mode() | 0o755);
        fs::set_permissions(path, perm)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// PE-bear / DIE / Cutter all publish exactly one Linux AppImage asset on
/// their latest release - download, chmod +x, done.
fn install_appimage(
    owner: &str,
    repo: &str,
    subdir: &str,
    saved_name: &str,
) -> anyhow::Result<PathBuf> {
    let assets = latest_release_assets(owner, repo)?;
    let asset = pick_asset(&assets, &[".appimage"], &[])
        .ok_or_else(|| anyhow!("no Linux AppImage found in {owner}/{repo}'s latest release"))?;
    let (name, url) = asset_download_url(asset)?;
    info!("Downloading {name} from {owner}/{repo}...");
    let bytes = http_get_bytes(url).with_context(|| format!("downloading {name}"))?;
    let dest_dir = tools_dir().join(subdir);
    fs::create_dir_all(&dest_dir)?;
    let dest = dest_dir.join(saved_name);
    fs::write(&dest, &bytes)?;
    make_executable(&dest)?;
    Ok(dest)
}

pub fn install_pebear() -> anyhow::Result<PathBuf> {
    install_appimage("hasherezade", "pe-bear", "pebear", "PE-bear.AppImage")
}

pub fn install_die() -> anyhow::Result<PathBuf> {
    install_appimage("horsicq", "DIE-engine", "die", "die.AppImage")
}

pub fn install_cutter() -> anyhow::Result<PathBuf> {
    install_appimage("rizinorg", "cutter", "cutter", "cutter.AppImage")
}

/// Anya publishes a static musl CLI tarball, matching how `tools.rs`
/// invokes it (`anya --file <path>`).
pub fn install_anya() -> anyhow::Result<PathBuf> {
    let assets = latest_release_assets("elementmerc", "anya")?;
    let asset = pick_asset(&assets, &["linux", "musl", ".tar.gz"], &[]).ok_or_else(|| {
        anyhow!("no Linux musl CLI tarball found in elementmerc/anya's latest release")
    })?;
    let (name, url) = asset_download_url(asset)?;
    info!("Downloading {name} from elementmerc/anya...");
    let bytes = http_get_bytes(url).with_context(|| format!("downloading {name}"))?;
    let extract_dir = tools_dir().join("anya");
    fs::create_dir_all(&extract_dir)?;
    let gz = flate2::read::GzDecoder::new(Cursor::new(bytes));
    tar::Archive::new(gz)
        .unpack(&extract_dir)
        .with_context(|| format!("extracting {name}"))?;
    let found = walkdir::WalkDir::new(&extract_dir)
        .into_iter()
        .filter_map(Result::ok)
        .find(|e| {
            e.file_type().is_file()
                && e.file_name()
                    .to_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case("anya"))
        })
        .map(walkdir::DirEntry::into_path)
        .ok_or_else(|| anyhow!("extracted {name} but couldn't locate the anya binary inside"))?;
    make_executable(&found)?;
    Ok(found)
}

/// Creates a virtualenv at `venv_dir` using a real system `python3` (never
/// the running Ingot binary, which isn't a Python interpreter at all) -
/// `--without-pip` then a two-step pip bootstrap, same fallback chain
/// `tool_bootstrap.py::_create_private_venv` uses after finding some
/// distros ship a `python3` with no `ensurepip` module.
fn create_private_venv(venv_dir: &Path) -> anyhow::Result<PathBuf> {
    let python = which_on_path("python3")
        .or_else(|| which_on_path("python"))
        .ok_or_else(|| {
            anyhow!("no system python3 found - needed to install this into a private virtualenv")
        })?;

    let out = Command::new(&python)
        .args(["-m", "venv", "--without-pip"])
        .arg(venv_dir)
        .output()
        .context("could not run python3 -m venv")?;
    if !out.status.success() {
        return Err(anyhow!(
            "python3 -m venv failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let venv_python = venv_dir
        .join(if cfg!(windows) { "Scripts" } else { "bin" })
        .join(if cfg!(windows) {
            "python.exe"
        } else {
            "python"
        });
    if !venv_python.is_file() {
        return Err(anyhow!(
            "virtualenv creation didn't produce a python binary"
        ));
    }

    let ensurepip = Command::new(&venv_python)
        .args(["-m", "ensurepip", "--upgrade"])
        .output();
    if !matches!(&ensurepip, Ok(o) if o.status.success()) {
        let bytes = http_get_bytes("https://bootstrap.pypa.io/get-pip.py")
            .context("could not download get-pip.py")?;
        let get_pip = venv_dir.join("get-pip.py");
        fs::write(&get_pip, &bytes)?;
        let out = Command::new(&venv_python)
            .arg(&get_pip)
            .output()
            .context("could not run get-pip.py")?;
        if !out.status.success() {
            return Err(anyhow!(
                "could not bootstrap pip in the private virtualenv: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    Ok(venv_python)
}

fn venv_bin(venv_dir: &Path, name: &str) -> PathBuf {
    venv_dir
        .join(if cfg!(windows) { "Scripts" } else { "bin" })
        .join(if cfg!(windows) {
            format!("{name}.exe")
        } else {
            name.to_string()
        })
}

fn pip_install(venv_python: &Path, pip_args: &[&str]) -> anyhow::Result<()> {
    let mut args = vec![
        "-m",
        "pip",
        "install",
        "--quiet",
        "--disable-pip-version-check",
    ];
    args.extend_from_slice(pip_args);
    let out = Command::new(venv_python)
        .args(&args)
        .output()
        .context("could not run pip install")?;
    if !out.status.success() {
        return Err(anyhow!(
            "pip install failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Plain PyPI package + console-script entry point, no native/Rust build
/// concerns - unblob's shape.
fn install_pip_venv_tool(package: &str, console_script: &str) -> anyhow::Result<PathBuf> {
    let venv_dir = tools_dir().join(format!("{package}-venv"));
    let venv_python = create_private_venv(&venv_dir)?;
    pip_install(&venv_python, &[package])?;
    let exe = venv_bin(&venv_dir, console_script);
    if !exe.is_file() {
        return Err(anyhow!(
            "{package} installed but no {console_script} console script was produced"
        ));
    }
    Ok(exe)
}

/// angr's own pyproject.toml has a Cargo-based native extension - try a
/// prebuilt wheel first so a machine with no Rust toolchain doesn't fall
/// through to a source build, matching `tool_bootstrap.py::_install_angr`.
pub fn install_angr() -> anyhow::Result<PathBuf> {
    let venv_dir = tools_dir().join("angr-venv");
    let venv_python = create_private_venv(&venv_dir)?;

    let mut last_err = String::new();
    let mut installed = false;
    for pip_args in [
        ["--only-binary=:all:", "angr"].as_slice(),
        ["angr"].as_slice(),
    ] {
        match pip_install(&venv_python, pip_args) {
            Ok(()) => {
                installed = true;
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    if !installed {
        return Err(anyhow!(
            "pip install angr failed (tried a prebuilt wheel and a source build): {last_err}"
        ));
    }
    let exe = venv_bin(&venv_dir, "angr");
    if !exe.is_file() {
        return Err(anyhow!(
            "angr installed but no angr console script was produced"
        ));
    }
    Ok(exe)
}

pub fn install_unblob() -> anyhow::Result<PathBuf> {
    install_pip_venv_tool("unblob", "unblob")
}

/// True only for the tool ids this module actually knows how to install on
/// the host OS - every one of them is Linux-only (see module docs).
pub fn is_installable(id: &str) -> bool {
    std::env::consts::OS == "linux"
        && matches!(id, "pebear" | "die" | "cutter" | "anya" | "angr" | "unblob")
}

/// Runs the real installer for `id`. Callers must check [`is_installable`]
/// first - this returns an error for anything it doesn't recognize rather
/// than guessing.
pub fn install(id: &str) -> anyhow::Result<PathBuf> {
    match id {
        "pebear" => install_pebear(),
        "die" => install_die(),
        "cutter" => install_cutter(),
        "anya" => install_anya(),
        "angr" => install_angr(),
        "unblob" => install_unblob(),
        _ => Err(anyhow!("no installer available for '{id}' on this OS")),
    }
}

/// "Here's where to actually get it" guidance for a tool [`is_installable`]
/// says no to - shown by the UI alongside the configured/auto-install tools
/// directory so a manual install still gets picked up automatically. Never
/// a fabricated one-shot download URL for something this project hasn't
/// already verified (see the module docs on why Windows/macOS tools stop
/// here rather than getting a real installer).
pub fn manual_hint(id: &str) -> &'static str {
    match id {
        "pestudio" => "PE Studio isn't auto-installable - download it from Winitor's official site (winitor.com).",
        "die" => "download the DIE-engine build for this OS from its GitHub releases (horsicq/DIE-engine).",
        "cff" => "download NTCore's CFF Explorer (Explorer Suite) from its official site.",
        "reshacker" => "download Resource Hacker from its official site (angusj.com/resourcehacker).",
        "x64dbg" | "x32dbg" => "download x64dbg from its GitHub releases (x64dbg/x64dbg).",
        "sigcheck" => "download Sysinternals Sigcheck from Microsoft's Sysinternals Live / Sysinternals site.",
        "cutter" => "download Cutter for this OS from its GitHub releases (rizinorg/cutter) or your package manager.",
        "radare2" => "install radare2 via your package manager (e.g. \"brew install radare2\") or from its GitHub releases (radareorg/radare2).",
        "gdb" => "install gdb via your OS's package manager - it needs a real package manager and can't be auto-installed.",
        "unblob" => "run: pip install unblob (or pipx install unblob) in a Python environment on this machine.",
        "angr" => "run: pip install angr (or pipx install angr) in a Python environment on this machine.",
        "anya" => "download Anya's CLI build for this OS from its GitHub releases (elementmerc/anya).",
        "pebear" => "download PE-bear for this OS from its GitHub releases (hasherezade/pe-bear).",
        _ => "install it manually.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installable_set_is_linux_only() {
        for id in ["pebear", "die", "cutter", "anya", "angr", "unblob"] {
            assert_eq!(is_installable(id), std::env::consts::OS == "linux");
        }
        assert!(!is_installable("pestudio"));
        assert!(!is_installable("gdb"));
        assert!(!is_installable("not-a-real-tool"));
    }

    #[test]
    fn every_windows_and_macos_tool_has_a_specific_hint() {
        for id in [
            "pestudio",
            "die",
            "cff",
            "reshacker",
            "x64dbg",
            "x32dbg",
            "sigcheck",
            "cutter",
            "radare2",
            "gdb",
            "unblob",
            "angr",
            "anya",
            "pebear",
        ] {
            assert_ne!(
                manual_hint(id),
                "install it manually.",
                "missing a specific hint for {id}"
            );
        }
    }

    #[test]
    fn pick_asset_matches_appimage_only() {
        let assets = serde_json::json!([
            {"name": "PE-bear-0.7.1-x64.Linux.AppImage"},
            {"name": "PE-bear-0.7.1-x64.Windows.zip"},
        ]);
        let hit = pick_asset(assets.as_array().unwrap(), &[".appimage"], &[]).unwrap();
        assert_eq!(hit["name"], "PE-bear-0.7.1-x64.Linux.AppImage");
    }
}
