//! OS-scoped quick-launch tools for the Results grid - the analogue of
//! Rowan's / Winnow's right-click menu.
//!
//! Ingot's scan engine runs on one OS at a time, so the tool *set* is
//! simply [`std::env::consts::OS`] - no install-time "which OS?" question is
//! needed (that framing was for a desktop installer). Each tool is resolved
//! against the configured tools directory (searched recursively) then the
//! system `PATH`; a tool that resolves nowhere is offered greyed-out.
//!
//! Tools launch on the machine running the Ingot service (loopback,
//! single-user). GUI tools are spawned detached; CLI-only tools open in a
//! terminal window so their stdout report is actually visible.
//!
//! Not ported: Speakeasy (no standalone binary - would need a Python env).
//! Ghidra headless is handled separately ([`resolve_ghidra_headless`] /
//! [`launch_ghidra`]).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context};
use serde::Serialize;
use tracing::info;
use walkdir::WalkDir;

pub struct ToolDef {
    pub id: &'static str,
    pub label: &'static str,
    /// Candidate binary names, tried in order.
    pub filenames: &'static [&'static str],
    /// argv inserted between the binary and the target path
    /// (e.g. `["--file"]` for Anya, `["decompile"]` for angr).
    pub args_before_target: &'static [&'static str],
    /// Execution-adjacent (a live debugger) - the UI confirms first.
    pub needs_confirm: bool,
    /// A stdout-only CLI tool - launch inside a terminal window.
    pub needs_terminal: bool,
}

macro_rules! tool {
    (@flag) => { false };
    (@flag $v:literal) => { $v };
    ($id:literal, $label:literal, [$($f:literal),*] $(, args=[$($a:literal),*])? $(, confirm=$c:literal)? $(, terminal=$t:literal)?) => {
        ToolDef {
            id: $id, label: $label,
            filenames: &[$($f),*],
            args_before_target: &[$($($a),*)?],
            needs_confirm: tool!(@flag $($c)?),
            needs_terminal: tool!(@flag $($t)?),
        }
    };
}

const WINDOWS_TOOLS: &[ToolDef] = &[
    tool!("pestudio", "Open in PE Studio", ["pestudio"]),
    tool!("die", "Open in DIE", ["diec", "die"]),
    tool!(
        "cff",
        "Open in CFF Explorer",
        ["CFF Explorer", "cff explorer"]
    ),
    tool!("reshacker", "Open in Resource Hacker", ["ResourceHacker"]),
    tool!("x64dbg", "Debug in x64dbg", ["x64dbg"], confirm = true),
    tool!("x32dbg", "Debug in x32dbg", ["x32dbg"], confirm = true),
    tool!(
        "sigcheck",
        "Sigcheck",
        ["sigcheck64", "sigcheck"],
        terminal = true
    ),
];

const LINUX_TOOLS: &[ToolDef] = &[
    tool!(
        "pebear",
        "Open in PE-bear",
        ["pe-bear", "PE-bear", "PEBear"]
    ),
    tool!(
        "anya",
        "Analyse with Anya",
        ["anya", "Anya"],
        args = ["--file"],
        terminal = true
    ),
    tool!("die", "Open in DIE", ["diec", "die"]),
    tool!("cutter", "Open in Cutter", ["Cutter", "cutter"]),
    tool!(
        "angr",
        "Decompile with angr",
        ["angr"],
        args = ["decompile"],
        terminal = true
    ),
    tool!(
        "gdb",
        "Debug in GDB (with GEF)",
        ["gdb"],
        confirm = true,
        terminal = true
    ),
    tool!("unblob", "Scan with unblob", ["unblob"], terminal = true),
];

const MACOS_TOOLS: &[ToolDef] = &[
    tool!("die", "Open in DIE", ["diec", "die"]),
    tool!("cutter", "Open in Cutter", ["Cutter", "cutter"]),
    tool!(
        "radare2",
        "Open in radare2",
        ["r2", "radare2"],
        terminal = true
    ),
];

pub fn tools_for_os() -> &'static [ToolDef] {
    match std::env::consts::OS {
        "windows" => WINDOWS_TOOLS,
        "macos" => MACOS_TOOLS,
        _ => LINUX_TOOLS,
    }
}

/// Would `path` plausibly be a launchable tool rather than a library / data
/// file that merely shares a name? On Windows only real executables count
/// (this is what stopped `x64dbg` resolving to `x64dbg.lib`); elsewhere an
/// extensionless file is fine (most Linux tools and Ghidra's `analyzeHeadless`
/// shell script) but obvious non-executables are rejected.
fn looks_launchable(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => {
            let ext = ext.to_ascii_lowercase();
            if cfg!(windows) {
                matches!(ext.as_str(), "exe" | "bat" | "cmd" | "com")
            } else {
                !matches!(
                    ext.as_str(),
                    "lib"
                        | "dll"
                        | "so"
                        | "dylib"
                        | "a"
                        | "o"
                        | "txt"
                        | "md"
                        | "json"
                        | "xml"
                        | "ini"
                        | "cfg"
                        | "conf"
                        | "yml"
                        | "yaml"
                        | "h"
                        | "c"
                        | "cpp"
                        | "py"
                        | "png"
                        | "svg"
                        | "html"
                )
            }
        }
        // no extension: a Unix binary/script, but never a Windows tool
        None => !cfg!(windows),
    }
}

/// Every launchable-looking file under `dir`, sorted for determinism.
fn walk_candidates(dir: &str) -> Vec<PathBuf> {
    if dir.is_empty() {
        return Vec::new();
    }
    let mut hits: Vec<PathBuf> = WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .filter(|p| looks_launchable(p))
        .collect();
    hits.sort();
    hits
}

/// First candidate matching one of `names` (by file name or stem,
/// case-insensitively). `names` are tried **in order** - the first name with
/// any match wins - so `["analyzeHeadless.bat", "analyzeHeadless"]` prefers
/// the `.bat` on Windows even though it sorts later on disk.
fn match_candidate(names: &[&str], candidates: &[PathBuf]) -> Option<PathBuf> {
    for name in names {
        if let Some(hit) = candidates.iter().find(|p| {
            let fname = p
                .file_name()
                .map(|s| s.to_string_lossy())
                .unwrap_or_default();
            let stem = p
                .file_stem()
                .map(|s| s.to_string_lossy())
                .unwrap_or_default();
            fname.eq_ignore_ascii_case(name) || stem.eq_ignore_ascii_case(name)
        }) {
            return Some(hit.clone());
        }
    }
    None
}

/// `PATH` lookup, tried in `names` order (with a `.exe` suffix as a fallback).
fn path_env_lookup(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for name in names {
        for dir in std::env::split_paths(&path) {
            for cand in [dir.join(name), dir.join(format!("{name}.exe"))] {
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

/// Resolve one tool: the configured directory (single recursive walk) first,
/// then `PATH`.
fn resolve_one(names: &[&str], tools_dir: &str) -> Option<PathBuf> {
    match_candidate(names, &walk_candidates(tools_dir)).or_else(|| path_env_lookup(names))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedTool {
    pub id: String,
    pub label: String,
    /// Resolved path, or `""` if the tool wasn't found.
    pub path: String,
    pub needs_confirm: bool,
    pub needs_terminal: bool,
}

pub fn resolve_tools(tools_dir: &str) -> Vec<ResolvedTool> {
    // one walk of the (possibly large) tools directory, shared across every
    // tool - previously this walked the whole tree once per tool.
    let candidates = walk_candidates(tools_dir);
    tools_for_os()
        .iter()
        .map(|t| ResolvedTool {
            id: t.id.to_string(),
            label: t.label.to_string(),
            path: match_candidate(t.filenames, &candidates)
                .or_else(|| path_env_lookup(t.filenames))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            needs_confirm: t.needs_confirm,
            needs_terminal: t.needs_terminal,
        })
        .collect()
}

fn tool_def(id: &str) -> Option<&'static ToolDef> {
    tools_for_os().iter().find(|t| t.id == id)
}

/// AppImage magic bytes at offset 8 (`AI\x01` / `AI\x02`).
fn is_appimage(path: &Path) -> bool {
    let mut buf = [0u8; 11];
    std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read(&mut f, &mut buf).map(|_| ()))
        .is_ok()
        && &buf[8..10] == b"AI"
        && matches!(buf[10], 1 | 2)
}

#[cfg(target_os = "linux")]
fn find_linux_terminal() -> Option<(String, Vec<&'static str>)> {
    for (name, prefix) in [
        ("x-terminal-emulator", vec!["-e"]),
        ("gnome-terminal", vec!["--"]),
        ("konsole", vec!["-e"]),
        ("xfce4-terminal", vec!["-x"]),
        ("xterm", vec!["-e"]),
    ] {
        if which(name) {
            return Some((name.to_string(), prefix));
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|d| d.join(name).is_file()))
        .unwrap_or(false)
}

/// Launch quick-launch tool `id` against `target`. Returns before the tool
/// exits (fire-and-forget, like the other variants).
pub fn launch_tool(id: &str, tool_path: &str, target: &Path) -> anyhow::Result<()> {
    let def = tool_def(id).ok_or_else(|| anyhow!("unknown tool '{id}' for this OS"))?;
    let tool_path = Path::new(tool_path);
    if tool_path.as_os_str().is_empty() || !tool_path.is_file() {
        return Err(anyhow!("{} is not installed", def.label));
    }
    if !target.is_file() {
        return Err(anyhow!(
            "target file no longer exists: {}",
            target.display()
        ));
    }

    let mut argv: Vec<String> = Vec::new();
    if cfg!(target_os = "linux") && is_appimage(tool_path) {
        argv.push("--appimage-extract-and-run".to_string());
    }
    argv.extend(def.args_before_target.iter().map(|s| s.to_string()));
    argv.push(target.to_string_lossy().into_owned());

    let cwd = tool_path.parent().unwrap_or(Path::new("."));

    if !def.needs_terminal {
        info!("Launching {} on {}", def.label, target.display());
        Command::new(tool_path)
            .args(&argv)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("could not launch {}", def.label))?;
        return Ok(());
    }

    // terminal tool
    let full: Vec<String> = std::iter::once(tool_path.to_string_lossy().into_owned())
        .chain(argv)
        .collect();
    let joined = shell_join(&full);

    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/c", "start", "", "cmd", "/k"])
            .arg(&joined)
            .spawn()
            .with_context(|| format!("could not open a console for {}", def.label))?;
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "tell application \"Terminal\" to do script \"{}\"",
            joined.replace('\\', "\\\\").replace('"', "\\\"")
        );
        Command::new("osascript").args(["-e", &script]).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        let (term, prefix) = find_linux_terminal()
            .ok_or_else(|| anyhow!("no terminal emulator found to run {}", def.label))?;
        let held = format!(
            "{joined}; status=$?; echo; printf '[exit %s - press Enter to close] ' \"$status\"; read _",
        );
        Command::new(term)
            .args(&prefix)
            .args(["sh", "-c", &held])
            .spawn()
            .with_context(|| format!("could not open a terminal for {}", def.label))?;
    }
    info!(
        "Launched {} in a terminal on {}",
        def.label,
        target.display()
    );
    Ok(())
}

fn shell_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| {
            if p.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./=:".contains(c))
            {
                p.clone()
            } else {
                format!("\"{}\"", p.replace('"', "\\\""))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------- Ghidra

/// `analyzeHeadless` (`.bat` on Windows) under `ghidra_dir`, or on PATH.
pub fn resolve_ghidra_headless(ghidra_dir: &str) -> Option<PathBuf> {
    let names: &[&str] = if cfg!(windows) {
        &["analyzeHeadless.bat", "analyzeHeadless"]
    } else {
        &["analyzeHeadless"]
    };
    resolve_one(names, ghidra_dir)
}

/// Kick off `analyzeHeadless` for `target` into `<report_dir>/ghidra_projects/`.
/// Fire-and-forget - headless analysis runs for minutes.
pub fn launch_ghidra(
    headless: &str,
    target: &Path,
    report_dir: &str,
    sha1: Option<&str>,
) -> anyhow::Result<PathBuf> {
    if report_dir.is_empty() {
        return Err(anyhow!(
            "configure a report directory first - Ghidra projects live under it"
        ));
    }
    if !target.is_file() {
        return Err(anyhow!("target file no longer exists"));
    }
    let projects_dir = Path::new(report_dir).join("ghidra_projects");
    std::fs::create_dir_all(&projects_dir)?;
    let project_name = match sha1.filter(|s| !s.is_empty()) {
        Some(s) => format!("BinSifter_{s}"),
        None => format!(
            "BinSifter_{}",
            target
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("sample")
        ),
    };

    Command::new(headless)
        .arg(&projects_dir)
        .arg(&project_name)
        .args(["-import"])
        .arg(target)
        .args(["-overwrite", "-analysisTimeoutPerFile", "300"])
        .current_dir(Path::new(headless).parent().unwrap_or(Path::new(".")))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("could not launch analyzeHeadless")?;

    info!("Ghidra headless analysis started for {}", target.display());
    Ok(projects_dir.join(format!("{project_name}.gpr")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_tool_set_is_nonempty_and_ids_unique() {
        let set = tools_for_os();
        assert!(!set.is_empty());
        let mut ids: Vec<&str> = set.iter().map(|t| t.id).collect();
        ids.sort();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate tool ids");
    }

    #[test]
    fn resolve_marks_missing_tools_empty() {
        let resolved = resolve_tools("");
        assert_eq!(resolved.len(), tools_for_os().len());
        // on a clean CI box none of these are installed
        for r in &resolved {
            if r.path.is_empty() {
                assert!(!r.id.is_empty());
            }
        }
    }

    #[test]
    fn launchable_filter_rejects_libraries() {
        assert!(!looks_launchable(Path::new("x64dbg.lib")));
        assert!(!looks_launchable(Path::new("some/dir/tool.dll")));
        assert!(!looks_launchable(Path::new("readme.txt")));
        if cfg!(windows) {
            assert!(looks_launchable(Path::new("pestudio.exe")));
            assert!(looks_launchable(Path::new("support/analyzeHeadless.bat")));
            assert!(!looks_launchable(Path::new("support/analyzeHeadless"))); // unix script
        } else {
            assert!(looks_launchable(Path::new("cutter")));
            assert!(looks_launchable(Path::new("support/analyzeHeadless")));
        }
    }

    #[test]
    fn match_candidate_honours_name_priority() {
        let cands = [
            PathBuf::from("/g/support/analyzeHeadless"),
            PathBuf::from("/g/support/analyzeHeadless.bat"),
        ];
        // ".bat" is listed first -> wins even though it sorts later on disk
        let hit = match_candidate(&["analyzeHeadless.bat", "analyzeHeadless"], &cands).unwrap();
        assert_eq!(hit, PathBuf::from("/g/support/analyzeHeadless.bat"));
    }

    #[test]
    fn launch_unknown_tool_errors() {
        let err = launch_tool("does-not-exist", "/bin/true", Path::new("/etc/hostname"));
        assert!(err.is_err());
    }

    #[test]
    fn launch_with_missing_binary_errors() {
        let err = launch_tool(
            tools_for_os()[0].id,
            "/no/such/tool",
            Path::new("/etc/hostname"),
        );
        assert!(err.is_err());
    }
}
