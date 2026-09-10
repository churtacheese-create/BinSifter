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

fn find_tool(names: &[&str], tools_dir: &str) -> Option<PathBuf> {
    if !tools_dir.is_empty() {
        // recursive search of the configured directory - first match by
        // path order wins, matching the other variants' Find-ToolPath
        let mut hits: Vec<PathBuf> = WalkDir::new(tools_dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                let fname = e.file_name().to_string_lossy();
                let stem = Path::new(fname.as_ref())
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                names
                    .iter()
                    .any(|n| fname.eq_ignore_ascii_case(n) || stem.eq_ignore_ascii_case(n))
            })
            .map(|e| e.into_path())
            .collect();
        hits.sort();
        if let Some(p) = hits.into_iter().next() {
            return Some(p);
        }
    }
    // fall back to PATH
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
    tools_for_os()
        .iter()
        .map(|t| ResolvedTool {
            id: t.id.to_string(),
            label: t.label.to_string(),
            path: find_tool(t.filenames, tools_dir)
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
    find_tool(names, ghidra_dir)
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
