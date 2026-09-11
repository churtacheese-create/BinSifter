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
    /// The tool's own command line is reserved for something else (e.g. CFF
    /// Explorer's is its Lua scripting engine, so a PE path there is
    /// silently ignored) - launch it with no target argument at all and
    /// copy the target path to the clipboard instead, matching Rowan's and
    /// Winnow's `copy_path_instead` behavior.
    pub copy_path_instead: bool,
    /// Execution-adjacent (a live debugger) - the UI confirms first.
    pub needs_confirm: bool,
    /// A stdout-only CLI tool - launch inside a terminal window.
    pub needs_terminal: bool,
}

macro_rules! tool {
    (@flag) => { false };
    (@flag $v:literal) => { $v };
    ($id:literal, $label:literal, [$($f:literal),*] $(, args=[$($a:literal),*])? $(, copy=$cp:literal)? $(, confirm=$c:literal)? $(, terminal=$t:literal)?) => {
        ToolDef {
            id: $id, label: $label,
            filenames: &[$($f),*],
            args_before_target: &[$($($a),*)?],
            copy_path_instead: tool!(@flag $($cp)?),
            needs_confirm: tool!(@flag $($c)?),
            needs_terminal: tool!(@flag $($t)?),
        }
    };
}

// `die` (the GUI) is listed before `diec` / `diel` (DIE's console / lite
// builds) so "Open in DIE" resolves to the window, not a CLI that prints to a
// discarded stdout and exits.
const WINDOWS_TOOLS: &[ToolDef] = &[
    tool!("pestudio", "Open in PE Studio", ["pestudio"]),
    tool!("die", "Open in DIE", ["die", "diec"]),
    // CFF Explorer's own command line is reserved for its Lua scripting
    // engine - a PE path passed as an argument is silently ignored, so this
    // opens the tool plain and copies the path to the clipboard instead.
    tool!(
        "cff",
        "Open in CFF Explorer (copies path to clipboard)",
        ["CFF Explorer", "cff explorer"],
        copy = true
    ),
    tool!("reshacker", "Open in Resource Hacker", ["ResourceHacker"]),
    tool!("x64dbg", "Debug in x64dbg", ["x64dbg"], confirm = true),
    tool!("x32dbg", "Debug in x32dbg", ["x32dbg"], confirm = true),
    // -accepteula: Sysinternals tools pop a blocking EULA dialog on first run
    // otherwise, which from a headless service just looks like nothing happened.
    tool!(
        "sigcheck",
        "Sigcheck",
        ["sigcheck64", "sigcheck"],
        args = ["-accepteula", "-nobanner"],
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
    tool!("die", "Open in DIE", ["die", "diec"]),
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
    tool!("die", "Open in DIE", ["die", "diec"]),
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
    if !def.copy_path_instead {
        argv.push(target.to_string_lossy().into_owned());
    }

    let cwd = tool_path.parent().unwrap_or(Path::new("."));

    if !def.needs_terminal {
        info!("Launching {} on {}", def.label, target.display());
        let child = Command::new(tool_path)
            .args(&argv)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("could not launch {}", def.label))?;
        if def.copy_path_instead {
            copy_target_to_clipboard(target);
        }
        // Ingot is a background service, so a GUI tool it spawns can't take
        // focus from the browser on Windows - nudge its window to the front.
        raise_foreground(&child);
        return Ok(());
    }

    // terminal tool
    let full: Vec<String> = std::iter::once(tool_path.to_string_lossy().into_owned())
        .chain(argv)
        .collect();
    let joined = shell_join(&full);

    #[cfg(target_os = "windows")]
    {
        // A temp .bat sidesteps the `cmd /c start "" cmd /k "..."` nested-quote
        // trap, and a fresh console window comes to the foreground on its own.
        let body = format!(
            "@echo off\r\ntitle {}\r\n{joined}\r\necho.\r\npause\r\n(goto) 2>nul & del \"%~f0\"\r\n",
            def.label
        );
        let mut bat = tempfile::Builder::new()
            .prefix("ingot-launch-")
            .suffix(".bat")
            .tempfile()
            .context("could not create a launch script")?;
        std::io::Write::write_all(&mut bat, body.as_bytes())?;
        let (_, bat_path) = bat.keep().context("could not persist the launch script")?;
        Command::new("cmd")
            .args(["/c", "start", ""])
            .arg(&bat_path)
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

/// Bring a just-spawned GUI tool's window to the foreground (Windows only;
/// a no-op elsewhere - X11/Wayland window managers raise new windows already).
#[cfg(windows)]
fn raise_foreground(child: &std::process::Child) {
    crate::win_foreground::raise_when_ready(child.id());
}
#[cfg(not(windows))]
fn raise_foreground(_child: &std::process::Child) {}

/// Put `target`'s path on the clipboard, for a tool whose own command line
/// can't take it directly (`ToolDef::copy_path_instead`).
#[cfg(windows)]
fn copy_target_to_clipboard(target: &Path) {
    if !crate::win_clipboard::set_text(&target.to_string_lossy()) {
        tracing::warn!("Could not copy {} to the clipboard", target.display());
    }
}
#[cfg(not(windows))]
fn copy_target_to_clipboard(_target: &Path) {}

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

/// Replace anything but ASCII letters/digits/`-`/`_` with `_`, so a
/// filename-derived string is safe to hand to Ghidra as a project name (see
/// the caller for the real failure this fixes).
fn sanitize_for_ghidra(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Copy `target` into `dir` under a generated, special-character-free name
/// (same extension, so Ghidra's own format sniffing still sees it), for
/// handing to Ghidra's `analyzeHeadless.bat` in place of a path that might
/// contain characters its own batch script's parser can't survive (see
/// `launch_ghidra`'s doc comment). Deleted by the launch script once
/// `-import` has read it - Ghidra copies the bytes into its own project
/// storage, so the staged copy isn't needed past that point.
#[cfg(windows)]
fn stage_safe_import_copy(target: &Path, dir: &Path) -> anyhow::Result<PathBuf> {
    let suffix = target
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let mut staged = tempfile::Builder::new()
        .prefix("ingot-ghidra-import-")
        .suffix(&suffix)
        .tempfile_in(dir)
        .context("could not stage a copy of the target file for Ghidra")?;
    let mut src =
        std::fs::File::open(target).context("could not open the target file to stage it")?;
    std::io::copy(&mut src, &mut staged)?;
    let (_, path) = staged.keep().context("could not persist the staged copy")?;
    Ok(path)
}

/// Kick off `analyzeHeadless` for `target` into `<report_dir>/ghidra_projects/`,
/// then - on success - open the resulting project in Ghidra's own GUI so the
/// analyzed program is loaded for review (the behaviour Winnow / Rowan have).
/// Fire-and-forget: the chain runs detached as one shell process, so it
/// survives an Ingot restart. Headless analysis runs for minutes.
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
    // The SHA1 branch is always plain hex, already safe. The fallback (no
    // SHA1 - e.g. Ghidra invoked before a scan populated the session) uses
    // the file's own stem, which can carry anything the original filename
    // had; sanitized because Ghidra's own argument parser, independently of
    // the cmd-level issues below, rejected a project name containing a
    // space + parens with `InvalidInputException: Bad argument` (confirmed
    // against a real sample) even when the import path was already a safe
    // staged copy.
    let project_name = match sha1.filter(|s| !s.is_empty()) {
        Some(s) => format!("BinSifter_{s}"),
        None => format!(
            "BinSifter_{}",
            sanitize_for_ghidra(
                target
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("sample")
            )
        ),
    };
    let gpr = projects_dir.join(format!("{project_name}.gpr"));

    // `analyzeHeadless` lives at `<ghidra>/support/analyzeHeadless[.bat]`;
    // `ghidraRun[.bat]` (the GUI launcher) sits at the install root.
    let ghidra_root = Path::new(headless)
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("."));
    let ghidra_run = ghidra_root.join(if cfg!(windows) {
        "ghidraRun.bat"
    } else {
        "ghidraRun"
    });

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        // cmd.exe's batch parser treats `(` / `)` as command-grouping syntax
        // EVEN INSIDE a double-quoted argument on the same line - confirmed
        // with a real sample filename containing "(2)": cmd exited 255,
        // "X.exe was unexpected at this time". The fix is the standard one
        // for paths with special characters in batch files: `set "VAR=value"`
        // each path on its own line (cmd does not re-tokenize inside a `set`
        // assignment), then reference `%VAR%` in the actual command -
        // expansion happens after the line is already parsed, so the
        // literal parens in the expanded value are never re-interpreted as
        // syntax.
        //
        // `call` is also required before each nested .bat/.cmd: without it,
        // invoking one batch file from another transfers control into it
        // permanently - when analyzeHeadless.bat finished, cmd would exit
        // the whole script right there, never reaching the ghidraRun line
        // (analysis itself completes fine; only the chain silently dies).
        //
        // Even with both fixes above, a real sample named "...(2).exe" still
        // failed - traced to Ghidra's OWN `analyzeHeadless.bat` (not ours):
        // its `-import` handling does `for %%f in ("%~2") do (...)`, and
        // cmd's `for ... in (set)` clause has the same "parens break parsing"
        // problem even for a value that arrived safely via our own `set`
        // var. Confirmed directly: analyzing a byte-identical copy under a
        // paren-free name succeeded in 15s ("Analysis succeeded"); the
        // original path silently produced zero output. Since this lives
        // inside Ghidra's bundled script, not ours, the fix is to never hand
        // it a risky path at all - stage a safe-named copy and import that.
        let import_target = stage_safe_import_copy(target, &projects_dir)?;
        let headless_s = headless.to_string();
        let projects_dir_s = projects_dir.to_string_lossy().into_owned();
        let target_s = import_target.to_string_lossy().into_owned();
        let ghidra_run_s = ghidra_run.to_string_lossy().into_owned();
        let gpr_s = gpr.to_string_lossy().into_owned();
        let body = format!(
            "@echo off\r\n\
             set \"INGOT_HEADLESS={headless_s}\"\r\n\
             set \"INGOT_PROJDIR={projects_dir_s}\"\r\n\
             set \"INGOT_PROJNAME={project_name}\"\r\n\
             set \"INGOT_TARGET={target_s}\"\r\n\
             set \"INGOT_GHIDRARUN={ghidra_run_s}\"\r\n\
             set \"INGOT_GPR={gpr_s}\"\r\n\
             call \"%INGOT_HEADLESS%\" \"%INGOT_PROJDIR%\" \"%INGOT_PROJNAME%\" -import \"%INGOT_TARGET%\" -overwrite -analysisTimeoutPerFile 300\r\n\
             set \"INGOT_RC=%errorlevel%\"\r\n\
             del \"%INGOT_TARGET%\"\r\n\
             if not \"%INGOT_RC%\" == \"0\" goto done\r\n\
             call \"%INGOT_GHIDRARUN%\" \"%INGOT_GPR%\"\r\n\
             :done\r\n\
             del \"%~f0\"\r\n"
        );
        let mut bat = tempfile::Builder::new()
            .prefix("ingot-ghidra-")
            .suffix(".bat")
            .tempfile()
            .context("could not create the Ghidra launch script")?;
        std::io::Write::write_all(&mut bat, body.as_bytes())?;
        let (_, bat_path) = bat.keep().context("could not persist the launch script")?;
        Command::new("cmd")
            .args(["/c"])
            .arg(&bat_path)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("could not launch analyzeHeadless")?;
        // The GUI opens at the end of a detached shell chain minutes from
        // now, with no PID on this side to hand to raise_when_ready() - so
        // watch for its window by the title Ghidra gives it instead
        // ("Ghidra: <project name>", confirmed against a real run). Timeout
        // covers the -analysisTimeoutPerFile 300 ceiling plus startup slack.
        crate::win_foreground::raise_when_titled(
            format!("Ghidra: {project_name}"),
            std::time::Duration::from_secs(480),
        );
    }
    #[cfg(not(target_os = "windows"))]
    {
        // POSIX sh doesn't share cmd's "parens are special even when quoted"
        // trap - `(`/`)` lose all special meaning inside double quotes - so
        // shell_join's plain quoting is sufficient here.
        let analyze = shell_join(&[
            headless.to_string(),
            projects_dir.to_string_lossy().into_owned(),
            project_name.clone(),
            "-import".into(),
            target.to_string_lossy().into_owned(),
            "-overwrite".into(),
            "-analysisTimeoutPerFile".into(),
            "300".into(),
        ]);
        let open_gui = shell_join(&[
            ghidra_run.to_string_lossy().into_owned(),
            gpr.to_string_lossy().into_owned(),
        ]);
        Command::new("sh")
            .arg("-c")
            .arg(format!("{analyze} && {open_gui}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("could not launch analyzeHeadless")?;
    }

    info!(
        "Ghidra headless analysis started for {} - the GUI opens with the project when it finishes",
        target.display()
    );
    Ok(gpr)
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
    fn sanitize_for_ghidra_strips_spaces_and_parens() {
        // real sample name that broke Ghidra's own Java argument parser
        assert_eq!(
            sanitize_for_ghidra("General_Player_V1.7.0.0.T.20150929 (2)"),
            "General_Player_V1_7_0_0_T_20150929__2_"
        );
        assert_eq!(sanitize_for_ghidra("plain_name-123"), "plain_name-123");
    }

    #[test]
    fn die_prefers_the_gui_over_the_console_build() {
        for set in [WINDOWS_TOOLS, LINUX_TOOLS, MACOS_TOOLS] {
            let die = set.iter().find(|t| t.id == "die").unwrap();
            // "die" (the GUI) must be tried before "diec" (DIE console)
            let pos = |n| die.filenames.iter().position(|f| *f == n);
            assert!(pos("die") < pos("diec"), "die must outrank diec");
        }
    }

    #[test]
    fn sigcheck_accepts_the_eula_non_interactively() {
        let sc = WINDOWS_TOOLS.iter().find(|t| t.id == "sigcheck").unwrap();
        assert!(sc.args_before_target.contains(&"-accepteula"));
        assert!(sc.needs_terminal);
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
