//! Windows-only: bring a just-launched GUI tool's window to the top.
//!
//! Ingot runs as a loopback HTTP service with no window of its own, so a GUI
//! tool it spawns can't take activation from the browser (Windows'
//! foreground-activation lock). [`raise_when_ready`] polls briefly for a
//! just-spawned process's top-level window (matched by PID);
//! [`raise_when_titled`] does the same for a tool - Ghidra - launched via a
//! detached shell chain, where no PID is available on the Rust side, so the
//! window is matched by its known title substring instead, over a much
//! longer window (headless analysis can run for minutes before the GUI ever
//! appears). Both lift the window with a `HWND_TOPMOST` -> `HWND_NOTOPMOST`
//! Z-order toggle.
//!
//! Deliberately does NOT use `AttachThreadInput` / forced `SetForegroundWindow`:
//! attaching to another process's input queue mid-startup crashes some Qt apps
//! (DIE was exiting ~4 s after launch). The toggle only changes Z-order - the
//! window ends up visible on top; the user clicks it to give it focus. Every
//! failure path is a silent no-op.

use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, EnumWindows, GetWindow, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, IsIconic, IsWindowVisible, SetForegroundWindow, SetWindowPos,
    ShowWindow, GW_OWNER, HWND_NOTOPMOST, HWND_TOPMOST, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE,
    SW_RESTORE,
};

/// What [`enum_proc`] is looking for - a specific process, or any window
/// whose title contains a substring (used when the target process' PID
/// isn't known, e.g. a GUI spawned at the end of a detached shell chain).
enum Match {
    Pid(u32),
    TitleContains(String),
}

struct Hunt {
    matcher: Match,
    found: HWND,
}

fn window_text(hwnd: HWND) -> String {
    unsafe {
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; len as usize + 1];
        let copied = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
        if copied <= 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..copied as usize])
    }
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let hunt = &mut *(lparam as *mut Hunt);
    // a real main window: visible, top-level (no owner window)
    if IsWindowVisible(hwnd) == 0 || !GetWindow(hwnd, GW_OWNER).is_null() {
        return 1; // keep going
    }
    let matches = match &hunt.matcher {
        Match::Pid(pid) => {
            let mut wpid: u32 = 0;
            GetWindowThreadProcessId(hwnd, &mut wpid);
            wpid == *pid
        }
        Match::TitleContains(needle) => window_text(hwnd).contains(needle.as_str()),
    };
    if matches {
        hunt.found = hwnd;
        return 0; // stop enumerating
    }
    1
}

fn find_window(matcher: Match) -> HWND {
    let mut hunt = Hunt {
        matcher,
        found: std::ptr::null_mut(),
    };
    unsafe { EnumWindows(Some(enum_proc), &mut hunt as *mut Hunt as LPARAM) };
    hunt.found
}

fn lift(hwnd: HWND) {
    const FLAGS: u32 = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;
    unsafe {
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        }
        // Z-order bump only - no input-queue attachment, safe for Qt apps.
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, FLAGS);
        SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, FLAGS);
        BringWindowToTop(hwnd);
        SetForegroundWindow(hwnd); // best effort; a no-op if the OS refuses
    }
}

/// Poll `find` every `poll_every` until `deadline`, lifting the first match
/// (and once more shortly after, to catch a splash-screen -> main window
/// swap - PE Studio and CFF Explorer both do this on launch).
fn watch_and_lift(deadline: Instant, poll_every: Duration, find: impl Fn() -> HWND) {
    loop {
        let hwnd = find();
        if !hwnd.is_null() {
            lift(hwnd);
            thread::sleep(Duration::from_millis(900));
            let again = find();
            if !again.is_null() {
                lift(again);
            }
            return;
        }
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(poll_every);
    }
}

/// Spawn a detached watcher: for up to ~8 s, look for a visible top-level
/// window owned by `pid` and lift it to the top. Returns immediately.
pub fn raise_when_ready(pid: u32) {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
        watch_and_lift(deadline, Duration::from_millis(200), || {
            find_window(Match::Pid(pid))
        });
    });
}

/// Spawn a detached watcher: for up to `timeout`, look for a visible
/// top-level window whose title contains `title_substring` and lift it to
/// the top. For a tool (Ghidra) launched at the end of a detached shell
/// chain, where no PID is available on the Rust side to match against, but
/// the eventual window's title is known ahead of time. Polls every 2s
/// rather than 200ms - this runs for minutes, not seconds.
pub fn raise_when_titled(title_substring: String, timeout: Duration) {
    thread::spawn(move || {
        let deadline = Instant::now() + timeout;
        watch_and_lift(deadline, Duration::from_secs(2), || {
            find_window(Match::TitleContains(title_substring.clone()))
        });
    });
}
