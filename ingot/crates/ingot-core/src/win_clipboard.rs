//! Windows-only: set the system clipboard text.
//!
//! Used for tools like CFF Explorer whose own command line is reserved for
//! something else (CFF's is its Lua scripting engine - passing a target
//! path there is silently ignored), so the quick-launch menu copies the
//! path instead and the analyst pastes it into the tool's Open dialog -
//! matching Rowan's and Winnow's `copy_path_instead` behavior. Ingot and the
//! browser it serves are always the same machine (loopback-only), so
//! setting the OS clipboard from the server process is exactly "the
//! analyst's clipboard".
//!
//! Best-effort: any failure just means the copy silently didn't happen - the
//! tool itself has already launched by the time this runs.

use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

/// Replace the clipboard contents with `text`. Returns whether it worked.
pub fn set_text(text: &str) -> bool {
    // UTF-16, NUL-terminated - what CF_UNICODETEXT requires.
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = wide.len() * std::mem::size_of::<u16>();

    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return false;
        }
        let ok = set_text_inner(&wide, byte_len);
        CloseClipboard();
        ok
    }
}

unsafe fn set_text_inner(wide: &[u16], byte_len: usize) -> bool {
    if EmptyClipboard() == 0 {
        return false;
    }
    let hmem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
    if hmem.is_null() {
        return false;
    }
    let ptr = GlobalLock(hmem);
    if ptr.is_null() {
        return false;
    }
    std::ptr::copy_nonoverlapping(wide.as_ptr().cast::<u8>(), ptr.cast::<u8>(), byte_len);
    GlobalUnlock(hmem);
    // The clipboard now owns hmem - it frees it, not us.
    !SetClipboardData(CF_UNICODETEXT as u32, hmem).is_null()
}
