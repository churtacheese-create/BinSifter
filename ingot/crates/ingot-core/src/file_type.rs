//! PE / ELF / shellcode magic-byte sniffing and capa-eligibility.
//!
//! Byte-for-byte port of `binsifter.core.file_type` (4096-byte header read,
//! same MZ/PE and `\x7fELF` checks, same shellcode extension/size
//! heuristic, same `PossibleFalseNegative` condition). This decides which
//! files reach real capa/FLOSS analysis in a later phase, so it must match
//! the other variants exactly rather than "close enough".

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// 4096, matching the other variants: a PE's `e_lfanew` can legitimately
/// sit past a small header read on files with an oversized DOS stub.
const HEADER_READ_SIZE: usize = 4096;

const PE_ELF_LIKE_EXTENSIONS: [&str; 4] = ["exe", "dll", "so", "elf"];
const SHELLCODE_EXCLUDED_EXTENSIONS: [&str; 8] =
    ["exe", "dll", "so", "elf", "bin", "o", "raw", "dat"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTypeInfo {
    pub is_pe: bool,
    pub is_elf: bool,
    pub is_shellcode: bool,
    pub capa_eligible: bool,
}

fn read_header(path: &Path) -> Vec<u8> {
    let mut buf = vec![0u8; HEADER_READ_SIZE];
    match File::open(path).and_then(|mut f| f.read(&mut buf)) {
        Ok(n) => {
            buf.truncate(n);
            buf
        }
        Err(_) => Vec::new(),
    }
}

/// Lowercase extension without the dot (`""` if none), matching
/// `pathlib.Path.suffix.lower()` minus the leading `.`.
fn ext_lower(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn classify(path: &Path, file_length: u64) -> FileTypeInfo {
    let header = read_header(path);
    let len = header.len();
    let extension = ext_lower(path);

    let mut is_pe = false;
    if len >= 64 && header[0] == 0x4D && header[1] == 0x5A {
        let pe_offset =
            i32::from_le_bytes([header[0x3C], header[0x3D], header[0x3E], header[0x3F]]);
        if pe_offset >= 0 {
            let off = pe_offset as usize;
            if off + 4 <= len && &header[off..off + 4] == b"PE\x00\x00" {
                is_pe = true;
            }
        }
    }

    let is_elf = len >= 4 && &header[0..4] == b"\x7fELF";

    let is_shellcode = (!is_pe && !is_elf)
        && (((extension == "raw" || extension == "bin") && file_length < 200_000)
            || (!SHELLCODE_EXCLUDED_EXTENSIONS.contains(&extension.as_str())
                && file_length < 100_000));

    FileTypeInfo {
        is_pe,
        is_elf,
        is_shellcode,
        capa_eligible: is_pe || is_elf || is_shellcode,
    }
}

/// A file whose extension claims to be a native executable but whose magic
/// bytes didn't validate as PE/ELF - it never reaches capa despite a YARA
/// hit, so it's worth surfacing (corrupt / truncated / header-stripped).
pub fn is_possible_false_negative(ft: &FileTypeInfo, yara_hit_count: i32, path: &Path) -> bool {
    yara_hit_count > 0
        && !ft.capa_eligible
        && PE_ELF_LIKE_EXTENSIONS.contains(&ext_lower(path).as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp(name: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(name);
        File::create(&p).unwrap().write_all(bytes).unwrap();
        (dir, p)
    }

    fn minimal_pe() -> Vec<u8> {
        // MZ, e_lfanew = 0x40 at offset 0x3C, "PE\0\0" at 0x40
        let mut v = vec![0u8; 0x48];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3C..0x40].copy_from_slice(&0x40i32.to_le_bytes());
        v[0x40..0x44].copy_from_slice(b"PE\x00\x00");
        v
    }

    #[test]
    fn detects_pe() {
        let (_d, p) = temp("a.exe", &minimal_pe());
        let ft = classify(&p, 0x48);
        assert!(ft.is_pe && ft.capa_eligible && !ft.is_elf && !ft.is_shellcode);
    }

    #[test]
    fn detects_elf() {
        let (_d, p) = temp("a.out", b"\x7fELF followed by whatever");
        let ft = classify(&p, 25);
        assert!(ft.is_elf && ft.capa_eligible && !ft.is_pe);
    }

    #[test]
    fn mz_without_pe_signature_is_not_pe() {
        let mut v = vec![0u8; 128];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3C..0x40].copy_from_slice(&0x40i32.to_le_bytes());
        // no "PE\0\0" at 0x40
        let (_d, p) = temp("a.exe", &v);
        let ft = classify(&p, 128);
        assert!(!ft.is_pe);
        // .exe is on the shellcode exclusion list -> not shellcode either
        assert!(!ft.is_shellcode && !ft.capa_eligible);
    }

    #[test]
    fn shellcode_heuristic() {
        // unknown extension, small -> shellcode
        let (_d, p) = temp("payload.sc", &[0x90u8; 200]);
        assert!(classify(&p, 200).is_shellcode);

        // .bin under 200k -> shellcode
        let (_d, p) = temp("stage.bin", &[0u8; 10]);
        assert!(classify(&p, 199_999).is_shellcode);
        assert!(!classify(&p, 200_001).is_shellcode);

        // unknown extension but >= 100k -> not shellcode
        let (_d, p) = temp("big.blob", &[0u8; 10]);
        assert!(!classify(&p, 100_000).is_shellcode);

        // .dat is excluded outright
        let (_d, p) = temp("x.dat", &[0u8; 10]);
        assert!(!classify(&p, 50).is_shellcode);
    }

    #[test]
    fn possible_false_negative() {
        let (_d, p) = temp("trojan.dll", b"not really a PE");
        let ft = classify(&p, 15);
        assert!(!ft.capa_eligible);
        assert!(is_possible_false_negative(&ft, 3, &p));
        assert!(!is_possible_false_negative(&ft, 0, &p)); // needs a YARA hit
        let (_d, p2) = temp("trojan.txt", b"not really a PE");
        assert!(!is_possible_false_negative(&classify(&p2, 15), 3, &p2)); // wrong ext
    }
}
