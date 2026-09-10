//! NSRL known-good hash lookup - cached, memory-mapped binary index.
//!
//! Port of `binsifter.core.nsrl`. The on-disk cache format is deliberately
//! **identical** to the Python/PowerShell variants (`struct.Struct("<4sIQqQ")`
//! header = 32 bytes) so a cache built by any variant is usable by the
//! others:
//!
//! ```text
//! header  (32 bytes, little-endian):
//!   magic           [u8; 4]   b"BSNL"
//!   format_version  u32       1
//!   record_count    u64
//!   source_mtime_ns i64
//!   source_size     u64
//! body:
//!   record_count * 20-byte raw SHA-1 digests, sorted ascending
//! ```
//!
//! The cache lives under `<report_dir>/.bsifter-nsrl-cache/` (never beside
//! the NSRL source, which is routinely on a read-only evidence drive).
//! Staleness is a two-field check: the source file's current mtime + size
//! must still match what the header recorded. Building streams 20-byte
//! records straight to a temp file, sorts them in place over an mmap, then
//! atomically renames into place.
//!
//! Source parsing accepts an RDSv2-style CSV (a `SHA-1` column) or a plain
//! one-hash-per-line list.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use memmap2::{Mmap, MmapMut};
use sha2::{Digest, Sha256};
use tracing::warn;

const MAGIC: [u8; 4] = *b"BSNL";
const FORMAT_VERSION: u32 = 1;
const RECORD_SIZE: usize = 20;
const HEADER_SIZE: usize = 32;

#[derive(Debug, Clone, Copy)]
struct Header {
    count: u64,
    source_mtime_ns: i64,
    source_size: u64,
}

impl Header {
    fn parse(bytes: &[u8]) -> Option<Header> {
        if bytes.len() < HEADER_SIZE || bytes[0..4] != MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        if version != FORMAT_VERSION {
            return None;
        }
        Some(Header {
            count: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            source_mtime_ns: i64::from_le_bytes(bytes[16..24].try_into().ok()?),
            source_size: u64::from_le_bytes(bytes[24..32].try_into().ok()?),
        })
    }

    fn to_bytes(self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.count.to_le_bytes());
        out[16..24].copy_from_slice(&self.source_mtime_ns.to_le_bytes());
        out[24..32].copy_from_slice(&self.source_size.to_le_bytes());
        out
    }
}

/// Read-only view over a sorted array of 20-byte binary SHA-1 digests.
/// `count == 0` covers both "not configured" and "configured but empty".
pub struct NsrlIndex {
    mmap: Option<Mmap>,
    count: usize,
}

impl NsrlIndex {
    pub fn empty() -> Self {
        NsrlIndex {
            mmap: None,
            count: 0,
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }

    fn records(&self) -> &[[u8; RECORD_SIZE]] {
        match &self.mmap {
            Some(m) => {
                let body = &m[HEADER_SIZE..HEADER_SIZE + self.count * RECORD_SIZE];
                bytemuck::cast_slice(body)
            }
            None => &[],
        }
    }

    /// `true` if `sha1_hex` (40 hex chars) is present in the index.
    pub fn contains(&self, sha1_hex: &str) -> bool {
        if self.count == 0 {
            return false;
        }
        let mut needle = [0u8; RECORD_SIZE];
        if hex::decode_to_slice(sha1_hex.trim(), &mut needle).is_err() {
            return false;
        }
        self.records().binary_search(&needle).is_ok()
    }
}

/// `os.path.normcase` equivalent for cache-filename identity: on Windows,
/// lowercase and switch `/` to `\`; elsewhere, unchanged.
fn normcase(path: &str) -> String {
    if cfg!(windows) {
        path.to_lowercase().replace('/', "\\")
    } else {
        path.to_string()
    }
}

/// Path of the cache file for a given NSRL source + report directory.
/// Creates the `.bsifter-nsrl-cache/` directory if missing.
pub fn get_cache_path(nsrl_path: &str, report_directory: &str) -> PathBuf {
    let report_directory = if report_directory.is_empty() {
        crate::config::data_root().join("Reports")
    } else {
        PathBuf::from(report_directory)
    };
    let cache_dir = report_directory.join(".bsifter-nsrl-cache");
    let _ = fs::create_dir_all(&cache_dir);

    let digest = hex::encode(Sha256::digest(normcase(nsrl_path).as_bytes()));
    let short = &digest[..16];
    let stem = Path::new(nsrl_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("nsrl");
    cache_dir.join(format!("{stem}_{short}.bsifter-nsrl-idx"))
}

fn read_header(cache_path: &Path) -> Option<Header> {
    let mut buf = [0u8; HEADER_SIZE];
    let mut f = File::open(cache_path).ok()?;
    f.read_exact(&mut buf).ok()?;
    Header::parse(&buf)
}

fn source_mtime_ns_and_size(source_path: &Path) -> Option<(i64, u64)> {
    let md = fs::metadata(source_path).ok()?;
    let size = md.len();
    let mtime = md.modified().ok()?;
    let ns = match mtime.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(e) => -(e.duration().as_nanos() as i64),
    };
    Some((ns, size))
}

/// `true` if a valid, current cache already exists for `source_path`.
pub fn cache_is_fresh(cache_path: &Path, source_path: &Path) -> bool {
    let Some(h) = read_header(cache_path) else {
        return false;
    };
    let Some((mtime_ns, size)) = source_mtime_ns_and_size(source_path) else {
        return false;
    };
    h.source_mtime_ns == mtime_ns && h.source_size == size
}

/// Record count from an existing cache header without mapping the body.
pub fn read_cached_count(cache_path: &Path) -> u64 {
    read_header(cache_path).map(|h| h.count).unwrap_or(0)
}

/// Streaming callback over every valid 40-hex SHA-1 in an NSRL source file.
fn for_each_sha1(source_path: &Path, mut emit: impl FnMut(&str)) -> std::io::Result<()> {
    let mut sniff = vec![0u8; 4096];
    let n = File::open(source_path)?.read(&mut sniff)?;
    let sniff_str = String::from_utf8_lossy(&sniff[..n]);
    let is_csv = sniff_str.contains(',') && sniff_str.to_uppercase().contains("SHA-1");

    let mut reader = BufReader::new(File::open(source_path)?);
    let valid = |s: &str| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit());

    if is_csv {
        let mut header_line = String::new();
        reader.read_line(&mut header_line)?;
        let Some(sha1_col) = header_line
            .trim_end()
            .split(',')
            .position(|h| h.trim().trim_matches('"').eq_ignore_ascii_case("SHA-1"))
        else {
            warn!(
                "NSRL file {} looked like CSV but had no SHA-1 column",
                source_path.display()
            );
            return Ok(());
        };
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            if let Some(cell) = line.trim_end().split(',').nth(sha1_col) {
                let cell = cell.trim().trim_matches('"');
                if valid(cell) {
                    emit(cell);
                }
            }
        }
    } else {
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let cand = line.trim();
            if valid(cand) {
                emit(cand);
            }
        }
    }
    Ok(())
}

/// Parse `source_path` once and write a sorted binary cache to `cache_path`.
/// Returns the record count. Expensive - only call when [`cache_is_fresh`]
/// reports the existing cache missing or stale.
pub fn build_index(source_path: &Path, cache_path: &Path) -> std::io::Result<u64> {
    let tmp_path = cache_path.with_extension("bsifter-nsrl-idx.tmp");

    let mut count: u64 = 0;
    {
        let mut w = BufWriter::new(File::create(&tmp_path)?);
        w.write_all(&[0u8; HEADER_SIZE])?; // placeholder, patched below
        let mut rec = [0u8; RECORD_SIZE];
        for_each_sha1(source_path, |hexstr| {
            if hex::decode_to_slice(hexstr, &mut rec).is_ok() {
                let _ = w.write_all(&rec);
                count += 1;
            }
        })?;
        w.flush()?;
    }

    if count > 0 {
        let file = File::options().read(true).write(true).open(&tmp_path)?;
        let mut mmap = unsafe { MmapMut::map_mut(&file)? };
        let body = &mut mmap[HEADER_SIZE..HEADER_SIZE + count as usize * RECORD_SIZE];
        let records: &mut [[u8; RECORD_SIZE]] = bytemuck::cast_slice_mut(body);
        records.sort_unstable();
        mmap.flush()?;
    }

    let (mtime_ns, size) = source_mtime_ns_and_size(source_path).unwrap_or((0, 0));
    let header = Header {
        count,
        source_mtime_ns: mtime_ns,
        source_size: size,
    };
    {
        let mut f = File::options().write(true).open(&tmp_path)?;
        f.write_all(&header.to_bytes())?;
        f.flush()?;
    }

    fs::rename(&tmp_path, cache_path)?;
    Ok(count)
}

/// Memory-map an existing cache built by [`build_index`]. Returns an empty
/// index (never errors) if the cache is missing or its header is unreadable.
pub fn open_index(cache_path: &Path) -> NsrlIndex {
    let Some(header) = read_header(cache_path) else {
        return NsrlIndex::empty();
    };
    if header.count == 0 {
        return NsrlIndex::empty();
    }
    let Ok(file) = File::open(cache_path) else {
        return NsrlIndex::empty();
    };
    let mmap = match unsafe { Mmap::map(&file) } {
        Ok(m) => m,
        Err(e) => {
            warn!("Could not mmap NSRL cache {}: {e}", cache_path.display());
            return NsrlIndex::empty();
        }
    };
    let expected = HEADER_SIZE + header.count as usize * RECORD_SIZE;
    if mmap.len() < expected {
        warn!(
            "NSRL cache {} is truncated ({} < {expected})",
            cache_path.display(),
            mmap.len()
        );
        return NsrlIndex::empty();
    }
    NsrlIndex {
        mmap: Some(mmap),
        count: header.count as usize,
    }
}

/// All-in-one: ensure a fresh cache exists for `nsrl_path` and return its
/// path, building it first if missing/stale. `None` if `nsrl_path` is blank
/// or not a real file.
pub fn prepare_nsrl_index(nsrl_path: &str, report_directory: &str) -> Option<PathBuf> {
    if nsrl_path.is_empty() || !Path::new(nsrl_path).is_file() {
        return None;
    }
    let cache_path = get_cache_path(nsrl_path, report_directory);
    if !cache_is_fresh(&cache_path, Path::new(nsrl_path)) {
        if let Err(e) = build_index(Path::new(nsrl_path), &cache_path) {
            warn!("Could not build NSRL cache: {e}");
            return None;
        }
    }
    Some(cache_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn header_roundtrips_and_size_is_32() {
        assert_eq!(HEADER_SIZE, 32);
        let h = Header {
            count: 7,
            source_mtime_ns: -123,
            source_size: 999,
        };
        let parsed = Header::parse(&h.to_bytes()).unwrap();
        assert_eq!(parsed.count, 7);
        assert_eq!(parsed.source_mtime_ns, -123);
        assert_eq!(parsed.source_size, 999);
    }

    #[test]
    fn build_then_lookup_plain_list() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("nsrl.txt");
        let mut f = File::create(&src).unwrap();
        writeln!(f, "A9993E364706816ABA3E25717850C26C9CD0D89D").unwrap();
        writeln!(f, "not a hash").unwrap();
        writeln!(f, "0000000000000000000000000000000000000000").unwrap();
        writeln!(f, "da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
        f.flush().unwrap();

        let cache = dir.path().join("nsrl.idx");
        assert_eq!(build_index(&src, &cache).unwrap(), 3);

        let idx = open_index(&cache);
        assert_eq!(idx.count(), 3);
        assert!(idx.contains("a9993e364706816aba3e25717850c26c9cd0d89d"));
        assert!(idx.contains("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"));
        assert!(idx.contains("0000000000000000000000000000000000000000"));
        assert!(!idx.contains("ffffffffffffffffffffffffffffffffffffffff"));
        assert!(!idx.contains("garbage"));
    }

    #[test]
    fn build_then_lookup_csv() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("NSRLFile.txt");
        let mut f = File::create(&src).unwrap();
        writeln!(f, "\"SHA-1\",\"MD5\",\"CRC32\",\"FileName\"").unwrap();
        writeln!(
            f,
            "\"A9993E364706816ABA3E25717850C26C9CD0D89D\",\"x\",\"y\",\"a.dll\""
        )
        .unwrap();
        f.flush().unwrap();

        let cache = dir.path().join("c.idx");
        assert_eq!(build_index(&src, &cache).unwrap(), 1);
        assert!(open_index(&cache).contains("a9993e364706816aba3e25717850c26c9cd0d89d"));
    }

    #[test]
    fn freshness_check() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("n.txt");
        fs::write(&src, "da39a3ee5e6b4b0d3255bfef95601890afd80709\n").unwrap();
        let cache = dir.path().join("n.idx");
        build_index(&src, &cache).unwrap();
        assert!(cache_is_fresh(&cache, &src));

        fs::write(
            &src,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709\na9993e364706816aba3e25717850c26c9cd0d89d\n",
        )
        .unwrap();
        assert!(!cache_is_fresh(&cache, &src));
    }

    #[test]
    fn missing_cache_opens_empty() {
        let idx = open_index(Path::new("/no/such/cache"));
        assert_eq!(idx.count(), 0);
        assert!(!idx.contains("a9993e364706816aba3e25717850c26c9cd0d89d"));
    }
}
