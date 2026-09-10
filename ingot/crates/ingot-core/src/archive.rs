//! Archive / compressed-file expansion - port of `binsifter.core.archive`.
//!
//! Decompresses zip / tar / gzip / 7z archives found under the scan source
//! so their contents get scanned as ordinary files. All pure-Rust so static
//! cross builds stay possible: `zip` (+ AES), `tar` + `flate2` / `lzma-rs` /
//! `bzip2-rs` for the tar.* family, `sevenz-rust2` for 7z.
//!
//! Two-pass password handling (same as Winnow): [`expand_archives`]
//! extracts everything that isn't locked and collects the locked ones;
//! [`resolve_locked_archives`] then extracts those a password was supplied
//! for and copies the rest into a `password_protected/` directory for
//! external cracking. Extracted files appear in Results as their own rows,
//! distinguished only by `SourceArchive`. Nested archives expand
//! recursively, bounded by [`MAX_NESTED_DEPTH`].

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};
use tracing::{info, warn};
use walkdir::WalkDir;

/// A documented default, not a blocking design decision (matches Winnow).
pub const MAX_NESTED_DEPTH: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    SevenZip,
    Tar,
    Gzip,
}

/// Longer/compound tar suffixes are matched before the bare `.gz`.
const TAR_SUFFIXES: [&str; 7] = [
    ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar",
];

/// Extension-based (not content-sniffed) - matches `file_type`'s own
/// extension-led classification and avoids decompressing something that
/// merely shares a magic byte sequence.
pub fn classify(path: &Path) -> Option<ArchiveFormat> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if TAR_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        return Some(ArchiveFormat::Tar);
    }
    if name.ends_with(".zip") {
        return Some(ArchiveFormat::Zip);
    }
    if name.ends_with(".7z") {
        return Some(ArchiveFormat::SevenZip);
    }
    if name.ends_with(".gz") {
        return Some(ArchiveFormat::Gzip);
    }
    None
}

pub fn is_archive(path: &Path) -> bool {
    classify(path).is_some()
}

pub fn find_archives(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|p| is_archive(Path::new(p)))
        .cloned()
        .collect()
}

/// Best-effort, read-only: does `path` need a password to extract? tar/gzip
/// have no encryption concept, so always `false` for those.
pub fn needs_password(path: &Path) -> bool {
    match classify(path) {
        Some(ArchiveFormat::Zip) => {
            let Ok(file) = File::open(path) else {
                return false;
            };
            let Ok(mut archive) = zip::ZipArchive::new(file) else {
                return false;
            };
            (0..archive.len()).any(|i| {
                archive
                    .by_index_raw(i)
                    .map(|f| f.encrypted())
                    .unwrap_or(false)
            })
        }
        Some(ArchiveFormat::SevenZip) => matches!(
            sevenz_rust2::ArchiveReader::open(path, sevenz_rust2::Password::empty()),
            Err(sevenz_rust2::Error::PasswordRequired | sevenz_rust2::Error::MaybeBadPassword(_))
        ),
        _ => false,
    }
}

#[derive(Debug, Default)]
pub struct ExpansionResult {
    pub extracted_files: Vec<String>,
    /// extracted path -> the *immediate* containing archive (not the
    /// top-level one, if archives are nested).
    pub source_archive_by_path: HashMap<String, String>,
    /// Populated by pass 1 only.
    pub locked_archives: Vec<String>,
    /// Populated by pass 2 only.
    pub unresolved_archives: Vec<String>,
}

fn dest_dir_for(archive_path: &str, extraction_root: &Path) -> PathBuf {
    let digest = hex::encode(Sha1::digest(archive_path.as_bytes()));
    let stem = Path::new(archive_path)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".to_string());
    let dir = extraction_root.join(format!("{stem}_{}", &digest[..10]));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn unique_path(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    let ext = path.extension().map(|s| s.to_os_string());
    for i in 1.. {
        let mut name = stem.clone();
        name.push(format!("_{i}"));
        if let Some(e) = &ext {
            name.push(".");
            name.push(e);
        }
        let candidate = path.with_file_name(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

// ---------------------------------------------------------------- extractors

fn extract_zip(path: &Path, dest: &Path, password: Option<&str>) -> io::Result<()> {
    let mut archive = zip::ZipArchive::new(File::open(path)?)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let pw = password.map(|p| p.as_bytes().to_vec());
    for i in 0..archive.len() {
        let opts = zip::ZipReadOptions::new().password(pw.as_deref());
        let mut entry = archive
            .by_index_with_options(i, opts)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if entry.is_dir() {
            continue;
        }
        let Some(rel) = entry.enclosed_name() else {
            continue; // path traversal / absolute path - skip
        };
        let out_path = dest.join(rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        io::copy(&mut entry, &mut File::create(&out_path)?)?;
    }
    Ok(())
}

fn extract_7z(path: &Path, dest: &Path, password: Option<&str>) -> io::Result<()> {
    let result = match password {
        Some(pw) => sevenz_rust2::decompress_file_with_password(
            path,
            dest,
            sevenz_rust2::Password::from(pw),
        ),
        None => sevenz_rust2::decompress_file(path, dest),
    };
    result.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

fn extract_tar(path: &Path, dest: &Path) -> io::Result<()> {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    let file = File::open(path)?;
    let reader: Box<dyn Read> = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Box::new(flate2::read::GzDecoder::new(file))
    } else if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        let mut buf = Vec::new();
        lzma_rs::xz_decompress(&mut io::BufReader::new(file), &mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Box::new(io::Cursor::new(buf))
    } else if name.ends_with(".tar.bz2") || name.ends_with(".tbz2") {
        Box::new(bzip2_rs::DecoderReader::new(file))
    } else {
        Box::new(file)
    };

    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_dir() {
            continue;
        }
        // unpack_in returns Ok(false) for an unsafe (traversal/absolute) path
        let _ = entry.unpack_in(dest)?;
    }
    Ok(())
}

fn extract_gzip(path: &Path, dest: &Path) -> io::Result<()> {
    let stem = path
        .file_stem()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    let out_name = if path.extension().and_then(|e| e.to_str()) == Some("gz") {
        stem
    } else {
        let mut n = path.file_name().unwrap_or_default().to_os_string();
        n.push(".decompressed");
        n
    };
    let out_path = dest.join(out_name);
    let mut decoder = flate2::read::GzDecoder::new(File::open(path)?);
    io::copy(&mut decoder, &mut File::create(&out_path)?)?;
    Ok(())
}

fn extract(fmt: ArchiveFormat, path: &Path, dest: &Path, password: Option<&str>) -> io::Result<()> {
    match fmt {
        ArchiveFormat::Zip => extract_zip(path, dest, password),
        ArchiveFormat::SevenZip => extract_7z(path, dest, password),
        ArchiveFormat::Tar => extract_tar(path, dest),
        ArchiveFormat::Gzip => extract_gzip(path, dest),
    }
}

/// Real files under `dir` after an extraction.
fn enumerate_extracted(dir: &Path) -> Vec<String> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_string_lossy().into_owned())
        .collect()
}

// ---------------------------------------------------------------- passes

fn expand_recursive(
    paths: &[String],
    extraction_root: &Path,
    result: &mut ExpansionResult,
    depth: usize,
    on_locked: &mut dyn FnMut(&str, &mut ExpansionResult),
) {
    for path in paths {
        let p = Path::new(path);
        let Some(fmt) = classify(p) else { continue };

        if needs_password(p) {
            on_locked(path, result);
            continue;
        }

        let dest_dir = dest_dir_for(path, extraction_root);
        if let Err(e) = extract(fmt, p, &dest_dir, None) {
            warn!("Could not extract archive {path}, skipping: {e}");
            continue;
        }

        let extracted = enumerate_extracted(&dest_dir);
        for ep in &extracted {
            result.extracted_files.push(ep.clone());
            result
                .source_archive_by_path
                .insert(ep.clone(), path.clone());
        }

        let nested: Vec<String> = extracted
            .into_iter()
            .filter(|e| is_archive(Path::new(e)))
            .collect();
        if nested.is_empty() {
            continue;
        }
        if depth >= MAX_NESTED_DEPTH {
            info!(
                "{} archive(s) nested inside {path} past the {MAX_NESTED_DEPTH}-level cap - left as plain files.",
                nested.len()
            );
            continue;
        }
        expand_recursive(&nested, extraction_root, result, depth + 1, on_locked);
    }
}

/// Pass 1 - extract every archive that does not need a password
/// (recursively); collect every one that does, without opening it.
pub fn expand_archives(archive_paths: &[String], extraction_root: &Path) -> ExpansionResult {
    let mut result = ExpansionResult::default();
    let mut on_locked =
        |path: &str, r: &mut ExpansionResult| r.locked_archives.push(path.to_string());
    expand_recursive(
        archive_paths,
        extraction_root,
        &mut result,
        0,
        &mut on_locked,
    );
    result
}

/// Pass 2 - for each locked archive, extract with `password_map[path]` if
/// present; on any failure (wrong/absent password, corruption) copy the
/// archive into `unresolved_dir` for external cracking. Never mutates the
/// analyst's originals.
pub fn resolve_locked_archives(
    locked_archives: &[String],
    password_map: &HashMap<String, String>,
    extraction_root: &Path,
    unresolved_dir: &Path,
) -> ExpansionResult {
    let mut result = ExpansionResult::default();
    let _ = fs::create_dir_all(unresolved_dir);

    let save_unresolved = |path: &str, r: &mut ExpansionResult| {
        let dest =
            unique_path(unresolved_dir.join(Path::new(path).file_name().unwrap_or_default()));
        if let Err(e) = fs::copy(path, &dest) {
            warn!("Could not copy locked archive {path} for cracking: {e}");
            return;
        }
        info!(
            "Password-protected archive saved for external cracking: {path} -> {}",
            dest.display()
        );
        r.unresolved_archives
            .push(dest.to_string_lossy().into_owned());
    };

    for path in locked_archives {
        let p = Path::new(path);
        let Some(fmt) = classify(p) else { continue };
        let Some(password) = password_map.get(path).filter(|s| !s.is_empty()) else {
            save_unresolved(path, &mut result);
            continue;
        };

        let dest_dir = dest_dir_for(path, extraction_root);
        if let Err(e) = extract(fmt, p, &dest_dir, Some(password)) {
            warn!("Could not unlock archive {path} with the supplied password: {e}");
            save_unresolved(path, &mut result);
            continue;
        }

        let extracted = enumerate_extracted(&dest_dir);
        for ep in &extracted {
            result.extracted_files.push(ep.clone());
            result
                .source_archive_by_path
                .insert(ep.clone(), path.clone());
        }
        let nested: Vec<String> = extracted
            .into_iter()
            .filter(|e| is_archive(Path::new(e)))
            .collect();
        if !nested.is_empty() {
            // a nested locked archive discovered here goes straight to
            // unresolved rather than triggering a second prompt round
            let mut on_locked = |np: &str, r: &mut ExpansionResult| save_unresolved(np, r);
            expand_recursive(&nested, extraction_root, &mut result, 1, &mut on_locked);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn classify_by_extension() {
        assert_eq!(classify(Path::new("a.zip")), Some(ArchiveFormat::Zip));
        assert_eq!(classify(Path::new("a.7z")), Some(ArchiveFormat::SevenZip));
        assert_eq!(classify(Path::new("a.tar")), Some(ArchiveFormat::Tar));
        assert_eq!(classify(Path::new("a.tar.gz")), Some(ArchiveFormat::Tar));
        assert_eq!(classify(Path::new("a.tgz")), Some(ArchiveFormat::Tar));
        assert_eq!(classify(Path::new("a.tar.xz")), Some(ArchiveFormat::Tar));
        assert_eq!(classify(Path::new("a.gz")), Some(ArchiveFormat::Gzip));
        assert_eq!(classify(Path::new("a.rar")), None);
        assert_eq!(classify(Path::new("a.exe")), None);
    }

    fn make_zip(path: &Path, entries: &[(&str, &[u8])], password: Option<&str>) {
        let mut w = zip::ZipWriter::new(File::create(path).unwrap());
        for (name, data) in entries {
            let opts = zip::write::SimpleFileOptions::default();
            let opts = match password {
                Some(pw) => opts.with_aes_encryption(zip::AesMode::Aes256, pw),
                None => opts,
            };
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }

    #[test]
    fn plain_zip_expands() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("bundle.zip");
        make_zip(
            &zip_path,
            &[("a.txt", b"hello"), ("sub/b.bin", b"MZ....")],
            None,
        );

        assert!(!needs_password(&zip_path));
        let root = dir.path().join("extracted");
        let r = expand_archives(&[zip_path.to_string_lossy().into_owned()], &root);
        assert_eq!(r.extracted_files.len(), 2);
        assert!(r.locked_archives.is_empty());
        assert!(r.extracted_files.iter().any(|p| p.ends_with("a.txt")));
        for ep in &r.extracted_files {
            assert_eq!(r.source_archive_by_path[ep], zip_path.to_string_lossy());
        }
    }

    #[test]
    fn aes_zip_is_locked_then_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("secret.zip");
        make_zip(&zip_path, &[("flag.txt", b"S3CR3T")], Some("hunter2"));

        assert!(needs_password(&zip_path));
        let root = dir.path().join("extracted");
        let p1 = expand_archives(&[zip_path.to_string_lossy().into_owned()], &root);
        assert!(p1.extracted_files.is_empty());
        assert_eq!(p1.locked_archives.len(), 1);

        // wrong / no password -> saved for cracking
        let unresolved = dir.path().join("pw");
        let p2 = resolve_locked_archives(&p1.locked_archives, &HashMap::new(), &root, &unresolved);
        assert_eq!(p2.unresolved_archives.len(), 1);
        assert!(Path::new(&p2.unresolved_archives[0]).is_file());

        // right password -> extracted
        let mut pw = HashMap::new();
        pw.insert(
            zip_path.to_string_lossy().into_owned(),
            "hunter2".to_string(),
        );
        let p3 = resolve_locked_archives(&p1.locked_archives, &pw, &root, &unresolved);
        assert_eq!(p3.extracted_files.len(), 1);
        let content = fs::read_to_string(&p3.extracted_files[0]).unwrap();
        assert_eq!(content, "S3CR3T");
    }

    #[test]
    fn nested_zip_expands_recursively() {
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("inner.zip");
        make_zip(&inner, &[("payload.bin", b"inner data")], None);
        let inner_bytes = fs::read(&inner).unwrap();
        let outer = dir.path().join("outer.zip");
        make_zip(&outer, &[("nested/inner.zip", &inner_bytes)], None);

        let root = dir.path().join("x");
        let r = expand_archives(&[outer.to_string_lossy().into_owned()], &root);
        // both the inner.zip itself and its payload.bin
        assert!(r.extracted_files.iter().any(|p| p.ends_with("inner.zip")));
        assert!(r.extracted_files.iter().any(|p| p.ends_with("payload.bin")));
    }

    #[test]
    fn gzip_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("data.bin.gz");
        {
            let mut enc = flate2::write::GzEncoder::new(
                File::create(&gz).unwrap(),
                flate2::Compression::default(),
            );
            enc.write_all(b"decompressed contents").unwrap();
            enc.finish().unwrap();
        }
        let root = dir.path().join("x");
        let r = expand_archives(&[gz.to_string_lossy().into_owned()], &root);
        assert_eq!(r.extracted_files.len(), 1);
        assert!(r.extracted_files[0].ends_with("data.bin"));
        assert_eq!(
            fs::read_to_string(&r.extracted_files[0]).unwrap(),
            "decompressed contents"
        );
    }
}
