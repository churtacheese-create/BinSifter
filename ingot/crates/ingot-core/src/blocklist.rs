//! Offline known-bad hash blocklist - the mirror image of [`crate::nsrl`].
//!
//! Port of `binsifter.core.blocklist`. Accepts either a plain
//! one-hash-per-line list or a MalwareBazaar-style CSV export (comment lines
//! starting with `#`, hash somewhere in the columns). A missing or
//! unparsable blocklist just means the check is skipped this run, never a
//! scan-ending error. Hashes are stored uppercase; lookups test SHA-256,
//! then SHA-1, then MD5.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use tracing::warn;

fn is_hash_token(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Returns a set of uppercase hashes (whatever kinds the source file holds).
/// Returns an empty set on any read error (graceful skip).
pub fn load_blocklist_hashes(path: &Path) -> HashSet<String> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            warn!("Could not read blocklist {}: {e}", path.display());
            return HashSet::new();
        }
    };

    let mut hashes = HashSet::new();
    let looks_like_csv = text
        .lines()
        .take(5)
        .any(|line| !line.starts_with('#') && line.contains(','));

    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if looks_like_csv {
            for cell in line.split(',') {
                let candidate = cell.trim().trim_matches('"');
                if is_hash_token(candidate) {
                    hashes.insert(candidate.to_ascii_uppercase());
                }
            }
        } else {
            let candidate = line.trim();
            if is_hash_token(candidate) {
                hashes.insert(candidate.to_ascii_uppercase());
            }
        }
    }
    hashes
}

/// Returns `(ReputationStatus, ReputationSource)` - `("KnownBad", "<kind>")`
/// on a hit, `("Clean", "")` otherwise. Checks all three hash kinds since a
/// blocklist export might key on any of them.
pub fn check_reputation(
    md5: &str,
    sha1: &str,
    sha256: &str,
    blocklist: &HashSet<String>,
) -> (String, String) {
    if blocklist.contains(&sha256.to_ascii_uppercase()) {
        return ("KnownBad".to_string(), "SHA-256".to_string());
    }
    if blocklist.contains(&sha1.to_ascii_uppercase()) {
        return ("KnownBad".to_string(), "SHA-1".to_string());
    }
    if blocklist.contains(&md5.to_ascii_uppercase()) {
        return ("KnownBad".to_string(), "MD5".to_string());
    }
    ("Clean".to_string(), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_with(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn plain_list_parsing() {
        let f = temp_with(
            "d41d8cd98f00b204e9800998ecf8427e\n\
             # a comment\n\
             da39a3ee5e6b4b0d3255bfef95601890afd80709\n\
             not-a-hash\n",
        );
        let set = load_blocklist_hashes(f.path());
        assert_eq!(set.len(), 2);
        assert!(set.contains("D41D8CD98F00B204E9800998ECF8427E"));
    }

    #[test]
    fn malwarebazaar_style_csv() {
        let f = temp_with(
            "# some header banner\n\
             \"first_seen\",\"sha256_hash\",\"md5_hash\"\n\
             \"2024-01-01\",\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\",\"900150983cd24fb0d6963f7d28e17f72\"\n",
        );
        let set = load_blocklist_hashes(f.path());
        assert!(set.contains("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));
        assert!(set.contains("900150983CD24FB0D6963F7D28E17F72"));
    }

    #[test]
    fn reputation_precedence_and_miss() {
        let mut set = HashSet::new();
        set.insert("AAAA".to_string());
        set.insert("900150983CD24FB0D6963F7D28E17F72".to_string());
        let (status, source) = check_reputation("900150983cd24fb0d6963f7d28e17f72", "x", "y", &set);
        assert_eq!(status, "KnownBad");
        assert_eq!(source, "MD5");

        let (status, source) = check_reputation("a", "b", "c", &set);
        assert_eq!(status, "Clean");
        assert_eq!(source, "");
    }

    #[test]
    fn missing_file_is_empty_not_error() {
        let set = load_blocklist_hashes(Path::new("/no/such/blocklist/file"));
        assert!(set.is_empty());
    }
}
