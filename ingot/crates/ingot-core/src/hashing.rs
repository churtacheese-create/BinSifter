//! Hashing + Shannon entropy - the one pass every scanned file goes through
//! regardless of configuration.
//!
//! Port of `binsifter.core.hashing`: a single streaming read builds MD5,
//! SHA-1, SHA-256 and a byte-frequency histogram together ("free once the
//! file is already being read for SHA-1/MD5"). Entropy is bits/byte over the
//! whole file, `-1.0` for a zero-length file (undefined, not zero - matches
//! the `-1` "not computed" sentinel used elsewhere).

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// 1 MiB - matches the read buffer size the other variants use.
const CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HashResult {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    /// bits/byte, 0.0..=8.0, or -1.0 for a zero-length file.
    pub entropy: f64,
    pub length: u64,
}

pub fn hash_and_score_file(path: &Path) -> io::Result<HashResult> {
    let mut file = File::open(path)?;
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut counts = [0u64; 256];
    let mut total: u64 = 0;

    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
        for &b in chunk {
            counts[b as usize] += 1;
        }
        total += n as u64;
    }

    Ok(HashResult {
        md5: hex::encode(md5.finalize()),
        sha1: hex::encode(sha1.finalize()),
        sha256: hex::encode(sha256.finalize()),
        entropy: shannon_entropy(&counts, total),
        length: total,
    })
}

fn shannon_entropy(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return -1.0;
    }
    let total = total as f64;
    let mut entropy = 0.0f64;
    for &count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / total;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn known_vectors_for_abc() {
        let f = write_temp(b"abc");
        let r = hash_and_score_file(f.path()).unwrap();
        assert_eq!(r.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(r.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            r.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(r.length, 3);
    }

    #[test]
    fn empty_file_entropy_is_negative_one() {
        let f = write_temp(b"");
        let r = hash_and_score_file(f.path()).unwrap();
        assert_eq!(r.entropy, -1.0);
        assert_eq!(r.length, 0);
        // hash of the empty input is still well-defined
        assert_eq!(r.md5, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn single_byte_repeated_has_zero_entropy() {
        let f = write_temp(&[0x41u8; 4096]);
        let r = hash_and_score_file(f.path()).unwrap();
        assert!(r.entropy.abs() < 1e-9, "entropy was {}", r.entropy);
    }

    #[test]
    fn uniform_bytes_approach_eight_bits() {
        let data: Vec<u8> = (0..=255u16)
            .cycle()
            .take(256 * 400)
            .map(|b| b as u8)
            .collect();
        let f = write_temp(&data);
        let r = hash_and_score_file(f.path()).unwrap();
        assert!((r.entropy - 8.0).abs() < 1e-6, "entropy was {}", r.entropy);
    }
}
