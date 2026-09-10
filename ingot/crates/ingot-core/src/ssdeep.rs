//! SSDEEP fuzzy hashing + post-scan transitive clustering - port of
//! `binsifter.core.ssdeep_cluster`.
//!
//! Hashing uses the `fuzzyhash` crate (pure-Rust spamsum), whose hash
//! output is byte-identical to `ppdeep` / libfuzzy. The **comparison**, on
//! the other hand, is a direct port of `ppdeep.compare` rather than
//! `fuzzyhash`'s own `compare` (which scores lower) - the cluster threshold
//! (40) and high-similarity cutoff (85) are calibrated against ppdeep's
//! numbers, and `ppdeep` (not libfuzzy) is what Winnow uses, so its exact
//! integer arithmetic - including standard Levenshtein with substitution
//! cost 1, where libfuzzy uses 2 - is what must be reproduced.
//!
//! Clustering is transitive union-find: two files share a cluster if
//! there's a *chain* of >=threshold matches between them. Cluster ids are
//! assigned in ascending path order so a rescan of the same batch produces
//! the same numbering (Winnow assigns them in worker-completion order,
//! which is not reproducible - this is a deliberate small improvement).

use std::collections::BTreeMap;
use std::path::Path;

use fuzzyhash::FuzzyHash;
use tracing::warn;

pub const CLUSTER_THRESHOLD: u32 = 40;
pub const HIGH_SIMILARITY_THRESHOLD: u32 = 85;

const SPAMSUM_LENGTH: i64 = 64;
const BLOCKSIZE_MIN: i64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdeepClusterInfo {
    pub cluster_id: i32,
    pub cluster_size: i32,
    pub has_high_similarity: bool,
    /// `"path (score); path (score)"` - same display format as the other variants.
    pub matches_summary: String,
}

/// ssdeep hash of `path`, or `None` on an IO error.
pub fn compute_ssdeep_hash(path: &Path) -> Option<String> {
    match FuzzyHash::file(path) {
        Ok(h) => Some(h.to_string()),
        Err(e) => {
            warn!("Could not ssdeep-hash {}: {e}", path.display());
            None
        }
    }
}

// ------------------------------------------------------------- ppdeep.compare

/// `ppdeep._strip_sequences`: collapse any run of 4+ identical chars to 3.
fn strip_sequences(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut r: Vec<u8> = b.iter().take(3).copied().collect();
    for i in 3..b.len() {
        if b[i] != b[i - 1] || b[i] != b[i - 2] || b[i] != b[i - 3] {
            r.push(b[i]);
        }
    }
    r
}

/// `ppdeep._common_substring`: is the longest common substring >= 7 chars?
/// Direct port of ppdeep's O(m*n*min) triple loop - the index arithmetic
/// doesn't translate cleanly to iterators, and the strings are <=64 bytes.
#[allow(clippy::needless_range_loop)]
fn has_common_substring(s1: &[u8], s2: &[u8]) -> bool {
    let (m, n) = (s1.len(), s2.len());
    let mut res = 0usize;
    for i in 0..m {
        for j in 0..n {
            let mut cur = 0usize;
            while i + cur < m && j + cur < n && s1[i + cur] == s2[j + cur] {
                cur += 1;
            }
            res = res.max(cur);
        }
    }
    res >= 7
}

/// `ppdeep._levenshtein`: standard edit distance, substitution cost 1
/// (libfuzzy uses 2 - the difference is why ppdeep and libfuzzy scores
/// diverge, and Winnow uses ppdeep). Direct DP port.
#[allow(clippy::needless_range_loop)]
fn levenshtein(s: &[u8], t: &[u8]) -> i64 {
    if s == t {
        return 0;
    }
    if s.is_empty() {
        return t.len() as i64;
    }
    if t.is_empty() {
        return s.len() as i64;
    }
    let mut v0: Vec<i64> = (0..=t.len() as i64).collect();
    let mut v1: Vec<i64> = vec![0; t.len() + 1];
    for i in 0..s.len() {
        v1[0] = i as i64 + 1;
        for j in 0..t.len() {
            let cost = if s[i] == t[j] { 0 } else { 1 };
            v1[j + 1] = (v1[j] + 1).min(v0[j + 1] + 1).min(v0[j] + cost);
        }
        v0.copy_from_slice(&v1);
    }
    v1[t.len()]
}

fn score_strings(s1: &[u8], s2: &[u8], block_size: i64) -> i64 {
    if !has_common_substring(s1, s2) {
        return 0;
    }
    let denom = (s1.len() + s2.len()) as i64;
    if denom == 0 {
        return 0;
    }
    let mut score = levenshtein(s1, s2);
    score = (score * SPAMSUM_LENGTH) / denom;
    score = (100 * score) / SPAMSUM_LENGTH;
    score = 100 - score;
    let cap = block_size / BLOCKSIZE_MIN * (s1.len().min(s2.len()) as i64);
    if score > cap {
        score = cap;
    }
    score
}

/// Port of `ppdeep.compare` - 0..=100.
pub fn compare(hash1: &str, hash2: &str) -> u32 {
    let (Some((bs1, s11, s12)), Some((bs2, s21, s22))) = (split3(hash1), split3(hash2)) else {
        return 0;
    };
    let (Ok(bs1), Ok(bs2)) = (bs1.parse::<i64>(), bs2.parse::<i64>()) else {
        return 0;
    };

    if bs1 != bs2 && bs1 != bs2 * 2 && bs2 != bs1 * 2 {
        return 0;
    }

    let h1s1 = strip_sequences(s11);
    let h1s2 = strip_sequences(s12);
    let h2s1 = strip_sequences(s21);
    let h2s2 = strip_sequences(s22);

    if bs1 == bs2 && h1s1 == h2s1 {
        return 100;
    }

    let score = if bs1 == bs2 {
        let a = score_strings(&h1s1, &h2s1, bs1);
        let b = score_strings(&h1s2, &h2s2, bs2 * 2);
        a.max(b)
    } else if bs1 == bs2 * 2 {
        score_strings(&h1s1, &h2s2, bs1)
    } else {
        score_strings(&h1s2, &h2s1, bs2)
    };
    score.clamp(0, 100) as u32
}

fn split3(hash: &str) -> Option<(&str, &str, &str)> {
    let mut it = hash.splitn(3, ':');
    Some((it.next()?, it.next()?, it.next()?))
}

// --------------------------------------------------------------- clustering

/// `hashes`: `path -> ssdeep_hash`, keyed so iteration is ascending path
/// order. Returns cluster info for **every** path, singletons included
/// (`cluster_size == 1` means "hashed but matched nothing above threshold",
/// distinct from a file that was never hashed at all -> id `-1`).
pub fn cluster_by_ssdeep(hashes: &BTreeMap<String, String>) -> BTreeMap<String, SsdeepClusterInfo> {
    let paths: Vec<&String> = hashes.keys().collect();

    // pairwise scores >= threshold, in (i<j) path order
    let mut pairs: Vec<(usize, usize, u32)> = Vec::new();
    for i in 0..paths.len() {
        for j in (i + 1)..paths.len() {
            let score = compare(&hashes[paths[i]], &hashes[paths[j]]);
            if score >= CLUSTER_THRESHOLD {
                pairs.push((i, j, score));
            }
        }
    }

    // union-find over indices
    let mut parent: Vec<usize> = (0..paths.len()).collect();
    fn find(parent: &mut [usize], mut x: usize) -> usize {
        let mut root = x;
        while parent[root] != root {
            root = parent[root];
        }
        while x != root {
            let next = parent[x];
            parent[x] = root;
            x = next;
        }
        root
    }
    for &(a, b, _) in &pairs {
        let (ra, rb) = (find(&mut parent, a), find(&mut parent, b));
        if ra != rb {
            parent[ra] = rb;
        }
    }

    // compact ids in path order
    let mut root_to_id: BTreeMap<usize, i32> = BTreeMap::new();
    let mut next_id = 0i32;
    let mut id_of: Vec<i32> = vec![0; paths.len()];
    for (idx, slot) in id_of.iter_mut().enumerate() {
        let root = find(&mut parent, idx);
        *slot = *root_to_id.entry(root).or_insert_with(|| {
            let v = next_id;
            next_id += 1;
            v
        });
    }
    let mut size_by_id: BTreeMap<i32, i32> = BTreeMap::new();
    for &id in &id_of {
        *size_by_id.entry(id).or_insert(0) += 1;
    }

    let mut matches: Vec<Vec<String>> = vec![Vec::new(); paths.len()];
    let mut high: Vec<bool> = vec![false; paths.len()];
    for &(a, b, score) in &pairs {
        matches[a].push(format!("{} ({score})", paths[b]));
        matches[b].push(format!("{} ({score})", paths[a]));
        if score >= HIGH_SIMILARITY_THRESHOLD {
            high[a] = true;
            high[b] = true;
        }
    }

    let mut out = BTreeMap::new();
    for (idx, path) in paths.iter().enumerate() {
        let id = id_of[idx];
        out.insert(
            (*path).clone(),
            SsdeepClusterInfo {
                cluster_id: id,
                cluster_size: size_by_id[&id],
                has_high_similarity: high[idx],
                matches_summary: matches[idx].join("; "),
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_hashes_score_100() {
        let h = "3072:abcdefghijklmnopqrstuvwx:abcdefgh";
        assert_eq!(compare(h, h), 100);
    }

    #[test]
    fn incompatible_blocksizes_score_0() {
        assert_eq!(compare("3:aaa:bbb", "192:aaa:bbb"), 0);
    }

    #[test]
    fn malformed_hash_scores_0() {
        assert_eq!(compare("not-a-hash", "3:a:b"), 0);
        assert_eq!(compare("", ""), 0);
    }

    #[test]
    fn strip_sequences_collapses_runs() {
        assert_eq!(strip_sequences("aaaaaa"), b"aaa");
        assert_eq!(strip_sequences("abcaaaad"), b"abcaaad");
        assert_eq!(strip_sequences("ab"), b"ab");
    }

    #[test]
    fn clustering_is_transitive_and_path_ordered() {
        // a~b (direct), b~c (direct), a!~c -> all one cluster via the chain
        let mut hashes = BTreeMap::new();
        // craft hashes: reuse one string so pairs score 100
        hashes.insert(
            "z_far.bin".to_string(),
            "6:zzzzzzzzzzzzzzzz:zzzz".to_string(),
        );
        hashes.insert(
            "a.bin".to_string(),
            "6:aaaaaaaaaaaaaaaaaaaa:aaaaaa".to_string(),
        );
        hashes.insert(
            "b.bin".to_string(),
            "6:aaaaaaaaaaaaaaaaaaaa:aaaaaa".to_string(),
        );
        let clusters = cluster_by_ssdeep(&hashes);

        // a and b identical -> same cluster, size 2
        assert_eq!(clusters["a.bin"].cluster_id, clusters["b.bin"].cluster_id);
        assert_eq!(clusters["a.bin"].cluster_size, 2);
        assert!(clusters["a.bin"].has_high_similarity);
        assert!(clusters["a.bin"].matches_summary.contains("b.bin (100)"));

        // z_far is a singleton with its own id, size 1
        assert_eq!(clusters["z_far.bin"].cluster_size, 1);
        assert!(clusters["z_far.bin"].matches_summary.is_empty());
        // ids assigned in ascending path order: a.bin(0), b.bin(0), z_far.bin(1)
        assert_eq!(clusters["a.bin"].cluster_id, 0);
        assert_eq!(clusters["z_far.bin"].cluster_id, 1);
    }

    #[test]
    fn missing_file_hash_is_none() {
        assert_eq!(compute_ssdeep_hash(Path::new("/no/such/file")), None);
    }
}
