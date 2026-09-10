//! Import-table hash (imphash) - port of `binsifter.core.imphash.compute_imphash`.
//!
//! Reproduces pefile's `PE.get_imphash()` (the Mandiant import-hash
//! algorithm) byte-for-byte, using `goblin` for PE parsing instead of
//! pefile:
//!
//! 1. For each imported DLL, lowercase its name and strip a trailing
//!    `.dll` / `.ocx` / `.sys` (only those three).
//! 2. For each imported symbol, in import-table order:
//!    - by name  -> the name, lowercased
//!    - by ordinal -> the name from the `ordlookup` table for that DLL
//!      (see [`crate::imphash_ordinals`]), or `ord<N>` if not found
//! 3. Join `"<lib>.<func>"` entries with `,` and MD5 the result.
//!
//! Returns `None` for a non-PE, a PE with no import directory, or a parse
//! failure - the same best-effort contract as the Python variant
//! (`imphash or None`).
//!
//! Rich-header hash (`RichHash`) is deliberately not computed here - the
//! Python variant hasn't ported it either (its byte layout needs checking
//! against a known sample first), so Ingot leaves `rich_hash` unset too.
//!
//! [`cluster_by_imphash`] is the post-scan exact-match grouping pass.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use goblin::pe::options::{ParseMode, ParseOptions};
use goblin::pe::PE;
use md5::{Digest, Md5};
use tracing::warn;

use crate::imphash_ordinals::ORDINAL_TABLES;

/// pefile: `if len(parts) > 1 and parts[1] in ["ocx", "sys", "dll"]`.
fn strip_dll_ext(name_lower: &str) -> &str {
    if let Some((base, ext)) = name_lower.rsplit_once('.') {
        if matches!(ext, "ocx" | "sys" | "dll") {
            return base;
        }
    }
    name_lower
}

/// pefile: `ordlookup.ordLookup(dll_lower, ordinal, make_name=True)`.
fn ordinal_lookup(dll_lower: &str, ordinal: u16) -> String {
    for (dll, table) in ORDINAL_TABLES {
        if *dll == dll_lower {
            if let Ok(i) = table.binary_search_by_key(&ordinal, |&(o, _)| o) {
                return table[i].1.to_string();
            }
            break;
        }
    }
    format!("ord{ordinal}")
}

/// MD5-hex imphash of `path`, or `None` if it isn't a PE with imports.
pub fn compute_imphash(path: &Path) -> Option<String> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            warn!("Could not read {} for imphash: {e}", path.display());
            return None;
        }
    };

    let opts = ParseOptions::default().with_parse_mode(ParseMode::Permissive);
    let pe = PE::parse_with_opts(&bytes, &opts).ok()?;
    let import_data = pe.import_data?;

    let mut impstrs: Vec<String> = Vec::new();
    for entry in &import_data.import_data {
        let dll_full = entry.name.to_ascii_lowercase();
        let libname = strip_dll_ext(&dll_full);
        let Some(ilt) = &entry.import_lookup_table else {
            continue;
        };
        for lut in ilt {
            use goblin::pe::import::SyntheticImportLookupTableEntry as E;
            let funcname = match lut {
                E::HintNameTableRVA((_, hint)) if !hint.name.is_empty() => hint.name.to_string(),
                // Empty name on a hint/name entry: pefile falls back to an
                // ordinal lookup keyed on the hint, so do the same.
                E::HintNameTableRVA((_, hint)) => ordinal_lookup(&dll_full, hint.hint),
                E::OrdinalNumber(ord) => ordinal_lookup(&dll_full, *ord),
            };
            if funcname.is_empty() {
                continue;
            }
            impstrs.push(format!("{}.{}", libname, funcname.to_ascii_lowercase()));
        }
    }

    if impstrs.is_empty() {
        return None;
    }
    Some(hex::encode(Md5::digest(impstrs.join(",").as_bytes())))
}

/// Exact-match clustering across a scan batch - port of
/// `imphash.cluster_by_imphash`. `imphashes`: `path -> imphash-or-None`,
/// keyed so iteration is ascending path order. Returns `path -> (cluster_id,
/// cluster_size)` only for files whose imphash is shared by at least one
/// other file in the batch; callers default the rest to `(-1, 0)`. Cluster
/// ids are numbered in first-seen-imphash order.
pub fn cluster_by_imphash(
    imphashes: &BTreeMap<String, Option<String>>,
) -> BTreeMap<String, (i32, i32)> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for (path, ih) in imphashes {
        let Some(ih) = ih.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        groups
            .entry(ih.to_string())
            .or_insert_with(|| {
                order.push(ih.to_string());
                Vec::new()
            })
            .push(path.clone());
    }

    let mut out = BTreeMap::new();
    let mut cluster_id = 0i32;
    for ih in &order {
        let members = &groups[ih];
        if members.len() < 2 {
            continue;
        }
        let size = members.len() as i32;
        for p in members {
            out.insert(p.clone(), (cluster_id, size));
        }
        cluster_id += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ext_matches_pefile() {
        assert_eq!(strip_dll_ext("kernel32.dll"), "kernel32");
        assert_eq!(strip_dll_ext("comctl32.ocx"), "comctl32");
        assert_eq!(strip_dll_ext("ntoskrnl.sys"), "ntoskrnl");
        // not one of the three -> keep whole
        assert_eq!(
            strip_dll_ext("api-ms-win-crt-runtime-l1-1-0.dll"),
            "api-ms-win-crt-runtime-l1-1-0"
        );
        assert_eq!(strip_dll_ext("foo.bar"), "foo.bar");
        assert_eq!(strip_dll_ext("noext"), "noext");
    }

    #[test]
    fn ordinal_lookup_known_and_unknown() {
        // ws2_32.dll ordinal 1 = accept (from ordlookup)
        assert_eq!(ordinal_lookup("ws2_32.dll", 1), "accept");
        assert_eq!(ordinal_lookup("wsock32.dll", 2), "bind");
        // known dll, unknown ordinal -> ord<N>
        assert_eq!(ordinal_lookup("ws2_32.dll", 65000), "ord65000");
        // unknown dll -> ord<N>
        assert_eq!(ordinal_lookup("weird.dll", 7), "ord7");
    }

    #[test]
    fn non_pe_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, b"not a PE file at all").unwrap();
        assert_eq!(compute_imphash(&f), None);
    }

    #[test]
    fn missing_file_returns_none() {
        assert_eq!(compute_imphash(Path::new("/no/such/file.exe")), None);
    }

    #[test]
    fn cluster_groups_shared_imphashes_only() {
        let mut m = BTreeMap::new();
        m.insert("a.exe".to_string(), Some("HHHH".to_string()));
        m.insert("b.exe".to_string(), Some("HHHH".to_string()));
        m.insert("c.exe".to_string(), Some("KKKK".to_string())); // unique -> absent
        m.insert("d.exe".to_string(), None); // no imphash -> absent
        m.insert("e.exe".to_string(), Some("HHHH".to_string()));

        let clusters = cluster_by_imphash(&m);
        assert_eq!(clusters.len(), 3);
        assert_eq!(clusters["a.exe"], (0, 3));
        assert_eq!(clusters["b.exe"], (0, 3));
        assert_eq!(clusters["e.exe"], (0, 3));
        assert!(!clusters.contains_key("c.exe"));
        assert!(!clusters.contains_key("d.exe"));
    }
}
