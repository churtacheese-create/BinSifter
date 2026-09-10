//! Draft YARA rule auto-generation per SSDEEP cluster - port of
//! `binsifter.core.yara_rule_gen`.
//!
//! Best-effort, clearly-labelled-as-draft rules built from strings common
//! to every member of a size>=2 SSDEEP cluster. Only cluster members that
//! went through the `PossibleFalseNegative` FLOSS fallback contribute
//! strings (`static_strings_by_path`); a cluster with no contributing
//! members falls back to a filesize-range-only skeleton explicitly flagged
//! as needing manual work. Written to `<report_dir>/generated_rules/` for
//! manual review - never auto-imported.
//!
//! FLOSS isn't ported yet, so `static_strings_by_path` is currently always
//! empty and every generated rule takes the skeleton fallback path - the
//! same behaviour Winnow has today. The full intersection logic is kept so
//! Phase 5 only needs to populate the map.
//!
//! Two quirks are carried over verbatim, not "fixed":
//!
//! * the condition always reads `(3 of them)` regardless of how many
//!   strings were found (a rule built from 1-2 strings can never match) -
//!   these are explicitly unreviewed drafts.
//! * an all-empty-files cluster (`min_size == 0`) skips the size condition.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use crate::model::FileRecord;

const MIN_STRING_LEN: usize = 8;
const MAX_STRING_LEN: usize = 128;
const MAX_COMMON_STRINGS: usize = 12;
const MIN_CLUSTER_SIZE_FOR_RULE: usize = 2;
const FIXED_MATCH_COUNT: u32 = 3;

#[derive(Debug, Clone)]
pub struct DraftRuleGenResult {
    pub rules_written: usize,
    pub output_dir: String,
}

fn sanitize_rule_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `records_by_cluster`: `cluster_id -> members` (callers pass only size>=2
/// clusters; re-checked defensively). Returns how many `.yar` files were
/// written.
pub fn generate_draft_rules(
    records_by_cluster: &BTreeMap<i32, Vec<&FileRecord>>,
    static_strings_by_path: &HashMap<String, Vec<String>>,
    report_directory: &str,
    ssdeep_cluster_threshold: u32,
    timestamp: &str,
) -> std::io::Result<DraftRuleGenResult> {
    let output_dir = PathBuf::from(report_directory).join("generated_rules");
    std::fs::create_dir_all(&output_dir)?;

    let mut rules_written = 0;
    for (&cluster_id, members) in records_by_cluster {
        if members.len() < MIN_CLUSTER_SIZE_FOR_RULE {
            continue;
        }
        let common = intersect_static_strings(members, static_strings_by_path);
        let size_condition = build_size_condition(members);
        let rule_name =
            sanitize_rule_name(&format!("bsifter_ssdeep_cluster_{cluster_id}_{timestamp}"));

        let body = build_rule_lines(
            &rule_name,
            cluster_id,
            members.len(),
            ssdeep_cluster_threshold,
            &common,
            size_condition.as_deref(),
            timestamp,
        );
        std::fs::write(output_dir.join(format!("{rule_name}.yar")), body + "\n")?;
        rules_written += 1;
    }

    Ok(DraftRuleGenResult {
        rules_written,
        output_dir: output_dir.to_string_lossy().into_owned(),
    })
}

fn intersect_static_strings(
    members: &[&FileRecord],
    static_strings_by_path: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    use std::collections::HashSet;

    let mut per_member_sets: Vec<HashSet<String>> = Vec::new();
    let mut ordered_candidates: Option<Vec<String>> = None;

    for member in members {
        if member.path.is_empty() {
            continue;
        }
        let Some(raw) = static_strings_by_path.get(&member.path) else {
            continue;
        };
        let filtered: Vec<String> = raw
            .iter()
            .filter(|s| !s.is_empty() && (MIN_STRING_LEN..=MAX_STRING_LEN).contains(&s.len()))
            .cloned()
            .collect();
        if filtered.is_empty() {
            continue;
        }
        if ordered_candidates.is_none() {
            ordered_candidates = Some(filtered.clone());
        }
        per_member_sets.push(filtered.into_iter().collect());
    }

    let (Some(candidates), true) = (ordered_candidates, per_member_sets.len() >= 2) else {
        return Vec::new();
    };

    let mut common = per_member_sets[0].clone();
    for s in &per_member_sets[1..] {
        common.retain(|x| s.contains(x));
    }

    candidates
        .into_iter()
        .filter(|s| common.contains(s))
        .take(MAX_COMMON_STRINGS)
        .collect()
}

fn build_size_condition(members: &[&FileRecord]) -> Option<String> {
    let sizes: Vec<u64> = members
        .iter()
        .filter(|m| !m.path.is_empty())
        .filter_map(|m| std::fs::metadata(&m.path).ok().map(|md| md.len()))
        .collect();
    let (min_size, max_size) = (*sizes.iter().min()?, *sizes.iter().max()?);
    if min_size == 0 || max_size == 0 {
        return None;
    }
    Some(format!(
        "filesize >= {} and filesize <= {}",
        min_size.saturating_sub(4096),
        max_size + 4096
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_rule_lines(
    rule_name: &str,
    cluster_id: i32,
    cluster_size: usize,
    threshold: u32,
    common_strings: &[String],
    size_condition: Option<&str>,
    timestamp: &str,
) -> String {
    let mut lines = vec![
        "// AUTO-GENERATED DRAFT - review before use. BinSifter Ingot (Rust variant).".to_string(),
        format!("// Built from SSDEEP cluster {cluster_id} ({cluster_size} files, threshold {threshold})."),
        format!(
            "// Common-string basis: {} string(s) shared across FLOSS-analyzed cluster members.",
            common_strings.len()
        ),
        format!("rule {rule_name}"),
        "{".to_string(),
        "    meta:".to_string(),
        r#"        source = "BinSifter auto-generated - DRAFT, not reviewed""#.to_string(),
        format!("        cluster_size = {cluster_size}"),
        format!(r#"        generated = "{timestamp}""#),
    ];

    if !common_strings.is_empty() {
        lines.push("    strings:".to_string());
        for (i, s) in common_strings.iter().enumerate() {
            let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
            lines.push(format!(r#"        $s{i} = "{escaped}""#));
        }
        lines.push("    condition:".to_string());
        let mut cond = "uint16(0) == 0x5A4D and ".to_string();
        if let Some(sc) = size_condition {
            cond.push_str(sc);
            cond.push_str(" and ");
        }
        cond.push_str(&format!("({FIXED_MATCH_COUNT} of them)"));
        lines.push(format!("        {cond}"));
    } else {
        lines.push("    condition:".to_string());
        let mut cond = "uint16(0) == 0x5A4D".to_string();
        if let Some(sc) = size_condition {
            cond.push_str(&format!(" and {sc}"));
        }
        lines.push(format!(
            "        {cond} // TODO: no common strings found - add real detection logic before use"
        ));
    }

    lines.push("}".to_string());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn rec(path: &str) -> FileRecord {
        FileRecord::new(path)
    }

    #[test]
    fn skeleton_rule_when_no_strings() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");
        std::fs::write(&a, vec![0u8; 5000]).unwrap();
        std::fs::write(&b, vec![0u8; 9000]).unwrap();

        let (ra, rb) = (rec(&a.to_string_lossy()), rec(&b.to_string_lossy()));
        let mut by_cluster = BTreeMap::new();
        by_cluster.insert(0, vec![&ra, &rb]);

        let res = generate_draft_rules(
            &by_cluster,
            &HashMap::new(),
            &dir.path().to_string_lossy(),
            40,
            "2026-09-10_120000",
        )
        .unwrap();
        assert_eq!(res.rules_written, 1);

        // the timestamp's dashes are sanitised to underscores in the filename
        // and rule name, same as the Python/PowerShell versions
        let out = std::fs::read_to_string(
            Path::new(&res.output_dir).join("bsifter_ssdeep_cluster_0_2026_09_10_120000.yar"),
        )
        .unwrap();
        assert!(out.contains("rule bsifter_ssdeep_cluster_0_2026_09_10_120000"));
        assert!(out.contains("AUTO-GENERATED DRAFT"));
        assert!(out.contains("uint16(0) == 0x5A4D and filesize >= 904 and filesize <= 13096"));
        assert!(out.contains("TODO: no common strings"));
        assert!(!out.contains("strings:"));
    }

    #[test]
    fn strings_rule_from_common_intersection() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");
        std::fs::write(&a, vec![1u8; 100]).unwrap();
        std::fs::write(&b, vec![1u8; 100]).unwrap();

        let mut strings = HashMap::new();
        strings.insert(
            a.to_string_lossy().into_owned(),
            vec![
                "shared_marker_one".to_string(),
                "only_in_a_here".to_string(),
                "shared_marker_two".to_string(),
            ],
        );
        strings.insert(
            b.to_string_lossy().into_owned(),
            vec![
                "shared_marker_two".to_string(),
                "only_in_b_zzz".to_string(),
                "shared_marker_one".to_string(),
            ],
        );

        let (ra, rb) = (rec(&a.to_string_lossy()), rec(&b.to_string_lossy()));
        let mut by_cluster = BTreeMap::new();
        by_cluster.insert(5, vec![&ra, &rb]);

        let res = generate_draft_rules(
            &by_cluster,
            &strings,
            &dir.path().to_string_lossy(),
            40,
            "T",
        )
        .unwrap();
        let out = std::fs::read_to_string(
            Path::new(&res.output_dir).join("bsifter_ssdeep_cluster_5_T.yar"),
        )
        .unwrap();
        // first contributing member's order = a's order: marker_one then marker_two
        assert!(out.contains(r#"$s0 = "shared_marker_one""#));
        assert!(out.contains(r#"$s1 = "shared_marker_two""#));
        assert!(!out.contains("only_in_a"));
        assert!(out.contains("(3 of them)"));
    }

    #[test]
    fn too_small_cluster_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let solo = rec("solo.bin");
        let mut by_cluster = BTreeMap::new();
        by_cluster.insert(0, vec![&solo]);
        let res = generate_draft_rules(
            &by_cluster,
            &HashMap::new(),
            &dir.path().to_string_lossy(),
            40,
            "T",
        )
        .unwrap();
        assert_eq!(res.rules_written, 0);
    }
}
