//! MITRE ATT&CK technique enrichment - port of
//! `binsifter.core.attack_db.AttackDb`.
//!
//! Loads MITRE's public STIX 2.x `enterprise-attack.json` bundle once per
//! scan (`config.attack_data_path` - optional, same "leave it blank to
//! skip" convention as NSRL/blocklist/YARA) and resolves
//! `attack.mitre.org/...` reference URLs found in a matched YARA rule's
//! metadata to the ATT&CK technique(s) they map to.
//!
//! Direct technique links (`.../techniques/T1082`) resolve immediately.
//! Software / group links (`.../software/S0061`, `.../groups/G0016`)
//! resolve indirectly through that entity's `uses` relationships.
//!
//! Two quirks are carried over verbatim from the C#/Python source for
//! identical-output parity, not "fixed":
//!
//! * The 10-technique cap is checked once per matched URL, after that URL's
//!   whole branch has run - a single software/group URL that resolves to
//!   more than 10 `uses` entries can push the list past 10 in one step.
//! * `ident` is trimmed of `/ . )` even though the capture group can never
//!   contain `)` - kept for exact parity.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;
use tracing::warn;

static ATTACK_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)attack\.mitre\.org/(techniques|software|groups)/([A-Za-z0-9./]+)").unwrap()
});

const MAX_RESOLVED_TECHNIQUES: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackTechniqueInfo {
    pub id: String,
    pub name: String,
    pub tactic: Option<String>,
}

#[derive(Debug, Default)]
pub struct AttackDb {
    /// keyed by lowercased external id (e.g. "t1055.011")
    techniques_by_id: HashMap<String, AttackTechniqueInfo>,
    /// keyed by lowercased entity external id (e.g. "s0061"), value = STIX id
    entity_external_id_to_stix_id: HashMap<String, String>,
    /// keyed by lowercased STIX id, value = external technique ids it "uses"
    uses_techniques: HashMap<String, Vec<String>>,
}

impl AttackDb {
    pub fn technique_count(&self) -> usize {
        self.techniques_by_id.len()
    }

    /// Errors on a missing / unreadable / malformed file - the caller
    /// (engine) logs it and disables TTP mapping for the scan rather than
    /// aborting, mirroring the other variants.
    pub fn load(json_path: &Path) -> anyhow::Result<AttackDb> {
        let bytes = std::fs::read(json_path)?;
        let doc: Value = serde_json::from_slice(&bytes)?;
        let objects = doc
            .get("objects")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let mut db = AttackDb::default();
        // Local to this load: STIX id -> ATT&CK external id, used only to
        // resolve relationship target_refs in the second pass.
        let mut stix_id_to_external_id: HashMap<String, String> = HashMap::new();

        for obj in objects {
            let obj_type = obj.get("type").and_then(Value::as_str).unwrap_or("");
            if !matches!(
                obj_type,
                "attack-pattern" | "malware" | "tool" | "intrusion-set"
            ) {
                continue;
            }
            if obj.get("revoked") == Some(&Value::Bool(true))
                || obj.get("x_mitre_deprecated") == Some(&Value::Bool(true))
            {
                continue;
            }

            let Some(stix_id) = obj.get("id").and_then(Value::as_str) else {
                continue;
            };
            let Some(external_id) = attack_external_id(obj) else {
                continue;
            };

            stix_id_to_external_id.insert(stix_id.to_lowercase(), external_id.to_string());

            if obj_type == "attack-pattern" {
                let name = obj
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(external_id)
                    .to_string();
                db.techniques_by_id.insert(
                    external_id.to_lowercase(),
                    AttackTechniqueInfo {
                        id: external_id.to_string(),
                        name,
                        tactic: primary_tactic(obj),
                    },
                );
            } else {
                db.entity_external_id_to_stix_id
                    .insert(external_id.to_lowercase(), stix_id.to_string());
            }
        }

        for obj in objects {
            if obj.get("type").and_then(Value::as_str) != Some("relationship") {
                continue;
            }
            if obj.get("relationship_type").and_then(Value::as_str) != Some("uses") {
                continue;
            }
            if obj.get("revoked") == Some(&Value::Bool(true)) {
                continue;
            }
            let (Some(source_ref), Some(target_ref)) = (
                obj.get("source_ref").and_then(Value::as_str),
                obj.get("target_ref").and_then(Value::as_str),
            ) else {
                continue;
            };
            if !target_ref.to_lowercase().starts_with("attack-pattern--") {
                continue;
            }
            let Some(tech_external_id) = stix_id_to_external_id.get(&target_ref.to_lowercase())
            else {
                continue;
            };
            db.uses_techniques
                .entry(source_ref.to_lowercase())
                .or_default()
                .push(tech_external_id.clone());
        }

        Ok(db)
    }

    /// Every technique resolvable from a matched rule's metadata values
    /// (each already stringified), deduplicated case-insensitively on
    /// technique id, capped at [`MAX_RESOLVED_TECHNIQUES`].
    pub fn resolve<'a, I>(&self, meta_values: I) -> Vec<AttackTechniqueInfo>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut results: Vec<AttackTechniqueInfo> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for value in meta_values {
            if value.is_empty() {
                continue;
            }
            for caps in ATTACK_URL_RE.captures_iter(value) {
                let kind = caps[1].to_lowercase();
                let ident = caps[2].trim_matches(['/', '.', ')']);

                if kind == "techniques" {
                    let tech_id = ident.replace('/', ".");
                    if let Some(info) = self.techniques_by_id.get(&tech_id.to_lowercase()) {
                        if seen.insert(info.id.to_lowercase()) {
                            results.push(info.clone());
                        }
                    }
                } else if let Some(stix_id) = self
                    .entity_external_id_to_stix_id
                    .get(&ident.to_lowercase())
                {
                    if let Some(tech_ids) = self.uses_techniques.get(&stix_id.to_lowercase()) {
                        for tech_id in tech_ids {
                            if let Some(info) = self.techniques_by_id.get(&tech_id.to_lowercase()) {
                                if seen.insert(info.id.to_lowercase()) {
                                    results.push(info.clone());
                                }
                            }
                        }
                    }
                }

                if results.len() >= MAX_RESOLVED_TECHNIQUES {
                    return results;
                }
            }
        }
        results
    }
}

pub fn load_optional(attack_data_path: &str) -> Option<AttackDb> {
    if attack_data_path.is_empty() || !Path::new(attack_data_path).is_file() {
        return None;
    }
    match AttackDb::load(Path::new(attack_data_path)) {
        Ok(db) => Some(db),
        Err(e) => {
            warn!("Could not load MITRE ATT&CK data, TTP mapping disabled for this scan: {e}");
            None
        }
    }
}

fn attack_external_id(obj: &Value) -> Option<&str> {
    obj.get("external_references")?
        .as_array()?
        .iter()
        .find(|r| r.get("source_name").and_then(Value::as_str) == Some("mitre-attack"))
        .and_then(|r| r.get("external_id"))
        .and_then(Value::as_str)
}

fn primary_tactic(obj: &Value) -> Option<String> {
    let phases = obj.get("kill_chain_phases")?.as_array()?;
    let names: Vec<String> = phases
        .iter()
        .filter(|p| p.get("kill_chain_name").and_then(Value::as_str) == Some("mitre-attack"))
        .filter_map(|p| p.get("phase_name").and_then(Value::as_str))
        .map(title_case)
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names.join("/"))
    }
}

/// `"initial-access"` -> `"Initial Access"` - only the first char of each
/// hyphen part is uppercased (matches the C#/Python minimal transform, not
/// a full title-case pass).
fn title_case(kebab: &str) -> String {
    kebab
        .split('-')
        .map(|p| {
            let mut chars = p.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn mini_bundle() -> String {
        serde_json::json!({
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--aaaa",
                    "name": "Process Injection",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1055"}],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
                        {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}
                    ]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--bbbb",
                    "name": "System Information Discovery",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1082"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--old",
                    "revoked": true,
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]
                },
                {
                    "type": "malware",
                    "id": "malware--mmmm",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "S0061"}]
                },
                {
                    "type": "relationship",
                    "relationship_type": "uses",
                    "source_ref": "malware--mmmm",
                    "target_ref": "attack-pattern--aaaa"
                },
                {
                    "type": "relationship",
                    "relationship_type": "uses",
                    "source_ref": "malware--mmmm",
                    "target_ref": "attack-pattern--bbbb"
                }
            ]
        })
        .to_string()
    }

    fn load_mini() -> AttackDb {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(mini_bundle().as_bytes()).unwrap();
        f.flush().unwrap();
        AttackDb::load(f.path()).unwrap()
    }

    #[test]
    fn counts_only_live_techniques() {
        let db = load_mini();
        assert_eq!(db.technique_count(), 2); // T9999 is revoked
    }

    #[test]
    fn direct_technique_link_resolves() {
        let db = load_mini();
        let got = db.resolve(["see https://attack.mitre.org/techniques/T1082/ for detail"]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "T1082");
        assert_eq!(got[0].name, "System Information Discovery");
        assert_eq!(got[0].tactic, None);
    }

    #[test]
    fn subtechnique_slash_form_and_tactic() {
        let db = load_mini();
        // techniques/T1055/011 style -> "T1055.011" (not in mini db) but T1055 is
        let got = db.resolve(["https://attack.mitre.org/techniques/T1055"]);
        assert_eq!(got[0].id, "T1055");
        assert_eq!(
            got[0].tactic.as_deref(),
            Some("Defense Evasion/Privilege Escalation")
        );
    }

    #[test]
    fn software_link_resolves_via_uses_and_dedups() {
        let db = load_mini();
        let got = db.resolve([
            "https://attack.mitre.org/software/S0061",
            "https://attack.mitre.org/techniques/T1082", // already covered by S0061's uses
        ]);
        let ids: Vec<&str> = got.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, ["T1055", "T1082"]);
    }

    #[test]
    fn no_match_is_empty() {
        let db = load_mini();
        assert!(db.resolve(["nothing to see", "score = 90"]).is_empty());
    }
}
