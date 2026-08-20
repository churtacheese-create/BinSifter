"""MITRE ATT&CK technique enrichment - resolves attack.mitre.org reference
URLs found in a matched YARA rule's meta values to the ATT&CK technique(s)
they map to.

Direct port of the C# `BinSifter.AttackDb` class embedded in
BinSifter-Rowan.ps1 (lines ~655-860). Loads MITRE's public
STIX 2.x "enterprise-attack.json" bundle once per scan (config.AttackDataPath
- optional, same "leave the folder empty to skip this feature" convention as
NSRL/blocklist/YARA/capa) and builds three lookup tables:

  - technique external ID (e.g. "T1055.011") -> AttackTechniqueInfo, from
    every non-revoked/non-deprecated "attack-pattern" object.
  - software/group external ID (e.g. "S0061", "G0016") -> its STIX id, from
    every non-revoked/non-deprecated "malware"/"tool"/"intrusion-set" object.
  - STIX id -> list of technique external IDs that entity "uses", from every
    non-revoked "relationship" object with relationship_type == "uses"
    whose target is an attack-pattern.

Direct technique links (.../techniques/T1082) resolve immediately. Software/
group links (.../software/S0061, .../groups/G0016) resolve indirectly
through that entity's "uses" relationships, since a rule referencing a piece
of malware by name doesn't by itself say which technique matched - only
that the file might be related to that malware/group.

Ported field-for-field/behavior-for-behavior against the C# source,
including two quirks that are deliberately NOT "fixed" here since the goal
is identical output for identical input, not an improved algorithm:

  - Resolve()'s 10-technique cap is checked once per regex match (i.e. once
    per attack.mitre.org URL found), not once per technique appended. A
    single software/group URL that resolves to more than 10 "uses" entries
    can push the result list past 10 in one step, before the cap check
    fires - see the loop structure below, matching the C# `if (results.Count
    >= 10) return results;` placement exactly (it's inside the per-Match
    loop, after the whole if/else branch for that match has run, not inside
    the inner per-technique loop).
  - id.strip("/.)")  mirrors the C# `.Trim('/', '.', ')')` on the regex's
    second capture group - dead code in practice (the capture group's own
    character class, [A-Za-z0-9./]+, can never actually contain ')'), kept
    only for exact parity rather than being quietly dropped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

# Same pattern as the C# version's AttackUrlPattern - case-insensitive,
# same three link kinds (techniques/software/groups).
_ATTACK_URL_RE = re.compile(
    r"attack\.mitre\.org/(techniques|software|groups)/([A-Za-z0-9./]+)",
    re.IGNORECASE,
)

# Resolve() stops adding once the running total reaches this - a prolific
# threat actor can use 50+ techniques, past which point it stops being
# useful on a single dashboard row. See module docstring for the exact
# (not-per-technique) point this is checked.
_MAX_RESOLVED_TECHNIQUES = 10


@dataclass
class AttackTechniqueInfo:
    id: str
    name: str
    tactic: str | None


class AttackDb:
    def __init__(self) -> None:
        # All three keyed by a lowercased version of their natural key, for
        # case-insensitive lookup - matches the C# version's
        # StringComparer.OrdinalIgnoreCase dictionaries throughout.
        self._techniques_by_id: dict[str, AttackTechniqueInfo] = {}
        self._entity_external_id_to_stix_id: dict[str, str] = {}
        self._uses_techniques: dict[str, list[str]] = {}

    @property
    def technique_count(self) -> int:
        return len(self._techniques_by_id)

    @classmethod
    def load(cls, json_path: str) -> "AttackDb":
        """Raises on a missing/unreadable/malformed file - same as the C#
        version's Load(), which the PowerShell caller wraps in its own
        try/catch ("Could not load MITRE ATT&CK data, TTP mapping disabled
        for this scan") rather than swallowing here. engine.py mirrors that
        same try/except at the call site.
        """
        db = cls()
        # Maps a STIX object's own id -> its ATT&CK external id, local to
        # this load() call (not stored on the db) - only needed to resolve
        # relationship target_refs to technique external ids during the
        # second pass below, same as the C# version's local
        # stixIdToExternalId dict.
        stix_id_to_external_id: dict[str, str] = {}

        with open(json_path, "r", encoding="utf-8") as f:
            doc = json.load(f)

        objects = doc.get("objects", [])

        for obj in objects:
            obj_type = obj.get("type")
            if obj_type not in ("attack-pattern", "malware", "tool", "intrusion-set"):
                continue
            if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
                continue

            stix_id = obj.get("id")
            external_id = _get_attack_external_id(obj)
            if not stix_id or external_id is None:
                continue

            stix_id_to_external_id[stix_id.lower()] = external_id

            if obj_type == "attack-pattern":
                name = obj.get("name") or external_id
                db._techniques_by_id[external_id.lower()] = AttackTechniqueInfo(
                    id=external_id, name=name, tactic=_get_primary_tactic(obj)
                )
            else:
                db._entity_external_id_to_stix_id[external_id.lower()] = stix_id

        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != "uses":
                continue
            if obj.get("revoked") is True:
                continue

            source_ref = obj.get("source_ref")
            target_ref = obj.get("target_ref")
            if not source_ref or not target_ref:
                continue
            if not target_ref.lower().startswith("attack-pattern--"):
                continue

            tech_external_id = stix_id_to_external_id.get(target_ref.lower())
            if tech_external_id is None:
                continue

            db._uses_techniques.setdefault(source_ref.lower(), []).append(tech_external_id)

        return db

    def resolve(self, meta: dict) -> list[AttackTechniqueInfo]:
        """Returns every technique resolvable from a matched YARA rule's
        meta values, deduplicated (case-insensitive, on technique id),
        capped at _MAX_RESOLVED_TECHNIQUES - see module docstring for the
        exact point the cap is checked.
        """
        results: list[AttackTechniqueInfo] = []
        seen: set[str] = set()

        for value in meta.values():
            if value is None:
                continue
            value_str = value if isinstance(value, str) else str(value)
            if not value_str:
                continue

            for m in _ATTACK_URL_RE.finditer(value_str):
                kind = m.group(1).lower()
                ident = m.group(2).strip("/.)")

                if kind == "techniques":
                    tech_id = ident.replace("/", ".")
                    info = self._techniques_by_id.get(tech_id.lower())
                    if info is not None and info.id.lower() not in seen:
                        seen.add(info.id.lower())
                        results.append(info)
                else:
                    stix_id = self._entity_external_id_to_stix_id.get(ident.lower())
                    if stix_id is None:
                        continue
                    tech_ids = self._uses_techniques.get(stix_id.lower())
                    if not tech_ids:
                        continue
                    for tech_id in tech_ids:
                        info = self._techniques_by_id.get(tech_id.lower())
                        if info is not None and info.id.lower() not in seen:
                            seen.add(info.id.lower())
                            results.append(info)

                if len(results) >= _MAX_RESOLVED_TECHNIQUES:
                    return results

        return results


def _get_attack_external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
            return ref["external_id"]
    return None


def _get_primary_tactic(obj: dict) -> str | None:
    names = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack" and "phase_name" in phase:
            names.append(_title_case(phase["phase_name"]))
    return "/".join(names) if names else None


def _title_case(kebab: str) -> str:
    """"initial-access" -> "Initial Access" - only the first character of
    each hyphen-separated part is uppercased (matches the C# version's
    char.ToUpperInvariant(parts[i][0]) + parts[i].Substring(1), not a full
    str.title()/capitalize() pass), since ATT&CK phase names are already
    all-lowercase kebab-case and this is a deliberately minimal transform.
    """
    if not kebab:
        return kebab
    parts = kebab.split("-")
    return " ".join(p[0].upper() + p[1:] if p else p for p in parts)
