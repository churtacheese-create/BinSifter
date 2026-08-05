"""Regression tests for binsifter.core.attack_db - the MITRE ATT&CK
technique-resolution logic ported from the C# BinSifter.AttackDb class
(BinSifter-Rowan_v1.3.0-beta.1.ps1, lines ~655-860). Uses a small hand-built
STIX-shaped fixture rather than the real ~50MB enterprise-attack.json (that
file is user-provided, gitignored, and far too large to check in) - the
fixture below covers the same object/relationship shapes actually read by
AttackDb.load().
"""

import json

import pytest

from binsifter.core.attack_db import AttackDb

_TECHNIQUE_T1082 = {
    "type": "attack-pattern",
    "id": "attack-pattern--11111111-1111-1111-1111-111111111111",
    "name": "System Information Discovery",
    "external_references": [
        {"source_name": "mitre-attack", "url": "https://attack.mitre.org/techniques/T1082", "external_id": "T1082"},
    ],
    "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "discovery"},
    ],
}

_TECHNIQUE_T1055_011 = {
    "type": "attack-pattern",
    "id": "attack-pattern--22222222-2222-2222-2222-222222222222",
    "name": "Extra Window Memory Injection",
    "external_references": [
        {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/techniques/T1055/011",
            "external_id": "T1055.011",
        },
    ],
    "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
        {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"},
    ],
}

_REVOKED_TECHNIQUE = {
    "type": "attack-pattern",
    "id": "attack-pattern--33333333-3333-3333-3333-333333333333",
    "name": "Revoked Technique",
    "revoked": True,
    "external_references": [
        {"source_name": "mitre-attack", "url": "https://attack.mitre.org/techniques/T9999", "external_id": "T9999"},
    ],
}

_MALWARE_HDOOR = {
    "type": "malware",
    "id": "malware--44444444-4444-4444-4444-444444444444",
    "name": "HDoor",
    "external_references": [
        {"source_name": "mitre-attack", "url": "https://attack.mitre.org/software/S0061", "external_id": "S0061"},
    ],
}

_RELATIONSHIP_HDOOR_USES_T1082 = {
    "type": "relationship",
    "id": "relationship--55555555-5555-5555-5555-555555555555",
    "relationship_type": "uses",
    "source_ref": _MALWARE_HDOOR["id"],
    "target_ref": _TECHNIQUE_T1082["id"],
}

_REVOKED_RELATIONSHIP = {
    "type": "relationship",
    "id": "relationship--66666666-6666-6666-6666-666666666666",
    "relationship_type": "uses",
    "revoked": True,
    "source_ref": _MALWARE_HDOOR["id"],
    "target_ref": _TECHNIQUE_T1055_011["id"],
}

_ALL_OBJECTS = [
    _TECHNIQUE_T1082,
    _TECHNIQUE_T1055_011,
    _REVOKED_TECHNIQUE,
    _MALWARE_HDOOR,
    _RELATIONSHIP_HDOOR_USES_T1082,
    _REVOKED_RELATIONSHIP,
]


@pytest.fixture
def db(tmp_path):
    fixture_path = tmp_path / "enterprise-attack.json"
    fixture_path.write_text(json.dumps({"objects": _ALL_OBJECTS}), encoding="utf-8")
    return AttackDb.load(str(fixture_path))


def test_technique_count_excludes_revoked(db):
    # 2 real techniques loaded; the revoked one must not be indexed.
    assert db.technique_count == 2


def test_direct_technique_link_resolves(db):
    results = db.resolve({"reference": "See https://attack.mitre.org/techniques/T1082 for details"})
    assert len(results) == 1
    assert results[0].id == "T1082"
    assert results[0].name == "System Information Discovery"
    assert results[0].tactic == "Discovery"


def test_technique_id_with_sub_technique_slash_normalized_to_dot(db):
    # /techniques/T1055/011 -> "T1055.011", matching the external_id format
    # - same as the C# version's id.Replace("/", ".").
    results = db.resolve({"reference": "https://attack.mitre.org/techniques/T1055/011"})
    assert len(results) == 1
    assert results[0].id == "T1055.011"
    # Multiple kill-chain phases join with "/" - matches GetPrimaryTactic's
    # string.Join("/", names).
    assert results[0].tactic == "Defense Evasion/Privilege Escalation"


def test_software_link_resolves_via_uses_relationship(db):
    # S0061 (HDoor) uses T1082 per the fixture relationship - a software
    # link should resolve to the technique it's documented to use, not to
    # itself.
    results = db.resolve({"reference": "https://attack.mitre.org/software/S0061"})
    assert len(results) == 1
    assert results[0].id == "T1082"


def test_revoked_relationship_not_followed(db):
    # HDoor "uses" T1055.011 only via a revoked relationship - must not
    # resolve.
    results = db.resolve({"a": "https://attack.mitre.org/software/S0061", "b": "no other refs here"})
    ids = {r.id for r in results}
    assert "T1055.011" not in ids


def test_revoked_technique_never_resolves(db):
    results = db.resolve({"reference": "https://attack.mitre.org/techniques/T9999"})
    assert results == []


def test_dedup_across_meta_values(db):
    # Same technique referenced twice (once directly, once via the
    # software link) should only appear once.
    results = db.resolve(
        {
            "ref1": "https://attack.mitre.org/techniques/T1082",
            "ref2": "https://attack.mitre.org/software/S0061",
        }
    )
    assert len(results) == 1
    assert results[0].id == "T1082"


def test_no_matching_url_resolves_to_empty_list(db):
    assert db.resolve({"description": "just a plain rule description"}) == []


def test_non_string_meta_values_do_not_raise(db):
    # yara-python meta values can be int/bool, not just str - resolve()
    # must not crash on those.
    results = db.resolve({"score": 80, "flag": True})
    assert results == []


def test_case_insensitive_url_matching(db):
    results = db.resolve({"reference": "HTTPS://ATTACK.MITRE.ORG/TECHNIQUES/T1082"})
    assert len(results) == 1
    assert results[0].id == "T1082"
