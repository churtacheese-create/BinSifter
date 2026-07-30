"""YARA scanning - imported as a library (yara-python) instead of shelling
out to yara64.exe. Direct port of the C# SeverityScorer class and
Get-SeverityRank function from BinSifter_v1.3.0-alpha.2.ps1 (lines ~601-653
and ~1986-1995) - the severity bucketing logic is copied faithfully since
getting it subtly wrong would silently change what counts as "Critical" on
the dashboard.

MITRE ATT&CK technique enrichment (YaraAttackTechniques) is NOT ported yet -
that depended on the local enterprise-attack.json lookup table, which is a
separate module still to be written.
"""

from __future__ import annotations

from dataclasses import dataclass

import yara


@dataclass
class YaraMatchResult:
    rule_names: list[str]
    hit_count: int
    severity: str  # "Critical"/"High"/"Medium"/"Low"/"Unknown"
    severity_score: int  # 0-100 normalized, or -1 when the bucket came from a word not a number


_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def compile_rules(yara_rules_path: str) -> yara.Rules:
    """YaraRules is a single file (which may itself `include` others) -
    same as the PowerShell version's Settings field, a File not a
    Directory."""
    return yara.compile(filepath=yara_rules_path)


def scan_file(rules: yara.Rules, target_path: str) -> YaraMatchResult:
    matches = rules.match(filepath=target_path)
    if not matches:
        return YaraMatchResult(rule_names=[], hit_count=0, severity="Unknown", severity_score=-1)

    best_severity = "Unknown"
    best_score = -1
    for m in matches:
        severity, score = _resolve_severity(m.meta)
        if _SEVERITY_RANK[severity] > _SEVERITY_RANK[best_severity]:
            best_severity = severity
            best_score = score

    return YaraMatchResult(
        rule_names=[m.rule for m in matches],
        hit_count=len(matches),
        severity=best_severity,
        severity_score=best_score,
    )


def _bucket_score(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 1:
        return "Low"
    return "Unknown"


def _normalize_word(word: str) -> str | None:
    normalized = word.strip().lower()
    if normalized == "low":
        return "Low"
    if normalized in ("medium", "moderate"):
        return "Medium"
    if normalized == "high":
        return "High"
    if normalized in ("critical", "severe"):
        return "Critical"
    return None


def _resolve_severity(meta: dict) -> tuple[str, int]:
    """Priority: explicit 0-100 "score" meta field, bucketed on CVSS's
    official severity bands - then ReversingLabs' documented 0-5
    tc_detection_factor (scaled x20) - then a plain severity word if
    present. No usable field means "Unknown", not a guessed default.
    """
    if "score" in meta:
        try:
            score = int(meta["score"])
            return _bucket_score(score), score
        except (TypeError, ValueError):
            pass

    if "tc_detection_factor" in meta:
        try:
            scaled = int(meta["tc_detection_factor"]) * 20
            return _bucket_score(scaled), scaled
        except (TypeError, ValueError):
            pass

    for key in ("severity", "tc_policy_severity", "importance"):
        if key in meta:
            normalized = _normalize_word(str(meta[key]))
            if normalized is not None:
                return normalized, -1

    return "Unknown", -1
