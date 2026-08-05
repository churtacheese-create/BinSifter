"""Dashboard aggregate statistics - pure-Python (no Qt import) port of the
per-file metric accumulation and SSDEEP-metrics computation in the
PowerShell version (BinSifter-Rowan_v1.3.0-beta.1.ps1, lines ~5663-5691 for the
UiTotals metrics, ~3117-3174 for SsdeepMetrics). Kept separate from the Qt
page widget so these aggregations are unit-testable without a display.

The PowerShell version computes these incrementally (subtract a stale
snapshot, add a fresh one) because it's updating a live UI off a
dirty-path queue during an in-progress scan. This port recomputes from
scratch over the full ScanResult.records list instead, since the GUI's
current scan-trigger design (see main_window.py) runs one scan to
completion and then renders once - same end totals, simpler code, revisit
if/when a live-updating progress view is built.

One metric-that-isn't-derivable-from-FileRecord-alone gap, handled here
rather than by changing engine.py: AvgScore (the SSDEEP heat map's average
pairwise match score) isn't retained anywhere as structured data after
ssdeep_cluster.cluster_by_ssdeep() returns - only each record's
SsdeepMatches display string ("path (score); path (score)"). Re-parsing
the score numbers back out of that string and averaging them is
equivalent to averaging the real pairwise score list (each match appears
twice, once per side, which doesn't change the average of the set), so no
engine.py/ssdeep_cluster.py change was needed for this.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from binsifter.core.models import FileRecord

_KNOWN_SEVERITIES = ("Critical", "High", "Medium", "Low")
_SCORE_RE = re.compile(r"\((\d+)\)")


@dataclass
class DashboardStats:
    completed_count: int = 0
    yara_hits: int = 0
    capa_scans: int = 0
    capa_hits: int = 0
    nsrl_matches: int = 0
    imphash_clustered: int = 0
    unsigned: int = 0
    known_bad: int = 0
    with_iocs: int = 0
    escalated: int = 0
    severity: dict[str, int] = field(default_factory=lambda: {k: 0 for k in (*_KNOWN_SEVERITIES, "Unknown")})

    num_clusters: int = 0
    largest_cluster_size: int = 0
    # -1 = no cluster with size >= 2 exists yet. Which cluster "wins" a tie
    # for largest matters for the Dashboard's click-to-filter (clicking the
    # "Largest Cluster" tile filters Results to this specific cluster id) -
    # see the tie-break note in from_records() below.
    largest_cluster_id: int = -1
    singletons: int = 0
    avg_score: float = 0.0
    files_above_85: int = 0
    previously_seen_clusters: int = 0
    total_hashed_files: int = 0

    @property
    def heat_denominator(self) -> int:
        # Get-HeatColor divides by max(1, TotalHashedFiles) - never a
        # divide-by-zero even on a scan with nothing SSDEEP-hashed.
        return max(1, self.total_hashed_files)

    @classmethod
    def from_records(cls, records: list[FileRecord]) -> "DashboardStats":
        stats = cls()

        cluster_sizes: dict[int, int] = {}
        cluster_previously_seen: dict[int, bool] = {}
        all_scores: list[int] = []

        for r in records:
            if r.Status == "Completed":
                stats.completed_count += 1

            stats.yara_hits += r.YaraHitCount
            stats.capa_hits += r.CapaDetectionCount
            if r.CapaEligible:
                stats.capa_scans += 1
            if r.NsrlMatch:
                stats.nsrl_matches += 1

            if r.ImphashClusterId >= 0 and r.ImphashClusterSize >= 2:
                stats.imphash_clustered += 1
            # "Unsigned" per the original: any non-empty status that isn't
            # exactly "Valid" - NotSigned/NotTrusted/HashMismatch/
            # UnknownError all count, same as the PowerShell version's
            # `$r.SignatureStatus -and $r.SignatureStatus -ne 'Valid'`.
            if r.SignatureStatus and r.SignatureStatus != "Valid":
                stats.unsigned += 1
            if r.ReputationStatus == "KnownBad":
                stats.known_bad += 1
            if r.IocCount > 0:
                stats.with_iocs += 1
            if r.Disposition == "Escalated":
                stats.escalated += 1

            if r.YaraHitCount > 0:
                bucket = r.YaraSeverity if r.YaraSeverity in _KNOWN_SEVERITIES else "Unknown"
                stats.severity[bucket] += 1

            if r.SSDEEP:
                stats.total_hashed_files += 1
            if r.SsdeepClusterSize == 1:
                stats.singletons += 1
            if r.SsdeepClusterId >= 0 and r.SsdeepClusterSize >= 2:
                cluster_sizes[r.SsdeepClusterId] = r.SsdeepClusterSize
                if r.SsdeepPreviouslySeen:
                    cluster_previously_seen[r.SsdeepClusterId] = True
            if r.SsdeepHasHighSimilarity:
                stats.files_above_85 += 1
            if r.SsdeepMatches:
                all_scores.extend(int(m) for m in _SCORE_RE.findall(r.SsdeepMatches))

        stats.num_clusters = len(cluster_sizes)
        # Strictly-greater-than comparison over insertion order (matches
        # each cluster's first-encountered-in-scan order, same as the
        # PowerShell version's Dictionary enumeration) - so on a tie, the
        # cluster that was FIRST seen during this scan wins, same
        # tie-break as BinSifter-Rowan_v1.3.0-beta.1.ps1 lines ~3118-3123
        # (`foreach ($kvp in $clusterSizes.GetEnumerator()) { if
        # ($kvp.Value -gt $largestClusterSize) ... }`), not just "whichever
        # dict.values() happens to return max() for".
        largest_id, largest_size = -1, 0
        for cid, size in cluster_sizes.items():
            if size > largest_size:
                largest_id, largest_size = cid, size
        stats.largest_cluster_id = largest_id
        stats.largest_cluster_size = largest_size
        stats.previously_seen_clusters = sum(1 for cid in cluster_sizes if cluster_previously_seen.get(cid))
        stats.avg_score = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0

        return stats
