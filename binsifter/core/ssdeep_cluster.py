"""SSDEEP fuzzy hashing and post-scan clustering.

Uses `ppdeep` (pure Python, ssdeep-hash-compatible) instead of a compiled
ssdeep.exe - see pyproject.toml for why. The union-find clustering logic
below is a direct port of the C# SsdeepClusterer class
(BinSifter-Rowan_v1.3.0-beta.1.ps1, lines ~973-1047): two files land in the same
cluster if there's a *chain* of above-threshold matches between them, even
if they don't match each other directly (transitive "these are all variants
of one family" grouping). Threshold=40 and the high-similarity cutoff of 85
are copied from the PowerShell version's $ssdeepClusterThreshold and the
SsdeepHasHighSimilarity field's documented cutoff - don't change these
without a reason, dashboards/tests elsewhere will assume these exact values.

NOTE: pairwise O(n^2) comparison, same complexity class as the original's
`ssdeep.exe -c` cluster mode - not a performance regression introduced by
this port, but worth revisiting if scan batches grow very large.
"""

from __future__ import annotations

from dataclasses import dataclass

import ppdeep

CLUSTER_THRESHOLD = 40
HIGH_SIMILARITY_THRESHOLD = 85


@dataclass
class SsdeepClusterInfo:
    cluster_id: int
    cluster_size: int
    has_high_similarity: bool
    matches_summary: str  # "path (score); path (score)" - same display format as the PowerShell version


def compute_ssdeep_hash(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        return ppdeep.hash(data)
    except OSError:
        return None


def cluster_by_ssdeep(
    hashes: dict[str, str],
    threshold: int = CLUSTER_THRESHOLD,
) -> dict[str, SsdeepClusterInfo]:
    """hashes: {file_path: ssdeep_hash}. Returns {file_path: SsdeepClusterInfo}
    for every path in `hashes`, including size-1 clusters (singletons -
    hashed but matched nothing above threshold), matching the PowerShell
    version's "-1 = never ssdeep-hashed at all" vs "hashed but singleton"
    distinction (the latter still gets a real cluster_id here, size 1).
    """
    paths = list(hashes.keys())
    pairwise_scores: dict[tuple[str, str], int] = {}

    for i, path_a in enumerate(paths):
        for path_b in paths[i + 1:]:
            score = ppdeep.compare(hashes[path_a], hashes[path_b])
            if score >= threshold:
                pairwise_scores[(path_a, path_b)] = score

    parent: dict[str, str] = {p: p for p in paths}

    def find(x: str) -> str:
        root = x
        while parent[root] != root:
            root = parent[root]
        cur = x
        while cur != root:
            nxt = parent[cur]
            parent[cur] = root
            cur = nxt
        return root

    for (path_a, path_b) in pairwise_scores:
        root_a, root_b = find(path_a), find(path_b)
        if root_a != root_b:
            parent[root_a] = root_b

    # Compact sequential IDs per distinct root, assigned in `paths` order so
    # results are stable/reproducible across runs given the same input.
    root_to_id: dict[str, int] = {}
    size_by_id: dict[int, int] = {}
    next_id = 0
    path_to_root = {}
    for p in paths:
        root = find(p)
        path_to_root[p] = root
        if root not in root_to_id:
            root_to_id[root] = next_id
            next_id += 1
    for p in paths:
        cid = root_to_id[path_to_root[p]]
        size_by_id[cid] = size_by_id.get(cid, 0) + 1

    # Per-file match summary + high-similarity flag
    matches_by_path: dict[str, list[str]] = {p: [] for p in paths}
    high_similarity: dict[str, bool] = {p: False for p in paths}
    for (path_a, path_b), score in pairwise_scores.items():
        matches_by_path[path_a].append(f"{path_b} ({score})")
        matches_by_path[path_b].append(f"{path_a} ({score})")
        if score >= HIGH_SIMILARITY_THRESHOLD:
            high_similarity[path_a] = True
            high_similarity[path_b] = True

    result: dict[str, SsdeepClusterInfo] = {}
    for p in paths:
        cid = root_to_id[path_to_root[p]]
        result[p] = SsdeepClusterInfo(
            cluster_id=cid,
            cluster_size=size_by_id[cid],
            has_high_similarity=high_similarity[p],
            matches_summary="; ".join(matches_by_path[p]),
        )
    return result
