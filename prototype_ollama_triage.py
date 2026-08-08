"""Standalone prototype (2026-08-08): can a local Ollama model, given only
BinSifter's already-extracted findings for a file (YARA hits, capa
detections, ssdeep/imphash clustering, Authenticode status, IOCs, ATT&CK
techniques), write a useful hypothesis about what a suspected-nefarious
binary is likely doing?

This is deliberately NOT wired into engine.py or either GUI yet - it is a
feasibility test, run by hand against a real completed triage CSV, before
deciding whether this becomes a real cross-variant BinSifter feature (see
TODO.md). It reads a CSV produced by report.py, sends a compact per-file
JSON summary of the findings to a locally-running Ollama server, and asks
for a SCHEMA-CONSTRAINED structured response back (Ollama's `format`
parameter, backed by XGrammar - the model literally cannot emit anything
that doesn't validate against the schema below, so the output always
parses cleanly into the result CSV).

What this deliberately does NOT do:
  - Send the model any raw file bytes. It only ever sees the SAME text
    BinSifter's own Results grid already shows an analyst - if the
    underlying detections are wrong, the AI layer will be wrong the same
    way, not independently verified.
  - Treat the output as a verdict. Every response is a hypothesis with a
    confidence level, not a detection - this script's CSV output column
    names are prefixed `AI_` specifically so they're never confused with
    BinSifter's own deterministic fields (YaraHitCount, SignatureStatus,
    etc.) if this ever gets merged back into a real report.
  - Call out to anything but the local Ollama endpoint. No network access
    beyond http://localhost:11434 (or whatever --endpoint you point it
    at) is ever used - this stays fully offline, same requirement that
    motivated Ollama over a cloud API in the first place for a tool that
    routinely handles live malware case data.

Prerequisites:
  1. Install Ollama: https://ollama.com/download
  2. Pull a model that supports Ollama's structured-output/tool-calling
     path, e.g.:  ollama pull qwen2.5:7b
  3. Make sure Ollama is running (it runs as a background service after
     install on Windows/macOS; `ollama list` should work from any shell
     without needing to manually start anything).

Usage:
    python prototype_ollama_triage.py <path_to_triage_csv> [options]

Options:
    --model NAME          Ollama model tag (default: qwen2.5:7b)
    --endpoint URL         Ollama server URL (default: http://localhost:11434)
    --output PATH          Where to write results (default: <input>_ai_assessment.csv)
    --limit N               Only process the first N eligible files (default: all)
    --include-known-good    Also send NSRL-matched (IsKnownGood) rows - off by
                             default, same "don't bother re-checking known-good
                             files" philosophy engine.py already uses to gate
                             YARA/capa/ssdeep behind `not record.NsrlMatch`.
    --timeout SECONDS       Per-file request timeout (default: 120)
    --dry-run               Build and print each file's prompt payload without
                             calling Ollama at all - useful for sanity-checking
                             what would be sent, or for testing this script
                             before Ollama/a model are even installed.

Output: a new CSV alongside the input (or wherever --output points), one
row per file sent, with FilePath/SHA1/MD5/Disposition carried over from
the original plus new AI_LikelyCategory / AI_Confidence / AI_InsufficientSignal
/ AI_NotableSignals / AI_Rationale columns. The original CSV is never
modified.

Only requires the Python standard library - no `requests`/`ollama` pip
package needed, so there's nothing extra to install beyond Ollama itself.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Which report.py CSV columns actually matter for this and how to trim them.
# See report.py's COLUMNS list (2026-08-08 grep) for the authoritative
# header names - these must match exactly or DictReader just won't find them
# and every field silently comes back empty.
# ---------------------------------------------------------------------------
_RELEVANT_COLUMNS = [
    "FilePath", "SHA1", "MD5", "SSDEEP", "IsKnownGood",
    "YaraHitCount", "YaraMatches", "YaraSeverity", "YaraSeverityScore",
    "AttackTechniques",
    "CapaEligible", "PossibleFalseNegative", "CapaDetections",
    "Entropy", "CapaShellcodeFormat", "FlossStringCount",
    "SsdeepMatches", "SsdeepClusterSize", "SsdeepHighSimilarity",
    "SsdeepPreviouslySeen",
    "PackerDetected", "Compiler",
    "Imphash", "ImphashClusterSize",
    "SignatureStatus", "SignerName",
    "IocCount", "ExtractedIOCs",
    "ReputationStatus", "ReputationSource",
    "Disposition", "SourceArchive",
]

# Fields that should never be dropped even if empty/falsy - identifying
# info the output CSV needs regardless of what the model says.
_ALWAYS_KEEP = {"FilePath", "SHA1", "MD5"}

_TRUNCATE_AT = 800  # keeps a single noisy field (e.g. a long YaraMatches
                     # list) from blowing up the prompt size/latency.

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "insufficient_signal": {
            "type": "boolean",
            "description": "True if the provided findings are too sparse "
                            "or ambiguous to say anything meaningful.",
        },
        "likely_category": {
            "type": "string",
            "enum": [
                "ransomware", "infostealer", "loader_dropper", "backdoor_rat",
                "trojan_generic", "worm", "adware_pup", "cryptominer",
                "exploit_tool", "legitimate_or_benign", "unknown",
            ],
        },
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "notable_signals": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Short bullet-style callouts of the specific "
                            "findings that most drove this assessment.",
        },
        "rationale": {
            "type": "string",
            "description": "1-3 sentence explanation grounded ONLY in the "
                            "findings provided - never invent detail.",
        },
    },
    "required": [
        "insufficient_signal", "likely_category", "confidence",
        "notable_signals", "rationale",
    ],
}

_SYSTEM_PROMPT = """You are assisting a malware triage analyst. You will be \
given a JSON object describing the automated findings BinSifter already \
extracted for one file: hashes, YARA rule hits, capa capability \
detections, MITRE ATT&CK technique mappings, ssdeep/imphash clustering, \
Authenticode signature status, and extracted IOCs.

Reason ONLY from the fields provided. Do not invent capabilities, \
file behavior, or IOCs that are not present in the input. If the fields \
present are too sparse or contradictory to support a real conclusion, \
set insufficient_signal to true and likely_category to "unknown" rather \
than guessing. Your response will be shown to a human analyst as a \
hypothesis to investigate further, not as an authoritative detection - \
write rationale accordingly (e.g. "the combination of X and Y is \
consistent with..." rather than declarative claims of fact)."""


def _compact_row(row: dict) -> dict:
    """Drop empty/zero/False fields (except identifying ones) and truncate
    anything unreasonably long, so the prompt only contains signal.
    """
    out: dict = {}
    for key in _RELEVANT_COLUMNS:
        value = row.get(key, "")
        if key not in _ALWAYS_KEEP and value in ("", "0", "False", None):
            continue
        if isinstance(value, str) and len(value) > _TRUNCATE_AT:
            value = value[:_TRUNCATE_AT] + f"...(truncated, {len(value)} chars total)"
        out[key] = value
    return out


def _is_known_good(row: dict) -> bool:
    return str(row.get("IsKnownGood", "")).strip().lower() in ("true", "1", "yes")


def _call_ollama(endpoint: str, model: str, payload: dict, timeout: int) -> dict:
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, indent=2)},
        ],
        "format": _RESPONSE_SCHEMA,
        "stream": False,
    }).encode("utf-8")

    request = urllib.request.Request(
        f"{endpoint.rstrip('/')}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # HTTPError IS a URLError subclass, so without this the generic
        # "Could not reach Ollama" handler in main() would catch it too -
        # but a non-2xx response means Ollama DID respond, just with an
        # error, and its JSON body (e.g. {"error": "model \"qwen2.5:7b\"
        # not found, try pulling it first"}) is exactly what explains WHY.
        # Re-raise as a plain RuntimeError carrying that body so main()'s
        # generic URLError handler (the "is Ollama even running?" case)
        # doesn't swallow it under the wrong message.
        error_detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Ollama responded with HTTP {exc.code} {exc.reason}: {error_detail}"
        ) from exc

    # Ollama's /api/chat wraps the model's (schema-constrained) reply as a
    # JSON STRING under response_body["message"]["content"] - it still
    # needs one more json.loads() to become the actual structured object.
    return json.loads(response_body["message"]["content"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv_path", help="Path to a BinSifter triage CSV (report.py output)")
    parser.add_argument("--model", default="qwen2.5:7b")
    parser.add_argument("--endpoint", default="http://localhost:11434")
    parser.add_argument("--output", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--include-known-good", action="store_true")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--dry-run", action="store_true",
                         help="Build and print each payload without calling Ollama.")
    args = parser.parse_args()

    csv_path = Path(args.csv_path)
    if not csv_path.is_file():
        print(f"Not a file: {csv_path}")
        sys.exit(1)

    output_path = Path(args.output) if args.output else csv_path.with_name(csv_path.stem + "_ai_assessment.csv")

    with open(csv_path, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))

    eligible = [r for r in rows if args.include_known_good or not _is_known_good(r)]
    if args.limit is not None:
        eligible = eligible[: args.limit]

    print(f"{len(rows)} row(s) in {csv_path.name}, {len(eligible)} eligible for AI review "
          f"({'including' if args.include_known_good else 'excluding'} NSRL-known-good).")

    if not eligible:
        print("Nothing to do.")
        return

    results = []
    for i, row in enumerate(eligible, start=1):
        payload = _compact_row(row)
        display_name = payload.get("FilePath", "(unknown path)")
        print(f"[{i}/{len(eligible)}] {display_name}")

        if args.dry_run:
            print(json.dumps(payload, indent=2))
            continue

        try:
            assessment = _call_ollama(args.endpoint, args.model, payload, args.timeout)
        except RuntimeError as exc:
            # Ollama responded but with a non-2xx status - see the
            # HTTPError handling in _call_ollama(). Usually means the
            # model tag hasn't been pulled, or the schema/request body
            # itself is being rejected - the message below is Ollama's
            # own explanation, not a guess.
            print(f"    {exc}")
            sys.exit(1)
        except urllib.error.URLError as exc:
            print(f"    Could not reach Ollama at {args.endpoint}: {exc}\n"
                  f"    Is Ollama running? Try `ollama list` in another shell first.")
            sys.exit(1)
        except (KeyError, json.JSONDecodeError) as exc:
            print(f"    Unexpected response shape from Ollama: {exc}")
            continue

        results.append({
            "FilePath": row.get("FilePath", ""),
            "SHA1": row.get("SHA1", ""),
            "MD5": row.get("MD5", ""),
            "Disposition": row.get("Disposition", ""),
            "AI_LikelyCategory": assessment.get("likely_category", ""),
            "AI_Confidence": assessment.get("confidence", ""),
            "AI_InsufficientSignal": assessment.get("insufficient_signal", ""),
            "AI_NotableSignals": "; ".join(assessment.get("notable_signals", [])),
            "AI_Rationale": assessment.get("rationale", ""),
        })
        print(f"    -> {assessment.get('likely_category')} "
              f"(confidence: {assessment.get('confidence')}, "
              f"insufficient_signal: {assessment.get('insufficient_signal')})")

    if args.dry_run:
        print("\nDry run complete - nothing written, no Ollama calls made.")
        return

    if not results:
        print("No results to write (every call failed or was skipped).")
        return

    with open(output_path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(results[0].keys()), lineterminator="\r\n")
        writer.writeheader()
        writer.writerows(results)

    print(f"\nWrote {len(results)} assessment(s) to {output_path}")


if __name__ == "__main__":
    main()
