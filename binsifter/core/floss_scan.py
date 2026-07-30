"""FLOSS string-extraction fallback - real library integration.

Verified against flare-floss's own source (not guessed) before writing
this:
- github.com/mandiant/flare-floss doc/installation.md only shows
  `import floss; print(dir(floss))` - not enough to build on.
- floss/main.py has no small standalone "extract_strings(path)" library
  function - the real pipeline (vivisect workspace load, decoding-function
  identification, stackstring/tightstring/decoded-string extraction) is
  substantial and easy to get subtly wrong by hand-porting.
- HOWEVER, floss/main.py's own ArgumentParser subclass has this comment:
  "argparse will call sys.exit upon parsing invalid arguments. we don't
  want that, because we might be parsing args within test cases, run as a
  module, etc." - i.e. FLOSS's maintainers deliberately designed main(argv)
  to be safely callable in-process from another program, not just from a
  real CLI invocation. That's the actual "library API" here: call
  floss.main.main(argv) with a constructed argv list and --json, capture
  stdout, parse the JSON. This reuses FLOSS's real, tested extraction
  pipeline rather than reimplementing it, while still avoiding a real
  subprocess spawn (no process-launch overhead, no floss.exe path lookup).
- floss/results.py confirms the exact JSON shape: top-level "strings" key
  with static_strings/stack_strings/tight_strings/decoded_strings lists,
  each entry a dict with a "string" key holding the actual text - verified
  directly from the ResultDocument/StaticString/StackString/DecodedString
  dataclasses, not assumed.

Deliberately passes `--only static stack tight decoded` (all four types
explicitly) rather than leaving FLOSS's defaults untouched: main() has an
interactive "enable string deobfuscation?" prompt that only fires when
neither --no nor --only was given AND the file is identified as Go/Rust -
since stdout is being captured (not a real tty) that prompt would silently
resolve to "no" and disable stack/tight/decoded extraction for exactly
those files, which is the opposite of what BinSifter wants from a
fallback tool. Passing --only explicitly sidesteps that branch entirely.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
from dataclasses import dataclass

import floss.main

logger = logging.getLogger(__name__)


@dataclass
class FlossResult:
    string_count: int
    strings: list[str]
    # static_strings only (not stack/tight/decoded) - kept separate from the
    # combined `strings` list above because the draft-YARA-rule-generation
    # step (see yara_rule_gen.py) intersects only static strings across
    # cluster members, matching the PowerShell version's persisted
    # floss_reports/<sha1>.json re-read at that later stage (this port
    # keeps the same in-memory data instead of writing/re-reading JSON -
    # see yara_rule_gen.py's module docstring).
    static_strings: list[str]


def scan_file(target_path: str) -> FlossResult:
    """Runs FLOSS's default extraction (static + stack + tight + decoded
    strings) against target_path. Returns an empty FlossResult (not an
    exception) on any failure - same graceful-skip philosophy as the rest
    of core/, since a file FLOSS can't handle just means this particular
    fallback recovers nothing, not a scan-ending error.
    """
    argv = [
        "--json",
        "--quiet",
        "--only", "static", "stack", "tight", "decoded",
        "--",
        target_path,
    ]

    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            return_code = floss.main.main(argv)
    except Exception:
        logger.exception("FLOSS raised while processing %s", target_path)
        return FlossResult(string_count=0, strings=[], static_strings=[])

    if return_code != 0:
        logger.info("FLOSS returned %s for %s - no strings recovered", return_code, target_path)
        return FlossResult(string_count=0, strings=[], static_strings=[])

    try:
        doc = json.loads(captured.getvalue())
    except json.JSONDecodeError:
        logger.warning("Could not parse FLOSS JSON output for %s", target_path)
        return FlossResult(string_count=0, strings=[], static_strings=[])

    strings_section = doc.get("strings", {})

    def _collect(key: str) -> list[str]:
        values = []
        for entry in strings_section.get(key, []):
            value = entry.get("string")
            if value:
                values.append(value)
        return values

    static_strings = _collect("static_strings")
    collected: list[str] = list(static_strings)
    for key in ("stack_strings", "tight_strings", "decoded_strings"):
        collected.extend(_collect(key))

    return FlossResult(string_count=len(collected), strings=collected, static_strings=static_strings)
