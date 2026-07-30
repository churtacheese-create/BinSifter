"""CAPA capability detection - real library integration.

Verified against capa's own source (not guessed) before writing this:
- github.com/mandiant/capa/blob/master/capa/ghidra/capa_ghidra.py showed the
  general shape (capa.rules.get_rules(), capa.capabilities.common.
  find_capabilities()), but that script targets a different capa version -
  it destructures find_capabilities()'s return as a (capabilities, counts)
  tuple, which does NOT match the currently-installed flare-capa 9.4.0.
- github.com/mandiant/capa/blob/master/capa/capabilities/common.py (the
  actual installed version's source) confirms find_capabilities() returns a
  single `Capabilities` dataclass with a `.matches` dict (rule name -> list
  of (address, Result)) and a `.feature_counts` field - NOT a tuple. This
  mismatch between two "official-looking" examples is exactly why each
  capa/FLOSS/Speakeasy module's docstring insists on checking the installed
  version's real source rather than trusting one example script.
- github.com/mandiant/capa/blob/master/capa/loader.py provided
  get_extractor(), which is the real standalone-file (non-Ghidra/IDA)
  entrypoint, using backend="vivisect" by default - the same backend
  capa's own CLI (and the compiled capa.exe the PowerShell version shelled
  out to) uses, so detection fidelity should match the original, not a
  faster-but-shallower alternative (backend="pefile" also exists and skips
  vivisect entirely, but only extracts file-level features - no function/
  basic-block-scope rules would match, which would be a real accuracy
  regression versus the original capa.exe. Not used here for that reason.)

KNOWN GAP: sigpaths (FLIRT library-code-identification signatures) are
passed as an empty list - the original capa.exe binary has these bundled;
flare-capa via pip does not (see capa's own install docs). This can
increase false-attribution of statically-linked library code as
"developer-authored" capability matches. No BinSifter Settings field
exists for a sigs directory yet - flagged here rather than silently
accepted or unilaterally adding a new Settings field (Steve was
deliberate about keeping the Settings page to 6 fields).
"""

from __future__ import annotations

import logging
import pathlib
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# capa.main is never called directly here, but importing it is required:
# capa's internals (e.g. capa.rules.get_rules()) reach for submodules like
# capa.rules.cache via attribute access, which Python only binds onto the
# capa.rules module once that submodule has actually been imported
# somewhere in the process. capa's own CLI always goes through capa.main
# first, which transitively imports the whole tree as a side effect -
# importing just capa.rules/capa.loader/capa.capabilities.common (as this
# module originally did) skips that wiring and produces
# "AttributeError: module 'capa.rules' has no attribute 'cache'" the first
# time get_rules() runs. Confirmed by hitting this exact error against a
# real capa rules directory, not a hypothetical.
import capa.main  # noqa: F401

import capa.capabilities.common
import capa.loader
import capa.rules
from capa.features.common import FORMAT_AUTO, FORMAT_SC32, FORMAT_SC64, OS_AUTO


@dataclass
class CapaResult:
    detection_count: int
    output: str
    shellcode_format: str | None  # "sc32"/"sc64"/None


def load_rules(capa_rules_dir: str) -> capa.rules.RuleSet:
    """CapaRules is a directory (BinSifter's existing Settings field type),
    matching capa.rules.get_rules()'s expected input."""
    rules = capa.rules.get_rules([pathlib.Path(capa_rules_dir)])
    # Loud on purpose (info, not debug): a rule silently failing to load
    # (bad YAML, a schema validation issue) looks identical to "capa ran
    # and legitimately found nothing" from the FileRecord output alone -
    # the difference matters a lot when trying to tell "the pipeline is
    # broken" from "this file really doesn't match anything".
    rule_names = sorted(rules.rules.keys())
    logger.info("Loaded %d capa rule(s) from %s: %s", len(rule_names), capa_rules_dir, rule_names)
    return rules


def _find_capabilities(rules: capa.rules.RuleSet, target_path: pathlib.Path, input_format: str):
    extractor = capa.loader.get_extractor(
        target_path,
        input_format,
        OS_AUTO,
        capa.loader.BACKEND_VIV,
        sigpaths=[],
        disable_progress=True,
    )
    return capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)


def _summarize(rules: capa.rules.RuleSet, capabilities: capa.capabilities.common.Capabilities) -> tuple[int, str]:
    matched_names = sorted(capabilities.matches.keys())
    lines = []
    for rule_name in matched_names:
        rule = rules[rule_name]
        description = rule.meta.get("description", "")
        lines.append(f"{rule_name} - {description}" if description else rule_name)
    return len(matched_names), "\n".join(lines)


def scan_file(target_path: str, rules: capa.rules.RuleSet, is_shellcode: bool = False) -> CapaResult:
    path = pathlib.Path(target_path)

    if not is_shellcode:
        capabilities = _find_capabilities(rules, path, FORMAT_AUTO)
        count, output = _summarize(rules, capabilities)
        return CapaResult(detection_count=count, output=output, shellcode_format=None)

    # Shellcode: -f sc32 then -f sc64, same order the PowerShell version
    # used (real headers can't disambiguate bitness for headerless input,
    # so both are tried explicitly). Whichever format doesn't raise wins;
    # if both raise, no detection - matches the original's graceful-skip
    # behavior rather than surfacing a hard error for ambiguous shellcode.
    for input_format, label in ((FORMAT_SC32, "sc32"), (FORMAT_SC64, "sc64")):
        try:
            capabilities = _find_capabilities(rules, path, input_format)
        except Exception:  # noqa: BLE001 - trying the other bitness next is the whole point
            continue
        count, output = _summarize(rules, capabilities)
        return CapaResult(detection_count=count, output=output, shellcode_format=label)

    return CapaResult(detection_count=0, output="", shellcode_format=None)
