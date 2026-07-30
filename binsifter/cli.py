"""Headless scan entry point - `binsifter-scan` console script.

No GUI/PySide6 import anywhere in this module or in binsifter.core - this
is what makes a future Docker image of just the scan engine possible
without dragging in a windowing toolkit. See the "BinSifter post-prototype
roadmap" project note for why a containerized GUI was ruled out in favor
of this.

Real, not a placeholder: runs the full currently-implemented pipeline
(hash/entropy, NSRL, blocklist, YARA, capa, FLOSS, Authenticode, IOC
extraction, MITRE ATT&CK enrichment, imphash/ssdeep clustering, draft YARA
rule generation) and writes the 4 CSV reports - engine.scan_directory()
does the actual report writing now (see report.py), so this module no
longer maintains its own separate/ad hoc CSV writer.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from binsifter.core.config import build_default_config
from binsifter.core.engine import scan_directory


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binsifter-scan",
        description="Headless BinSifter scan - no GUI required.",
    )
    parser.add_argument("--src-dir", required=True, help="Directory of files to scan")
    parser.add_argument("--nsrl-path", default="", help="NSRL known-good hash set")
    parser.add_argument("--yara-rules", default="", help="YARA rules file")
    parser.add_argument("--capa-rules", default="", help="capa rules directory")
    parser.add_argument("--blocklist-path", default="", help="Known-bad hash blocklist (overrides the default)")
    parser.add_argument("--report-dir", default="", help="Where to write the CSV report (overrides the default)")
    return parser


def main(argv: list[str] | None = None) -> int:
    # binsifter.core's diagnostic logging (e.g. "loaded N capa rules from
    # X") is INFO-level and otherwise silently swallowed by Python's
    # default logging config - without this, a rule silently failing to
    # load looks identical to "capa ran and found nothing" in the output.
    # Root stays at WARNING (not INFO) deliberately: capa's dependencies
    # (vivisect especially) are known to be very noisy at INFO - FLOSS's
    # own CLI explicitly suppresses vivisect's logger for exactly this
    # reason. Only binsifter's own loggers get bumped to INFO.
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    logging.getLogger("binsifter").setLevel(logging.INFO)

    args = _build_arg_parser().parse_args(argv)

    config = build_default_config()
    config.SrcDir = args.src_dir
    config.NsrlPath = args.nsrl_path
    config.YaraRules = args.yara_rules
    config.CapaRules = args.capa_rules
    if args.blocklist_path:
        config.BlocklistPath = args.blocklist_path
    if args.report_dir:
        config.ReportDirectory = args.report_dir
        Path(config.ReportDirectory).mkdir(parents=True, exist_ok=True)

    def _progress(done: int, total: int, path: str) -> None:
        print(f"[{done}/{total}] {path}", file=sys.stderr)

    result = scan_directory(config, progress_callback=_progress)

    print(f"Scanned {len(result.records)} file(s).")
    if result.report_paths:
        print(f"Full report: {result.report_paths.full}")
        print(f"Suspicious/unknown (non-NSRL): {result.report_paths.suspicious}")
        print(f"YARA matches: {result.report_paths.yara_matches}")
        print(f"Capa-compatible: {result.report_paths.capa_compatible}")
    else:
        print("No ReportDirectory configured - no CSV reports were written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
