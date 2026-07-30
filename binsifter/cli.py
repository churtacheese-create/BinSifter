"""Headless scan entry point - `binsifter-scan` console script.

No GUI/PySide6 import anywhere in this module or in binsifter.core - this
is what makes a future Docker image of just the scan engine possible
without dragging in a windowing toolkit. See the "BinSifter post-prototype
roadmap" project note for why a containerized GUI was ruled out in favor
of this.

Minimal but real: runs the currently-implemented pipeline stages
(hash/entropy, NSRL, blocklist, YARA, imphash/ssdeep clustering) and writes
a CSV report - the same stages engine.scan_directory supports today. capa/
FLOSS/Speakeasy/Authenticode results will appear in the CSV once those
modules are finished; the columns are already there via dataclasses.
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import asdict, fields
from datetime import datetime, timezone
from pathlib import Path

from binsifter.core.config import build_default_config
from binsifter.core.engine import scan_directory
from binsifter.core.models import FileRecord


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binsifter-scan",
        description="Headless BinSifter scan - no GUI required.",
    )
    parser.add_argument("--src-dir", required=True, help="Directory of files to scan")
    parser.add_argument("--nsrl-path", default="", help="NSRL known-good hash set")
    parser.add_argument("--yara-rules", default="", help="YARA rules file")
    parser.add_argument("--blocklist-path", default="", help="Known-bad hash blocklist (overrides the default)")
    parser.add_argument("--report-dir", default="", help="Where to write the CSV report (overrides the default)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    config = build_default_config()
    config.SrcDir = args.src_dir
    config.NsrlPath = args.nsrl_path
    config.YaraRules = args.yara_rules
    if args.blocklist_path:
        config.BlocklistPath = args.blocklist_path
    if args.report_dir:
        config.ReportDirectory = args.report_dir
        Path(config.ReportDirectory).mkdir(parents=True, exist_ok=True)

    def _progress(done: int, total: int, path: str) -> None:
        print(f"[{done}/{total}] {path}", file=sys.stderr)

    records = scan_directory(config, progress_callback=_progress)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = Path(config.ReportDirectory) / f"binsifter_scan_{timestamp}.csv"
    _write_csv_report(records, report_path)
    print(f"Wrote {len(records)} records to {report_path}")
    return 0


def _write_csv_report(records: list[FileRecord], report_path: Path) -> None:
    column_names = [f.name for f in fields(FileRecord)]
    with open(report_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=column_names)
        writer.writeheader()
        for record in records:
            writer.writerow(asdict(record))


if __name__ == "__main__":
    sys.exit(main())
