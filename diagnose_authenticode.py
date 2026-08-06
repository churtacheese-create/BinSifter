"""One-off diagnostic for TODO.md's open item: "38 files (36 .dll/.exe + 2
.msi) still raise signify.exceptions.ParseError and land in
NotSupportedFileFormat." That entry's working hypothesis ("legacy NT4/2000/
XP-era PE binaries with header conventions that predate something signify's
modern parser assumes") was never actually confirmed against a real file -
this dev sandbox is Linux-only with no Windows binaries available, so the
investigation could only get as far as reading signify's own source.

That source read (2026-08-07, binsifter/core/authenticode.py's
check_signature()) narrows the hypothesis a lot further than "some header
field": `AuthenticodeFile.from_stream()` only raises ParseError when EVERY
registered subclass's `_try_open()` returns None for the file, and:
  - SignedPEFile._try_open() ONLY checks that the first 2 bytes equal "MZ" -
    nothing else. If a file's header starts with "MZ", this branch always
    succeeds; no PE structure is parsed at this stage at all.
  - SignedMsiFile._try_open() checks the first 8 bytes against the OLE
    compound-file magic (D0 CF 11 E0 A1 B1 1A E1); if they match, it tries
    to open the file as a real OLE container (via `olefile`), which CAN
    still fail on a malformed one even with a matching magic.

In short: for a GENUINE PE file (any real .exe/.dll, however old), there is
no code path in signify that should raise ParseError purely from an
unusual/legacy header - _try_open() doesn't look far enough into the file
to notice. If these 36 files are really landing here, the far more likely
explanations are (a) they don't actually start with "MZ" at all (truncated,
corrupted, or not really PE despite the extension), or (b) something else
entirely (permissions, a reparse point/symlink resolving oddly, a 0-byte
file). This script answers that directly and cheaply, against the REAL
files, rather than guessing further from source alone.

Usage (run on Steve's own machine, against a real SrcDir or the specific
files already identified from a triage CSV):

    python diagnose_authenticode.py <path_or_dir> [<path_or_dir> ...]

Each argument can be a single file or a directory (searched recursively for
.exe/.dll/.msi files). For every file, this prints:
  - the first 16 bytes as hex (so you can SEE whether it's really "4d 5a...")
  - whether BinSifter's own check_signature() call chain succeeds and what
    status it lands on
  - if it raises signify.exceptions.ParseError (the specific case this is
    investigating), the FULL exception type and message - not just the
    logger.debug-level, easy-to-miss line check_signature() itself logs
    during a normal scan

Read-only: opens each file in binary mode, never writes or modifies
anything. Requires `signify` to be installed (same environment BinSifter
itself runs in - `pip install -e .` from the repo root first if needed).
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

try:
    from signify.authenticode import AuthenticodeFile
    from signify.exceptions import ParseError as SignifyParseError
except ImportError:
    print("signify is not installed in this environment - run `pip install -e .` from the repo root first.")
    sys.exit(1)

_TARGET_EXTENSIONS = {".exe", ".dll", ".msi"}


def _iter_target_files(args: list[str]):
    for arg in args:
        path = Path(arg)
        if path.is_file():
            yield path
        elif path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_file() and candidate.suffix.lower() in _TARGET_EXTENSIONS:
                    yield candidate
        else:
            print(f"Skipping (not a file or directory): {arg}")


def _diagnose_one(path: Path) -> str:
    """Returns a short, grouping-friendly label for this file's outcome -
    used to print a summary histogram at the end, since the interesting
    result here is "how many distinct causes are there," not just a wall
    of per-file text.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(16)
    except OSError as exc:
        print(f"  {path}")
        print(f"    Could not even open/read the file: {exc}")
        return f"OSError: {exc}"

    header_hex = " ".join(f"{b:02x}" for b in header)
    starts_with_mz = header[:2] == b"MZ"
    starts_with_ole = header[:8] == bytes.fromhex("D0CF11E0A1B11AE1")

    print(f"  {path}")
    print(f"    First 16 bytes: {header_hex or '(file is empty or unreadable)'}")
    print(f"    Starts with 'MZ' (PE magic): {starts_with_mz}")
    print(f"    Starts with OLE compound-file magic (MSI magic): {starts_with_ole}")

    try:
        with open(path, "rb") as f:
            signed_file = AuthenticodeFile.from_stream(f)
            result, exc = signed_file.explain_verify()
        print(f"    check_signature() would resolve to: {result.name} (exception: {exc!r})")
        return f"resolved: {result.name}"
    except SignifyParseError as exc:
        # This is the exact exception check_signature() catches and maps to
        # NotSupportedFileFormat - the one this whole script exists to
        # explain, not just report the fact of.
        print(f"    AuthenticodeFile.from_stream() raised {type(exc).__name__}: {exc}")
        return f"from_stream() raised {type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001 - diagnostic script, report everything, don't hide it
        print(f"    Unexpected {type(exc).__name__}: {exc}")
        return f"unexpected {type(exc).__name__}: {exc}"


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    files = list(_iter_target_files(sys.argv[1:]))
    if not files:
        print("No .exe/.dll/.msi files found under the given path(s).")
        sys.exit(1)

    print(f"Checking {len(files)} file(s)...\n")
    outcomes: Counter[str] = Counter()
    for path in files:
        outcomes[_diagnose_one(path)] += 1
        print()

    print("=" * 70)
    print("Summary (grouped by outcome, most common first):")
    for outcome, count in outcomes.most_common():
        print(f"  {count:4d}  {outcome}")


if __name__ == "__main__":
    main()
