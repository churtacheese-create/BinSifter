"""Archive/compressed-file support - decompress and expand the contents of
zip/tar/gzip/7z archives found under the scan source directory, so their
contents get scanned as ordinary files rather than the archive being
scanned only as an opaque single blob. Added 2026-08-07 per Steve's
2026-08-06 request (see TODO.md's "Planned - next session" entry for the
original ask and open design questions).

Three design decisions Steve confirmed directly (AskUserQuestion,
2026-08-06/07) that this module and its call site in engine.py's
scan_directory() are built around:

1. **Password-protected archives are handled by a pre-scan pass**, not a
   mid-scan interruption: every locked archive under SrcDir is found and
   collected before the real per-file scan starts, prompted for all at
   once (one batch dialog), then extracted with whatever passwords were
   supplied. See expand_archives()/resolve_locked_archives() below - two
   separate passes, called from engine.py with a GUI round-trip in between.
2. **Extracted files show up in Results as their own ordinary rows**, not
   grouped/nested under the archive's row - see models.py's
   FileRecord.SourceArchive, set to the immediate containing archive's
   path (not necessarily the top-level one, if archives are nested) so
   provenance is never lost even a few levels deep.
3. **Supported formats for this first pass: zip, tar (+ .tar.gz/.tgz/
   .tar.bz2/.tbz2/.tar.xz/.txz via tarfile's own transparent compression
   detection), standalone gzip, and 7z** (needs the third-party py7zr
   library - see pyproject.toml). RAR was explicitly NOT included - it
   needs an external unrar/unar binary the same way Sigcheck/Ghidra need a
   configured .exe, and there's no confirmed real need for it yet; revisit
   if that changes.

One thing TODO.md's original entry flagged as a real, unresolved
architecture question turned out to have a much simpler answer once
actually worked through: "how does a multiprocessing.Pool WORKER PROCESS
pop a Qt dialog on the GUI thread and block for a password" was the wrong
question, because archive expansion never needs to run inside the
per-file worker pool at all. It happens as a serial pre-scan step - the
same place NSRL/blocklist/YARA/capa already get loaded once, before the
pool is even created (see engine.py's scan_directory()) - which already
runs on a background QThread in the SAME process as the GUI (see
main_window.py's _ScanWorker), not a separate process. A QThread can
signal the GUI thread and block on a threading.Event waiting for an
answer, the ordinary safe Qt cross-THREAD coordination pattern - nothing
like the cross-PROCESS problem the original TODO entry worried about. By
the time the multiprocessing pool is created, every extracted file is
just an ordinary file sitting on disk with a real path;
_process_one_file()/_pool_worker_init() in engine.py need zero changes to
scan them.

Nested archives (a zip inside a zip) are expanded recursively, bounded by
MAX_NESTED_DEPTH - a sensible, documented DEFAULT rather than a
Steve-confirmed decision (this specific sub-question wasn't one of the 3
put to AskUserQuestion; format scope / password-prompt architecture /
Results display were judged the load-bearing ones worth blocking on).
Nested archives newly discovered while resolving an already-password-
prompted archive (resolve_locked_archives(), below) are saved straight to
the "for external cracking" directory rather than triggering a SECOND
prompting round - keeps the password workflow a single, bounded
round-trip with the analyst instead of something that could theoretically
chain through several dialogs for a deeply nested tree.
"""

from __future__ import annotations

import gzip
import hashlib
import logging
import shutil
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import py7zr
import py7zr.exceptions
import pyzipper

logger = logging.getLogger(__name__)

# See module docstring - a documented default, not a blocking decision.
MAX_NESTED_DEPTH = 3

_ZIP_EXTS = (".zip",)
_SEVENZIP_EXTS = (".7z",)
# Longer/compound suffixes must be checked before the bare ".gz" below -
# classify() relies on iteration order, not "longest match wins" logic.
_TAR_EXTS = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")
_GZIP_EXTS = (".gz",)  # standalone (non-.tar.gz) single-file gzip

ARCHIVE_SUFFIXES = _ZIP_EXTS + _SEVENZIP_EXTS + _TAR_EXTS + _GZIP_EXTS


def classify(path: str | Path) -> str | None:
    """Returns "zip" | "7z" | "tar" | "gzip", or None if `path`'s extension
    isn't a recognized archive format. Extension-based, not content-
    sniffed - matches file_type.py's own extension-led CapaEligible
    classification, and keeps a file that merely happens to share a magic
    byte sequence from being silently decompressed when it wasn't meant to
    be treated as an archive at all.
    """
    name = Path(path).name.lower()
    for suf in _TAR_EXTS:
        if name.endswith(suf):
            return "tar"
    for suf in _ZIP_EXTS:
        if name.endswith(suf):
            return "zip"
    for suf in _SEVENZIP_EXTS:
        if name.endswith(suf):
            return "7z"
    for suf in _GZIP_EXTS:
        if name.endswith(suf):
            return "gzip"
    return None


def is_archive(path: str | Path) -> bool:
    return classify(path) is not None


def find_archives(paths: list[str]) -> list[str]:
    """Filters an already-enumerated file list (e.g. engine.enumerate_files()'s
    output) down to just the recognized archive files."""
    return [p for p in paths if is_archive(p)]


def needs_password(path: str | Path) -> bool:
    """Best-effort, read-only check for whether `path` requires a password
    to extract - never attempts extraction itself. tar/gzip are never
    password-protected (neither format has a native encryption concept -
    a colloquial "password-protected gzip" is almost always a zip/7z with
    a misleading extension, which classify() would catch by its real
    extension, not this function), so always False for those.

    Returns False (not "unknown") for anything unreadable/corrupt - a real
    extraction attempt happens either way at extraction time and will
    raise its own real error there; this pre-check exists purely to decide
    whether an archive belongs in the up-front password-prompt batch, and
    treating a merely-corrupt archive as "needs a password" would prompt
    for something that was never going to fix it.
    """
    fmt = classify(path)
    if fmt == "zip":
        try:
            # Deliberately still stdlib zipfile, not pyzipper, here - unlike
            # _extract_zip() (see its docstring, 2026-08-08), this only
            # reads each entry's flag_bits out of the central directory,
            # which doesn't require decompressing/decrypting anything, so
            # stdlib zipfile opens and lists an AES-encrypted zip just fine
            # even though it can't actually extract one.
            with zipfile.ZipFile(path) as zf:
                return any(info.flag_bits & 0x1 for info in zf.infolist())
        except (zipfile.BadZipFile, OSError):
            return False
    if fmt == "7z":
        try:
            with py7zr.SevenZipFile(path, "r") as zf:
                return zf.needs_password()
        except py7zr.exceptions.PasswordRequired:
            return True  # header itself is encrypted - can't even list contents without one
        except Exception:  # noqa: BLE001 - genuine corruption, not a password question
            return False
    return False


@dataclass
class ExpansionResult:
    """Accumulated across one call to expand_archives() or
    resolve_locked_archives() - see engine.py's scan_directory() for how
    the two passes' results get merged into the real file list/FileRecord
    set the scan actually processes."""

    extracted_files: list[str] = field(default_factory=list)
    # extracted file path -> the archive it came out of (the immediate
    # containing archive, not necessarily the top-level one if archives
    # are nested - see module docstring, decision 2).
    source_archive_by_path: dict[str, str] = field(default_factory=dict)
    # Archives that needed a password and didn't get a working one - only
    # ever populated by expand_archives() (pass 1); resolve_locked_archives()
    # (pass 2) either resolves an archive or moves it to unresolved_archives,
    # nothing is left in limbo after pass 2.
    locked_archives: list[str] = field(default_factory=list)
    # Archives copied into the "for external cracking" directory - only
    # ever populated by resolve_locked_archives() (pass 2).
    unresolved_archives: list[str] = field(default_factory=list)


def _dest_dir_for(archive_path: str, extraction_root: str) -> str:
    """One dedicated subdirectory per archive under extraction_root, named
    for readability (the archive's own stem) plus a short stable hash of
    its full path to guarantee no collision between two same-named
    archives from different source subfolders. Kept under ReportDirectory
    (see engine.py's caller), not a temp directory cleaned up after the
    scan - matters for two reasons: disk space accounting stays visible to
    the analyst instead of vanishing silently, and Ghidra/Sigcheck/
    Speakeasy quick-launch (results.py) need a real, still-existing path to
    point at for any extracted file the analyst later right-clicks.
    """
    p = Path(archive_path)
    digest = hashlib.sha1(str(p).encode("utf-8", errors="surrogateescape")).hexdigest()[:10]
    dest = Path(extraction_root) / f"{p.stem}_{digest}"
    dest.mkdir(parents=True, exist_ok=True)
    return str(dest)


def _unique_path(path: Path) -> Path:
    """Appends _1, _2, ... before the suffix if `path` already exists -
    used when copying a locked archive into the shared unresolved-archives
    directory, where two same-named archives from different source
    subfolders would otherwise silently clobber each other."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    i = 1
    while True:
        candidate = path.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def _extract_zip(path: str, dest_dir: str, password: str | None) -> list[str]:
    """Uses pyzipper.AESZipFile, not stdlib zipfile.ZipFile (2026-08-08 fix)
    - stdlib zipfile can only decrypt legacy ZipCrypto-encrypted entries; it
    can open/list a WinZip AE-x (AES-256) encrypted zip fine (reading the
    central directory doesn't need the key), but raises
    NotImplementedError("That compression method is not supported") the
    instant it tries to actually decompress an AES entry (compress_type 99,
    which it doesn't recognize at all) - regardless of whether the password
    supplied is correct. Found via a real scan against Malware Bazaar zips
    (which use AES-256, not ZipCrypto) - every archive came back "wrong
    password" even with the right one. pyzipper.AESZipFile is a drop-in
    superset of zipfile.ZipFile (same extract()/infolist()/setpassword()
    API) that adds real AE-1/AE-2 decryption, while still handling
    legacy-ZipCrypto and unencrypted zips exactly the same way stdlib
    zipfile did - no behavior change for anything that already worked.
    """
    extracted: list[str] = []
    with pyzipper.AESZipFile(path) as zf:
        if password:
            zf.setpassword(password.encode("utf-8"))
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Raises RuntimeError on a missing/wrong password - callers
            # differentiate "needed a password at all" via needs_password()
            # BEFORE ever reaching this function (pass 1 never calls this
            # on a flagged-encrypted archive), so any RuntimeError seen here
            # always means "the supplied password didn't work" (pass 2) or
            # genuine corruption (pass 1, on an archive needs_password()
            # said was NOT encrypted) - either way, the caller's try/except
            # handles it, no need to distinguish further here.
            zf.extract(info, path=dest_dir)
            extracted.append(str(Path(dest_dir) / info.filename))
    return extracted


def _extract_7z(path: str, dest_dir: str, password: str | None) -> list[str]:
    extracted: list[str] = []
    with py7zr.SevenZipFile(path, "r", password=password) as zf:
        names = list(zf.getnames())
        zf.extractall(path=dest_dir)
    for name in names:
        candidate = Path(dest_dir) / name
        if candidate.is_file():
            extracted.append(str(candidate))
    return extracted


def _extract_tar(path: str, dest_dir: str) -> list[str]:
    extracted: list[str] = []
    with tarfile.open(path, mode="r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            try:
                # filter="data" - PEP 706's safe-extraction filter (blocks
                # path traversal/absolute-path/device-file member tricks).
                # Backported to 3.10.12+/3.11.4+; BinSifter's own floor is
                # bare "3.10" (pyproject.toml), so an older 3.10.x patch
                # without this kwarg needs the fallback below rather than
                # a hard crash on import machinery it doesn't have yet.
                tf.extract(member, path=dest_dir, filter="data")
            except TypeError:
                tf.extract(member, path=dest_dir)
            extracted.append(str(Path(dest_dir) / member.name))
    return extracted


def _extract_gzip(path: str, dest_dir: str) -> list[str]:
    src = Path(path)
    dest_name = src.stem if src.suffix.lower() == ".gz" else src.name + ".decompressed"
    dest_path = Path(dest_dir) / dest_name
    with gzip.open(src, "rb") as fsrc, open(dest_path, "wb") as fdst:
        shutil.copyfileobj(fsrc, fdst)
    return [str(dest_path)]


def _extract(fmt: str, path: str, dest_dir: str, password: str | None) -> list[str]:
    if fmt == "zip":
        return _extract_zip(path, dest_dir, password)
    if fmt == "7z":
        return _extract_7z(path, dest_dir, password)
    if fmt == "tar":
        return _extract_tar(path, dest_dir)
    if fmt == "gzip":
        return _extract_gzip(path, dest_dir)
    raise ValueError(f"Unsupported archive format: {fmt}")  # pragma: no cover - classify() already gates this


def _expand_recursive(
    paths: list[str],
    extraction_root: str,
    result: ExpansionResult,
    depth: int,
    on_locked: Callable[[str], None],
) -> None:
    """Shared recursion core for both passes - `on_locked` is where the two
    passes actually differ: expand_archives() (pass 1) appends to
    result.locked_archives for later prompting, resolve_locked_archives()
    (pass 2) saves straight to the unresolved-archives directory instead
    (see module docstring on why a nested find during pass 2 doesn't
    trigger a second prompt round).

    `depth` counts levels of NESTING already recursed into, not "how deep
    is this archive" in an absolute sense - every archive passed into
    `paths` (whatever depth it arrives at) is always attempted, since
    MAX_NESTED_DEPTH bounds how far this function will recurse INTO what it
    finds, not whether the archive it was just handed gets opened at all.
    That distinction matters at the boundary: MAX_NESTED_DEPTH=0 still
    extracts every top-level archive under SrcDir (depth 0, not "nested" at
    all) - it just stops before recursing into anything found inside them.
    """
    for path in paths:
        fmt = classify(path)
        if fmt is None:
            continue  # not actually an archive - shouldn't happen, callers only pass archive paths

        if needs_password(path):
            on_locked(path)
            continue

        dest_dir = _dest_dir_for(path, extraction_root)
        try:
            extracted = _extract(fmt, path, dest_dir, password=None)
        except Exception as exc:  # noqa: BLE001 - one bad archive shouldn't abort the whole pre-scan
            logger.warning("Could not extract archive %s, skipping: %s", path, exc)
            continue

        for extracted_path in extracted:
            result.extracted_files.append(extracted_path)
            result.source_archive_by_path[extracted_path] = path

        nested = [p for p in extracted if is_archive(p)]
        if not nested:
            continue
        if depth >= MAX_NESTED_DEPTH:
            logger.info(
                "%d archive(s) found nested inside %s past the %d-level recursion cap - left "
                "as plain extracted files; their own contents will not be separately expanded.",
                len(nested), path, MAX_NESTED_DEPTH,
            )
            continue
        _expand_recursive(nested, extraction_root, result, depth + 1, on_locked)


def expand_archives(archive_paths: list[str], extraction_root: str) -> ExpansionResult:
    """Pass 1 - called once per scan, before the multiprocessing pool is
    created (see engine.py's scan_directory()). Extracts every archive in
    `archive_paths` that does NOT need a password (recursively, into any
    nested archives found along the way, up to MAX_NESTED_DEPTH), and
    separately collects every archive - top-level or nested - that DOES
    need one, without attempting to open those at all.

    Corrupt/unsupported-variant archives are logged and skipped outright,
    never added to locked_archives - a real parse failure isn't "needs a
    password", and mis-classifying it that way would prompt the analyst
    for a password that was never going to fix anything.
    """
    result = ExpansionResult()
    _expand_recursive(archive_paths, extraction_root, result, depth=0, on_locked=result.locked_archives.append)
    return result


def resolve_locked_archives(
    locked_archives: list[str],
    password_map: dict[str, str],
    extraction_root: str,
    unresolved_dest_dir: str,
) -> ExpansionResult:
    """Pass 2 - called once, after the GUI has prompted for passwords on
    every archive expand_archives() (pass 1) collected in
    result.locked_archives. For each one: extract with
    password_map.get(path) if a password was supplied; on ANY failure
    (wrong password, no password given at all, or a real error even with
    the right one - these aren't distinguished further, see
    _extract_zip()'s docstring), the archive itself is COPIED (never
    moved - never mutate the analyst's original evidence under SrcDir) into
    unresolved_dest_dir for the analyst to run through John/hashcat/etc.
    outside BinSifter, per Steve's original request.

    Successfully-unlocked archives are expanded recursively the same way
    pass 1 does; a nested locked archive discovered here is saved straight
    to unresolved_dest_dir instead of triggering a second prompting round
    (see module docstring).
    """
    result = ExpansionResult()
    unresolved_root = Path(unresolved_dest_dir)
    unresolved_root.mkdir(parents=True, exist_ok=True)

    def _save_unresolved(path: str) -> None:
        dest = _unique_path(unresolved_root / Path(path).name)
        shutil.copy2(path, dest)
        result.unresolved_archives.append(str(dest))
        logger.info("Password-protected archive saved for external cracking: %s -> %s", path, dest)

    for path in locked_archives:
        fmt = classify(path)
        password = password_map.get(path)
        if not password:
            _save_unresolved(path)
            continue

        dest_dir = _dest_dir_for(path, extraction_root)
        try:
            extracted = _extract(fmt, path, dest_dir, password=password)
        except Exception as exc:  # noqa: BLE001 - wrong password or genuine corruption, either way this archive stays locked
            logger.warning("Could not unlock archive %s with the supplied password: %s", path, exc)
            _save_unresolved(path)
            continue

        for extracted_path in extracted:
            result.extracted_files.append(extracted_path)
            result.source_archive_by_path[extracted_path] = path

        nested = [p for p in extracted if is_archive(p)]
        if nested:
            _expand_recursive(nested, extraction_root, result, depth=1, on_locked=_save_unresolved)

    return result
