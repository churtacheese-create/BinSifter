"""Tests for binsifter.core.archive - archive/compressed-file support added
2026-08-07 (see that module's docstring for the design this pins down:
format scope, the two-pass password-prompt architecture, and nested-archive
recursion). Builds real zip/tar/gzip/7z fixtures on disk with pytest's
tmp_path rather than mocking the underlying libraries - this feature is
almost entirely "does the real zipfile/tarfile/py7zr call do what we think
it does", which a mock would just assert away.
"""

import gzip
import tarfile
import zipfile

import py7zr
import pyzipper
import pytest

from binsifter.core import archive


# ---------- classify() / is_archive() ----------

@pytest.mark.parametrize(
    "name,expected",
    [
        ("sample.zip", "zip"),
        ("sample.7z", "7z"),
        ("sample.tar", "tar"),
        ("sample.tar.gz", "tar"),
        ("sample.tgz", "tar"),
        ("sample.tar.bz2", "tar"),
        ("sample.tbz2", "tar"),
        ("sample.tar.xz", "tar"),
        ("sample.txz", "tar"),
        ("sample.gz", "gzip"),
        ("SAMPLE.ZIP", "zip"),  # case-insensitive
        ("sample.exe", None),
        ("sample.rar", None),  # explicitly out of scope for this pass
    ],
)
def test_classify_by_extension(name, expected):
    assert archive.classify(name) == expected


def test_is_archive_and_find_archives():
    assert archive.is_archive("a.zip") is True
    assert archive.is_archive("a.txt") is False
    assert archive.find_archives(["a.zip", "b.txt", "c.tar.gz", "d.exe"]) == ["a.zip", "c.tar.gz"]


# ---------- fixture builders ----------

def _make_plain_zip(path, files):
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)


def _make_password_zip(path, files, password):
    # zipfile can't WRITE ZipCrypto-encrypted entries itself (read-only
    # support for encryption) - shell out to the `zip` CLI, same tradeoff
    # any BinSifter test fixture involving a password-protected zip has to
    # make. Skipped gracefully if `zip` isn't on PATH (see the fixture
    # below).
    import subprocess

    src_dir = path.parent / f"{path.stem}_src"
    src_dir.mkdir()
    names = []
    for name, content in files.items():
        (src_dir / name).write_bytes(content)
        names.append(name)
    subprocess.run(
        ["zip", "-q", "-P", password, str(path), *names],
        cwd=src_dir, check=True,
    )


def _make_aes_zip(path, files, password):
    # 2026-08-08: the real-world case that surfaced the "stdlib zipfile
    # can't decrypt AES zips" bug - Malware Bazaar (and most current
    # malware-sample repositories) ship WinZip AE-x/AES-256 encrypted
    # zips, not legacy ZipCrypto ones. Built with pyzipper directly
    # (no `zip` CLI needed, unlike _make_password_zip's ZipCrypto fixture,
    # since the `zip` CLI doesn't support writing AES entries either).
    with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode("utf-8"))
        for name, content in files.items():
            zf.writestr(name, content)


def _make_tar_gz(path, files):
    import io

    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))


def _make_gzip(path, content):
    with gzip.open(path, "wb") as fh:
        fh.write(content)


def _make_plain_7z(path, files):
    with py7zr.SevenZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(content, name)


def _make_password_7z(path, files, password):
    with py7zr.SevenZipFile(path, "w", password=password) as zf:
        for name, content in files.items():
            zf.writestr(content, name)


# ---------- needs_password() ----------

def test_needs_password_false_for_plain_zip(tmp_path):
    p = tmp_path / "plain.zip"
    _make_plain_zip(p, {"a.txt": b"hello"})
    assert archive.needs_password(str(p)) is False


def test_needs_password_true_for_encrypted_zip(tmp_path):
    p = tmp_path / "locked.zip"
    try:
        _make_password_zip(p, {"a.txt": b"hello"}, "secret123")
    except FileNotFoundError:
        pytest.skip("`zip` CLI not available in this environment")
    assert archive.needs_password(str(p)) is True


def test_needs_password_true_for_aes_encrypted_zip(tmp_path):
    # Central-directory listing doesn't need the AES key, so this should
    # correctly detect "needs a password" the same way it does for a
    # legacy ZipCrypto zip - see needs_password()'s comment on why it can
    # stay on stdlib zipfile even though extraction can't.
    p = tmp_path / "locked_aes.zip"
    _make_aes_zip(p, {"a.txt": b"hello"}, "infected")
    assert archive.needs_password(str(p)) is True


def test_needs_password_false_for_plain_7z(tmp_path):
    p = tmp_path / "plain.7z"
    _make_plain_7z(p, {"a.txt": b"hello"})
    assert archive.needs_password(str(p)) is False


def test_needs_password_true_for_encrypted_7z(tmp_path):
    p = tmp_path / "locked.7z"
    _make_password_7z(p, {"a.txt": b"hello"}, "secret123")
    assert archive.needs_password(str(p)) is True


def test_needs_password_false_for_tar_and_gzip(tmp_path):
    tar_path = tmp_path / "a.tar.gz"
    _make_tar_gz(tar_path, {"a.txt": b"hello"})
    gz_path = tmp_path / "a.txt.gz"
    _make_gzip(gz_path, b"hello")

    assert archive.needs_password(str(tar_path)) is False
    assert archive.needs_password(str(gz_path)) is False


def test_needs_password_false_for_corrupt_archive(tmp_path):
    p = tmp_path / "corrupt.zip"
    p.write_bytes(b"not actually a zip file")
    assert archive.needs_password(str(p)) is False


# ---------- expand_archives() (pass 1) ----------

def test_expand_archives_extracts_plain_zip(tmp_path):
    archive_path = tmp_path / "plain.zip"
    _make_plain_zip(archive_path, {"a.txt": b"hello", "b.txt": b"world"})
    extraction_root = tmp_path / "extracted"

    result = archive.expand_archives([str(archive_path)], str(extraction_root))

    assert len(result.extracted_files) == 2
    assert not result.locked_archives
    for extracted_path in result.extracted_files:
        assert result.source_archive_by_path[extracted_path] == str(archive_path)


def test_expand_archives_extracts_tar_gz_and_gzip(tmp_path):
    tar_path = tmp_path / "bundle.tar.gz"
    _make_tar_gz(tar_path, {"a.txt": b"hello", "b.txt": b"world"})
    gz_path = tmp_path / "solo.txt.gz"
    _make_gzip(gz_path, b"solo content")
    extraction_root = tmp_path / "extracted"

    result = archive.expand_archives([str(tar_path), str(gz_path)], str(extraction_root))

    assert len(result.extracted_files) == 3  # 2 from the tar.gz, 1 from the standalone gzip
    solo_extracted = [p for p in result.extracted_files if p.endswith("solo.txt")]
    assert len(solo_extracted) == 1
    assert (tmp_path / "extracted").exists()


def test_expand_archives_extracts_7z(tmp_path):
    p = tmp_path / "plain.7z"
    _make_plain_7z(p, {"a.txt": b"hello", "b.txt": b"world"})
    extraction_root = tmp_path / "extracted"

    result = archive.expand_archives([str(p)], str(extraction_root))

    assert len(result.extracted_files) == 2
    assert not result.locked_archives


def test_expand_archives_collects_locked_without_extracting(tmp_path):
    locked = tmp_path / "locked.7z"
    _make_password_7z(locked, {"a.txt": b"hello"}, "secret123")
    extraction_root = tmp_path / "extracted"

    result = archive.expand_archives([str(locked)], str(extraction_root))

    assert result.extracted_files == []
    assert result.locked_archives == [str(locked)]


def test_expand_archives_skips_corrupt_archive_without_crashing(tmp_path):
    corrupt = tmp_path / "corrupt.zip"
    corrupt.write_bytes(b"not actually a zip file")
    extraction_root = tmp_path / "extracted"

    # Should not raise, and a corrupt (not password-protected) archive
    # should NOT show up in locked_archives - see needs_password()'s
    # docstring on why misclassifying corruption as "needs a password"
    # would be worse than just skipping it.
    result = archive.expand_archives([str(corrupt)], str(extraction_root))

    assert result.extracted_files == []
    assert result.locked_archives == []


def test_expand_archives_recurses_into_nested_archive(tmp_path):
    inner = tmp_path / "inner.zip"
    _make_plain_zip(inner, {"secret.txt": b"nested content"})
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, arcname="inner.zip")
    extraction_root = tmp_path / "extracted"

    result = archive.expand_archives([str(outer)], str(extraction_root))

    # inner.zip itself gets extracted out of outer.zip, AND its own
    # contents get recursively expanded - so secret.txt should show up as
    # a fully-extracted file, not just the inner archive sitting there
    # unopened.
    assert any(p.endswith("secret.txt") for p in result.extracted_files)


def test_expand_archives_stops_recursing_past_max_depth(tmp_path, monkeypatch):
    # Force a shallow cap so the test doesn't need to actually build 3+
    # levels of real nested zips to exercise the boundary.
    monkeypatch.setattr(archive, "MAX_NESTED_DEPTH", 0)

    inner = tmp_path / "inner.zip"
    _make_plain_zip(inner, {"secret.txt": b"nested content"})
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, arcname="inner.zip")
    extraction_root = tmp_path / "extracted"

    result = archive.expand_archives([str(outer)], str(extraction_root))

    # outer.zip (depth 0) is still allowed to extract - the cap only stops
    # recursing INTO what it finds once depth has already reached the cap.
    extracted_names = [p.split("/")[-1] for p in result.extracted_files]
    assert "inner.zip" in extracted_names
    assert not any(p.endswith("secret.txt") for p in result.extracted_files)


# ---------- resolve_locked_archives() (pass 2) ----------

def test_resolve_locked_archives_extracts_with_correct_password(tmp_path):
    locked = tmp_path / "locked.7z"
    _make_password_7z(locked, {"a.txt": b"hello"}, "secret123")
    extraction_root = tmp_path / "extracted"
    unresolved_dir = tmp_path / "password_protected"

    result = archive.resolve_locked_archives(
        [str(locked)], {str(locked): "secret123"}, str(extraction_root), str(unresolved_dir)
    )

    assert len(result.extracted_files) == 1
    assert result.unresolved_archives == []


def test_resolve_locked_archives_extracts_aes_zip_with_correct_password(tmp_path):
    # Regression test for the real 2026-08-08 bug: a Malware Bazaar-style
    # AES-256-encrypted zip, with the CORRECT password supplied, used to
    # come back as "wrong password" (NotImplementedError from stdlib
    # zipfile, caught by resolve_locked_archives()'s broad except and
    # treated identically to an actual wrong password) even though the
    # password was right - pyzipper.AESZipFile fixes this. See
    # core/archive.py's _extract_zip() docstring for the full story.
    locked = tmp_path / "locked_aes.zip"
    _make_aes_zip(locked, {"malware.exe": b"MZ" + b"\x00" * 100}, "infected")
    extraction_root = tmp_path / "extracted"
    unresolved_dir = tmp_path / "password_protected"

    result = archive.resolve_locked_archives(
        [str(locked)], {str(locked): "infected"}, str(extraction_root), str(unresolved_dir)
    )

    assert len(result.extracted_files) == 1
    assert result.unresolved_archives == []
    assert result.source_archive_by_path[result.extracted_files[0]] == str(locked)


def test_resolve_locked_archives_saves_unresolved_on_wrong_password(tmp_path):
    locked = tmp_path / "locked.7z"
    _make_password_7z(locked, {"a.txt": b"hello"}, "secret123")
    extraction_root = tmp_path / "extracted"
    unresolved_dir = tmp_path / "password_protected"

    result = archive.resolve_locked_archives(
        [str(locked)], {str(locked): "wrongpassword"}, str(extraction_root), str(unresolved_dir)
    )

    assert result.extracted_files == []
    assert len(result.unresolved_archives) == 1
    assert (unresolved_dir / "locked.7z").is_file()
    # Original file under the "SrcDir" is untouched - copied, not moved.
    assert locked.is_file()


def test_resolve_locked_archives_saves_unresolved_when_no_password_given(tmp_path):
    locked = tmp_path / "locked.7z"
    _make_password_7z(locked, {"a.txt": b"hello"}, "secret123")
    extraction_root = tmp_path / "extracted"
    unresolved_dir = tmp_path / "password_protected"

    result = archive.resolve_locked_archives(
        [str(locked)], {}, str(extraction_root), str(unresolved_dir)
    )

    assert result.extracted_files == []
    assert len(result.unresolved_archives) == 1


def test_resolve_locked_archives_handles_name_collision(tmp_path):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    locked_a = dir_a / "locked.7z"
    locked_b = dir_b / "locked.7z"
    _make_password_7z(locked_a, {"a.txt": b"hello"}, "secret123")
    _make_password_7z(locked_b, {"a.txt": b"hello"}, "secret123")
    extraction_root = tmp_path / "extracted"
    unresolved_dir = tmp_path / "password_protected"

    result = archive.resolve_locked_archives(
        [str(locked_a), str(locked_b)], {}, str(extraction_root), str(unresolved_dir)
    )

    assert len(result.unresolved_archives) == 2
    # Both preserved, not one clobbering the other.
    assert len(set(result.unresolved_archives)) == 2
