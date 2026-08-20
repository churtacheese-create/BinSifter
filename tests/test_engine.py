"""Tests for the cooperative pause/stop hooks and the richer per-file
progress_callback added to engine.scan_directory() - the pieces that make
a live Scan Queue page possible (see gui/pages/scan_queue.py). Runs against
real small files on disk (tmp_path), not mocks - hashing/entropy/
Authenticode/file-type classification all work fine on plain non-PE files,
and no YaraRules/CapaRules/NsrlPath are configured here, so this stays fast
and dependency-free while still exercising the real scan_directory() code
path end to end.
"""

import zipfile

from binsifter.core.config import BinSifterConfig
from binsifter.core.disposition import save_disposition_entry
from binsifter.core.engine import scan_directory


def _make_files(tmp_path, count: int) -> str:
    src = tmp_path / "src"
    src.mkdir()
    for i in range(count):
        (src / f"file{i}.bin").write_bytes(f"not a real PE, file {i}".encode())
    return str(src)


def _config(src_dir: str) -> BinSifterConfig:
    return BinSifterConfig(SrcDir=src_dir)


def test_progress_callback_fires_scanning_then_completed():
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        src_dir = _make_files(__import__("pathlib").Path(tmp), 1)
        config = _config(src_dir)

        statuses_seen: list[str] = []

        def progress(done, total, path, record):
            statuses_seen.append(record.Status)

        result = scan_directory(config, progress_callback=progress)

        assert statuses_seen == ["Scanning", "Completed"]
        assert result.records[0].Status == "Completed"


def test_progress_callback_reports_error_status_not_completed(tmp_path, monkeypatch):
    src_dir = _make_files(tmp_path, 1)
    config = _config(src_dir)

    # Force the hashing stage to blow up so the Error path (not Completed) is
    # what progress_callback's second call sees for this file.
    import binsifter.core.engine as engine_mod

    def boom(path):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(engine_mod.hashing, "hash_and_score_file", boom)

    statuses_seen: list[str] = []

    def progress(done, total, path, record):
        statuses_seen.append(record.Status)

    result = scan_directory(config, progress_callback=progress)

    assert statuses_seen == ["Scanning", "Error"]
    assert result.records[0].Status == "Error"
    assert result.records[0].Error == "simulated failure"


def test_stop_before_first_file_cancels_everything(tmp_path):
    src_dir = _make_files(tmp_path, 3)
    config = _config(src_dir)

    result = scan_directory(config, should_stop=lambda: True)

    assert all(r.Status == "Cancelled" for r in result.records)


def test_stop_after_first_file_cancels_only_the_rest(tmp_path):
    src_dir = _make_files(tmp_path, 3)
    config = _config(src_dir)

    calls = {"count": 0}

    def should_stop():
        # False on the pre-file-0 check, True from then on - lets exactly
        # one file complete before the cooperative stop kicks in.
        calls["count"] += 1
        return calls["count"] > 1

    result = scan_directory(config, should_stop=should_stop)

    statuses = sorted(r.Status for r in result.records)
    assert statuses == ["Cancelled", "Cancelled", "Completed"]


def test_pause_blocks_dispatch_until_cleared(tmp_path, monkeypatch):
    src_dir = _make_files(tmp_path, 1)
    config = _config(src_dir)

    import binsifter.core.engine as engine_mod

    sleep_calls = {"count": 0}

    def fake_sleep(seconds):
        sleep_calls["count"] += 1
        if sleep_calls["count"] >= 3:
            # Simulate the analyst clicking "Resume" after a couple of polls.
            pause_state["paused"] = False

    monkeypatch.setattr(engine_mod.time, "sleep", fake_sleep)

    pause_state = {"paused": True}
    result = scan_directory(config, should_pause=lambda: pause_state["paused"])

    assert sleep_calls["count"] >= 3
    assert result.records[0].Status == "Completed"


def test_pause_then_stop_cancels_without_hanging(tmp_path, monkeypatch):
    src_dir = _make_files(tmp_path, 2)
    config = _config(src_dir)

    import binsifter.core.engine as engine_mod

    state = {"paused": True, "stop": False, "sleeps": 0}

    def fake_sleep(seconds):
        state["sleeps"] += 1
        if state["sleeps"] >= 2:
            state["stop"] = True  # analyst clicks Stop while paused

    monkeypatch.setattr(engine_mod.time, "sleep", fake_sleep)

    result = scan_directory(
        config,
        should_pause=lambda: state["paused"],
        should_stop=lambda: state["stop"],
    )

    assert all(r.Status == "Cancelled" for r in result.records)
    assert state["sleeps"] < 100  # sanity: didn't spin forever


def test_prior_disposition_carries_into_next_scan(tmp_path):
    """A file's SHA-1 keeps its analyst-set disposition across scans, as
    long as ReportDirectory (where the history file lives) stays the same -
    mirrors the PowerShell dispatcher reading .bsifter-disposition-history.txt
    back in at the start of each scan."""
    src_dir = _make_files(tmp_path, 1)
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    config = BinSifterConfig(SrcDir=src_dir, ReportDirectory=str(report_dir))

    first_pass = scan_directory(config)
    assert first_pass.records[0].Disposition == "Untriaged"  # FileRecord's default

    sha1 = first_pass.records[0].SHA1
    save_disposition_entry(str(report_dir), sha1, "Escalated")

    second_pass = scan_directory(config)
    assert second_pass.records[0].Disposition == "Escalated"
    assert second_pass.records[0].SHA1 == sha1


def test_nsrl_match_through_real_worker_pool(tmp_path):
    """End-to-end check for the 2026-08-04 NSRL rewrite (see nsrl.py's
    module docstring): scan_directory() hands each pool worker a cache file
    PATH, not a parsed set, and each worker opens/mmaps it independently in
    _pool_worker_init(). A unit test against nsrl.py alone can't catch a
    bug in that wiring (e.g. the wrong thing crossing the multiprocessing
    initargs boundary, or a worker failing to open the cache) - this runs a
    real two-file scan through the real multiprocessing.Pool and checks
    both the known-good and known-unknown outcomes actually reach
    FileRecord.NsrlMatch correctly.
    """
    import hashlib

    src_dir = _make_files(tmp_path, 2)  # file0.bin, file1.bin
    known_sha1 = hashlib.sha1(b"not a real PE, file 0").hexdigest()

    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    nsrl_path = tmp_path / "nsrl.txt"
    # Mix of upper/lowercase and a decoy hash, same tolerance the real NSRL
    # parser is expected to handle.
    nsrl_path.write_text(f"{known_sha1.upper()}\n" + "a" * 40 + "\n", encoding="utf-8")

    config = BinSifterConfig(SrcDir=src_dir, ReportDirectory=str(report_dir), NsrlPath=str(nsrl_path))
    result = scan_directory(config)

    known_record = next(r for r in result.records if r.SHA1 == known_sha1)
    unknown_records = [r for r in result.records if r.SHA1 != known_sha1]

    assert known_record.NsrlMatch is True
    assert len(unknown_records) == 1
    assert unknown_records[0].NsrlMatch is False


def test_nsrl_match_skips_imphash_ssdeep_unknown_file_still_gets_them(tmp_path):
    """2026-08-05 gating fix: a file NSRL already resolved as known-good
    should skip imphash/ssdeep (and YARA/capa/FLOSS) entirely - see
    engine.py's 2026-08-05 comment above the `if not record.NsrlMatch:`
    block, and BinSifter-Rowan.ps1:2208 for the reference
    behavior. ssdeep is the cleanest observable signal here: ppdeep
    produces a real fuzzy hash even for tiny non-PE content (confirmed
    directly - '3:fFQEqQqV:tnu' for this exact test corpus's file
    content), so SSDEEP being populated vs. staying at its None default is
    a direct read on whether the stage ran at all, not just what it found.
    """
    import hashlib

    src_dir = _make_files(tmp_path, 2)  # file0.bin, file1.bin
    known_sha1 = hashlib.sha1(b"not a real PE, file 0").hexdigest()

    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    nsrl_path = tmp_path / "nsrl.txt"
    nsrl_path.write_text(f"{known_sha1.upper()}\n", encoding="utf-8")

    config = BinSifterConfig(SrcDir=src_dir, ReportDirectory=str(report_dir), NsrlPath=str(nsrl_path))
    result = scan_directory(config)

    known_record = next(r for r in result.records if r.SHA1 == known_sha1)
    unknown_record = next(r for r in result.records if r.SHA1 != known_sha1)

    assert known_record.NsrlMatch is True
    assert known_record.SSDEEP is None  # stage skipped, not "ran and found nothing"
    assert unknown_record.NsrlMatch is False
    assert unknown_record.SSDEEP is not None  # stage actually ran for the non-match


def test_capa_not_invoked_without_a_yara_hit(tmp_path):
    """2026-08-05 gating fix: CapaEligible must only ever get computed -
    and capa only ever run - inside a real YARA hit, matching Rowan's
    nesting (BinSifter-Rowan.ps1:2257-2459, CapaEligible is set
    INSIDE the "if ($yaraText not empty)" branch). No YaraRules are
    configured here, so YaraHitCount stays 0 for every file regardless of
    format - _make_files() writes plain '.bin' files, which file_type.classify()
    would call capa-eligible via the shellcode heuristic (small file,
    extension in the (".raw", ".bin") branch) if the YARA gate weren't in
    the way, so this genuinely exercises the gate rather than just
    "non-PE files were never eligible anyway".
    """
    src_dir = _make_files(tmp_path, 1)
    config = BinSifterConfig(SrcDir=src_dir, CapaRules=str(tmp_path))  # CapaRules configured; no YaraRules
    result = scan_directory(config)

    record = result.records[0]
    assert record.YaraHitCount == 0
    assert record.CapaEligible is False  # never computed - stays at the dataclass default
    assert record.CapaDetectionCount == 0
    assert record.CAPAOutput is None


def test_stalled_worker_is_abandoned_instead_of_hanging_forever(tmp_path, monkeypatch):
    """2026-08-14: a real FLARE VM scan (Winnow_scanLogs_08142026.txt) got to
    651/652 files and then produced zero further log output for over 3
    hours before it was force-closed - one file's worker got stuck inside a
    stage with no timeout protection (only capa has one; hashing/
    authenticode/YARA/ssdeep/FLOSS don't), and the old plain
    result_queue.get() in the draining loop waited for that result forever.
    See RESULT_STALL_TIMEOUT_SECONDS' module-level comment for the full
    root-cause writeup.

    Exercising the real 1200s default here isn't practical, so this
    replaces _NoDaemonPool with a fake, synchronous, in-process stand-in
    that calls _process_one_file() directly for every file except one
    designated "stuck" path, whose callback is simply never invoked -
    exactly what a permanently-hung real worker looks like from the
    draining loop's point of view. RESULT_STALL_TIMEOUT_SECONDS is
    monkeypatched down to a fraction of a second so the test doesn't
    actually wait 20 minutes.
    """
    import binsifter.core.engine as engine_mod

    src_dir = _make_files(tmp_path, 3)  # file0.bin, file1.bin, file2.bin
    stuck_path = str((tmp_path / "src" / "file1.bin"))
    config = _config(src_dir)

    class _FakePool:
        def __init__(self, *, processes, initializer, initargs):
            # Mirrors what a real spawned worker's _pool_worker_init() call
            # does, just in this same test process instead of a child -
            # sets up the _worker_* globals _process_one_file() reads.
            initializer(*initargs)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def apply_async(self, func, args, callback=None, error_callback=None):
            path = args[0]
            if path == stuck_path:
                return  # simulated permanently-hung worker - callback never fires
            try:
                result = func(*args)
            except Exception as exc:  # noqa: BLE001 - mirrors error_callback's real contract
                if error_callback:
                    error_callback(exc)
            else:
                if callback:
                    callback(result)

    monkeypatch.setattr(engine_mod, "_NoDaemonPool", _FakePool)
    monkeypatch.setattr(engine_mod, "RESULT_STALL_TIMEOUT_SECONDS", 0.2)

    result = scan_directory(config)

    by_path = {r.Path: r for r in result.records}
    assert by_path[stuck_path].Status == "Error"
    assert "did not respond" in by_path[stuck_path].Error
    # The two healthy files still completed normally - one stuck file
    # doesn't take the rest of the batch down with it.
    other_statuses = [r.Status for p, r in by_path.items() if p != stuck_path]
    assert other_statuses == ["Completed", "Completed"]


def test_stop_clicked_mid_scan_actually_stops_instead_of_reverting(tmp_path, monkeypatch):
    """2026-08-14: real-world report - clicking Stop mid-scan showed
    "Stopping..." in the status bar and then went right back to
    "Scanning...", repeatedly, with no way to actually abort short of
    force-closing the whole app. Root cause: should_stop() was only ever
    polled in the SUBMISSION loop (between dispatching each file to the
    pool) - but pool.apply_async() doesn't block on worker availability, so
    every file is typically already queued to the pool within milliseconds
    of a scan starting, long before a human could click anything. Once
    submission finished, should_stop() was never checked again for the
    rest of the scan.

    Same fake-pool approach as test_stalled_worker_is_abandoned_instead_of_
    hanging_forever above: two files (file1/file2) never call back,
    simulating work still in flight when Stop gets clicked - confirms the
    draining loop (not just the submission loop) now actually reacts to
    should_stop(), marking still-outstanding files Cancelled instead of
    waiting on them forever.
    """
    import binsifter.core.engine as engine_mod

    src_dir = _make_files(tmp_path, 3)  # file0.bin, file1.bin, file2.bin
    still_running_paths = {
        str(tmp_path / "src" / "file1.bin"),
        str(tmp_path / "src" / "file2.bin"),
    }
    config = _config(src_dir)

    class _FakePool:
        def __init__(self, *, processes, initializer, initargs):
            initializer(*initargs)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def apply_async(self, func, args, callback=None, error_callback=None):
            path = args[0]
            if path in still_running_paths:
                return  # simulated in-flight worker - callback never fires
            try:
                result = func(*args)
            except Exception as exc:  # noqa: BLE001 - mirrors error_callback's real contract
                if error_callback:
                    error_callback(exc)
            else:
                if callback:
                    callback(result)

    monkeypatch.setattr(engine_mod, "_NoDaemonPool", _FakePool)
    monkeypatch.setattr(engine_mod, "RESULT_STALL_TIMEOUT_SECONDS", 0.2)
    # 2026-08-15: STOP_GRACE_SECONDS is a separate, shorter threshold added
    # after this test first exposed a real bug - see its own comment in
    # engine.py. Left at the real default (5s) this fake-pool test would
    # need to actually wait out 5 real seconds of Empty polling before the
    # draining loop would honor should_stop(); shrunk here the same way
    # RESULT_STALL_TIMEOUT_SECONDS already is above, purely to keep this a
    # fast unit test.
    monkeypatch.setattr(engine_mod, "STOP_GRACE_SECONDS", 0.05)

    # should_stop() is polled once per file in the submission loop too
    # (before each dispatch) - False for those first 3 calls so all 3 files
    # actually get dispatched, matching the real pool.apply_async()
    # behavior this fake pool stands in for (it never blocks on worker
    # availability, so submission always finishes before a human could
    # click anything). True from the 4th call onward - the draining loop's
    # first check - simulates a user clicking Stop just after the scan
    # starts, while two files are still "running".
    calls = {"count": 0}

    def should_stop():
        calls["count"] += 1
        return calls["count"] > 3

    result = scan_directory(config, should_stop=should_stop)

    by_path = {r.Path: r for r in result.records}
    assert by_path[str(tmp_path / "src" / "file0.bin")].Status == "Completed"
    for p in still_running_paths:
        assert by_path[p].Status == "Cancelled"


def test_archive_contents_scanned_through_real_worker_pool_with_source_archive_set(tmp_path):
    """End-to-end check for 2026-08-07's archive-expansion wiring (see
    core/archive.py and this module's own archive-expansion block) run
    through the REAL multiprocessing.Pool, not archive.py in isolation -
    same "unit tests can't catch the cross-process wiring bug" rationale as
    test_nsrl_match_through_real_worker_pool above.

    This is a real regression test for a real bug caught during manual
    end-to-end verification (2026-08-07): SourceArchive was originally set
    on the placeholder FileRecord dict built BEFORE the pool ran, which
    then got silently clobbered the moment each file's real result came
    back from a worker (`records[result.record.Path] = result.record`
    replaces the whole FileRecord object, not just merges fields) - every
    extracted file's SourceArchive came back blank in a real scan despite
    the assignment code existing. Fixed by applying source_archive_by_path
    AFTER the pool's completion-draining loop instead of before it starts.
    """
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "plain.txt").write_bytes(b"a normal file, not from any archive")
    archive_path = src_dir / "bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("inner1.txt", "inner file 1")
        zf.writestr("inner2.txt", "inner file 2")

    report_dir = tmp_path / "reports"
    report_dir.mkdir()

    config = BinSifterConfig(SrcDir=str(src_dir), ReportDirectory=str(report_dir))
    result = scan_directory(config)

    by_name = {r.Path.split("/")[-1]: r for r in result.records}
    assert set(by_name) == {"plain.txt", "bundle.zip", "inner1.txt", "inner2.txt"}
    assert all(r.Status == "Completed" for r in by_name.values())

    # The two directly-scanned files (the plain file and the archive itself)
    # were never extracted from anything.
    assert by_name["plain.txt"].SourceArchive == ""
    assert by_name["bundle.zip"].SourceArchive == ""

    # The two files that came OUT of the archive point back at it - the
    # actual bug this test guards against.
    assert by_name["inner1.txt"].SourceArchive == str(archive_path)
    assert by_name["inner2.txt"].SourceArchive == str(archive_path)
