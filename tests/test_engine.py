"""Tests for the cooperative pause/stop hooks and the richer per-file
progress_callback added to engine.scan_directory() - the pieces that make
a live Scan Queue page possible (see gui/pages/scan_queue.py). Runs against
real small files on disk (tmp_path), not mocks - hashing/entropy/
Authenticode/file-type classification all work fine on plain non-PE files,
and no YaraRules/CapaRules/NsrlPath are configured here, so this stays fast
and dependency-free while still exercising the real scan_directory() code
path end to end.
"""

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
