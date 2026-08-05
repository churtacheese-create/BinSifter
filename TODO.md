# BinSifter (Winnow) - TODO

_Last updated: 2026-08-05_

## Done

- [x] **Fix engine.py's missing pipeline gating (2026-08-05).** `engine.py` was running imphash/ssdeep/YARA on every file regardless of NSRL match, and capa on every format-eligible file regardless of YARA hit count - on the 652-file/1-YARA-hit scan, capa should have run on at most 1 file and ran on 549. Fixed to match `BinSifter-Rowan_v1.3.0-beta.1.ps1:2208-2459`: imphash/ssdeep/YARA now wrapped in `if not record.NsrlMatch:`; `file_type_mod.classify()`/`CapaEligible`/the capa call now nested inside `if record.YaraHitCount > 0:`. FLOSS's own gate (`file_type.py:79`) already correctly checked `yara_hit_count > 0`, untouched. Covered by two new tests in `test_engine.py` (`test_nsrl_match_skips_imphash_ssdeep_unknown_file_still_gets_them`, `test_capa_not_invoked_without_a_yara_hit`) - full suite passes except the two known pre-existing failures (cross-process monkeypatch limitation in `test_progress_callback_reports_error_status_not_completed`, and the capa stub's lack of real analysis in `test_capa_scan.py`, neither related to this change). **Not yet validated against a real scan** - next real 652-file run is what actually confirms capa's share of scan time collapses as expected.

## Performance tuning

- [ ] **Re-run the real scan and re-measure everything below - the gating fix changes the workload completely.** All capa-timeout and ssdeep numbers below were measured while capa/ssdeep were running on far more files than intended (549 capa scans instead of at most 1; ssdeep on all 652 files instead of the ~549 non-NSRL-match ones). They're historical context now, not current targets:
  - capa timeout (`DEFAULT_TIMEOUT_SECONDS = 90` currently) - 120s: 4192.7s total scan, 186/549 capa timeouts, 66.1% capa success; 90s: 2042.1s total, 223/549 timeouts, 59.4% success; 60s: 1539.5s total, 252/549 timeouts, 54.1% success.
  - ssdeep stage cost - consistently ~5-8% of total scan time across those same three runs (1636.8-1794.1 CPU-seconds, ~2.5-2.75s/file average) - worth a fresh look once its real (much smaller, non-NSRL-match-only) workload is known.

## Correctness / trust

- [ ] **Authenticode trust store.** `signify` has no root CA bundle wired up, so every signed file currently resolves to `SignatureStatus = "NotTrusted"` instead of `"Valid"` (see `core/authenticode.py` module docstring). This means the dashboard's "Unsigned" tile (`SignatureStatus != "Valid"`) currently lumps genuinely-unsigned files together with properly-signed-but-unverified ones - on the last scan that showed 558/652 as "Unsigned," which is likely a big overcount. Two options, not mutually exclusive:
  - Wire up a real trust store so Valid/NotTrusted split correctly.
  - Rename the "Unsigned" tile to something honest (e.g. "Not Verified") until the above is done, so the number isn't misleading in the meantime.

## Parked

- [ ] **Ingot (Rust variant).** Revisit whenever - no active work planned.
