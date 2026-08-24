# Testing checklist - real-machine confirmations still needed

Generated from TODO.md's open items, 2026-08-21. This isn't a new bug list - every
item below is a fix that's already been made in code but hasn't been confirmed
against real hardware yet, or (for Ingot/Defender) isn't a "run a test" item at
all. Check items off in TODO.md itself once confirmed, same as every other entry
there - this file is just a working list to run through, not a replacement for it.

## Rowan - fresh installer build, DPI/scaling smoke test

The 2026-08-18/19 DPI and Settings-page fixes (rounds 1-7, TODO.md lines 128-138)
were all confirmed by running the updated `.ps1` directly on the host PC - none
of them have been confirmed through an actually-*packaged* build yet (MSI,
Setup.exe, or the portable zip). Since the last confirmed installer builds
predate those fixes, this needs a fresh round:

- [x] **Confirmed 2026-08-21**: all four Rowan package formats (MSI, Setup.exe, portable zip - both host PC and FLARE VM) ran the same 652-file scan clean end to end, 0 errors.
- [x] **Confirmed 2026-08-21 - DPI/scaling smoke test passed on real hardware.** Host PC at 175% scaling, 3840x3160 - all windows scaled cleanly, no misaligned or skewed text. FLARE VM at 100% (1920x1080, unscaled) - also clean, as expected. Covers all four package formats since the same fixed `.ps1` ships in every one of them.
- [x] **Confirmed 2026-08-24, portable zip specifically, live-resize test.** Started on a host-PC monitor at 175% scaling, dragged the window's corners to resize both larger and smaller - no skewing, images resized cleanly. Dragged the whole window over to a second monitor at 150% scaling and repeated the same resize test - same clean result. Repeated once more on the FLARE VM at 100% scaling - also clean. This is a stronger test than the 2026-08-21 static confirmation (live cross-monitor drag + resize, not just launch-and-look) and covers the one format (portable) that hadn't been resize-tested yet. **This whole section can be considered closed.**

## Rowan - Add-Type failure visibility fix

TODO.md line 92, 2026-08-17. Previously a C# compile failure inside `Add-Type`
was silently swallowed (app looked fine until something tried to use the type
that failed to compile, hours later). Fixed with `-ErrorAction Stop` plus an
immediate MessageBox showing the real compiler diagnostic - not yet re-tested
against a real scan.

- [ ] **No reliable way to test this on demand** - it only fires if the C# `Add-Type` block genuinely fails to compile, which hasn't happened in any real scan since the original report. There's no safe way to force that failure deliberately without actually breaking the app for the test (e.g., temporarily introducing a real syntax error into the C# block, which risks leaving it broken if the revert is forgotten). Treat this as **confirmed by absence** for now - every scan across every format has run clean, meaning the original compile failure hasn't recurred - and if it ever does happen again on any machine, the thing to check is whether the new dialog shows a real compiler diagnostic immediately (the fix) instead of a delayed, unrelated "type not found" crash hours later (the old bug). Not something to chase proactively.

## Winnow - authenticode fingerprint re-hash fix

TODO.md line 144, 2026-08-19 - the most recent open item. A large file
(`WindowsXP-KB936929-SP3-x86-RUS.exe`) was being re-hashed from scratch once per
loaded catalog (thousands of times), which is why it took 38+ minutes on one
machine and stalled/errored out on another. Fixed via a per-instance fingerprint
cache.

- [x] **Confirmed 2026-08-21, via Winnow's Setup.exe test on both machines.** FLARE VM (1899 catalogs loaded): `WindowsXP-KB936929-SP3-x86-RUS.exe` finished in 277.2s, no stall/error - authenticode averaged 887.1ms/file overall (14.6% of CPU), down from the old 61.8s+/file. Host PC (5115 catalogs loaded): finished in 550.3s, authenticode averaged 521.7ms/file (5.8% of CPU). Both a dramatic improvement over the pre-fix tens-of-minutes-per-file / stall-and-error behavior - the fix is working. Worth noting this one file is still meaningfully slower than a typical file (hundreds of seconds vs. sub-second for most), so it may be worth a closer look at some point, but it's no longer breaking scans.

## Winnow - Speakeasy decoy-module path fix

TODO.md line 145, 2026-08-19. A mixed forward-slash/backslash path crashed
Speakeasy's decoy-module loading on the host PC specifically (`[Errno 22]`).
Fixed by normalizing the path at import time.

- [x] **Confirmed 2026-08-23, on the host PC** (the machine that originally hit this). Ran Speakeasy emulation against a real file and got back a complete, valid report (375 API calls observed, 0.409s runtime) with no `[Errno 22]`/`Unable to access file` anywhere in the output. Decoy-module loading works correctly now.

## Winnow - Stop button real-installer retest

TODO.md line 73, 2026-08-15. Fixed and covered by unit tests, but never
confirmed against an actual packaged installer + real scan.

- [x] **Run 2026-08-23 - this is what surfaced two more real bugs, both fixed the same day (TODO.md's "Winnow Pause/Stop buttons" section).** Stop actually did work (log: `Scan stopped by request while 6 file(s) were still in flight`), but the status label reverting to "Scanning..." made it look broken - that was a separate, purely cosmetic tick-handler bug, now fixed. Pause turned out to be a genuine no-op on any real multi-file scan - now fixed via a dispatch-throttling semaphore.
- [x] **CONFIRMED 2026-08-24, against a real installed Setup.exe build, two scans on the host PC.** Scan 1 (stop only): stopped cleanly at 648/652 completed, the remaining 4 in-flight files correctly marked Cancelled instead of waited on. Scan 2 (pause, then resume, then stop): the raw scan log shows a clean 37-second window (14:57:52-14:58:29) with zero new `Scanning:` (dispatch) lines - the files already in flight when Pause was clicked finished out normally during that window (e.g. one still completed at 14:57:52, 110.1s after its own dispatch), but nothing NEW was picked up - then at 14:58:29 a burst of new `Scanning:` lines fires all at once, exactly matching a Resume click waking the throttled submission loop back up. Scan then ran another ~21s before Stop was clicked and honored cleanly (293 completed, 359 cancelled, totals check out at 652). This is real, measurable evidence the dispatch-throttling fix works as designed, not just "the label changed." **This whole section can be considered closed.**

## Winnow - tool-version footer retest

TODO.md line 79, 2026-08-15. Footer showed "YARA: not installed" / "Capa: not
installed" / "SSDEEP: not installed" despite all three working, because
PyInstaller wasn't bundling their `.dist-info` metadata. Fixed via
`copy_metadata()` in the spec file.

- [x] **Confirmed 2026-08-21** - every test showed real tool versions in the footer, not "not installed".

## Winnow - logo/title-bar icon retest

TODO.md line 62, 2026-08-14. Bundled logos rendered blank and the window had no
title-bar icon, due to a PyInstaller 6.0 onedir layout change. Fixed via
`sys._MEIPASS`-aware asset lookup plus an explicit `setWindowIcon()` call.

- [x] **Confirmed 2026-08-21** - logos and title-bar icon rendered correctly in every test.

## Winnow - admin-mode install retest

TODO.md line 54, 2026-08-13. An all-users/admin install crashed on every launch
(`PermissionError` trying to write to `Program Files`). Fixed via a
write-access probe that falls back to `%LOCALAPPDATA%`.

- [x] **Confirmed 2026-08-23** - installed to the all-users `Program Files` location. Log's first line: write-access probe correctly detected `C:\Program Files\BinSifter Winnow` wasn't writable and fell back cleanly to `%LOCALAPPDATA%\BinSifter Winnow` for Reports/settings/cache - no crash. Scan then completed 652/652, 0 errors.

## Rowan - portable zip missing assets + orphaned-process fixes (new, 2026-08-21)

Found during this same test round, retested 2026-08-24:

- [x] **Confirmed 2026-08-24, both host PC and FLARE VM.** Portable zip rendered all logos and icons correctly (sidebar, About page, title bar) on both machines.
- [x] **Confirmed 2026-08-24, both machines - logs corroborate this directly.** `BinSIfter-Rowan-Portable_HOSTPC_08242026.txt` and the FLARE VM equivalent both show Reports/generated_rules/CSVs saved under the extracted portable folder itself (`...\BinSifter-Rowan-Portable\BinSifter-Rowan-Portable\Reports\...` on the host PC, `Z:\FLARE\BinSifter-Rowan-Portable\Reports\...` on the FLARE VM) - next to the exe, not the `%LOCALAPPDATA%\BinSifter` fallback. Both scans also completed clean (652/652, 0 errors visible in either log).
- [x] **Confirmed 2026-08-24, both machines.** No orphaned `BinSifter-Rowan.exe` process after closing the window normally on either the host PC or the FLARE VM. **This whole section can be considered closed.**

## Not a test - ongoing item

- [ ] **Microsoft Defender false-positive flag on Winnow.** Not something a test confirms or fixes. **New detail 2026-08-23**: this round's Defender alert (`Trojan:Win32/Malgent`, Severe) named the exact file for the first time - `C:\Program Files\BinSifter Winnow\_internal\speakeasy\winenv\decoys\x86\default_exe.exe`, the same generic decoy-module PE stub the Speakeasy path-fix above got loading correctly. Makes sense as the trigger: a minimal, near-empty PE stub with no legitimate-looking metadata is exactly the shape of file a heuristic/ML AV engine flags with nothing else to go on. Still needs Microsoft's file-submission portal, not a code change - but worth noting BinSifter's own Defender-exclusion Settings button only excludes `Reports\extracted_archives`, not the app's own install directory, so it doesn't cover this specific file at all today.

## Explicitly not on this list

- **Ingot (Rust variant)** - TODO.md line 209 states no active work is planned, so there's nothing to test yet.
- **"Which stage hung" investigation** (TODO.md line 64) - this was really asking which per-file stage was responsible for the original hang; the 2026-08-19 authenticode work answered that directly (it was the fingerprint re-hash, see above), so this doesn't need a separate test of its own.
