# FRED Setup TODO — BinSifter Environment Bring-up

**Purpose of this file:** Development and troubleshooting done on the primary machine (2026-07-30 to
2026-07-31) turned up a batch of environment fixes and gotchas that haven't been applied to the FRED
(Forensic Recovery of Evidence Device) yet. The code itself is already synced via git — this file captures
the environment setup steps and context still missing on the FRED side so they don't have to be
rediscovered from scratch. Work the checklist top to bottom and check items off (`[ ]` to `[x]`) as you go.

## 0. Network access (blocks everything else)

- [ ] Confirm the FRED is off the `opnsense` proxy and on the unfettered WiFi AP. Everything below — pip
      installs and the winget command — needs unauthenticated outbound access. If still behind the proxy,
      `pip install` calls need `--proxy http://user:pass@opnsense...:3128` appended (use the real
      credentials; don't guess at them).

## 1. Sync the repo

- [ ] Repo: `https://github.com/churtacheese-create/BinSifter.git`, branch `main`. As of 2026-07-31 the
      latest commit is `f19b9dd` ("Add capa hang safety net, Results quick-launch tools, footer status,
      Help/About pages") and it's fully pushed — local `main` matches `origin/main` with nothing ahead or
      behind.
- [ ] On the FRED: if BinSifter isn't cloned yet, clone it. If it is, pull latest via **GitHub Desktop only**
      — this project's established workflow is GitHub Desktop UI, never terminal/bash `git`, because bash git
      has caused `index.lock` races here before.
- [ ] Read `BinSifter_CHANGELOG.md` (repo root) top-to-bottom for full project history/context.

## 2. Fix the Python 3.14 / MSVC build gap

`yara-python` and `binary2strings` don't ship prebuilt Windows wheels for Python 3.14 yet, so pip tries to
compile their C extensions and fails with `Microsoft Visual C++ 14.0 or greater is required` unless a
compiler is present.

- [ ] Install the compiler (elevated PowerShell):
  ```
  winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
  ```
- [ ] From the BinSifter repo root: `python -m pip install -e ".[dev]"` (add `--proxy ...` if still behind
      one). Confirm `yara-python` and `binary2strings` both build successfully this time — no more MSVC error.
- [ ] If `pip`/`python` scripts warn "not on PATH" (they will), either add
      `%LOCALAPPDATA%\Python\pythoncore-3.14-64\Scripts` to PATH, or just invoke via `python -m binsifter`
      instead of the bare `binsifter` command.

## 3. Undo the speakeasy version clobber, if it happened on this machine too

Earlier troubleshooting on the FRED involved installing a *separate* local clone (`speakeasy-master`,
version `2.0.0b4`) as an editable package to test a standalone `speakeasy` CLI. That uninstalled the
`unicorn==1.0.2` / `speakeasy-emulator==1.5.11` pair BinSifter's `pyproject.toml` actually pins, replacing
them with `unicorn 2.1.4` / `speakeasy-emulator 2.0.0b4` — a different, incompatible API that
`binsifter/core/speakeasy_scan.py` was not written against.

- [ ] Check installed versions: `pip show speakeasy-emulator unicorn`
- [ ] If they're not `1.5.11` / `1.0.2`, force them back:
  ```
  python -m pip install --force-reinstall speakeasy-emulator==1.5.11 unicorn==1.0.2
  ```
- [ ] Do **not** `pip install -e` the standalone `speakeasy-master` clone into this same environment again.
      If you need the standalone CLI for manual testing, use a separate venv.

## 4. Verify BinSifter actually runs

- [ ] Launch the GUI: `python -m binsifter` (or `binsifter` if Scripts dir is on PATH). Dashboard should
      open; footer status line (bottom right) should populate with YARA/capa/SSDEEP versions — this comes
      from `binsifter/core/tool_metadata.py`, added in the same batch as the capa timeout fix.
- [ ] Run the test suite: `pytest` from repo root. Pay particular attention to `tests/test_capa_scan.py` and
      `tests/test_subprocess_timeout.py` — these cover the new capa hang safety net (see below).
- [ ] Point BinSifter at a real sample directory and run a scan through the GUI. Confirm:
  - Results grid populates and capa detections show up for eligible files.
  - Results-grid right-click quick-launch menu works for Ghidra, Sigcheck, and Speakeasy entries.
  - No file hangs the batch for 30-90+ seconds — that's the exact failure mode
    `capa_scan.scan_file_with_timeout()` was added to prevent (confirmed against bash.exe, curl.exe,
    notepad.exe on 2026-07-30; see `binsifter/core/subprocess_timeout.py` docstring for the full incident).

## 5. Known gotchas worth knowing before you start (don't rediscover these)

- Running `python .\speakeasy\` (pointing python at a *directory*) puts that directory itself on
  `sys.path[0]`, so a same-named file inside it (`speakeasy/struct.py`) shadows the stdlib `struct` module
  and breaks `ctypes` with a circular-import error. Always run packages with `python -m <package>`, never by
  pointing at the directory.
- `capa`'s `import:` feature matching is DLL-name-literal — it misses `api-ms-win-core-*` forwarder DLLs.
  This is a known upstream limitation, not a bug in BinSifter's vivisect integration.
- Never call `SettingsPage.save()` / `save_settings_cache()` in a test or sandbox context without redirecting
  the config path first — it writes to the real project's live settings cache.

## 6. Once everything above is checked off

- [ ] Confirm the FRED is caught up before more feature work resumes there.
- [ ] This file can be deleted from the repo (or left as a historical note) once the FRED is fully synced —
      it's a one-time bridge document, not a permanent part of the project docs.
