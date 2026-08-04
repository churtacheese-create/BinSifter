# BinSifter (Loom) - TODO

_Last updated: 2026-08-04_

## Pipeline correctness (do this first)

- [ ] **Fix engine.py's missing pipeline gating - this is the real root cause behind the capa timing saga below.** Steve's intended design (confirmed against `BinSifter_v1.3.0-beta.1.ps1:2208-2459`, which implements it correctly): NSRL match skips imphash/ssdeep/YARA entirely; a YARA hit is required before `CapaEligible` even gets computed or capa runs at all; FLOSS only runs on the YARA-hit-but-capa-ineligible subset; MITRE ATT&CK comes from YARA rule metadata. `engine.py` currently runs imphash/ssdeep/YARA on every file regardless of NSRL match, and runs capa on every format-eligible file regardless of YARA hit count (`engine.py:434`, gated only on `config.CapaRules and record.CapaEligible`, no `YaraHitCount` check). On the 652-file / 1-YARA-hit scan, capa should have run on at most 1 file - it ran on 549. Fix:
  - Wrap the imphash + ssdeep + YARA block in `if not record.NsrlMatch:`.
  - Move `file_type_mod.classify()` / `record.CapaEligible` / the capa call inside `if record.YaraHitCount > 0:`, matching the nesting in the PS1.
  - FLOSS's own gate (`file_type.py:79`) already correctly checks `yara_hit_count > 0` - no change needed there.
  - Re-run the 652-file scan afterward and compare against today's logs - capa's share of scan time should collapse for a mostly-known-good corpus like this one.

## Performance tuning

- [ ] **Re-evaluate the capa timeout once the gating fix above lands.** Currently `DEFAULT_TIMEOUT_SECONDS = 90` in `core/capa_scan.py`, tuned against a workload (capa on all 549 eligible files) that the gating fix will make obsolete - once capa only runs on YARA-hit files, this may not matter much or may need re-tuning against a very different (much smaller) sample size. Prior data points, for reference:
  - 120s: 4192.7s total scan, 186/549 capa timeouts, 66.1% capa success
  - 90s: 2042.1s total scan, 223/549 capa timeouts, 59.4% capa success
  - 60s: 1539.5s total scan, 252/549 capa timeouts, 54.1% capa success

- [ ] **Look at ssdeep stage cost.** Consistently ~5-8% of total scan time across all three runs (1636.8-1794.1 CPU-seconds, ~2.5-2.75s/file average). Small next to capa, but that per-file average seems high for fuzzy hashing and hasn't been investigated yet.

## Correctness / trust

- [ ] **Authenticode trust store.** `signify` has no root CA bundle wired up, so every signed file currently resolves to `SignatureStatus = "NotTrusted"` instead of `"Valid"` (see `core/authenticode.py` module docstring). This means the dashboard's "Unsigned" tile (`SignatureStatus != "Valid"`) currently lumps genuinely-unsigned files together with properly-signed-but-unverified ones - on the last scan that showed 558/652 as "Unsigned," which is likely a big overcount. Two options, not mutually exclusive:
  - Wire up a real trust store so Valid/NotTrusted split correctly.
  - Rename the "Unsigned" tile to something honest (e.g. "Not Verified") until the above is done, so the number isn't misleading in the meantime.

## Parked

- [ ] **Rust variant.** Revisit whenever - no active work planned.
