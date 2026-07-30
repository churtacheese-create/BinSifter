# BinSifter Python smoke test

Exercises the real pipeline (hashing, NSRL, YARA, PE/ELF classification,
capa, FLOSS fallback, imphash/ssdeep clustering) end to end using ordinary,
benign local executables instead of malware - no download needed, nothing
here is malicious.

## 1. Get sample files

Copy a few small, legitimate Windows executables into `smoketest\samples\`.
Anything from your own System32 folder works - these are just being read,
not executed. For example, from the `BinSifter` folder:

```
mkdir smoketest\samples
copy C:\Windows\System32\notepad.exe smoketest\samples\
copy C:\Windows\System32\calc.exe smoketest\samples\
copy C:\Windows\System32\write.exe smoketest\samples\
```

(If any of those don't exist on your build of Windows, substitute any other
small .exe you have handy - anything under a few MB keeps capa's analysis
fast.)

## 2. Run the scan

```
binsifter-scan --src-dir smoketest\samples --yara-rules smoketest\yara_rules.yar --capa-rules smoketest\capa_rules
```

## 3. What to expect

- Every file should get real MD5/SHA-1/entropy values.
- `Smoketest_DOS_Stub_Present` and `Smoketest_PE_Magic_Bytes` should both
  match on every sample (YaraHitCount = 2) - this is what proves YARA
  scanning itself works, and it's also what makes CapaEligible get set
  (real PE magic bytes, not the shellcode heuristic).
- Because these are real PE files, capa should run via the vivisect
  backend and find the "imports common kernel32 API" smoke-test rule on
  most samples. As of 2026-07-30, expect CapaDetectionCount = 1 for
  at.exe, bash.exe, curl.exe, and notepad.exe. This is the real proof
  point: it confirms `capa.loader.get_extractor(..., backend="vivisect")`
  and `capa.capabilities.common.find_capabilities()` actually work in this
  environment, not just that the import succeeds.
  cacls.exe, calc.exe, and nslookup.exe are expected to show
  CapaDetectionCount = 0 - they genuinely don't import any of the rule's
  target functions directly (confirmed via objdump against their raw PE
  import tables), not a pipeline bug.
  (This rule went through two failed iterations before landing here: (1)
  originally matched the DOS stub string - failed because capa's
  file-scope string extraction comes from the binary's mapped/section
  content, not a raw scan of the whole file, and the DOS stub sits before
  any PE section; (2) then switched to DLL-qualified imports like
  `kernel32.GetProcAddress` - still only matched 1 of 7 samples, because
  modern Windows PEs resolve most kernel32 functions through "API Set"
  forwarder DLLs (`api-ms-win-core-libraryloader-l1-2-0.dll`) rather than
  a literal `KERNEL32.dll` import entry, and capa's `import:` feature is
  DLL-name-sensitive by design. The current rule uses capa's documented
  "wildcard module name" import syntax (`import: GetProcAddress` with no
  DLL prefix) to match regardless of which DLL literally provides the
  function. See the rule file's own description for the full story - the
  API Set gotcha is worth remembering for any future BinSifter capa rule
  that names a DLL explicitly. The rule file is still named
  `dos-stub-present.yml` for now - cosmetic only, doesn't affect anything.)
- FLOSS should NOT run on these files (PossibleFalseNegative requires a
  YARA hit AND capa-ineligibility - real PE files with a YARA hit are
  capa-eligible, so the FLOSS fallback branch is correctly skipped here).
  If you want to exercise the FLOSS path specifically, rename a copy of
  one sample to strip its extension oddity or truncate it so its PE magic
  bytes don't validate - not necessary for this smoke test, just a note
  for later.

Report the actual output (or traceback) back so we can fix whatever's
wrong rather than assume it works.

## Cleanup

`smoketest\samples\` is gitignored - the copied .exe files never get
committed. Delete the folder whenever you're done with it.
