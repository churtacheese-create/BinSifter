/*
 * Smoke-test YARA rules for BinSifter's Python rewrite.
 *
 * These are NOT real detection rules - they match universally-present PE
 * structure (the DOS stub message, the MZ/PE magic bytes) so that scanning
 * ordinary, benign local executables produces a guaranteed, deterministic
 * hit. This exists to exercise BinSifter's YARA -> severity-bucketing ->
 * capa-eligibility -> capa pipeline end to end without needing malware
 * samples or a real-world rule set.
 */

rule Smoketest_DOS_Stub_Present
{
    meta:
        description = "Matches the standard MS-DOS stub message present in virtually every real PE file"
        severity = "low"

    strings:
        $dos_stub = "This program cannot be run in DOS mode."

    condition:
        $dos_stub
}

rule Smoketest_PE_Magic_Bytes
{
    meta:
        description = "Matches the MZ header + PE signature bytes"
        score = 10

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}
