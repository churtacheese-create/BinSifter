"""Regression tests for the PE/ELF/shellcode classification logic ported
from the PowerShell version - this gates whether capa/FLOSS ever run on a
file, so it needs to match the original precisely, not approximately.
"""

from binsifter.core.file_type import classify, is_possible_false_negative

# Minimal-but-valid MZ+PE header: "MZ" magic, e_lfanew at 0x3C pointing to
# offset 0x40, "PE\0\0" signature at that offset.
_PE_HEADER = bytearray(128)
_PE_HEADER[0:2] = b"MZ"
_PE_HEADER[0x3C:0x40] = (0x40).to_bytes(4, "little")
_PE_HEADER[0x40:0x44] = b"PE\x00\x00"
_PE_HEADER = bytes(_PE_HEADER)

_ELF_HEADER = b"\x7fELF" + b"\x00" * 60


def test_pe_magic_detected(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_PE_HEADER)
    result = classify(str(sample), len(_PE_HEADER))
    assert result.is_pe is True
    assert result.is_elf is False
    assert result.capa_eligible is True


def test_elf_magic_detected(tmp_path):
    sample = tmp_path / "sample.elf"
    sample.write_bytes(_ELF_HEADER)
    result = classify(str(sample), len(_ELF_HEADER))
    assert result.is_elf is True
    assert result.is_pe is False
    assert result.capa_eligible is True


def test_small_raw_file_is_shellcode_eligible(tmp_path):
    sample = tmp_path / "sample.raw"
    content = b"\x90" * 100  # no PE/ELF magic
    sample.write_bytes(content)
    result = classify(str(sample), len(content))
    assert result.is_shellcode is True
    assert result.capa_eligible is True


def test_large_raw_file_is_not_shellcode_eligible(tmp_path):
    sample = tmp_path / "sample.raw"
    content = b"\x90" * 300000  # exceeds the .raw/.bin 200000-byte cutoff
    sample.write_bytes(content)
    result = classify(str(sample), len(content))
    assert result.is_shellcode is False
    assert result.capa_eligible is False


def test_txt_extension_under_size_cutoff_is_shellcode_eligible(tmp_path):
    sample = tmp_path / "sample.txt"
    content = b"A" * 50000  # under the general 100000-byte cutoff, not an excluded extension
    sample.write_bytes(content)
    result = classify(str(sample), len(content))
    assert result.is_shellcode is True


def test_exe_extension_with_bad_magic_is_possible_false_negative(tmp_path):
    # Claims to be an .exe by extension, but the bytes don't validate as
    # PE/ELF, and .exe is on the shellcode fallback's exclusion list - so
    # it falls through both branches despite a YARA hit.
    sample = tmp_path / "corrupt.exe"
    content = b"not a real PE file" + b"\x00" * 100
    sample.write_bytes(content)
    result = classify(str(sample), len(content))
    assert result.capa_eligible is False
    assert is_possible_false_negative(result, yara_hit_count=1, path=str(sample)) is True


def test_no_yara_hits_is_never_a_possible_false_negative(tmp_path):
    sample = tmp_path / "corrupt.exe"
    content = b"not a real PE file" + b"\x00" * 100
    sample.write_bytes(content)
    result = classify(str(sample), len(content))
    assert is_possible_false_negative(result, yara_hit_count=0, path=str(sample)) is False
