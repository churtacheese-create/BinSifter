"""PE/ELF/shellcode magic-byte sniffing and capa-eligibility classification.

Direct port of BinSifter-Rowan.ps1, lines ~2087/2258-2301 - copied
byte-for-byte in logic (4096-byte header buffer, same MZ/PE and \\x7fELF
checks, same shellcode extension/size heuristic, same PossibleFalseNegative
condition) since this determines which files get real capa/FLOSS analysis
and which get silently skipped - exactly the kind of thing that must match
the original precisely, not "close enough."
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# 4096, not something smaller like 64 - deliberately matches the original's
# buffer size. A PE's e_lfanew (the offset to the "PE\0\0" signature) can
# legitimately sit well past a small header read on files with an oversized
# DOS stub; 4096 covers realistic cases while still capping the read for a
# known evasion trick (an absurdly large stub) - see the PowerShell
# version's comment at that line for the same reasoning.
_HEADER_READ_SIZE = 4096

_PE_ELF_LIKE_EXTENSIONS = {".exe", ".dll", ".so", ".elf"}
_SHELLCODE_EXCLUDED_EXTENSIONS = {".exe", ".dll", ".so", ".elf", ".bin", ".o", ".raw", ".dat"}


@dataclass
class FileTypeInfo:
    is_pe: bool
    is_elf: bool
    is_shellcode: bool
    capa_eligible: bool


def _read_header(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(_HEADER_READ_SIZE)
    except OSError:
        return b""


def classify(path: str, file_length: int) -> FileTypeInfo:
    header = _read_header(path)
    header_length = len(header)
    extension = Path(path).suffix.lower()

    is_pe = False
    if header_length >= 64 and header[0] == 0x4D and header[1] == 0x5A:
        pe_offset = int.from_bytes(header[0x3C:0x40], "little", signed=True)
        if (
            pe_offset >= 0
            and pe_offset + 4 <= header_length
            and header[pe_offset:pe_offset + 4] == b"PE\x00\x00"
        ):
            is_pe = True

    is_elf = header_length >= 4 and header[0:4] == b"\x7fELF"

    is_shellcode = (not is_pe and not is_elf) and (
        (extension in (".raw", ".bin") and file_length < 200000)
        or (extension not in _SHELLCODE_EXCLUDED_EXTENSIONS and file_length < 100000)
    )

    capa_eligible = is_pe or is_elf or is_shellcode
    return FileTypeInfo(is_pe=is_pe, is_elf=is_elf, is_shellcode=is_shellcode, capa_eligible=capa_eligible)


def is_possible_false_negative(file_type: FileTypeInfo, yara_hit_count: int, path: str) -> bool:
    """A file whose extension explicitly claims to be a native executable
    but whose magic bytes didn't validate as PE/ELF is excluded from both
    the PE/ELF branch AND the shellcode fallback (those extensions are on
    the fallback's exclusion list) - so it never reaches capa despite a
    YARA hit. Worth surfacing explicitly: could be a corrupted file, a
    truncated capture, or a deliberately header-stripped/anti-analysis
    binary.
    """
    extension = Path(path).suffix.lower()
    return yara_hit_count > 0 and not file_type.capa_eligible and extension in _PE_ELF_LIKE_EXTENSIONS
