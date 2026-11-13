"""Parsing oracles and an access-recording stream.

``resolve_memberships`` is the reference behaviour expected of a safe
server-side parser: it walks every symbol, follows SHN_XINDEX through the
SHT_SYMTAB_SHNDX section identified by its sh_link, and verifies that every
resolved index names a section that actually exists.

``naive_resolve_memberships`` is a deliberately defective variant: it
ignores the extended index table entirely, so an SHN_XINDEX symbol is
attributed to the raw reserved value instead of the linked table. The
self-test in the unittest module asserts that the fuzz suite catches this
behaviour, proving the assertions are strong enough to detect membership
confusion.
"""
from __future__ import annotations

from io import BytesIO
from typing import Any

from elftools.common.exceptions import ELFError
from elftools.elf.constants import SHN_INDICES
from elftools.elf.elffile import ELFFile

from .builder import (
    IDX_SHNDX,
    IDX_SYMTAB,
    SHN_XINDEX,
)


class AccessTrackingStream(BytesIO):
    """Remembers the inclusive byte range ever read or seeked to.

    The recorded range is the parser's actual file-access envelope for one
    parse attempt, which the fuzz report prints alongside every failing
    input.
    """

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.min_offset: int | None = None
        self.max_offset = 0

    def _mark(self, pos: int, length: int = 0) -> None:
        if self.min_offset is None:
            self.min_offset = pos
        else:
            self.min_offset = min(self.min_offset, pos)
        self.max_offset = max(self.max_offset, pos + length)

    @property
    def access_range(self) -> tuple[int, int] | None:
        if self.min_offset is None:
            return None
        return (self.min_offset, self.max_offset)

    def seek(self, pos: int, whence: int = 0) -> int:
        result = super().seek(pos, whence)
        self._mark(result)
        return result

    def read(self, size: int = -1) -> bytes:
        start = self.tell()
        chunk = super().read(size)
        # Record both the starting position and the position after reading,
        # so the envelope covers every byte actually consumed.
        self._mark(start)
        self._mark(start + len(chunk))
        return chunk


def _shndx_int(value: Any) -> int:
    """Normalize construct enum names / IntEnum members to plain ints."""
    if isinstance(value, str):
        return int(getattr(SHN_INDICES, value))
    return int(value)


def _linked_shndx_section(elf: ELFFile):
    """Return the SHT_SYMTAB_SHNDX section after validating its sh_link."""
    shndx = elf.get_section(IDX_SHNDX)
    if shndx['sh_type'] != 'SHT_SYMTAB_SHNDX':
        raise ELFError(
            f'expected SHT_SYMTAB_SHNDX at {IDX_SHNDX}, '
            f"got {shndx['sh_type']}")
    if int(shndx['sh_link']) != IDX_SYMTAB:
        raise ELFError(
            f'SHT_SYMTAB_SHNDX sh_link={int(shndx["sh_link"])} does not '
            f'point at symbol table {IDX_SYMTAB}')
    return shndx


def resolve_memberships(data: bytes) -> dict[str, Any]:
    """Reference resolution; raises ELFError on any broken relationship.

    A membership result is accepted only when the extended index entry
    points at a section number inside the parsed section table. A corrupted
    link or table must never silently land on a section that merely exists.
    """
    return resolve_memberships_on_stream(
        AccessTrackingStream(data), len(data))


def resolve_memberships_on_stream(stream: AccessTrackingStream,
                                  file_size: int) -> dict[str, Any]:
    """Same check as :func:`resolve_memberships` on a caller-owned stream,
    so the caller can read back the recorded byte-access envelope."""
    elf = ELFFile(stream)
    num_sections = elf.num_sections()
    shstrndx = elf.get_shstrndx()
    if not 0 <= shstrndx < num_sections:
        raise ELFError(
            f'shstrndx {shstrndx} out of range for {num_sections} sections')

    shstrtab = elf.get_section(shstrndx)
    if shstrtab['sh_type'] != 'SHT_STRTAB':
        raise ELFError(
            f'shstrndx {shstrndx} names {shstrtab["sh_type"]}, '
            'expected SHT_STRTAB')

    symtab = elf.get_section(IDX_SYMTAB)
    if symtab['sh_type'] != 'SHT_SYMTAB':
        raise ELFError(f'section {IDX_SYMTAB} is not SHT_SYMTAB')
    symbol_count = symtab.num_symbols()
    if symbol_count < 1:
        raise ELFError('symbol table is missing the reserved null entry')

    shndx = _linked_shndx_section(elf)
    if int(shndx['sh_size']) != symbol_count * int(shndx['sh_entsize']):
        raise ELFError('SHT_SYMTAB_SHNDX length does not match symbol count')

    memberships: list[int] = []
    for index in range(symtab.num_symbols()):
        symbol = symtab.get_symbol(index)
        raw = _shndx_int(symbol['st_shndx'])
        if raw == SHN_XINDEX:
            resolved = int(shndx.get_section_index(index))
            if not 0 <= resolved < num_sections:
                raise ELFError(
                    f'extended index {resolved} for symbol {index} is out of '
                    f'range for {num_sections} sections')
            memberships.append(resolved)
        else:
            memberships.append(raw)

    # Whole-table envelope check last: a server iterates every header (name
    # maps, section scans), so an inflated count whose table runs past EOF
    # must still be rejected even when the early sections parse fine.
    table_end = int(elf['e_shoff']) + num_sections * int(elf['e_shentsize'])
    if table_end > file_size:
        raise ELFError(
            f'section header table ends at {table_end} past EOF {file_size}')

    return {
        'num_sections': num_sections,
        'shstrndx': shstrndx,
        'memberships': memberships,
        'access_range': stream.access_range,
        'file_size': file_size,
    }


def naive_resolve_memberships(data: bytes) -> dict[str, Any]:
    """Defective resolver that intentionally ignores extended indices.

    It performs every other check like the reference resolver but treats
    the raw st_shndx value as authoritative, so SHN_XINDEX symbols are
    reported as belonging to section 0xffff rather than to the section
    named by the SHT_SYMTAB_SHNDX entry.
    """
    stream = AccessTrackingStream(data)
    elf = ELFFile(stream)
    num_sections = elf.num_sections()
    symtab = elf.get_section(IDX_SYMTAB)
    # Deliberately no SHT_SYMTAB_SHNDX lookup and no sh_link validation.
    memberships = [
        _shndx_int(symtab.get_symbol(index)['st_shndx'])
        for index in range(symtab.num_symbols())
    ]
    return {
        'num_sections': num_sections,
        'shstrndx': elf.get_shstrndx(),
        'memberships': memberships,
        'access_range': stream.access_range,
        'file_size': len(data),
    }
