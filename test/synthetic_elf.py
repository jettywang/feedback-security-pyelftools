#------------------------------------------------------------------------------
# elftools tests: tiny in-memory ELF shared-object builder
#
# Builds minimal 64-bit little-endian ET_DYN files with a PT_DYNAMIC segment,
# a dynamic symbol table, DT_VERSYM and DT_VERNEED, optionally without a
# section header table. Used to exercise versioned-import parsing on crafted
# edge cases (duplicate names, hidden bits, broken VERNEED auxiliary chains)
# that no checked-in fixture happens to contain.
#
# This code is in the public domain
#------------------------------------------------------------------------------
from __future__ import annotations

import struct
from dataclasses import dataclass
from io import BytesIO

ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_DYN = 3
EM_X86_64 = 62

PT_LOAD = 1
PT_DYNAMIC = 2
PF_R = 4
PF_W = 2
PF_X = 1

SHT_NULL = 0
SHT_STRTAB = 3
SHT_DYNSYM = 11
SHT_DYNAMIC = 6
SHT_GNU_VERSYM = 0x6FFFFFFF
SHT_GNU_VERNEED = 0x6FFFFFFE

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_VERSYM = 0x6FFFFFF0
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STT_NOTYPE = 0
STT_FUNC = 2
STN_UNDEF = 0
SHN_UNDEF = 0

VER_NDX_LOCAL = 0
VER_NDX_GLOBAL = 1
VERSYM_HIDDEN = 0x8000


def _st_info(bind: int, stype: int) -> int:
    return (bind << 4) | (stype & 0xF)


@dataclass
class SyntheticSymbol:
    name: str
    bind: int = STB_GLOBAL
    stype: int = STT_FUNC
    version_index: int | str = VER_NDX_GLOBAL
    hidden: bool = False


@dataclass
class SyntheticVersion:
    """ One VERNEED entry: a needed library plus its named versions. """
    library: str
    versions: list[tuple[str, int]]  # (version name, vna_other index)


class SyntheticELFBuilder:
    """ Assemble a minimal versioned ET_DYN image in memory. """

    def __init__(
        self,
        symbols: list[SyntheticSymbol],
        requirements: list[SyntheticVersion],
        needed_libraries: list[str] | None = None,
    ) -> None:
        self.symbols = symbols
        self.requirements = requirements
        self.needed_libraries = (
            needed_libraries
            if needed_libraries is not None
            else [req.library for req in requirements])
        self.include_section_headers = True
        self.break_vernaux_chain = False
        self.break_verneed_chain = False
        self.duplicate_vna_other: int | None = None
        self.drop_verneednum = False

    def build(self) -> BytesIO:
        dynstr = _StringTable()
        # Order strings deterministically; remember their offsets.
        needed_offsets = [dynstr.add(name) for name in self.needed_libraries]
        symbol_name_offsets = [dynstr.add(sym.name) for sym in self.symbols]
        version_name_offsets: list[list[int]] = []
        library_name_offsets: list[int] = []
        for req in self.requirements:
            library_name_offsets.append(dynstr.add(req.library))
            version_name_offsets.append(
                [dynstr.add(name) for name, _ in req.versions])
        dynstr_bytes = dynstr.data()

        # Symbol table starts with the mandatory null symbol.
        sym_entries = [b'\x00' * 24]
        for sym, name_offset in zip(self.symbols, symbol_name_offsets):
            sym_entries.append(struct.pack(
                '<IBBHQQ',
                name_offset,
                _st_info(sym.bind, sym.stype),
                0,                # st_other
                SHN_UNDEF,        # all crafted symbols are imports
                0, 0))            # st_value, st_size
        dynsym_bytes = b''.join(sym_entries)

        versym_entries: list[int] = [VER_NDX_LOCAL]
        for sym in self.symbols:
            value = sym.version_index
            if isinstance(value, str):
                value = {'VER_NDX_LOCAL': 0, 'VER_NDX_GLOBAL': 1}[value]
            if sym.hidden:
                value |= VERSYM_HIDDEN
            versym_entries.append(value)
        versym_bytes = b''.join(struct.pack('<H', v) for v in versym_entries)

        verneed_bytes, verneed_count = self._build_verneed(
            library_name_offsets, version_name_offsets)

        # Layout one PT_LOAD covering everything, page-aligned in file size.
        base = 0x0  # vaddr equals file offset for simplicity
        dynamic_bytes, dynamic_layout = self._build_dynamic(
            needed_offsets, verneed_count)

        chunks = [
            ('dynsym', dynsym_bytes, 8),
            ('dynstr', dynstr_bytes, 1),
            ('versym', versym_bytes, 2),
            ('verneed', verneed_bytes, 4),
            ('dynamic', dynamic_bytes, 8),
        ]
        layout: dict[str, tuple[int, bytes]] = {}
        cursor = self._elf_header_size() + self._phdr_size()
        vaddr_cursor = cursor
        for name, data, align in chunks:
            if cursor % align:
                cursor += align - cursor % align
                vaddr_cursor = cursor
            layout[name] = (cursor, data)
            cursor += len(data)
            vaddr_cursor = cursor

        dynsym_addr = layout['dynsym'][0]
        dynstr_addr = layout['dynstr'][0]
        versym_addr = layout['versym'][0]
        verneed_addr = layout['verneed'][0]
        dynamic_addr = layout['dynamic'][0]

        tag_values = {
            'DT_STRTAB': base + dynstr_addr,
            'DT_SYMTAB': base + dynsym_addr,
            'DT_STRSZ': len(dynstr_bytes),
            'DT_SYMENT': 24,
            'DT_VERSYM': base + versym_addr,
            'DT_VERNEED': base + verneed_addr,
        }
        dynamic_bytes, _ = self._build_dynamic(
            needed_offsets, verneed_count, tag_values)
        layout['dynamic'] = (dynamic_addr, dynamic_bytes)

        load_end = cursor
        image = self._assemble(
            layout, dynamic_addr, load_end)
        if self.include_section_headers:
            self._append_section_headers(
                image, layout, len(dynsym_bytes), len(versym_bytes),
                verneed_count)
        else:
            self._zero_section_header_fields(image)
        return image

    # -- internals ----------------------------------------------------------

    def _build_verneed(
        self,
        library_offsets: list[int],
        version_offsets: list[list[int]],
    ) -> tuple[bytes, int]:
        out = BytesIO()
        count = 0
        for req_index, req in enumerate(self.requirements):
            lib_off = library_offsets[req_index]
            aux_list = list(zip(req.versions, version_offsets[req_index]))
            vernaux_bytes = b''
            for aux_index, ((name, vna_other), name_off) in enumerate(
                    aux_list):
                other = vna_other
                if (self.duplicate_vna_other is not None
                        and aux_index > 0):
                    other = self.duplicate_vna_other
                is_last = aux_index == len(aux_list) - 1
                # A zero vna_next on a non-final entry is a broken chain:
                # the linker would stop there and lose the rest.
                vna_next = 0 if (is_last or self.break_vernaux_chain) else 16
                vernaux_bytes += struct.pack(
                    '<IHHII',
                    0,              # vna_hash
                    0,              # vna_flags
                    other,          # vna_other
                    name_off,       # vna_name
                    vna_next)
            vn_aux = 16
            is_last_requirement = req_index == len(self.requirements) - 1
            # A zero vn_next on a non-final Verneed truncates the table.
            vn_next = 0 if (is_last_requirement
                            or self.break_verneed_chain) else (
                16 + len(aux_list) * 16)
            out.write(struct.pack(
                '<HHIII',
                1,                  # vn_version
                len(aux_list),      # vn_cnt
                lib_off,            # vn_file
                vn_aux,             # vn_aux
                vn_next))           # vn_next
            out.write(vernaux_bytes)
            count += 1
        return out.getvalue(), count

    def _build_dynamic(
        self,
        needed_offsets: list[int],
        verneed_count: int,
        values: dict[str, int] | None = None,
    ) -> tuple[bytes, dict[str, int]]:
        values = dict(values or {})
        tags: list[tuple[int, int]] = []
        for offset in needed_offsets:
            tags.append((DT_NEEDED, offset))
        tags.append((DT_STRTAB, values.get('DT_STRTAB', 0)))
        tags.append((DT_SYMTAB, values.get('DT_SYMTAB', 0)))
        tags.append((DT_STRSZ, values.get('DT_STRSZ', 0)))
        tags.append((DT_SYMENT, values.get('DT_SYMENT', 24)))
        tags.append((DT_VERSYM, values.get('DT_VERSYM', 0)))
        tags.append((DT_VERNEED, values.get('DT_VERNEED', 0)))
        if not self.drop_verneednum:
            tags.append((DT_VERNEEDNUM, verneed_count))
        tags.append((DT_NULL, 0))
        return b''.join(struct.pack('<QQ', tag, val) for tag, val in tags), {}

    def _elf_header_size(self) -> int:
        return 64

    def _phdr_size(self) -> int:
        return 56 * 2

    def _assemble(
        self,
        layout: dict[str, tuple[int, bytes]],
        dynamic_addr: int,
        load_end: int,
    ) -> BytesIO:
        image = BytesIO()
        # ELF header (e_phnum=2, no section headers yet).
        image.write(b'\x7fELF')
        image.write(bytes([
            ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0,
            0, 0, 0, 0, 0, 0, 0, 0]))
        image.write(struct.pack(
            '<HHIQQQIHHHHHH',
            ET_DYN, EM_X86_64, EV_CURRENT,
            0,                  # e_entry
            64,                 # e_phoff
            0,                  # e_shoff (filled later)
            0,                  # e_flags
            64,                 # e_ehsize
            56,                 # e_phentsize
            2,                  # e_phnum
            64,                 # e_shentsize
            0,                  # e_shnum
            0))                 # e_shstrndx

        def phdr(p_type: int, flags: int, offset: int, vaddr: int,
                 filesz: int, memsz: int, align: int) -> bytes:
            return struct.pack(
                '<IIQQQQQQ',
                p_type, flags, offset, vaddr,
                0,                  # p_paddr
                filesz, memsz, align)

        load_size = (load_end + 0xFFF) & ~0xFFF
        image.write(phdr(
            PT_LOAD, PF_R | PF_W | PF_X, 0, 0,
            load_end, load_size, 0x1000))
        image.write(phdr(
            PT_DYNAMIC, PF_R | PF_W, dynamic_addr, dynamic_addr,
            len(layout['dynamic'][1]), len(layout['dynamic'][1]), 8))

        for name, (offset, data) in layout.items():
            image.seek(offset)
            image.write(data)
        image.seek(load_size)
        image.truncate(load_size)
        return image

    def _zero_section_header_fields(self, image: BytesIO) -> None:
        # e_shoff=0, e_shnum=0, e_shstrndx=0 already set in the header.
        image.seek(0)
        assert image.read(4) == b'\x7fELF'

    def _append_section_headers(
        self,
        image: BytesIO,
        layout: dict[str, tuple[int, bytes]],
        dynsym_size: int,
        versym_size: int,
        verneed_count: int,
    ) -> None:
        shstr = _StringTable()
        names = {
            name: shstr.add(f'.{name}')
            for name in ('shstrtab', 'dynsym', 'dynstr', 'versym',
                         'verneed', 'dynamic')}
        shstr_off = len(image.getvalue())
        if shstr_off % 8:
            shstr_off += 8 - shstr_off % 8
        image.seek(shstr_off)
        image.write(shstr.data())

        headers = [b'\x00' * 64]  # SHT_NULL
        # Section indices: 1=dynstr, 2=dynsym, 3=versym, 4=verneed,
        # 5=dynamic, 6=shstrtab.
        entries = [
            ('dynstr', SHT_STRTAB, 0, layout['dynstr'][0],
             len(layout['dynstr'][1]), 0, 0, 1, 0),
            ('dynsym', SHT_DYNSYM, 0, layout['dynsym'][0],
             dynsym_size, 1, 0, 8, 24),
            ('versym', SHT_GNU_VERSYM, 0, layout['versym'][0],
             versym_size, 2, 0, 2, 2),
            ('verneed', SHT_GNU_VERNEED, 0, layout['verneed'][0],
             len(layout['verneed'][1]), 1, verneed_count, 4, 16),
            ('dynamic', SHT_DYNAMIC, 3, layout['dynamic'][0],
             len(layout['dynamic'][1]), 1, 0, 8, 16),
            ('shstrtab', SHT_STRTAB, 0, shstr_off,
             len(shstr.data()), 0, 0, 1, 0),
        ]
        for (name, sh_type, flags, offset, size, link, info,
             align, entsize) in entries:
            headers.append(struct.pack(
                '<IIQQQQIIQQ',
                names[name], sh_type, flags, offset, offset,
                size, link, info, align, entsize))
        shoff = len(image.getvalue())
        if shoff % 8:
            shoff += 8 - shoff % 8
        image.seek(shoff)
        for header in headers:
            image.write(header)
        shstr_index = len(headers) - 1
        # Patch ELF header section fields.
        image.seek(40)
        image.write(struct.pack(
            '<QIHHHHHH',
            shoff, 0, 64, 56, 2, 64, len(headers), shstr_index))


class _StringTable:
    """ Dynamic string table: offset 0 holds the empty string. """

    def __init__(self) -> None:
        self._buffer = bytearray(b'\x00')
        self._offsets: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value in self._offsets:
            return self._offsets[value]
        offset = len(self._buffer)
        self._buffer.extend(value.encode('utf-8'))
        self._buffer.append(0)
        self._offsets[value] = offset
        return offset

    def data(self) -> bytes:
        return bytes(self._buffer)
