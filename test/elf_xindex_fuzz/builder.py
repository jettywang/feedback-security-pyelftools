"""Hand-laid-out ELF32 templates with interlinked section zero, symbol
table and SHT_SYMTAB_SHNDX sections.

The templates are deliberately tiny and fully deterministic. Instead of
emitting random bytes, :class:`Template` exposes the exact byte offsets of
every header field so that mutators can break a single structural
relationship (count, link target, index-table length) while keeping the
rest of the object well formed.

Two legal representations of the same object are produced:

* ``normal``  - e_shnum/e_shstrndx hold their values directly.
* ``extended``- e_shnum == 0 (real count in section zero's sh_size) and
                e_shstrndx == SHN_XINDEX (real index in section zero's
                sh_link).

Both describe identical section and symbol memberships.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# ELF constants used while laying out the object.
ELFCLASS32 = 1
ELFDATA2LSB = 1
ET_REL = 1
EM_386 = 3
EV_CURRENT = 1

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_SYMTAB = 2
SHT_SYMTAB_SHNDX = 18

SHF_ALLOC = 0x2
SHN_XINDEX = 0xFFFF
SHN_UNDEF = 0

EHDR_SIZE = 52
SHDR_SIZE = 40
SYM_SIZE = 16
WORD_SIZE = 4

# Section layout of every template.
IDX_NULL = 0
IDX_DECOY = 1
IDX_SHSTRTAB = 2
IDX_STRTAB = 3
IDX_SYMTAB = 4
IDX_SHNDX = 5
IDX_DATA = 6
SECTION_COUNT = 7

# Symbol layout of every template.
SYM_NULL = 0
SYM_UNDEF = 1
SYM_TARGET = 2
SYMBOL_COUNT = 3

# Membership the oracles have to agree on. The target symbol lives in the
# .data section; .decoy deliberately sits at a lower, still-valid index so a
# confused resolver cannot succeed by accident.
EXPECTED_TARGET_SECTION = IDX_DATA
DECOY_SECTION = IDX_DECOY

_SHDR_PACK = struct.Struct('<10I')
_SYM_PACK = struct.Struct('<IIIBBH')
_EHDR_PACK = struct.Struct('<HHIIIIIHHHHHH')


def _pack_shdr(sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
               sh_link, sh_info, sh_addralign, sh_entsize):
    return _SHDR_PACK.pack(sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                           sh_size, sh_link, sh_info, sh_addralign,
                           sh_entsize)


def _pack_sym(st_name, st_value, st_size, st_info, st_other, st_shndx):
    return _SYM_PACK.pack(st_name, st_value, st_size, st_info, st_other,
                          st_shndx)


@dataclass
class FieldRef:
    """Byte range of one header/table field inside the serialized file."""
    offset: int
    size: int


@dataclass
class Template:
    """A serialized ELF32 object plus a map of mutable field ranges."""
    data: bytearray
    mode: str
    refs: dict[str, FieldRef] = field(default_factory=dict)
    # Offsets and sizes of the blobs, useful for truncation and length work.
    layout: dict[str, tuple[int, int]] = field(default_factory=dict)

    def set_u16(self, name: str, value: int) -> None:
        ref = self.refs[name]
        struct.pack_into('<H', self.data, ref.offset, value & 0xFFFF)

    def get_u16(self, name: str) -> int:
        ref = self.refs[name]
        return struct.unpack_from('<H', self.data, ref.offset)[0]

    def set_u32(self, name: str, value: int) -> None:
        ref = self.refs[name]
        struct.pack_into('<I', self.data, ref.offset, value & 0xFFFFFFFF)

    def get_u32(self, name: str) -> int:
        ref = self.refs[name]
        return struct.unpack_from('<I', self.data, ref.offset)[0]


def build_template(mode: str) -> Template:
    """Build the canonical object in ``normal`` or ``extended`` mode.

    Both modes encode the same sections and the same symbol memberships.
    """
    if mode not in ('normal', 'extended'):
        raise ValueError(f'unknown mode {mode!r}')
    extended = mode == 'extended'

    # --- Section content blobs ---------------------------------------------
    shstr = b'\x00.decoy\x00.shstrtab\x00.strtab\x00.symtab\x00' \
            b'.symtab_shndx\x00.data\x00'
    name_decoy = 1
    name_shstrtab = 8
    name_strtab = 18
    name_symtab = 26
    name_shndx = 34
    name_data = 48

    # String table: NUL, then the target symbol name.
    strtab = b'\x00target\x00'

    # Symbol entries. The target symbol claims SHN_XINDEX, so its real
    # membership must come from the SHT_SYMTAB_SHNDX section.
    sym_null = _pack_sym(0, 0, 0, 0, 0, SHN_UNDEF)
    sym_undef = _pack_sym(0, 0, 0, 0, 0, SHN_UNDEF)
    sym_target = _pack_sym(1, 0x1000, 4, 0x10, 0, SHN_XINDEX)
    symtab = sym_null + sym_undef + sym_target

    # One Elf32_Word per symbol, including the reserved null entry.
    shndx = struct.pack('<3I', SHN_UNDEF, SHN_UNDEF, EXPECTED_TARGET_SECTION)
    data_blob = b'\x00' * 8

    # --- Place blobs immediately after the 52-byte ELF header --------------
    cursor = EHDR_SIZE
    blob_offsets = {}
    blobs = [
        ('shstrtab', shstr),
        ('strtab', strtab),
        ('symtab', symtab),
        ('shndx', shndx),
        ('data', data_blob),
    ]
    for name, blob in blobs:
        blob_offsets[name] = (cursor, len(blob))
        cursor += len(blob)

    shoff = cursor
    shstrtab_off, _ = blob_offsets['shstrtab']
    strtab_off, _ = blob_offsets['strtab']
    symtab_off, _ = blob_offsets['symtab']
    shndx_off, shndx_size = blob_offsets['shndx']
    data_off, data_size = blob_offsets['data']

    # --- Section headers ----------------------------------------------------
    # Section zero: in extended mode it carries the real section count
    # (sh_size) and the real shstrndx (sh_link), per the generic ABI.
    null_shdr = _pack_shdr(
        0, SHT_NULL, 0, 0, 0,
        SECTION_COUNT if extended else 0,
        IDX_SHSTRTAB if extended else 0,
        0, 0, 0)
    decoy_shdr = _pack_shdr(name_decoy, SHT_PROGBITS, SHF_ALLOC, 0,
                            data_off, 0, 0, 0, 1, 0)
    shstrtab_shdr = _pack_shdr(name_shstrtab, SHT_STRTAB, 0, 0,
                               shstrtab_off, len(shstr), 0, 0, 1, 0)
    strtab_shdr = _pack_shdr(name_strtab, SHT_STRTAB, 0, 0,
                             strtab_off, len(strtab), 0, 0, 1, 0)
    symtab_shdr = _pack_shdr(name_symtab, SHT_SYMTAB, 0, 0,
                             symtab_off, len(symtab), IDX_STRTAB,
                             SYM_TARGET, 4, SYM_SIZE)
    shndx_shdr = _pack_shdr(name_shndx, SHT_SYMTAB_SHNDX, 0, 0,
                            shndx_off, shndx_size, IDX_SYMTAB, 0, 4,
                            WORD_SIZE)
    data_shdr = _pack_shdr(name_data, SHT_PROGBITS, SHF_ALLOC, 0,
                           data_off, data_size, 0, 0, 1, 0)
    shdrs = (null_shdr, decoy_shdr, shstrtab_shdr, strtab_shdr,
             symtab_shdr, shndx_shdr, data_shdr)

    # --- ELF header ---------------------------------------------------------
    e_shnum = 0 if extended else SECTION_COUNT
    e_shstrndx = SHN_XINDEX if extended else IDX_SHSTRTAB
    ident = bytearray(16)
    ident[0:4] = b'\x7fELF'
    ident[4] = ELFCLASS32
    ident[5] = ELFDATA2LSB
    ident[6] = EV_CURRENT
    ehdr = bytearray(ident)
    ehdr += _EHDR_PACK.pack(
        ET_REL, EM_386, EV_CURRENT,
        0,            # e_entry
        0,            # e_phoff
        shoff,        # e_shoff
        0,            # e_flags
        EHDR_SIZE,    # e_ehsize
        0,            # e_phentsize
        0,            # e_phnum
        SHDR_SIZE,    # e_shentsize
        e_shnum,      # e_shnum
        e_shstrndx)   # e_shstrndx

    raw = bytearray(ehdr)
    for _, blob in blobs:
        raw += blob
    shdr_offsets = []
    for shdr in shdrs:
        shdr_offsets.append(len(raw))
        raw += shdr

    template = Template(data=raw, mode=mode)
    template.layout = dict(blob_offsets)
    template.layout['ehdr'] = (0, EHDR_SIZE)
    template.layout['shdr_table'] = (shoff, SECTION_COUNT * SHDR_SIZE)

    # ELF header field ranges (e_shnum/e_shstrndx are the last two halfwords).
    template.refs['e_shoff'] = FieldRef(0x20, 4)
    template.refs['e_shentsize'] = FieldRef(0x2E, 2)
    template.refs['e_shnum'] = FieldRef(0x30, 2)
    template.refs['e_shstrndx'] = FieldRef(0x32, 2)

    # Section header field ranges, indexed by section number.
    sh_fields = ('sh_name', 'sh_type', 'sh_flags', 'sh_addr', 'sh_offset',
                 'sh_size', 'sh_link', 'sh_info', 'sh_addralign',
                 'sh_entsize')
    for index, base in enumerate(shdr_offsets):
        for field_index, field_name in enumerate(sh_fields):
            template.refs[f'shdr{index}.{field_name}'] = FieldRef(
                base + field_index * 4, 4)

    # Individual SHT_SYMTAB_SHNDX slots for index-length mutations.
    shndx_base = shndx_off
    for slot in range(SYMBOL_COUNT):
        template.refs[f'shndx.slot{slot}'] = FieldRef(
            shndx_base + slot * WORD_SIZE, WORD_SIZE)
    return template
