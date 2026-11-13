#!/usr/bin/env python3
#-------------------------------------------------------------------------------
# make_relro_fixtures.py
#
# Hand-crafts small x86-64 little-endian ET_DYN ELF files for the RELRO
# analysis example.  The host toolchain emits Mach-O on macOS, so instead of
# relying on a compiler/linker these files are assembled byte by byte; this
# also makes the exact placement of .got/.got.plt relative to the page boundary
# fully deterministic.
#
# Three layouts are produced.  They share identical virtual-address layout
# and relocations; only the PT_GNU_RELRO extent, the BIND_NOW flag and one
# segment's writability differ:
#
#   * "partial" - PT_GNU_RELRO ends in the middle of the .got.plt page, BIND_NOW
#     is absent (lazy binding), and a second writable mapping starts at the
#     page boundary (mapping conflict).
#   * "full"    - PT_GNU_RELRO is extended to the end of the page and BIND_NOW
#     (DF_BIND_NOW in DT_FLAGS plus DT_BIND_NOW) is present (immediate binding).
#   * "rounded" - BIND_NOW is present but PT_GNU_RELRO ends mid-page, with no
#     writable mapping crossing the boundary, exposing protection that exists
#     only because the effective range is page rounded.
#
# A section-header-less variant of every file can be generated, exercising
# the analyzer's segment-only fallback when no section names exist.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
from __future__ import annotations

import struct

# --- ELF constants -----------------------------------------------------------
ELFMAG = b'\x7fELF'
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ELFOSABI_NONE = 0
ET_DYN = 3
EM_X86_64 = 62

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_RELRO = 0x647e4552
PF_R = 4
PF_W = 2

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_DYNSYM = 11
SHT_RELA = 4
SHT_DYNAMIC = 6
SHF_WRITE = 1
SHF_ALLOC = 2

DT_NULL = 0
DT_PLTRELSZ = 2
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRTAB = 5
DT_STRSZ = 10
DT_SYMTAB = 6
DT_SYMENT = 11
DT_JMPREL = 23
DT_PLTREL = 20
DT_FLAGS = 30
DT_BIND_NOW = 24
DT_REL = 17
DF_BIND_NOW = 0x8

R_X86_64_GLOB_DAT = 6
R_X86_64_JUMP_SLOT = 7
R_X86_64_RELATIVE = 8

STB_GLOBAL = 1
STT_FUNC = 2
STT_OBJECT = 1

PAGE = 0x1000
# Virtual-address layout of the single writable PT_LOAD segment.
VADDR = 0x400000
DYNAMIC_VADDR = 0x400e00
GOT_VADDR = 0x400f00          # start of .got, page aligned in effect
GOTPLT_VADDR = 0x400fc0       # .got.plt shares the page with .got
DATA_VADDR = 0x401000         # plain writable data, next page
SHSTRTAB_VADDR = 0x401100

# Section name string table.
SHSTRTAB = b'\x00.got\x00.got.plt\x00.data\x00.dynamic\x00.rela.dyn\x00' \
           b'.rela.plt\x00.dynsym\x00.dynstr\x00.shstrtab\x00'
NAME_OFFSETS = {}
for _name in ('.got', '.got.plt', '.data', '.dynamic', '.rela.dyn',
              '.rela.plt', '.dynsym', '.dynstr', '.shstrtab'):
    NAME_OFFSETS[_name] = SHSTRTAB.index(_name.encode() + b'\x00')

# Dynamic string table (NUL separated, leading NUL for index 0).
DYNSTR = b'\x00data_slot\x00fn_slot\x00'
OFF_DATA_SLOT = DYNSTR.index(b'data_slot')
OFF_FN_SLOT = DYNSTR.index(b'fn_slot')


class _Blob:
    """Collects bytes at fixed virtual addresses inside the writable segment."""

    def __init__(self) -> None:
        self._chunks: list[tuple[int, bytes]] = []

    def put(self, vaddr: int, data: bytes) -> None:
        self._chunks.append((vaddr, data))

    def put_u64(self, vaddr: int, value: int) -> None:
        self.put(vaddr, struct.pack('<Q', value))

    def render(self) -> bytes:
        ordered = sorted(self._chunks)
        end = max(addr + len(data) for addr, data in ordered)
        image = bytearray(end - VADDR)
        for addr, data in ordered:
            start = addr - VADDR
            image[start:start + len(data)] = data
        return bytes(image)


def _round_up(value: int, page_size: int) -> int:
    return value - (value % page_size) + (
        page_size if value % page_size else 0)


def _round_down(value: int, page_size: int) -> int:
    return value - (value % page_size)


def _dyn_entry(tag: int, value: int) -> bytes:
    return struct.pack('<qQ', tag, value)


def _symbol(name: int, info: int, shndx: int = 0) -> bytes:
    # st_name, st_info, st_other, st_shndx, st_value, st_size
    return struct.pack('<IBBHQQ', name, info, 0, shndx, 0, 0)


def build_elf(relro_mode: str, strip_sections: bool = False,
              include_relro: bool = True) -> bytes:
    """Return the bytes of a crafted ELF.

    relro_mode is one of:
      * 'partial' - BIND_NOW absent, RELRO ends mid-.got.plt page, and a second
        writable mapping starts at the page boundary (mapping conflict).
      * 'full'    - BIND_NOW present, RELRO ends exactly at the page boundary,
        no conflict.
      * 'rounded' - BIND_NOW present, RELRO ends mid-page but no writable
        mapping crosses that boundary, so slots past the declared end are only
        protected by the page-rounded effective range.
    """
    assert relro_mode in ('partial', 'full', 'rounded')
    now = relro_mode in ('full', 'rounded')
    blob = _Blob()

    # --- .got: three 8-byte slots -------------------------------------------
    blob.put_u64(GOT_VADDR + 0x00, 0)       # R_X86_64_GLOB_DAT -> data_slot
    blob.put_u64(GOT_VADDR + 0x08, 0)       # R_X86_64_RELATIVE
    blob.put_u64(GOT_VADDR + 0x10, 0)       # R_X86_64_RELATIVE
    # .got ends at 0x400f18; padding up to .got.plt is zero bytes.

    # --- .got.plt: three 8-byte slots ---------------------------------------
    blob.put_u64(GOTPLT_VADDR + 0x00, 0)    # R_X86_64_RELATIVE
    blob.put_u64(GOTPLT_VADDR + 0x08, 0)    # R_X86_64_JUMP_SLOT -> fn_slot
    blob.put_u64(GOTPLT_VADDR + 0x10, 0)    # R_X86_64_JUMP_SLOT -> fn_slot

    # --- .data: writable data beyond the RELRO region -----------------------
    blob.put_u64(DATA_VADDR, 0xdeadbeef)

    # --- .dynsym / .dynstr ---------------------------------------------------
    dynsym = b''.join((
        _symbol(0, 0),                                  # index 0, null
        _symbol(OFF_DATA_SLOT, (STB_GLOBAL << 4) | STT_OBJECT),
        _symbol(OFF_FN_SLOT, (STB_GLOBAL << 4) | STT_FUNC),
    ))
    DYNSYM_VADDR = GOTPLT_VADDR + 0x18                  # 0x400fd8
    blob.put(DYNSYM_VADDR, dynsym)                      # 3 * 24 = 72 bytes
    DYNSTR_VADDR = DYNSYM_VADDR + len(dynsym)           # 0x401020
    blob.put(DYNSTR_VADDR, DYNSTR)

    # --- .rela.dyn: GLOB_DAT plus two RELATIVE entries -----------------------
    rela_dyn = b''.join((
        _rela_bytes(GOT_VADDR + 0x00, 1, R_X86_64_GLOB_DAT, 0),
        _rela_bytes(GOT_VADDR + 0x08, 0, R_X86_64_RELATIVE, 0x401000),
        _rela_bytes(GOTPLT_VADDR + 0x00, 0, R_X86_64_RELATIVE, 0x400e00),
    ))
    RELA_DYN_VADDR = DYNSTR_VADDR + len(DYNSTR)         # 0x401032 -> align
    RELA_DYN_VADDR = (RELA_DYN_VADDR + 7) & ~7          # 0x401038
    blob.put(RELA_DYN_VADDR, rela_dyn)

    # --- .rela.plt: two JUMP_SLOT entries ------------------------------------
    rela_plt = b''.join((
        _rela_bytes(GOTPLT_VADDR + 0x08, 2, R_X86_64_JUMP_SLOT, 0),
        _rela_bytes(GOTPLT_VADDR + 0x10, 2, R_X86_64_JUMP_SLOT, 0),
    ))
    RELA_PLT_VADDR = RELA_DYN_VADDR + len(rela_dyn)
    blob.put(RELA_PLT_VADDR, rela_plt)

    # --- .dynamic -------------------------------------------------------------
    dynamic = b''.join((
        _dyn_entry(DT_STRTAB, DYNSTR_VADDR),
        _dyn_entry(DT_STRSZ, len(DYNSTR)),
        _dyn_entry(DT_SYMTAB, DYNSYM_VADDR),
        _dyn_entry(DT_SYMENT, 24),
        _dyn_entry(DT_RELA, RELA_DYN_VADDR),
        _dyn_entry(DT_RELASZ, len(rela_dyn)),
        _dyn_entry(DT_RELAENT, 24),
        _dyn_entry(DT_JMPREL, RELA_PLT_VADDR),
        _dyn_entry(DT_PLTRELSZ, len(rela_plt)),
        _dyn_entry(DT_PLTREL, DT_RELA),
        _dyn_entry(DT_FLAGS, DF_BIND_NOW if now else 0),
        _dyn_entry(DT_BIND_NOW, 0) if now else b'',
        _dyn_entry(DT_NULL, 0),
    ))
    blob.put(DYNAMIC_VADDR, dynamic)

    blob.put(SHSTRTAB_VADDR, SHSTRTAB)
    image = blob.render()

    # --- ELF / program headers ------------------------------------------------
    # Canonical layout: segment contents keep file offset == virtual address,
    # so the ELF and program headers live in a leading zero page that is not
    # part of any PT_LOAD.  This keeps p_vaddr % p_align == p_offset % p_align
    # for every segment, which loaders (and ELFFile.address_offsets) require.
    # In partial/rounded mode RELRO ends at the start of .got.plt, so the
    # .got.plt slots sit past the declared end but inside the rounded page.
    relro_end = (DATA_VADDR if relro_mode == 'full'
                 else GOTPLT_VADDR)
    ehsize = 64
    phentsize = 56
    phnum = 4 if include_relro else 3

    image_end = VADDR + len(image)
    # The first mapping always spans the complete page holding .got/.got.plt.
    # RELRO itself may end mid-page (partial/rounded) or at the page boundary
    # (full).
    first_load_end = _round_up(relro_end, PAGE)
    if relro_mode == 'partial':
        # A second writable mapping is placed over the whole RELRO page as
        # well (its vaddr and file offset stay congruent), modelling a loader
        # view in which that page is reachable through a mapping that is not
        # the RELRO carrier.  mprotect()ing the page read-only would break
        # this mapping, so the analyzer must report a conservative conflict.
        second_vaddr = _round_down(relro_end, PAGE)
        second_flags = PF_R | PF_W
        second_size = image_end - second_vaddr
    elif relro_mode == 'rounded':
        # The mapping covering the following page is read-only, so no writable
        # mapping crosses the page-rounded RELRO boundary.  Slots past the
        # declared RELRO end therefore rely solely on page rounding.
        second_vaddr = DATA_VADDR
        second_flags = PF_R
        second_size = image_end - DATA_VADDR
    else:
        # Full RELRO: the next mapping starts exactly where protection ends.
        second_vaddr = DATA_VADDR
        second_flags = PF_R | PF_W
        second_size = image_end - DATA_VADDR
    segments = [
        # type, flags, offset, vaddr, paddr, filesz, memsz, align
        (PT_LOAD, PF_R | PF_W, VADDR, VADDR, VADDR,
         first_load_end - VADDR, first_load_end - VADDR, PAGE),
        (PT_LOAD, second_flags, second_vaddr, second_vaddr, second_vaddr,
         second_size, second_size, PAGE),
        (PT_DYNAMIC, PF_R | PF_W, DYNAMIC_VADDR,
         DYNAMIC_VADDR, DYNAMIC_VADDR, len(dynamic), len(dynamic), 8),
    ]
    if include_relro:
        segments.append(
            (PT_GNU_RELRO, PF_R, VADDR, VADDR, VADDR,
             relro_end - VADDR, relro_end - VADDR, PAGE))
    segments = tuple(segments)

    out = bytearray(VADDR)
    out[0:ehsize] = _elf_header(ehsize, phentsize, phnum)
    phoff = ehsize
    for index, seg in enumerate(segments):
        out[phoff + index * phentsize:phoff + (index + 1) * phentsize] = (
            _program_header(*seg))
    out[VADDR:VADDR + len(image)] = image

    if not strip_sections:
        # Section headers start after a padding word; shstrtab is section 10.
        shendoff = (len(out) + 7) & ~7
        out += b'\x00' * (shendoff - len(out))
        sections = _section_headers(relro_mode, dynamic, rela_dyn, rela_plt,
                                    dynsym, DYNSTR)
        shstrndx = 9
        out += sections
        # Patch e_shoff (offset 40), then e_shentsize/e_shnum/e_shstrndx
        # (offset 58) into the already emitted ELF header.
        struct.pack_into('<Q', out, 40, shendoff)
        struct.pack_into('<HHH', out, 58, 64, len(sections) // 64,
                         shstrndx)
    return bytes(out)


def _rela_bytes(offset: int, sym: int, rtype: int, addend: int) -> bytes:
    return struct.pack('<QQq', offset, (sym << 32) | rtype, addend)


def _elf_header(phoff: int, phentsize: int, phnum: int) -> bytes:
    e_ident = ELFMAG + bytes((ELFCLASS64, ELFDATA2LSB, EV_CURRENT,
                              ELFOSABI_NONE)) + b'\x00' * 8
    return e_ident + struct.pack(
        '<HHIQQQIHHHHHH',
        ET_DYN, EM_X86_64, EV_CURRENT,
        0,                      # e_entry
        phoff,                  # e_phoff
        0,                      # e_shoff (patched later when sections exist)
        0,                      # e_flags
        64,                     # e_ehsize
        phentsize, phnum,
        64, 0, 0)               # e_shentsize, e_shnum, e_shstrndx


def _program_header(p_type: int, p_flags: int, p_offset: int, p_vaddr: int,
                    p_paddr: int, p_filesz: int, p_memsz: int,
                    p_align: int) -> bytes:
    return struct.pack('<IIQQQQQQ', p_type, p_flags, p_offset, p_vaddr,
                       p_paddr, p_filesz, p_memsz, p_align)


def _section_headers(relro_mode: str, dynamic: bytes, rela_dyn: bytes,
                     rela_plt: bytes, dynsym: bytes,
                     dynstr: bytes) -> bytes:
    def sh(name: int, stype: int, flags: int, addr: int,
           size: int, link: int = 0, info: int = 0,
           addralign: int = 8, entsize: int = 0) -> bytes:
        # Allocated sections keep file offset == virtual address; the
        # non-allocated .shstrtab is placed at its vaddr too.
        offset = addr
        return struct.pack('<IIQQQQIIQQ', name, stype, flags, addr, offset,
                           size, link, info, addralign, entsize)

    DYNSYM_VADDR = 0x400fd8
    DYNSTR_VADDR = DYNSYM_VADDR + len(dynsym)
    RELA_DYN_VADDR = (DYNSTR_VADDR + len(dynstr) + 7) & ~7
    RELA_PLT_VADDR = RELA_DYN_VADDR + len(rela_dyn)
    # In rounded mode the page beyond RELRO is mapped read-only.
    data_flags = SHF_ALLOC if relro_mode == 'rounded' \
        else SHF_WRITE | SHF_ALLOC
    rows = [
        sh(0, SHT_NULL, 0, 0, 0),                                              # 0
        sh(NAME_OFFSETS['.dynamic'], SHT_DYNAMIC, SHF_WRITE | SHF_ALLOC,
           DYNAMIC_VADDR, len(dynamic), link=3, entsize=16),                  # 1
        sh(NAME_OFFSETS['.dynsym'], SHT_DYNSYM, SHF_ALLOC,
           DYNSYM_VADDR, len(dynsym), link=3, entsize=24),                    # 2
        sh(NAME_OFFSETS['.dynstr'], SHT_STRTAB, SHF_ALLOC,
           DYNSTR_VADDR, len(dynstr)),                                        # 3
        sh(NAME_OFFSETS['.rela.dyn'], SHT_RELA, SHF_ALLOC,
           RELA_DYN_VADDR, len(rela_dyn), link=2, entsize=24),                # 4
        sh(NAME_OFFSETS['.rela.plt'], SHT_RELA, SHF_ALLOC,
           RELA_PLT_VADDR, len(rela_plt), link=2, entsize=24),                # 5
        sh(NAME_OFFSETS['.got'], SHT_PROGBITS, SHF_WRITE | SHF_ALLOC,
           GOT_VADDR, GOTPLT_VADDR - GOT_VADDR),                              # 6
        sh(NAME_OFFSETS['.got.plt'], SHT_PROGBITS, SHF_WRITE | SHF_ALLOC,
           GOTPLT_VADDR, 0x18),                                               # 7
        sh(NAME_OFFSETS['.data'], SHT_PROGBITS, data_flags,
           DATA_VADDR, 8),                                                    # 8
        sh(NAME_OFFSETS['.shstrtab'], SHT_STRTAB, 0,
           SHSTRTAB_VADDR, len(SHSTRTAB)),                                    # 9
    ]
    return b''.join(rows)


def write_file(path: str, relro_mode: str,
               strip_sections: bool = False,
               include_relro: bool = True) -> str:
    data = build_elf(relro_mode, strip_sections=strip_sections,
                     include_relro=include_relro)
    with open(path, 'wb') as f:
        f.write(data)
    return path


if __name__ == '__main__':
    import os
    import sys

    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(outdir, exist_ok=True)
    for mode in ('partial', 'full', 'rounded'):
        for stripped in (False, True):
            tag = mode + ('_stripped' if stripped else '')
            write_file(os.path.join(outdir, f'relro_{tag}.elf'), mode,
                       strip_sections=stripped)
            print('wrote', os.path.join(outdir, f'relro_{tag}.elf'))
