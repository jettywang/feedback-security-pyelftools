#!/usr/bin/env python3
"""Build two small, reproducible ELF fixtures without a system linker.

These are metadata test vectors, not runnable programs: there are no meaningful
instruction streams. Neither fixture is loaded, relocated or executed by this
generator or by the probe.
"""

from __future__ import annotations

import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent / 'fixtures'


def pad_to(blob: bytearray, addr: int) -> None:
    assert len(blob) <= addr, (len(blob), addr)
    blob.extend(b'\0' * (addr - len(blob)))


def add(blob: bytearray, data: bytes) -> int:
    off = len(blob)
    blob.extend(data)
    return off


def shdr(name: int, typ: int, flags: int, addr: int, off: int, size: int,
         link: int = 0, info: int = 0, addralign: int = 1, entsize: int = 0) -> bytes:
    return struct.pack('<IIQQQQIIQQ', name, typ, flags, addr, off, size,
                       link, info, addralign, entsize)


def phdr64(typ: int, flags: int, off: int, vaddr: int, filesz: int, memsz: int,
           align_: int = 0x1000) -> bytes:
    return struct.pack('<IIQQQQQQ', typ, flags, off, vaddr, vaddr, filesz, memsz, align_)


def phdr32(typ: int, off: int, vaddr: int, filesz: int, memsz: int,
           flags: int, align_: int = 0x1000) -> bytes:
    return struct.pack('<IIIIIIII', typ, off, vaddr, vaddr, filesz, memsz, flags, align_)


def sym64(name: int, info: int, shndx: int, value: int, size: int = 0) -> bytes:
    return struct.pack('<IBBHQQ', name, info, 0, shndx, value, size)


def sym32(name: int, info: int, shndx: int, value: int, size: int = 0) -> bytes:
    return struct.pack('<IIIBBH', name, value, size, info, 0, shndx)


def rela64(offset: int, sym: int, typ: int, addend: int) -> bytes:
    return struct.pack('<QQq', offset, (sym << 32) | typ, addend)


def rel32(offset: int, sym: int, typ: int) -> bytes:
    return struct.pack('<II', offset, (sym << 8) | typ)


def dyn64(tag: int, val: int) -> bytes:
    return struct.pack('<qQ', tag, val)


def dyn32(tag: int, val: int) -> bytes:
    return struct.pack('<iI', tag, val)


def ehdr64(etype: int, machine: int, entry: int, phoff: int, phnum: int,
           shoff: int, shnum: int, shstrndx: int) -> bytes:
    ident = b'\x7fELF' + bytes([2, 1, 1, 0, 0]) + b'\0' * 7
    return ident + struct.pack('<HHIQQQIHHHHHH', etype, machine, 1, entry,
                               phoff, shoff, 0, 64, 56, phnum, 64, shnum, shstrndx)


def ehdr32(etype: int, machine: int, entry: int, phoff: int, phnum: int,
           shoff: int, shnum: int, shstrndx: int) -> bytes:
    ident = b'\x7fELF' + bytes([1, 1, 1, 0, 0]) + b'\0' * 7
    return ident + struct.pack('<HHIIIIIHHHHHH', etype, machine, 1, entry,
                               phoff, shoff, 0, 52, 32, phnum, 40, shnum, shstrndx)


def text_sled(size: int = 0x60) -> bytes:
    data = bytearray(b'\x90' * size)
    for off in (0x20, 0x30, 0x40, 0x50):
        data[off] = 0xc3  # ret, unreachable in this analysis
    return bytes(data)


def build_pie_rela() -> bytes:
    """ET_DYN x86-64, RELA, section headers, init arrays, IFUNC symbols."""
    b = bytearray()
    pad_to(b, 64); phoff = 64
    pad_to(b, phoff + 3 * 56)

    TEXT = 0x1000
    DYNSTR = 0x1100
    DYNSYM = 0x1180
    RELA = 0x1220
    GENERIC = 0x12d0
    PREINIT = 0x1300
    INIT = 0x1308
    FINI = 0x1318
    DYNAMIC = 0x1330
    SHSTRTAB = 0x1430

    pad_to(b, TEXT); text_off = add(b, text_sled())
    assert text_off == TEXT

    pad_to(b, DYNSTR)
    dynstr = b'\0libc.so.6\0main\0resolver_ifunc\0not_ifunc\0init_a\0init_b\0pre_a\0fini_a\0'
    def ds(name: str) -> int:
        return dynstr.index(name.encode() + b'\0')
    dynstr_off = add(b, dynstr)
    assert dynstr_off == DYNSTR

    pad_to(b, DYNSYM)
    dynsym = b''.join([
        sym64(0, 0, 0, 0),
        sym64(ds('resolver_ifunc'), (1 << 4) | 10, 1, 0x1020),  # STT_GNU_IFUNC(10)
        sym64(ds('not_ifunc'),      (1 << 4) | 2,  1, 0x1010),  # STT_FUNC decoy
        sym64(ds('init_a'),         (1 << 4) | 2,  1, 0x1040),
    ])
    dynsym_off = add(b, dynsym)
    assert dynsym_off == DYNSYM

    pad_to(b, RELA)
    # Every array slot is initialized by a relocation, as in a real PIE.
    # R_X86_64_GLOB_DAT = 6: a symbolic reference to an IFUNC resolver.
    # The loader calls the resolver and stores the returned code address.
    rela = b''.join([
        rela64(PREINIT, 0, 8, 0x1030),   # RELATIVE preinit[0] -> B+0x1030
        rela64(INIT,    0, 8, 0x1040),   # RELATIVE init[0]    -> B+0x1040
        rela64(INIT + 8, 0, 37, 0x1020), # IRELATIVE init[1]   -> resolver B+0x1020
        rela64(FINI,    0, 8, 0x1050),   # RELATIVE fini[0]    -> B+0x1050
        rela64(GENERIC, 0, 8, 0x1010),   # generic relative slot
        rela64(GENERIC + 8, 1, 6, 0),    # GLOB_DAT -> IFUNC resolver_ifunc
        rela64(GENERIC + 16, 2, 8, 0x1040),  # RELATIVE ignores decoy symbol
    ])
    rela_off = add(b, rela)
    assert rela_off == RELA

    pad_to(b, GENERIC)
    add(b, b'\0' * 0x28)                # generic pointer slots (addends in RELA)

    pad_to(b, PREINIT)
    add(b, struct.pack('<Q', 0))         # addend lives in RELA
    assert len(b) == PREINIT + 8
    add(b, struct.pack('<QQ', 0, 0))
    assert len(b) == INIT + 16
    add(b, struct.pack('<Q', 0))
    assert len(b) == FINI + 8

    pad_to(b, DYNAMIC)
    dynamics = b''.join([
        dyn64(1, ds('libc.so.6')),
        dyn64(5, DYNSTR), dyn64(6, DYNSYM),
        dyn64(10, len(dynstr)), dyn64(11, 24),
        dyn64(7, RELA), dyn64(8, len(rela)), dyn64(9, 24),
        dyn64(32, PREINIT), dyn64(33, 8),
        dyn64(25, INIT), dyn64(27, 16),
        dyn64(26, FINI), dyn64(28, 8),
        dyn64(12, 0x1030),
        dyn64(0, 0),
    ])
    dyn_off = add(b, dynamics)
    assert dyn_off == DYNAMIC

    pad_to(b, SHSTRTAB)
    names = ['', '.text', '.dynstr', '.dynsym', '.rela.dyn', '.preinit_array',
             '.init_array', '.fini_array', '.dynamic', '.shstrtab']
    shstr = bytearray(b'\0')
    name_off: dict[str, int] = {}
    for n in names[1:]:
        name_off[n] = len(shstr)
        shstr.extend(n.encode() + b'\0')
    shstr_off = add(b, bytes(shstr))
    assert shstr_off == SHSTRTAB

    pad_to(b, (len(b) + 7) & ~7)
    shoff = len(b)
    secs = [
        shdr(0, 0, 0, 0, 0, 0),
        shdr(name_off['.text'],           1, 0x6, 0x1000, text_off, 0x60, addralign=16),
        shdr(name_off['.dynstr'],         3, 0x2, 0x1100, dynstr_off, len(dynstr), addralign=1),
        shdr(name_off['.dynsym'],        11, 0x2, 0x1180, dynsym_off, len(dynsym), link=2, info=1, addralign=8, entsize=24),
        shdr(name_off['.rela.dyn'],       4, 0x2, 0x11e0, rela_off, len(rela), link=3, addralign=8, entsize=24),
        shdr(name_off['.preinit_array'], 16, 0x3, PREINIT, PREINIT, 8, addralign=8, entsize=8),
        shdr(name_off['.init_array'],    14, 0x3, INIT, INIT, 16, addralign=8, entsize=8),
        shdr(name_off['.fini_array'],    15, 0x3, FINI, FINI, 8, addralign=8, entsize=8),
        shdr(name_off['.dynamic'],        6, 0x3, DYNAMIC, dyn_off, len(dynamics), link=2, addralign=8, entsize=16),
        shdr(name_off['.shstrtab'],       3, 0,   0,     shstr_off, len(shstr), addralign=1),
    ]
    for s in secs:
        add(b, s)
    total = len(b)

    # Two PT_LOADs: R+X headers/text and R+W data. The data segment starts at
    # file offset 0x1100, so its vaddr equals its file offset (bias 0) while
    # remaining disjoint from the executable segment.
    b[phoff:phoff + 56] = phdr64(1, 5, 0, 0, 0x1100, 0x1100)
    b[phoff + 56:phoff + 112] = phdr64(1, 6, 0x1100, 0x1100, total - 0x1100, total - 0x1100)
    b[phoff + 112:phoff + 168] = phdr64(2, 6, dyn_off, DYNAMIC, len(dynamics), len(dynamics))
    b[0:64] = ehdr64(3, 62, 0x1000, phoff, 3, shoff, len(secs), 9)
    return bytes(b)


def build_stripped_rel() -> bytes:
    """ET_DYN i386, no section headers, REL in-place addends, DT_HASH.

    The section header table is absent (e_shoff = e_shnum = 0). Table
    discovery must use PT_DYNAMIC. DT_HASH supplies the symbol count; DT_SYMTAB
    and DT_STRTAB supply symbol bytes and names.
    """
    b = bytearray()
    pad_to(b, 52); phoff = 52
    pad_to(b, phoff + 3 * 32)

    TEXT = 0x1000
    DYNSTR = 0x1100
    DYNSYM = 0x1120
    HASH = 0x1160
    PREINIT = 0x1180
    INIT = 0x1184
    REL = 0x1190
    DYNAMIC = 0x11b0

    pad_to(b, TEXT); text_off = add(b, text_sled())
    assert text_off == TEXT

    pad_to(b, DYNSTR)
    dynstr = b'\0libc.so.6\0ifunc_resolver\0'
    dynstr_off = add(b, dynstr)
    assert dynstr_off == DYNSTR

    pad_to(b, DYNSYM)
    dynsym = b''.join([
        sym32(0, 0, 0, 0),
        sym32(11, (1 << 4) | 10, 1, 0x1020),  # IFUNC resolver
    ])
    dynsym_off = add(b, dynsym)
    assert dynsym_off == DYNSYM

    pad_to(b, HASH)
    # SysV hash: nbucket=1, nchain=2, buckets=[1], chains=[0,0]
    sysv_hash = struct.pack('<II', 1, 2) + struct.pack('<I', 1) + struct.pack('<II', 0, 0)
    hash_off = add(b, sysv_hash)
    assert hash_off == HASH

    pad_to(b, PREINIT)
    # REL has no addend field: these words are both array contents and the
    # in-place addends read by the loader.
    add(b, struct.pack('<I', 0x1030))              # preinit[0]
    add(b, struct.pack('<II', 0x1030, 0x1020))     # init[0], init[1]
    assert len(b) == INIT + 8

    pad_to(b, REL)
    rel = b''.join([
        rel32(PREINIT, 0, 8),     # R_386_RELATIVE at preinit[0]
        rel32(INIT, 0, 8),        # R_386_RELATIVE at init[0]
        rel32(INIT + 4, 0, 42),   # R_386_IRELATIVE at init[1]
    ])
    rel_off = add(b, rel)
    assert rel_off == REL

    pad_to(b, DYNAMIC)
    dynamics = b''.join([
        dyn32(1, 1),
        dyn32(5, DYNSTR), dyn32(6, DYNSYM),
        dyn32(10, len(dynstr)), dyn32(11, 16),
        dyn32(4, HASH),                       # HASH -> symbol count
        dyn32(17, REL), dyn32(18, len(rel)), dyn32(19, 8),
        dyn32(32, PREINIT), dyn32(33, 4),
        dyn32(25, INIT), dyn32(27, 8),
        dyn32(0, 0),
    ])
    dyn_off = add(b, dynamics)
    assert dyn_off == DYNAMIC
    total = len(b)

    b[phoff:phoff + 32] = phdr32(1, 0, 0, 0x1100, 0x1100, 5)
    b[phoff + 32:phoff + 64] = phdr32(1, 0x1100, 0x1100, total - 0x1100, total - 0x1100, 6)
    b[phoff + 64:phoff + 96] = phdr32(2, dyn_off, DYNAMIC, len(dynamics), len(dynamics), 6)
    b[0:52] = ehdr32(3, 3, 0x1000, phoff, 3, 0, 0, 0)
    return bytes(b)


def build_negative_addend() -> bytes:
    """ET_DYN x86-64 with RELA r_addend < 0 and a DT_INIT-only entry.

    Signed addends are legal arithmetic, but the resulting expression may fall
    outside any mapped segment. The probe must keep it symbolic, not clamp it.
    """
    b = bytearray()
    pad_to(b, 64); phoff = 64
    pad_to(b, phoff + 3 * 56)

    DYNSTR = 0x1000
    DYNSYM = 0x1040
    RELA = 0x1080
    SLOTS = 0x1100
    DYNAMIC = 0x1120

    pad_to(b, DYNSTR)
    dynstr = b'\0libc.so.6\0neg_init\0'
    dynstr_off = add(b, dynstr)
    pad_to(b, DYNSYM)
    dynsym_off = add(b, sym64(0, 0, 0, 0) + sym64(11, (1 << 4) | 2, 1, 0x2000))
    # Two RELATIVE relocations: one normal, one with a negative addend.
    rela = b''.join([
        rela64(0x1100, 0, 8, 0x1000),
        rela64(0x1108, 0, 8, -0x20),
    ])
    pad_to(b, RELA); rela_off = add(b, rela)
    pad_to(b, SLOTS); add(b, b'\0' * 16)
    pad_to(b, DYNAMIC)
    dynamics = b''.join([
        dyn64(1, 1), dyn64(5, DYNSTR), dyn64(6, DYNSYM),
        dyn64(10, len(dynstr)), dyn64(11, 24),
        dyn64(7, RELA), dyn64(8, len(rela)), dyn64(9, 24),
        dyn64(12, 0x1000),
        dyn64(0, 0),
    ])
    dyn_off = add(b, dynamics); total = len(b)
    b[phoff:phoff + 56] = phdr64(1, 5, 0, 0, 0x1000, 0x1000)
    b[phoff + 56:phoff + 112] = phdr64(1, 6, 0x1000, 0x1000, total - 0x1000, total - 0x1000)
    b[phoff + 112:phoff + 168] = phdr64(2, 6, dyn_off, DYNAMIC, len(dynamics), len(dynamics))
    b[0:64] = ehdr64(3, 62, 0x1000, phoff, 3, 0, 0, 0)
    return bytes(b)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, builder in [('pie-rela.so', build_pie_rela),
                          ('stripped-rel.so', build_stripped_rel),
                          ('negative-addend.so', build_negative_addend)]:
        data = builder()
        (OUT / name).write_bytes(data)
        print(f'{name}: {len(data)} bytes')


if __name__ == '__main__':
    main()
