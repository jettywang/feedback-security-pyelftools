#!/usr/bin/env python3
"""
Build a minimal x86-64 ELF (ET_REL) containing a hand-crafted .eh_frame
section with fully controlled CFI rows (no compiler/assembler required).

The CFI program deliberately contains:
  * DW_CFA_remember_state / DW_CFA_restore_state
  * a CFA register switch (rsp -> rbp) and CFA offset changes
  * FDEs that leave address gaps (uncovered PCs)
  * two adjacent functions whose FDEs meet exactly at a boundary, so a return
    address equal to that boundary lies on the *next* function's first row
"""
import os
import struct

# ---- DWARF CFI opcodes ----------------------------------------------------
DW_CFA_nop              = 0x00
DW_CFA_set_loc          = 0x01
DW_CFA_advance_loc1     = 0x02
DW_CFA_advance_loc2     = 0x03
DW_CFA_advance_loc4     = 0x04
DW_CFA_remember_state   = 0x0A
DW_CFA_restore_state    = 0x0B
DW_CFA_def_cfa          = 0x0C
DW_CFA_def_cfa_register = 0x0D
DW_CFA_def_cfa_offset   = 0x0E

RAX, RDX, RBX, RSP, RBP, RIP = 0, 1, 3, 7, 6, 16


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        b = n & 0x7F
        n >>= 7
        sign = b & 0x40
        if (n == 0 and not sign) or (n == -1 and sign):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def cfa_advance(delta: int) -> bytes:
    assert 0 <= delta < 64
    return bytes([0x40 | delta])


def cfa_offset(reg: int, factored_off: int) -> bytes:
    assert 0 <= reg < 64
    return bytes([0x80 | reg]) + uleb(factored_off)


def entry(body: bytes) -> bytes:
    """Prepend a 32-bit DWARF length field."""
    return struct.pack('<I', len(body)) + body


def align8(b: bytes) -> bytes:
    return b + b'\x00' * ((-len(b)) % 8)


def aligned_entry(body: bytes) -> bytes:
    """Pad with DW_CFA_nop so the *whole entry* (length field + body) is
    8-byte aligned. The length field covers the padded body, so a parser
    advancing by (length + 4) lands exactly on the next, aligned entry."""
    total_with_length = 4 + len(body)
    pad = (-total_with_length) % 8
    padded_body = body + bytes([DW_CFA_nop]) * pad
    return struct.pack('<I', len(padded_body)) + padded_body


# ---- CIE: zR augmentation, DW_EH_PE_absptr (plain 8-byte) FDE pointers ----
cie_body = b''.join([
    struct.pack('<I', 0),          # CIE_id = 0 (.eh_frame)
    bytes([1]),                    # version
    b'zR\x00',                     # augmentation
    uleb(1),                       # code_alignment_factor
    sleb(-8),                      # data_alignment_factor
    bytes([RIP]),                  # return_address_register
    uleb(1),                       # augmentation data length
    bytes([0x00]),                 # R = DW_EH_PE_absptr
    # initial instructions: standard x86-64 convention that the return
    # address (RIP, dwarf reg 16) is saved at [CFA].
    cfa_offset(RIP, 0),
])
cie = aligned_entry(cie_body)
CIE_SEC_OFF = 0


def make_fde(sec_off: int, base: int, size: int, instr: bytes) -> bytes:
    # pyelftools: cie_offset = fde_sec_off + (dwarf_format//8) - CIE_pointer
    # With dwarf_format=32, the constant is 4; for a CIE at section offset 0:
    #   CIE_pointer = fde_sec_off + 4 - CIE_SEC_OFF
    # Because the CIE augmentation starts with 'z', every FDE begins with a
    # ULEB augmentation-data-length (0 = no per-FDE augmentation bytes).
    cie_pointer = sec_off + (32 // 8) - CIE_SEC_OFF
    return aligned_entry(b''.join([
        struct.pack('<I', cie_pointer),
        struct.pack('<Q', base),
        struct.pack('<Q', size),
        uleb(0),
        instr,
    ]))


# ---- FDE A: funcA [0x1000, 0x1040) ----------------------------------------
BASE_A = 0x1000
fde_a_instr = b''.join([
    # row0 @0x1000: CFA=rsp+8 ; rbx/r15/r14 saved
    bytes([DW_CFA_def_cfa]), uleb(RSP), uleb(8),
    cfa_offset(RBX, 1),                    # rbx @ cfa-8
    bytes([0x80 | 15]), uleb(2),           # r15 @ cfa-16
    bytes([0x80 | 14]), uleb(3),           # r14 @ cfa-24
    bytes([DW_CFA_remember_state]),
    cfa_advance(8),                        # row1 @0x1008
    bytes([DW_CFA_def_cfa_offset]), uleb(16),
    cfa_advance(8),                        # row2 @0x1010
    bytes([DW_CFA_remember_state]),
    cfa_advance(8),                        # row3 @0x1018: switch CFA reg
    bytes([DW_CFA_def_cfa_register]), uleb(RBP),
    cfa_advance(8),                        # row4 @0x1020
    bytes([DW_CFA_restore_state]),         # back to row2's rbp state
    cfa_advance(8),                        # row5 @0x1028
    bytes([DW_CFA_restore_state]),         # back to row0's rsp state
    cfa_advance(8),                        # row6 @0x1030
    cfa_offset(RBP, 4),                    # rbp @ cfa-32
    bytes([DW_CFA_nop, DW_CFA_nop]),
])
off_a = len(cie)
fde_a = make_fde(off_a, BASE_A, 0x40, fde_a_instr)

# ---- FDE B: funcB [0x1040, 0x1060), adjacent, deliberately different rules -
BASE_B = 0x1040
fde_b_instr = b''.join([
    # row0 @0x1040: CFA=rbp+128 ; rbx at cfa-128 (distinct from funcA)
    bytes([DW_CFA_def_cfa]), uleb(RBP), uleb(128),
    cfa_offset(RBX, 16),
    bytes([DW_CFA_nop]),
])
off_b = off_a + len(fde_a)
fde_b = make_fde(off_b, BASE_B, 0x20, fde_b_instr)

# ---- FDE C: funcC [0x1080, 0x1090); gap 0x1060..0x1080 is uncovered -------
BASE_C = 0x1080
fde_c_instr = b''.join([
    bytes([DW_CFA_def_cfa]), uleb(RSP), uleb(64),
    bytes([DW_CFA_nop]),
])
off_c = off_b + len(fde_b)
fde_c = make_fde(off_c, BASE_C, 0x10, fde_c_instr)

eh_frame = cie + fde_a + fde_b + fde_c + b'\x00\x00\x00\x00'
assert off_c + len(fde_c) + 4 == len(eh_frame)

# ---- Minimal ET_REL ELF64 x86-64 ------------------------------------------
shstr = b'\x00.shstrtab\x00.eh_frame\x00'
name_shstr = 1
name_eh = 11

ELF_HDR_SIZE, SHDR_SIZE = 64, 64
off_eh = ELF_HDR_SIZE
off_shstr = off_eh + len(eh_frame)
off_shdr = (off_shstr + len(shstr) + 7) & ~7

ehdr = struct.pack('<16sHHIQQQIHHHHHH',
                   b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8,
                   1, 62, 1,                 # e_type, e_machine, e_version
                   0, 0, off_shdr,           # e_entry, e_phoff, e_shoff
                   0,                        # e_flags
                   ELF_HDR_SIZE, 0, 0,       # e_ehsize, e_phentsize, e_phnum
                   SHDR_SIZE, 3, 2)          # e_shentsize, e_shnum, e_shstrndx
assert struct.calcsize('<16sHHIQQQIHHHHHH') == ELF_HDR_SIZE

sh_null = b'\x00' * SHDR_SIZE
sh_eh = struct.pack('<IIQQQQIIQQ', name_eh, 1, 0, 0, off_eh, len(eh_frame),
                    0, 0, 8, 0)                      # SHT_PROGBITS
sh_shstr = struct.pack('<IIQQQQIIQQ', name_shstr, 3, 0, 0, off_shstr,
                       len(shstr), 0, 0, 1, 0)       # SHT_STRTAB

blob = bytearray(off_shdr + 3 * SHDR_SIZE)
blob[0:len(ehdr)] = ehdr
blob[off_eh:off_eh + len(eh_frame)] = eh_frame
blob[off_shstr:off_shstr + len(shstr)] = shstr
blob[off_shdr:off_shdr + SHDR_SIZE] = sh_null
blob[off_shdr + SHDR_SIZE:off_shdr + 2 * SHDR_SIZE] = sh_eh
blob[off_shdr + 2 * SHDR_SIZE:off_shdr + 3 * SHDR_SIZE] = sh_shstr

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   'sample_x86_64.ehframe.o')
with open(OUT, 'wb') as f:
    f.write(blob)
print(f'wrote {OUT}: {len(blob)} bytes, .eh_frame={len(eh_frame)}')
print('FDE A [0x%x,0x%x)  B [0x%x,0x%x)  C [0x%x,0x%x)'
      % (BASE_A, BASE_A + 0x40, BASE_B, BASE_B + 0x20, BASE_C, BASE_C + 0x10))
