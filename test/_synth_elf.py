#-------------------------------------------------------------------------------
# elftools tests: synthetic ELF/DWARF generator for location-eval tests.
#
# Builds a minimal, self-contained little-endian 64-bit ELF relocatable object
# carrying hand-crafted DWARF v4 .debug_info / .debug_abbrev / .debug_loc
# sections. Pure Python (no assembler/compiler), so the tests are hermetic and
# the exact DWARF location expressions are under our control.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
from __future__ import annotations

from dataclasses import dataclass


# DWARF tags / attributes / forms used by the synthetic generator.
DW_TAG_compile_unit = 0x11
DW_TAG_variable = 0x34
DW_CHILDREN_yes = 1
DW_CHILDREN_no = 0

DW_AT_name = 0x03
DW_AT_location = 0x02
DW_AT_low_pc = 0x11
DW_AT_stmt_list = 0x10

DW_FORM_addr = 0x01
DW_FORM_string = 0x08
DW_FORM_exprloc = 0x18
DW_FORM_sec_offset = 0x17
DW_FORM_data4 = 0x06


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        next_value = value >> 7
        sign_bit = byte & 0x40
        if (next_value == 0 and not sign_bit) or (
                next_value == -1 and sign_bit):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)
        value = next_value


@dataclass
class VarSpec:
    """A synthetic DW_TAG_variable.

    ``location`` is raw expression bytes for an inline DW_FORM_exprloc, or a
    list of (begin, end, expr_bytes) tuples / a (-1, -1, expr_bytes) default to
    emit a .debug_loc location list referenced by DW_FORM_sec_offset.
    """

    name: str
    location: object


@dataclass
class _Section:
    name: str
    data: bytes
    addr: int = 0
    link: int = 0
    entsize: int = 0


def _build_abbrev() -> bytes:
    out = bytearray()
    # Abbrev 1: compile unit, has children (the variables).
    out += uleb(1)
    out += uleb(DW_TAG_compile_unit)
    out += bytes([DW_CHILDREN_yes])
    out += uleb(DW_AT_low_pc) + uleb(DW_FORM_addr)
    out += uleb(DW_AT_stmt_list) + uleb(DW_FORM_data4)
    out += b'\x00\x00'  # end of attribute list
    # Abbrev 2: variable with an inline DW_FORM_exprloc location.
    out += uleb(2)
    out += uleb(DW_TAG_variable)
    out += bytes([DW_CHILDREN_no])
    out += uleb(DW_AT_name) + uleb(DW_FORM_string)
    out += uleb(DW_AT_location) + uleb(DW_FORM_exprloc)
    out += b'\x00\x00'
    # Abbrev 3: variable whose DW_AT_location is a .debug_loc sec_offset.
    out += uleb(3)
    out += uleb(DW_TAG_variable)
    out += bytes([DW_CHILDREN_no])
    out += uleb(DW_AT_name) + uleb(DW_FORM_string)
    out += uleb(DW_AT_location) + uleb(DW_FORM_sec_offset)
    out += b'\x00\x00'
    out += b'\x00'  # end of abbreviation table
    return bytes(out)


def _build_loc_and_patch(
    variables: list[VarSpec],
) -> tuple[bytes, dict[int, tuple[int, bool]]]:
    """Build .debug_loc; return its bytes and per-variable loc info.

    The mapping is VarSpec index -> (section offset, is_list). Inline
    expressions are flagged is_list=False and carry no offset here.
    """
    loc = bytearray()
    info: dict[int, tuple[int, bool]] = {}
    for index, var in enumerate(variables):
        if isinstance(var.location, (bytes, bytearray)):
            info[index] = (0, False)
            continue
        ranges = var.location
        offset = len(loc)
        # Emit one base-address selection entry (max address marker followed
        # by the base), so the following range entries are base-relative. This
        # exercises the BaseAddressEntry handling in the selector.
        concrete = [(b, e) for b, e, _ in ranges if not (b == -1 and e == -1)]
        base = min(b for b, _ in concrete) if concrete else 0
        loc += b'\xff' * 8 + base.to_bytes(8, 'little')
        for begin, end, expr in ranges:
            if begin == -1 and end == -1:
                # DW_LLE_default_location (two max-address markers).
                loc += b'\xff' * 8 + b'\xff' * 8
            else:
                loc += (begin - base).to_bytes(8, 'little', signed=True)
                loc += (end - base).to_bytes(8, 'little', signed=True)
            loc += len(expr).to_bytes(2, 'little')
            loc += expr
        loc += b'\x00' * 16  # end-of-list (two zero addresses)
        info[index] = (offset, True)
    return bytes(loc), info


def build_elf64_dwarf4(
    variables: list[VarSpec],
    cu_low_pc: int = 0x1000,
) -> bytes:
    """Return a complete ELF64 little-endian object with DWARF v4 info."""
    abbrev = _build_abbrev()
    loc, loc_info = _build_loc_and_patch(variables)

    # .debug_info body (after the 11-byte CU header is assembled below).
    info_body = bytearray()
    info_body += uleb(1)  # abbrev code 1 (compile unit)
    info_body += cu_low_pc.to_bytes(8, 'little')   # DW_AT_low_pc
    info_body += (0).to_bytes(4, 'little')         # DW_AT_stmt_list
    for index, var in enumerate(variables):
        is_list = loc_info[index][1]
        info_body += uleb(3 if is_list else 2)  # variable abbrev code
        info_body += var.name.encode() + b'\x00'   # DW_FORM_string value
        if is_list:
            # DW_FORM_sec_offset: 4-byte offset into .debug_loc.
            info_body += loc_info[index][0].to_bytes(4, 'little')
        else:
            # DW_FORM_exprloc: ULEB128 length followed by the expression.
            expr = bytes(var.location)
            info_body += uleb(len(expr)) + expr
    info_body += b'\x00'  # end of CU children

    cu_header = bytearray()
    # unit_length counts everything after its own 4 bytes: version(2) +
    # debug_abbrev_offset(4) + address_size(1) + the DIE tree.
    unit_length = 2 + 4 + 1 + len(info_body)
    cu_header += unit_length.to_bytes(4, 'little')
    cu_header += (4).to_bytes(2, 'little')            # DWARF version
    cu_header += (0).to_bytes(4, 'little')            # debug_abbrev offset
    cu_header += bytes([8])                           # address size
    debug_info = bytes(cu_header) + bytes(info_body)

    sections = [
        _Section('', b''),
        _Section('.text', b'\x90' * 16),
        _Section('.debug_info', debug_info),
        _Section('.debug_abbrev', abbrev),
        _Section('.debug_loc', loc),
    ]
    return _assemble_elf64(sections)


def _assemble_elf64(sections: list[_Section]) -> bytes:
    # Build the section-name string table (.shstrtab); it names every section
    # including itself, so append '.shstrtab' before snapshotting the bytes.
    shstr = bytearray(b'\x00')
    name_offsets = []
    for section in sections:
        name_offsets.append(len(shstr))
        shstr += section.name.encode() + b'\x00'
    shstrtab_index = len(sections)
    name_offsets.append(len(shstr))
    shstr += b'.shstrtab\x00'
    shstrtab = bytes(shstr)
    sections = sections + [_Section('.shstrtab', shstrtab)]
    ehdr_size = 64
    shentsize = 64
    total_sections = len(sections)
    # Layout file offsets: ELF header, then section data, then shdr table.
    offset = ehdr_size
    file_offsets = []
    for section in sections:
        if section.data:
            if offset % 8:
                offset += 8 - (offset % 8)
            file_offsets.append(offset)
            offset += len(section.data)
        else:
            file_offsets.append(0)
    if offset % 8:
        offset += 8 - (offset % 8)
    shdr_offset = offset

    # ELF64 header (ET_REL, x86-64). Field offsets follow the ELF64 spec; each
    # field is written at its exact offset so adjacent fields never overlap.
    ehdr = bytearray(64)
    ehdr[0:4] = b'\x7fELF'
    ehdr[4] = 2          # EI_CLASS: 64-bit
    ehdr[5] = 1          # EI_DATA: little endian
    ehdr[6] = 1          # EI_VERSION
    ehdr[16:18] = (1).to_bytes(2, 'little')    # e_type = ET_REL
    ehdr[18:20] = (62).to_bytes(2, 'little')   # e_machine = EM_X86_64
    ehdr[20:24] = (1).to_bytes(4, 'little')    # e_version
    ehdr[32:40] = (0).to_bytes(8, 'little')    # e_entry
    ehdr[40:48] = shdr_offset.to_bytes(8, 'little')  # e_shoff
    ehdr[48:52] = (0).to_bytes(4, 'little')    # e_flags
    ehdr[52:54] = ehdr_size.to_bytes(2, 'little')     # e_ehsize
    ehdr[54:56] = (0).to_bytes(2, 'little')           # e_phentsize
    ehdr[56:58] = (0).to_bytes(2, 'little')           # e_phnum
    ehdr[58:60] = shentsize.to_bytes(2, 'little')     # e_shentsize
    ehdr[60:62] = total_sections.to_bytes(2, 'little')  # e_shnum
    ehdr[62:64] = shstrtab_index.to_bytes(2, 'little')  # e_shstrndx
    # e_phoff (program header) is left zero (no program headers).

    blob = bytearray(ehdr)
    # Pad to each section offset and append section data.
    for section, foff in zip(sections, file_offsets):
        if not section.data:
            continue
        if len(blob) < foff:
            blob += b'\x00' * (foff - len(blob))
        blob += section.data

    # Section header table.
    if len(blob) < shdr_offset:
        blob += b'\x00' * (shdr_offset - len(blob))
    for index, section in enumerate(sections):
        shdr = bytearray(64)
        shdr[0:4] = name_offsets[index].to_bytes(4, 'little')  # sh_name
        if section.name == '.text':
            sh_type, sh_flags = 1, 0x6          # SHT_PROGBITS, AX
        elif section.name == '.shstrtab':
            sh_type, sh_flags = 3, 0            # SHT_STRTAB
        elif section.name:
            sh_type, sh_flags = 1, 0            # SHT_PROGBITS
        else:
            sh_type, sh_flags = 0, 0            # SHT_NULL
        shdr[4:8] = sh_type.to_bytes(4, 'little')
        shdr[8:16] = sh_flags.to_bytes(8, 'little')
        shdr[16:24] = section.addr.to_bytes(8, 'little')      # sh_addr
        shdr[24:32] = file_offsets[index].to_bytes(8, 'little')  # sh_offset
        shdr[32:40] = len(section.data).to_bytes(8, 'little')  # sh_size
        shdr[40:44] = section.link.to_bytes(4, 'little')       # sh_link
        shdr[44:48] = (0).to_bytes(4, 'little')                # sh_info
        shdr[48:52] = (1).to_bytes(4, 'little')                # sh_addralign
        shdr[56:64] = section.entsize.to_bytes(8, 'little')    # sh_entsize
        blob += shdr

    return bytes(blob)
