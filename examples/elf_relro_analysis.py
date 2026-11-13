#!/usr/bin/env python3
#-------------------------------------------------------------------------------
# elftools example: elf_relro_analysis.py
#
# Static RELRO (GNU read-only relocations) analysis that goes beyond reporting
# the mere presence of PT_GNU_RELRO.  For every relocation target slot the
# analyzer combines four pieces of evidence:
#
#   1. The PT_GNU_RELRO region, both as declared (p_vaddr .. p_vaddr+p_memsz)
#      and as the dynamic loader actually applies it (the region is mprotect'd
#      whole pages, so the effective range is page rounded).
#   2. The relocation target address (r_offset), classified by the section it
#      lands in (.got vs .got.plt) when section headers are available, and by
#      segment membership when they are not.
#   3. The BIND_NOW state (DF_BIND_NOW / DF_1_NOW / DT_BIND_NOW), which decides
#      whether JUMP_SLOT entries are resolved before the RELRO region is made
#      read-only (immediate binding) or stay writable for lazy binding.
#   4. Mapping conflicts: a RELRO page that also contains plain writable data
#      cannot be made read-only, so the loader has to leave it writable.
#
# Callers may select the loader page size (default 4096) and a load bias
# (base address) for ET_DYN objects.  Everything computed here is a static
# inference from the file; the tool deliberately does not claim to know the
# real kernel/loader memory protections at runtime.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from typing import IO

from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf import relocation as relocation_module
from elftools.elf.relocation import (
    RelocationSection,
    RelocationTable,
    RelrRelocationSection,
    RelrRelocationTable,
)
from elftools.elf.sections import Section
from elftools.elf.segments import Segment

PT_GNU_RELRO = 0x647e4552
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

# Protection verdicts, ordered from most to least reassuring.
PROTECTED = 'protected'
PROTECTED_PAGE_ROUNDED = 'protected (page-rounded)'
CONSERVATIVE_CONFLICT = 'unknown (mapping conflict, treated as writable)'
WRITABLE_LAZY = 'writable (lazy binding)'
WRITABLE_OUTSIDE = 'writable (outside RELRO region)'
NO_RELRO = 'writable (no PT_GNU_RELRO)'
UNKNOWN_NO_MAPPING = 'unknown (target is not mapped by any PT_LOAD)'


@dataclass
class RelroRegion:
    """PT_GNU_RELRO region in load-bias-relative and absolute coordinates."""

    declared_start: int          # p_vaddr (relative to the object base)
    declared_end: int            # p_vaddr + p_memsz
    effective_start: int         # page-rounded start (relative)
    effective_end: int           # page-rounded end (relative)
    base: int                    # caller supplied load bias
    page_size: int

    @property
    def absolute_declared(self) -> tuple[int, int]:
        return self.base + self.declared_start, self.base + self.declared_end

    @property
    def absolute_effective(self) -> tuple[int, int]:
        return self.base + self.effective_start, self.base + self.effective_end


@dataclass
class RelocationSlot:
    """One analyzed relocation target slot."""

    address: int                 # r_offset, relative to the object base
    size: int                    # address width of the slot (4 or 8)
    reloc_type: str              # human readable relocation type
    table: str                   # table the entry came from (.rela.dyn, ...)
    symbol: str                  # symbol name, or '' for relative entries
    section_name: str            # containing section, or '' when unavailable
    in_got_plt: bool             # target classified as .got.plt by section/name
    is_jump_slot: bool           # JUMP_SLOT style lazy-binding entry
    verdict: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class RelroAnalysis:
    """Complete result of analyze_relro(), suitable for programmatic use."""

    has_relro_segment: bool
    now_binding: bool
    now_sources: list[str]
    page_size: int
    base: int
    base_known: bool
    region: RelroRegion | None
    conflicts: list[tuple[int, int, int, int, int, int]]
    warnings: list[str]
    slots: list[RelocationSlot]


def _round_down(value: int, page_size: int) -> int:
    return value - (value % page_size)


def _round_up(value: int, page_size: int) -> int:
    return _round_down(value + page_size - 1, page_size)


def _reloc_type_name(elf: ELFFile, reloc: object, is_relr: bool) -> str:
    # RELR (SHT_RELR) entries encode only r_offset; they are always relative
    # relocations and carry no r_info_type field.
    if is_relr:
        return 'RELR (relative)'
    # Resolve the numeric r_info_type to the architecture's enum name when
    # pyelftools knows it (e.g. R_X86_64_JUMP_SLOT); fall back to the number.
    r_type = reloc['r_info_type']  # type: ignore[index]
    arch = elf.get_machine_arch()
    enum_name = 'ENUM_RELOC_TYPE_' + arch.replace('-', '_')
    enum = getattr(relocation_module, enum_name, None)
    if enum is not None:
        for name, value in enum.items():
            if value == r_type:
                return str(name)
    return f'type {r_type}'


def _slot_size(elf: ELFFile) -> int:
    return 8 if elf.elfclass == 64 else 4


def _find_relro_segment(elf: ELFFile) -> Segment | None:
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_GNU_RELRO' or \
                segment['p_type'] == PT_GNU_RELRO:
            return segment
    return None


def _dynamic_segments(elf: ELFFile) -> list[DynamicSegment]:
    return [seg for seg in elf.iter_segments()
            if seg['p_type'] == 'PT_DYNAMIC']


def _now_binding(dynamic_segments: list[DynamicSegment]) -> tuple[bool, list[str]]:
    """Detect immediate binding from all three documented NOW locations."""
    sources: list[str] = []
    for segment in dynamic_segments:
        for tag in segment.iter_tags():
            name = tag.entry.d_tag
            if name == 'DT_BIND_NOW':
                sources.append('DT_BIND_NOW')
            elif name == 'DT_FLAGS' and tag['d_val'] & DF_BIND_NOW:
                sources.append('DT_FLAGS DF_BIND_NOW')
            elif name == 'DT_FLAGS_1' and tag['d_val'] & DF_1_NOW:
                sources.append('DT_FLAGS_1 DF_1_NOW')
    return bool(sources), sources


def _collect_relocations(
    elf: ELFFile,
    dynamic_segments: list[DynamicSegment],
) -> list[tuple[RelocationTable | RelrRelocationTable, str]]:
    """Return (table, origin label) pairs, de-duplicated.

    Section headers are preferred because they carry names; when absent, the
    PT_DYNAMIC tags (DT_RELA/DT_REL/DT_RELR/DT_JMPREL) drive the same lookup.
    """
    seen: set[int] = set()
    tables: list[tuple[RelocationTable | RelrRelocationTable, str]] = []

    for section in elf.iter_sections():
        if isinstance(section, (RelocationSection, RelrRelocationSection)):
            key = section['sh_offset']
            if key not in seen:
                seen.add(key)
                tables.append((section, section.name
                               or '<unnamed reloc section>'))

    if tables:
        return tables

    # No section headers: the PT_DYNAMIC tags identify the same tables.  The
    # dynamic handler builds fresh objects per call, so de-duplicate by the
    # table's stream offset, which is also the DT_RELA/DT_REL/DT_JMPREL value.
    origin_labels = {
        'REL': 'REL (DT_REL)',
        'RELA': 'RELA (DT_RELA)',
        'RELR': 'RELR (DT_RELR)',
        'JMPREL': 'JMPREL (DT_JMPREL)',
    }
    for segment in dynamic_segments:
        for origin, table in segment.get_relocation_tables().items():
            key = table._offset
            if key not in seen:
                seen.add(key)
                tables.append((table, origin_labels.get(origin, origin)))
    return tables


def _containing_section(elf: ELFFile, address: int) -> Section | None:
    for section in elf.iter_sections():
        start = section['sh_addr']
        size = section['sh_size']
        if start and start <= address < start + size:
            return section
    return None


def _find_load_segment(elf: ELFFile, address: int) -> Segment | None:
    for segment in elf.iter_segments():
        if segment['p_type'] != 'PT_LOAD':
            continue
        start = segment['p_vaddr']
        if start <= address < start + segment['p_memsz']:
            return segment
    return None


def analyze_relro(
    stream: IO[bytes],
    page_size: int = 4096,
    base: int | None = None,
    assume_now: bool | None = None,
) -> RelroAnalysis:
    """Analyze RELRO coverage of every relocation slot in an ELF file.

    page_size: loader page size used to round the RELRO region.
    base: load bias for ET_DYN objects; None means the base is unknown, in
        which case addresses stay relative and the result is flagged.
    assume_now: when not None, override the file's BIND_NOW state.  This is a
        static "what-if" switch used to show how the NOW flag changes verdicts.
    """
    if page_size <= 0 or (page_size & (page_size - 1)) != 0:
        raise ValueError('page_size must be a positive power of two')

    elf = ELFFile(stream)
    width = _slot_size(elf)
    warnings: list[str] = []
    dynamic_segments = _dynamic_segments(elf)

    file_now, now_sources = _now_binding(dynamic_segments)
    if assume_now is None:
        now_binding = file_now
    else:
        now_binding = assume_now
        warnings.append(
            f'BIND_NOW overridden for analysis: file says '
            f'{"NOW" if file_now else "lazy"}, assuming '
            f'{"NOW" if assume_now else "lazy"}')

    base_known = base is not None
    if base is None:
        base = 0
        if elf['e_type'] == 'ET_DYN':
            warnings.append(
                'ET_DYN object with no load bias supplied; all addresses are '
                'relative to an unknown base and conclusions are base '
                'independent only because the RELRO region and targets share '
                'the same mapping')
    elif base % page_size != 0:
        warnings.append(
            f'load bias {base:#x} is not {page_size:#x}-aligned; page '
            'rounding of an absolute mapping could differ from this static '
            'view')

    relro_segment = _find_relro_segment(elf)
    region: RelroRegion | None = None
    if relro_segment is not None:
        start = relro_segment['p_vaddr']
        end = start + relro_segment['p_memsz']
        region = RelroRegion(
            declared_start=start,
            declared_end=end,
            effective_start=_round_down(start, page_size),
            effective_end=_round_up(end, page_size),
            base=base,
            page_size=page_size)

    # Detect mapping conflicts page by page.  The loader mprotect()s whole
    # pages read-only.  The PT_LOAD that carries the declared RELRO start and
    # stays within the page-rounded effective range is the mapping being
    # mprotect()d, so its own rounded tail is expected.  Any *other* writable
    # mapping that reaches the rounded tail cannot be forced read-only without
    # breaking it; the loader must leave such pages writable, which is reported
    # conservatively.  Record every conflicted page with the offending mapping.
    load_segments = [seg for seg in elf.iter_segments()
                     if seg['p_type'] == 'PT_LOAD']
    carrier_indices = set()
    if region is not None:
        for index, segment in enumerate(load_segments):
            seg_end = segment['p_vaddr'] + segment['p_memsz']
            if segment['p_vaddr'] <= region.declared_start and \
                    seg_end <= region.effective_end:
                carrier_indices.add(index)

    # Each conflict records, relative to the object base: the conflicted page
    # (start/end), the offending writable mapping (start/end) and its overlap
    # with the RELRO tail.  Keeping numbers rather than a formatted string lets
    # callers apply a load bias when rendering.
    conflicts: list[tuple[int, int, int, int, int, int]] = []
    if region is not None:
        page = region.effective_start
        while page < region.effective_end:
            page_end = page + page_size
            tail_start = max(page, region.declared_end)
            if tail_start < page_end:
                for index, segment in enumerate(load_segments):
                    if index in carrier_indices or \
                            not (segment['p_flags'] & 0x2):
                        continue
                    seg_start = segment['p_vaddr']
                    seg_end = seg_start + segment['p_memsz']
                    overlap_start = max(seg_start, tail_start)
                    overlap_end = min(seg_end, page_end)
                    if overlap_start < overlap_end:
                        conflicts.append((
                            page, page_end, seg_start, seg_end,
                            overlap_start, overlap_end))
                        break
            page = page_end

    slots: list[RelocationSlot] = []
    for table, origin in _collect_relocations(elf, dynamic_segments):
        is_relr = origin.startswith('RELR') or table.__class__.__name__ \
            .startswith('Relr')
        is_jump_table = origin.startswith('JMPREL') or origin.endswith('.plt') \
            or '.rela.plt' in origin or '.rel.plt' in origin
        for reloc in table.iter_relocations():
            address = int(reloc['r_offset'])
            r_type = _reloc_type_name(elf, reloc, is_relr)
            is_jump_slot = (not is_relr) and (
                is_jump_table or 'JUMP_SLOT' in r_type)

            section = _containing_section(elf, address)
            load_segment = _find_load_segment(elf, address)
            section_name = section.name if section is not None else ''
            in_got_plt = section_name == '.got.plt' or (
                section is None and is_jump_slot)
            symbol = ''
            sym_index = 0 if is_relr else reloc['r_info_sym']
            if sym_index and isinstance(table, RelocationSection):
                symtab = elf.get_section(table['sh_link'])
                if symtab is not None and sym_index < symtab.num_symbols():
                    symbol = symtab.get_symbol(sym_index).name

            reasons: list[str] = []
            verdict = _verdict_for(
                address, width, region, now_binding, is_jump_slot,
                load_segment, conflicts, page_size, reasons)

            slots.append(RelocationSlot(
                address=address,
                size=width,
                reloc_type=r_type,
                table=origin,
                symbol=symbol,
                section_name=section_name,
                in_got_plt=in_got_plt,
                is_jump_slot=is_jump_slot,
                verdict=verdict,
                reasons=reasons))

    slots.sort(key=lambda slot: (slot.address, slot.table))
    return RelroAnalysis(
        has_relro_segment=relro_segment is not None,
        now_binding=now_binding,
        now_sources=now_sources,
        page_size=page_size,
        base=base,
        base_known=base_known,
        region=region,
        conflicts=conflicts,
        warnings=warnings,
        slots=slots)


def _verdict_for(
    address: int,
    width: int,
    region: RelroRegion | None,
    now_binding: bool,
    is_jump_slot: bool,
    load_segment: Segment | None,
    conflicts: list[tuple[int, int, int, int, int, int]],
    page_size: int,
    reasons: list[str],
) -> str:
    slot_end = address + width

    if load_segment is None:
        reasons.append('r_offset is not covered by any PT_LOAD segment')
        return UNKNOWN_NO_MAPPING

    if region is None:
        reasons.append('file has no PT_GNU_RELRO segment')
        reasons.append('loader never mprotect()s this slot read-only')
        return NO_RELRO

    in_declared = region.declared_start <= address and \
        slot_end <= region.declared_end
    in_effective = region.effective_start <= address and \
        slot_end <= region.effective_end

    if not in_effective:
        reasons.append(
            f'slot {address:#x}..{slot_end:#x} lies outside the page-rounded '
            f'RELRO range {region.effective_start:#x}..'
            f'{region.effective_end:#x}')
        if is_jump_slot and not now_binding:
            reasons.append('JUMP_SLOT target additionally uses lazy binding '
                           '(no BIND_NOW) and stays writable for on-demand '
                           'resolution')
        return WRITABLE_OUTSIDE

    page_start = _round_down(address, page_size)
    conflicted = any(page == page_start
                     for page, _page_end, _seg_start, _seg_end,
                         _ov_start, _ov_end in conflicts)
    if conflicted:
        reasons.append(
            f'page {page_start:#x} also holds plain writable data beyond the '
            'declared RELRO region, so the loader cannot mprotect the page '
            'read-only')
        if is_jump_slot and not now_binding:
            reasons.append('JUMP_SLOT target additionally uses lazy binding '
                           '(no BIND_NOW)')
        return CONSERVATIVE_CONFLICT

    if is_jump_slot and not now_binding:
        reasons.append('JUMP_SLOT target with lazy binding (no BIND_NOW)')
        reasons.append('the loader keeps .got.plt writable to resolve the '
                       'symbol on first call')
        return WRITABLE_LAZY

    if in_declared:
        reasons.append('slot is inside the declared PT_GNU_RELRO region')
    else:
        reasons.append(
            'slot is past the declared RELRO end '
            f'{region.declared_end:#x} but inside its page-rounded effective '
            'range')
    if is_jump_slot:
        reasons.append('BIND_NOW forces resolution before RELRO is applied')
    reasons.append('loader mprotect()s the containing page read-only after '
                   'relocation processing')
    return PROTECTED if in_declared else PROTECTED_PAGE_ROUNDED


def format_analysis(result: RelroAnalysis) -> str:
    """Render a RelroAnalysis as the human-readable report used by the CLI."""
    lines: list[str] = []
    lines.append(f'page size: {result.page_size} bytes '
                 f'({result.page_size:#x})')
    if result.base_known:
        lines.append(f'load bias: {result.base:#x}')
    else:
        lines.append('load bias: unknown (addresses shown relative to base 0)')

    if not result.has_relro_segment:
        lines.append('PT_GNU_RELRO: absent')
    else:
        assert result.region is not None
        region = result.region
        lines.append('PT_GNU_RELRO: present')
        d_start, d_end = region.absolute_declared
        e_start, e_end = region.absolute_effective
        lines.append(f'  declared region : {d_start:#x} .. {d_end:#x}')
        lines.append(f'  effective pages: {e_start:#x} .. {e_end:#x} '
                     f'(page rounded, what mprotect covers)')
        if region.declared_start != region.effective_start or \
                region.declared_end != region.effective_end:
            lines.append('  note: declared region is not page aligned, so the '
                         'protected range differs from p_memsz')

    binding = 'immediate (BIND_NOW)' if result.now_binding else \
        'lazy (BIND_NOW absent)'
    lines.append(f'binding: {binding}')
    if result.now_sources:
        lines.append('  NOW evidence: ' + ', '.join(result.now_sources))

    if result.conflicts:
        lines.append('mapping conflicts (conservative: shared pages stay '
                     'writable):')
        for (page, page_end, seg_start, seg_end,
             overlap_start, overlap_end) in result.conflicts:
            base = result.base
            lines.append(
                f'  {base + page:#x} .. {base + page_end:#x}: separate '
                f'writable PT_LOAD {base + seg_start:#x}..'
                f'{base + seg_end:#x} maps {base + overlap_start:#x}..'
                f'{base + overlap_end:#x} beyond the declared RELRO end '
                f'{base + result.region.declared_end:#x}, so this page '
                'cannot be forced read-only')
    else:
        lines.append('mapping conflicts: none')

    for warning in result.warnings:
        lines.append(f'WARNING: {warning}')

    lines.append('')
    lines.append('relocation target slots:')
    header = (f'  {"target":>12}  {"section":<10} {"table":<22} '
              f'{"type":<22} {"verdict"}')
    lines.append(header)
    for slot in result.slots:
        target = result.base + slot.address
        location = slot.section_name or (
            '.got.plt (inferred)' if slot.in_got_plt else '<no section name>')
        symbol = f' -> {slot.symbol}' if slot.symbol else ''
        lines.append(
            f'  {target:#12x}  {location:<10} {slot.table:<22} '
            f'{slot.reloc_type:<22} {slot.verdict}{symbol}')
        for reason in slot.reasons:
            lines.append(f'      reason: {reason}')

    lines.append('')
    lines.append('static analysis only: actual kernel/loader page protections '
                 'are not observed')
    return '\n'.join(lines)


def process_file(filename: str, page_size: int, base: int | None,
                 assume_now: bool | None) -> None:
    print(f'Analyzing: {filename}')
    with open(filename, 'rb') as stream:
        result = analyze_relro(stream, page_size=page_size, base=base,
                               assume_now=assume_now)
    print(format_analysis(result))
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Static per-slot RELRO coverage analysis using pyelftools')
    parser.add_argument('elffile', nargs='+')
    parser.add_argument('--page-size', type=lambda value: int(value, 0),
                        default=4096,
                        help='loader page size (default 4096)')
    parser.add_argument('--base', type=lambda value: int(value, 0),
                        default=None,
                        help='load bias/base address for ET_DYN objects')
    now_group = parser.add_mutually_exclusive_group()
    now_group.add_argument('--assume-now', action='store_true',
                           help='assume BIND_NOW regardless of the file flags')
    now_group.add_argument('--assume-lazy', action='store_true',
                           help='assume lazy binding regardless of file flags')
    args = parser.parse_args()

    assume_now = True if args.assume_now else \
        False if args.assume_lazy else None
    for filename in args.elffile:
        process_file(filename, args.page_size, args.base, assume_now)
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        # Example-test entry point: fixed arguments, deterministic output.
        for name in sys.argv[2:]:
            process_file(name, page_size=4096, base=None, assume_now=None)
        sys.exit(0)
    sys.exit(main())
