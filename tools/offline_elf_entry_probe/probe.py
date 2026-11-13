#!/usr/bin/env python3
"""Offline inventory of ELF entry candidates a dynamic loader may invoke.

The probe reads the file bytes with pyelftools and never maps, relocates,
dlopen()s or executes the input. It reports the structure that supplied each
candidate, the loader conditions required for that candidate to matter, and
which addresses must remain symbolic expressions because the load bias or an
IFUNC resolver result is unknowable statically.

Static presence is not proof of execution.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import Relocation, RelocationSection
from elftools.elf.sections import Symbol, SymbolTableSection

# e_machine -> (R_*_RELATIVE, R_*_IRELATIVE). Values checked against the
# psABI values present in ELF toolchains; pyelftools 0.33 names all but the
# AArch64 IRELATIVE entry.
RELATIVE_TYPES: dict[str, tuple[int, int]] = {
    'EM_386': (8, 42),
    'EM_X86_64': (8, 37),
    'EM_ARM': (23, 140),
    'EM_AARCH64': (1027, 1032),
    'EM_RISCV': (3, 58),
    'EM_PPC64': (22, 248),
    'EM_S390': (12, 61),
    'EM_LOONGARCH': (3, 12),
}

TABLE_TAGS = (
    'DT_STRTAB', 'DT_SYMTAB', 'DT_RELA', 'DT_REL', 'DT_JMPREL',
    'DT_PREINIT_ARRAY', 'DT_PREINIT_ARRAYSZ',
    'DT_INIT_ARRAY', 'DT_INIT_ARRAYSZ',
    'DT_FINI_ARRAY', 'DT_FINI_ARRAYSZ',
    'DT_HASH', 'DT_GNU_HASH', 'DT_RELR', 'DT_RELRSZ',
)

ARRAY_SPECS = (
    # label, pointer tag, size tag, kind, startup?
    ('preinit_array', 'DT_PREINIT_ARRAY', 'DT_PREINIT_ARRAYSZ', 'preinit-array', True),
    ('init_array', 'DT_INIT_ARRAY', 'DT_INIT_ARRAYSZ', 'init-array', True),
    ('fini_array', 'DT_FINI_ARRAY', 'DT_FINI_ARRAYSZ', 'fini-array', False),
)


def uhex(value: int | None) -> str:
    if value is None:
        return '?'
    return f'-{(-value):#x}' if value < 0 else f'{value:#x}'


def add_expr(base: int) -> str:
    if base < 0:
        return f'B - {uhex(-base)}'
    return f'B + {uhex(base)}'


@dataclass
class Evidence:
    kind: str                 # entry|relative|irelative|ifunc-symbol|ifunc-reference|array-slot|dt-init|dt-fini|empty-array
    source: str               # exact ELF structure and location
    slot: str | None          # parser-side slot address, if one exists
    file_value: str           # bytes/fields observed without load-time changes
    initializer: str | None   # relocation/expression that rewrites the slot, if any
    final_target: str         # what may be called, or why it is unresolved
    address_form: str         # file-offset|parser-va|base+addend|resolver-result|raw-word|symbol-value|none
    requires_load_bias: bool  # cannot be made absolute without B
    loader_condition: str     # conditions that must hold for this candidate
    confidence: str           # observed|derived|unresolved
    notes: list[str] = field(default_factory=list)


@dataclass
class RelocRecord:
    provenance: str
    rel: Any
    is_rela: bool
    relr: bool = False
    also_seen: list[str] = field(default_factory=list)


@dataclass
class SymbolView:
    label: str
    table: Any               # SymbolTableSection or DynamicSegment
    count: int

    def get(self, index: int) -> Symbol:
        return self.table.get_symbol(index)

    def raw_info(self, elf: ELFFile, index: int) -> int | None:
        return raw_symbol_info(elf, self.table, index)


def read_bytes(elf: ELFFile, offset: int, size: int) -> bytes | None:
    stream = elf.stream
    pos = stream.tell()
    try:
        stream.seek(offset)
        data = stream.read(size)
    finally:
        stream.seek(pos)
    return data if len(data) == size else None


def load_segments(elf: ELFFile) -> list[Any]:
    return [seg for seg in elf.iter_segments() if seg['p_type'] == 'PT_LOAD']


def va_to_offset(elf: ELFFile, va: int, size: int = 1) -> int | None:
    for seg in load_segments(elf):
        start = int(seg['p_vaddr'])
        end = start + int(seg['p_filesz'])
        if start <= va and va + size <= end:
            return int(seg['p_offset']) + (va - start)
    return None


def slot_writable(elf: ELFFile, va: int) -> bool:
    for seg in load_segments(elf):
        start = int(seg['p_vaddr'])
        end = start + int(seg['p_memsz'])
        if start <= va < end:
            return bool(int(seg['p_flags']) & 0x2)  # PF_W
    return False


def read_pointer(elf: ELFFile, va: int, width: int | None = None) -> int | None:
    width = width or (elf.elfclass // 8)
    off = va_to_offset(elf, va, width)
    if off is None:
        return None
    data = read_bytes(elf, off, width)
    if data is None:
        return None
    return int.from_bytes(data, 'little' if elf.little_endian else 'big')


def section_names_usable(elf: ELFFile) -> bool:
    if elf.num_sections() == 0:
        return False
    return elf.get_section_by_name('.shstrtab') is not None


def dynamic_tags(elf: ELFFile) -> tuple[list[Any], str]:
    """Prefer PT_DYNAMIC (works without section headers); fall back to section."""
    segments = list(elf.iter_segments(type='PT_DYNAMIC'))
    if segments:
        # Multiple PT_DYNAMIC segments are not expected in a loadable image;
        # if present, use the first and let table recovery surface conflicts.
        return list(segments[0].iter_tags()), 'PT_DYNAMIC segment'
    sec = elf.get_section_by_name('.dynamic')
    if isinstance(sec, DynamicSection):
        return list(sec.iter_tags()), '.dynamic section'
    return [], 'absent'


def dynamic_value(tags: list[Any], name: str) -> int | None:
    for tag in tags:
        if tag.entry.d_tag == name:
            return int(tag.entry.d_val)
    return None


def symbol_table_entry_offset(elf: ELFFile, table: Any, index: int) -> int | None:
    if isinstance(table, SymbolTableSection):
        entsize = int(table['sh_entsize'])
        if entsize <= 0:
            return None
        return int(table['sh_offset']) + index * entsize
    if isinstance(table, DynamicSegment):
        _, tab_off = table.get_table_offset('DT_SYMTAB')
        if tab_off is None:
            return None
        entsize = dynamic_value(list(table.iter_tags()), 'DT_SYMENT')
        if entsize is None:
            entsize = 24 if elf.elfclass == 64 else 16
        return int(tab_off) + index * int(entsize)
    return None


def raw_symbol_info(elf: ELFFile, table: Any, index: int) -> int | None:
    """Read st_info directly; pyelftools cannot retain raw enum values.

    Value 10 is STT_GNU_IFUNC in the GNU/psABI namespace, but pyelftools 0.33
    maps it to the generic name STT_LOOS. The byte is authoritative.
    """
    off = symbol_table_entry_offset(elf, table, index)
    if off is None:
        return None
    # Elf64_Sym: st_name(4), st_info(1); Elf32_Sym: st_name(4), st_value(4),
    # st_size(4), st_info(1).
    info_off = off + (4 if elf.elfclass == 64 else 12)
    data = read_bytes(elf, info_off, 1)
    return data[0] if data else None


def symbol_views(elf: ELFFile) -> list[SymbolView]:
    out: list[SymbolView] = []
    for i, sec in enumerate(elf.iter_sections()):
        if isinstance(sec, SymbolTableSection):
            out.append(SymbolView(f'{sec["sh_type"]}[{i}]', sec, sec.num_symbols()))
    if out:
        return out
    for seg in elf.iter_segments(type='PT_DYNAMIC'):
        try:
            count = seg.num_symbols()
        except Exception:
            continue
        out.append(SymbolView(f'PT_DYNAMIC DT_SYMTAB ({count} symbols)', seg, count))
    return out


def find_symbol(elf: ELFFile, index: int) -> tuple[SymbolView, Symbol]:
    views = symbol_views(elf)
    if not views:
        raise ValueError('no symbol table can be recovered from sections or DT_SYMTAB')
    for view in views:
        if view.label.startswith('SHT_DYNSYM'):
            return view, view.get(index)
    for view in views:
        if view.label.startswith('PT_DYNAMIC'):
            return view, view.get(index)
    return views[0], views[0].get(index)


def symbol_type_name(elf: ELFFile, view: SymbolView, index: int, sym: Symbol) -> str:
    raw = view.raw_info(elf, index)
    if raw is not None and (raw & 0xf) == 10:
        return 'STT_GNU_IFUNC (raw 10; pyelftools may print STT_LOOS)'
    if raw is not None:
        return f'{sym["st_info"]["type"]} (raw {raw & 0xf})'
    return str(sym['st_info']['type'])


def is_ifunc(elf: ELFFile, view: SymbolView, index: int) -> bool:
    raw = view.raw_info(elf, index)
    return raw is not None and (raw & 0xf) == 10


def symbol_detail(elf: ELFFile, rel: Relocation) -> tuple[str | None, SymbolView | None, Symbol | None]:
    index = int(rel['r_info_sym'])
    if index == 0:
        return None, None, None
    try:
        view, sym = find_symbol(elf, index)
    except Exception as exc:
        return f'r_info_sym={index} <unresolved: {exc}>', None, None
    name = sym.name or f'<sym#{index}>'
    detail = (f'r_info_sym={index} {name} '
              f'(st_value={uhex(int(sym["st_value"]))}, {view.label}, '
              f'type={symbol_type_name(elf, view, index, sym)})')
    return detail, view, sym


def reloc_type_name(elf: ELFFile, rtype: int) -> str:
    try:
        name = describe_reloc_type(rtype, elf)
        if name and name != str(rtype):
            return name
    except Exception:
        pass
    return f'type {rtype} (unnamed in this pyelftools)'


def reloc_family(elf: ELFFile, rtype: int) -> str | None:
    pair = RELATIVE_TYPES.get(str(elf['e_machine']))
    if pair is None:
        return None
    if rtype == pair[0]:
        return 'relative'
    if rtype == pair[1]:
        return 'irelative'
    return None


def collect_relocations(elf: ELFFile, warnings: list[str]) -> list[RelocRecord]:
    records: dict[tuple[Any, ...], RelocRecord] = {}

    def add(record: RelocRecord) -> None:
        if record.relr:
            key = ('relr', int(record.rel['r_offset']))
        else:
            key = (record.is_rela, int(record.rel['r_offset']),
                   int(record.rel['r_info']),
                   int(record.rel['r_addend']) if record.is_rela else None)
        old = records.get(key)
        if old is None:
            records[key] = record
        elif record.provenance not in old.also_seen and record.provenance != old.provenance:
            old.also_seen.append(record.provenance)

    for i, sec in enumerate(elf.iter_sections()):
        if not isinstance(sec, RelocationSection):
            continue
        name = sec.name or f'#{i}'
        for rel in sec.iter_relocations():
            add(RelocRecord(f'section {name} ({sec["sh_type"]})', rel, rel.is_RELA()))

    for seg in elf.iter_segments(type='PT_DYNAMIC'):
        try:
            tables = seg.get_relocation_tables()
        except Exception as exc:
            warnings.append(f'could not load relocation tables from PT_DYNAMIC: {exc}')
            continue
        for key, table in tables.items():
            if key == 'RELR':
                for rel in table.iter_relocations():
                    add(RelocRecord('PT_DYNAMIC RELR table', rel, False, relr=True))
                continue
            is_rela = table.is_RELA()
            for rel in table.iter_relocations():
                add(RelocRecord(f'PT_DYNAMIC {key} table', rel, is_rela))

    return list(records.values())


def address_slot_text(elf: ELFFile, r_offset: int) -> str:
    if elf['e_type'] == 'ET_REL':
        return f'{uhex(r_offset)} (section offset; ET_REL is not loadable)'
    return f'{uhex(r_offset)} (parser VA; add B for ET_DYN runtime address)'


def relocation_evidence(elf: ELFFile, rec: RelocRecord, warnings: list[str]) -> Evidence | None:
    rel = rec.rel
    r_offset = int(rel['r_offset'])

    if rec.relr:
        width = elf.elfclass // 8
        inplace = read_pointer(elf, r_offset, width)
        value = 'unreadable in file-backed bytes' if inplace is None else f'[*{uhex(r_offset)}]={uhex(inplace)}'
        target = ('unresolved: in-place addend is not readable'
                  if inplace is None else f'{add_expr(inplace)} (RELR relative)')
        notes = ['RELR is a compressed RELATIVE table; addend is in place',
                 'B is unknown for ET_DYN and is not guessed from the file']
        if elf['e_type'] == 'ET_EXEC':
            notes.append('ET_EXEC expression assumes the loader honors fixed VAs; not proven')
        return Evidence(
            kind='relative',
            source=f'{rec.provenance}: RELR entry @ r_offset={uhex(r_offset)}',
            slot=address_slot_text(elf, r_offset),
            file_value=value,
            initializer=f'RELR relative write to slot {uhex(r_offset)}',
            final_target=target,
            address_form='base+addend',
            requires_load_bias=elf['e_type'] == 'ET_DYN',
            loader_condition=(('slot is in a PT_LOAD with PF_W' if slot_writable(elf, r_offset)
                               else 'slot is NOT in a writable PT_LOAD (PF_W absent); a real loader '
                                    'would fault or refuse the write')
                              + '; the loader must process DT_RELR/DT_RELRSZ; B is the actual load bias'),
            confidence='observed relocation; final address unresolved without B',
            notes=notes,
        )

    rtype = int(rel['r_info_type'])
    family = reloc_family(elf, rtype)
    sym_detail, sym_view, sym = symbol_detail(elf, rel)
    is_rela = rec.is_rela
    width = elf.elfclass // 8
    inplace = None if is_rela else read_pointer(elf, r_offset, width)
    addend = int(rel['r_addend']) if is_rela else inplace

    if family is None:
        # Not a RELATIVE/IRELATIVE entry. Still report a symbolic reference to
        # an IFUNC definition, because JUMP_SLOT/GLOB_DAT resolution calls it.
        if sym_detail is not None and sym_view is not None and is_ifunc(elf, sym_view, int(rel['r_info_sym'])):
            rtype_name = reloc_type_name(elf, rtype)
            symbolic = rtype_name in ('R_X86_64_GLOB_DAT', 'R_X86_64_JUMP_SLOT',
                                      'R_386_GLOB_DAT', 'R_386_JUMP_SLOT',
                                      'R_AARCH64_GLOB_DAT', 'R_AARCH64_JUMP_SLOT',
                                      'R_ARM_GLOB_DAT', 'R_ARM_JUMP_SLOT')
            if not symbolic:
                return None
            return Evidence(
                kind='ifunc-reference',
                source=(f'{rec.provenance}: {rtype_name} '
                        f'@ r_offset={uhex(r_offset)}; {sym_detail}'),
                slot=address_slot_text(elf, r_offset),
                file_value=f'{sym_detail}; relocation type {rtype_name}',
                initializer=None,
                final_target=('resolver result (the loader calls the IFUNC resolver and '
                              'writes the returned code address here)'),
                address_form='resolver-result',
                requires_load_bias=True,
                loader_condition=(('slot is in a PT_LOAD with PF_W' if slot_writable(elf, r_offset)
                                   else 'slot is NOT in a writable PT_LOAD (PF_W absent)')
                                  + '; the symbol must resolve to this IFUNC definition '
                                    '(preemption can change it); the loader must process this '
                                    'relocation table; the resolver must return a valid code address'),
                confidence='observed IFUNC symbol reference; returned address unknown',
                notes=['STT_GNU_IFUNC st_value is a resolver entry, not the final function',
                       'symbol interposition can replace this definition'],
            )
        return None

    addend_text: str
    if is_rela:
        addend_text = f'r_addend={uhex(addend)} (explicit RELA field)'
    elif inplace is None:
        addend_text = f'in-place word at {uhex(r_offset)} is not file-backed'
        warnings.append(f'{rec.provenance}: REL addend slot {uhex(r_offset)} is not readable')
    else:
        addend_text = f'[*{uhex(r_offset)}]={uhex(inplace)} (in-place REL word)'

    if addend is None:
        final_target = 'unresolved: addend cannot be recovered from file bytes'
        confidence = 'unresolved addend'
        form = 'raw-word'
    elif family == 'irelative':
        final_target = (f'call {add_expr(addend)} as resolver; the resolver return value '
                        'is the final IFUNC function address')
        confidence = 'observed relocation; returned address unknown without executing resolver'
        form = 'resolver-result'
    else:
        final_target = f'{add_expr(addend)} (relative relocation)'
        confidence = 'observed relocation; final address unresolved without B'
        form = 'base+addend'

    notes = [
        'REL/RELA determines where the addend lives; the slot is where the loader writes',
        'symbol field is ignored for RELATIVE/IRELATIVE; the addend determines the target',
    ]
    if family == 'irelative':
        notes.append('resolver address is not the final function address')
    if elf['e_type'] == 'ET_EXEC':
        notes.append('ET_EXEC expression assumes fixed-VA mapping; mapping is not proven')
    if rec.also_seen:
        notes.append('same table also recovered via: ' + ', '.join(rec.also_seen))

    return Evidence(
        kind=family,
        source=(f'{rec.provenance}: {reloc_type_name(elf, rtype)} '
                f'@ r_offset={uhex(r_offset)}; {addend_text}; '
                f'{sym_detail or "no symbol (r_info_sym=0)"}'),
        slot=address_slot_text(elf, r_offset),
        file_value=addend_text,
        initializer=(f'{reloc_type_name(elf, rtype)} writes the slot at {uhex(r_offset)}'),
        final_target=final_target,
        address_form=form,
        requires_load_bias=elf['e_type'] == 'ET_DYN',
        loader_condition=(('slot is in a PT_LOAD with PF_W' if slot_writable(elf, r_offset)
                           else 'slot is NOT in a writable PT_LOAD (PF_W absent); a real loader '
                                'would fault or refuse the write')
                          + '; the loader must process the applicable REL/RELA table; '
                            'B is the actual load bias'
                          + ('; resolver must be executable and return a code address'
                             if family == 'irelative' else '')),
        confidence=confidence,
        notes=notes,
    )


def ifunc_symbol_evidence(elf: ELFFile) -> list[Evidence]:
    out: list[Evidence] = []
    for view in symbol_views(elf):
        for index in range(view.count):
            try:
                sym = view.get(index)
            except Exception:
                continue
            if not is_ifunc(elf, view, index):
                continue
            shndx = sym['st_shndx']
            where = 'defined' if shndx not in ('SHN_UNDEF', 0) else 'undefined (provider is external)'
            out.append(Evidence(
                kind='ifunc-symbol',
                source=f'{view.label} symbol #{index} {sym.name!r}',
                slot=None,
                file_value=(f'st_value={uhex(int(sym["st_value"]))} '
                            f'({symbol_type_name(elf, view, index, sym)}), {where}'),
                initializer=None,
                final_target='resolver result; the resolver return value is the final function address',
                address_form='symbol-value',
                requires_load_bias=elf['e_type'] == 'ET_DYN',
                loader_condition=('a symbol reference must resolve to this definition; the loader '
                                  'or caller invokes the resolver; no call order is implied by presence'),
                confidence='observed symbol type; final address unknown',
                notes=['st_value is a resolver entry for STT_GNU_IFUNC',
                       'presence in .dynsym/.symtab is not proof of invocation',
                       'preemption may select another provider'],
            ))
    return out


def array_evidence(elf: ELFFile, tags: list[Any], spec: tuple[str, str, str, str, bool],
                   rels_by_slot: dict[int, list[RelocRecord]],
                   warnings: list[str]) -> list[Evidence]:
    label, ptr_tag, size_tag, kind, startup = spec
    ptr = dynamic_value(tags, ptr_tag)
    size = dynamic_value(tags, size_tag)
    if ptr is None or size is None:
        return []
    # DT_PREINIT_ARRAY is only honored for a main program image. A DSO must
    # not advertise it as a load-time callback.
    preinit_dso = (kind == 'preinit-array' and elf['e_type'] != 'ET_EXEC')
    width = elf.elfclass // 8
    if size % width:
        warnings.append(f'{ptr_tag}={uhex(ptr)} size {uhex(size)} is not a multiple of {width}')
    if ptr == 0 or size == 0:
        return [Evidence(
            kind='empty-array',
            source=f'{ptr_tag}={uhex(ptr)}, {size_tag}={uhex(size)}',
            slot=None,
            file_value='empty initializer table',
            initializer=None,
            final_target='no function candidate',
            address_form='none',
            requires_load_bias=False,
            loader_condition='loader may skip an empty table',
            confidence='observed',
        )]

    out: list[Evidence] = []
    for i in range(size // width):
        slot = ptr + i * width
        raw = read_pointer(elf, slot, width)
        candidate = f'{label}[{i}]'
        if raw is None:
            warnings.append(f'{candidate}: slot {uhex(slot)} is not file-backed')
            out.append(Evidence(
                kind='array-slot',
                source=f'{candidate}: {ptr_tag}={uhex(ptr)} + {i}*{width}',
                slot=f'{uhex(slot)} (parser VA; no file-backed PT_LOAD byte)',
                file_value='unreadable from file bytes',
                initializer=None,
                final_target='unresolved: slot must be mapped; its initial value is not in file bytes',
                address_form='raw-word',
                requires_load_bias=True,
                loader_condition='loader must map the array and initialize the slot',
                confidence='unresolved',
            ))
            continue

        records = rels_by_slot.get(slot, [])
        rec = records[0] if records else None
        initializer = None
        if rec is not None:
            if rec.relr:
                eff = raw
                final_target = f'{add_expr(eff)} (RELR relative write to this slot)'
                form = 'base+addend'
                requires_bias = elf['e_type'] == 'ET_DYN'
                initializer = 'RELR relative entry at this slot'
                confidence = 'observed slot and relocation'
            else:
                rtype = int(rec.rel['r_info_type'])
                family = reloc_family(elf, rtype)
                eff = int(rec.rel['r_addend']) if rec.is_rela else raw
                initializer = f'{reloc_type_name(elf, rtype)} at this slot ({rec.provenance})'
                if family == 'irelative':
                    final_target = (f'call {add_expr(eff)} as resolver, then the returned '
                                    'address is the function candidate')
                    form = 'resolver-result'
                    requires_bias = elf['e_type'] == 'ET_DYN'
                    confidence = 'observed IRELATIVE; resolver result unknown'
                elif family == 'relative':
                    final_target = f'{add_expr(eff)} (relative relocation rewrites this slot)'
                    form = 'base+addend'
                    requires_bias = elf['e_type'] == 'ET_DYN'
                    confidence = 'observed slot and relative relocation'
                else:
                    # A non-relative relocation can still be symbolic (e.g.
                    # GLOB_DAT to an IFUNC). Keep it unresolved rather than
                    # pretending the raw word is final.
                    sym_detail, sym_view, _ = symbol_detail(elf, rec.rel)
                    if sym_detail and sym_view is not None and is_ifunc(
                            elf, sym_view, int(rec.rel['r_info_sym'])):
                        final_target = ('resolver result for an IFUNC symbol; returned '
                                        'address is unknown')
                        form = 'resolver-result'
                    else:
                        final_target = (f'symbolic relocation expression; raw word '
                                        f'{uhex(raw)} is not the final address')
                        form = 'raw-word'
                    requires_bias = elf['e_type'] == 'ET_DYN'
                    confidence = 'observed relocation; final address unresolved'
        else:
            if elf['e_type'] == 'ET_EXEC':
                final_target = (f'{uhex(raw)} (ET_EXEC file VA candidate; relies on '
                                'fixed-VA mapping and no runtime rewrite)')
                form = 'parser-va'
                requires_bias = False
                confidence = 'observed raw word; mapping not proven'
            else:
                final_target = (f'raw word {uhex(raw)}; no relocation observed, so no final '
                                'address can be formed statically')
                form = 'raw-word'
                requires_bias = True
                confidence = 'observed raw word; final address unresolved'

        notes = [
            'raw slot contents and the final call target are distinct',
            'array element is invoked by the loader, not by this probe',
        ]
        if kind == 'init-array':
            notes.append('this slot is a load-time/startup candidate; whether it runs depends '
                         'on the loader reaching the array entry')
        elif kind == 'fini-array':
            notes.append('exit-time candidate, not a load-time initializer')
        if rec is not None:
            notes.append('slot is both an array element and a relocation target')
        if kind == 'preinit-array':
            notes.append('DT_PREINIT_ARRAY is honored only for a main executable, not for a '
                         'dlopen\'d DSO' if not preinit_dso else
                         'this is a shared object/DSO; DT_PREINIT_ARRAY is not honored here')
        if not startup:
            notes.append('DT_FINI_ARRAY is an exit-time table, not a startup initializer')
        out.append(Evidence(
            kind=('preinit-array-inapplicable' if preinit_dso
                  else (kind if startup else 'fini-array')),
            source=f'{candidate}: {ptr_tag}={uhex(ptr)} + {i}*{width} = slot {uhex(slot)}',
            slot=f'{uhex(slot)} (parser VA; add B for ET_DYN runtime address)',
            file_value=f'{uhex(raw)} (raw file word before relocation)',
            initializer=initializer,
            final_target=final_target,
            address_form=form,
            requires_load_bias=requires_bias,
            loader_condition=(('slot is in a PT_LOAD with PF_W' if slot_writable(elf, slot)
                               else 'slot is NOT in a writable PT_LOAD (PF_W absent)')
                              + '; the loader must process this dynamic table and map the array; '
                                'the element is invoked in loader-defined dependency/priority '
                                'order; the dynamic loader must also process any relocation for '
                                'the slot'),
            confidence=confidence,
            notes=notes,
        ))
    return out


def single_tag_evidence(elf: ELFFile, tags: list[Any], tag_name: str,
                        startup: bool) -> Evidence | None:
    value = dynamic_value(tags, tag_name)
    if value is None:
        return None
    return Evidence(
        kind='dt-init' if startup else 'dt-fini',
        source=f'{tag_name}={uhex(value)}',
        slot=None,
        file_value=f'{uhex(value)} (dynamic tag value; parser VA for ET_DYN)',
        initializer=None,
        final_target=(f'{add_expr(value)} (single function pointer)'
                      if elf['e_type'] == 'ET_DYN' else
                      f'{uhex(value)} (single function pointer; fixed-VA assumption)'),
        address_form='base+addend' if elf['e_type'] == 'ET_DYN' else 'parser-va',
        requires_load_bias=elf['e_type'] == 'ET_DYN',
        loader_condition=(f'loader must process {tag_name}; runtime address uses B for ET_DYN'
                          + ('' if startup else '; this is exit-time, not startup')),
        confidence='observed dynamic tag; presence is not proof of invocation',
        notes=['single function pointer, not an array',
               'the tag value is not a symbol value'],
    )


def entry_evidence(elf: ELFFile) -> Evidence:
    entry = int(elf['e_entry'])
    if entry == 0:
        return Evidence(
            kind='entry', source='ELF header e_entry', slot=None,
            file_value='0 (no process entry point)', initializer=None,
            final_target='no process entry point', address_form='none',
            requires_load_bias=False, loader_condition='none',
            confidence='observed',
        )
    if elf['e_type'] == 'ET_DYN':
        final = f'{add_expr(entry)} (process entry, not an initializer callback)'
        form = 'base+addend'
        bias = True
    else:
        final = f'{uhex(entry)} (process entry candidate; fixed-VA mapping assumed)'
        form = 'parser-va'
        bias = False
    return Evidence(
        kind='entry',
        source='ELF header e_entry',
        slot=None,
        file_value=f'{uhex(entry)} (parser VA)',
        initializer=None,
        final_target=final,
        address_form=form,
        requires_load_bias=bias,
        loader_condition=('the loader transfers control to this process entry after initialization; '
                          'it is not itself an initializer-array callback'
                          + ('; ET_DYN runtime value is B + e_entry' if bias else '')),
        confidence='observed header field; not proof of invocation',
        notes=['separate from DT_INIT/DT_INIT_ARRAY loader callbacks'],
    )


def build_report(path: str) -> dict[str, Any]:
    warnings: list[str] = []
    limitations: list[str] = []
    with open(path, 'rb') as stream:
        elf = ELFFile(stream)
        tags, dyn_provenance = dynamic_tags(elf)
        sh_ok = section_names_usable(elf)
        pt_load = load_segments(elf)
        rels = collect_relocations(elf, warnings)
        rels_by_slot: dict[int, list[RelocRecord]] = {}
        for rec in rels:
            rels_by_slot.setdefault(int(rec.rel['r_offset']), []).append(rec)

        if not sh_ok:
            limitations.append('section names are unavailable; table identities come from '
                               'PT_DYNAMIC tags and PT_LOAD mappings')
        if dyn_provenance == 'absent':
            limitations.append('no PT_DYNAMIC or .dynamic table; initializer arrays and '
                               'dynamic relocations cannot be recovered')
        if elf['e_type'] == 'ET_REL':
            limitations.append('ET_REL is a relocatable object, not a loadable image; '
                               'r_offset values are section-relative')
        if elf['e_type'] == 'ET_DYN':
            limitations.append('ET_DYN load bias B is chosen at load time (ASLR/loader); '
                               'no runtime absolute address is computed')
        if any(slot_writable(elf, ptr) for ptr in (
                dynamic_value(tags, 'DT_INIT_ARRAY'),
                dynamic_value(tags, 'DT_PREINIT_ARRAY'),
                dynamic_value(tags, 'DT_FINI_ARRAY')) if ptr is not None):
            limitations.append('writability is inferred from PT_LOAD PF_W; some loaders may '
                               'protect arrays or use RELRO, so a truly writable slot at load '
                               'time is not guaranteed by the file alone')
        limitations.append('static entry presence is not proof that the loader will call it')
        if not sh_ok and dynamic_value(tags, 'DT_SYMTAB') is not None:
            if (dynamic_value(tags, 'DT_HASH') is None
                    and dynamic_value(tags, 'DT_GNU_HASH') is None):
                limitations.append('DT_SYMTAB is present but neither DT_HASH nor DT_GNU_HASH '
                                   'gives a symbol count; IFUNC enumeration may be incomplete')
            limitations.append('DT_RELR is reported, but its compressed bitmap is not expanded '
                               'by this REL/RELA-focused prototype beyond pyelftools RELR entries')

        report: dict[str, Any] = {
            'file': path,
            'container': {
                'class': 'ELF32' if elf.elfclass == 32 else 'ELF64',
                'endian': 'little' if elf.little_endian else 'big',
                'type': elf['e_type'],
                'machine': elf['e_machine'],
                'entry': uhex(int(elf['e_entry'])),
            },
            'section_headers': {
                'available': sh_ok,
                'count': elf.num_sections(),
                'conclusion': ('usable section names are present; loader semantics still come '
                               'from dynamic tags' if sh_ok else
                               'no section names; use PT_DYNAMIC and DT_* table addresses'),
            },
            'dynamic': {
                'provenance': dyn_provenance,
                'tags': sorted({str(t.entry.d_tag) for t in tags}),
                'table_addresses': {
                    str(t.entry.d_tag): uhex(int(t.entry.d_val))
                    for t in tags if str(t.entry.d_tag) in TABLE_TAGS
                },
            },
            'pt_load': [
                {'index': i, 'vaddr': uhex(int(seg['p_vaddr'])),
                 'offset': uhex(int(seg['p_offset'])),
                 'filesz': uhex(int(seg['p_filesz'])),
                 'memsz': uhex(int(seg['p_memsz'])),
                 'flags': int(seg['p_flags'])}
                for i, seg in enumerate(pt_load)
            ],
            'warnings': warnings,
            'limitations': limitations,
            'evidence': [],
        }

        ev: list[Evidence] = [entry_evidence(elf)]
        for rec in rels:
            item = relocation_evidence(elf, rec, warnings)
            if item is not None:
                ev.append(item)
        ev.extend(ifunc_symbol_evidence(elf))
        for spec in ARRAY_SPECS:
            ev.extend(array_evidence(elf, tags, spec, rels_by_slot, warnings))
        for tag_name, startup in (('DT_INIT', True), ('DT_FINI', False)):
            item = single_tag_evidence(elf, tags, tag_name, startup)
            if item is not None:
                ev.append(item)

        report['evidence'] = [asdict(item) for item in ev]
        return report


def render_text(report: dict[str, Any]) -> str:
    c = report['container']
    lines = [
        f"file: {report['file']}",
        f"container: {c['class']} {c['endian']}-endian {c['type']} {c['machine']} entry={c['entry']}",
        f"section names: {'yes' if report['section_headers']['available'] else 'no'}"
        f" ({report['section_headers']['conclusion']})",
        f"dynamic provenance: {report['dynamic']['provenance']}",
        f"dynamic tags: {', '.join(report['dynamic']['tags']) or '-'}",
        'PT_LOAD:',
    ]
    for seg in report['pt_load']:
        lines.append(f"  #{seg['index']} vaddr={seg['vaddr']} off={seg['offset']} "
                     f"filesz={seg['filesz']} memsz={seg['memsz']} flags={seg['flags']}")
    if report['warnings']:
        lines.append('warnings:')
        lines.extend(f"  - {w}" for w in report['warnings'])
    lines.append('limitations:')
    lines.extend(f"  - {x}" for x in report['limitations'])
    lines.append('')
    lines.append('evidence:')
    for i, item in enumerate(report['evidence'], 1):
        lines.append(f"  [{i}] {item['kind']}: {item['source']}")
        lines.append(f"      slot: {item['slot'] or '-'}")
        lines.append(f"      file value: {item['file_value']}")
        lines.append(f"      initializer: {item['initializer'] or '-'}")
        lines.append(f"      final target: {item['final_target']}")
        lines.append(f"      address form: {item['address_form']}; "
                     f"requires load bias: {'yes' if item['requires_load_bias'] else 'no'}")
        lines.append(f"      loader condition: {item['loader_condition']}")
        lines.append(f"      confidence: {item['confidence']}")
        for note in item['notes']:
            lines.append(f"      note: {note}")
    return '\n'.join(lines)


def render_markdown(report: dict[str, Any]) -> str:
    c = report['container']
    lines = [
        f"## `{report['file']}`",
        '',
        f"- Container: {c['class']} {c['endian']}-endian, {c['type']}, {c['machine']}, `e_entry={c['entry']}`",
        f"- Section names: {'available' if report['section_headers']['available'] else 'absent'} — {report['section_headers']['conclusion']}",
        f"- Dynamic provenance: {report['dynamic']['provenance']}",
        f"- PT_LOAD: " + '; '.join(
            f"#{s['index']} vaddr={s['vaddr']} off={s['offset']} filesz={s['filesz']} flags={s['flags']}"
            for s in report['pt_load']),
        '',
        '### Evidence graph',
        '',
        '```text',
    ]
    for i, item in enumerate(report['evidence'], 1):
        edge = '--' if not item['requires_load_bias'] else '-B->'
        lines.append(f"[{item['kind']}] {item['source']}")
        lines.append(f"    | file value: {item['file_value']}")
        if item['initializer']:
            lines.append(f"    | initializer: {item['initializer']}")
        if item['slot']:
            lines.append(f"    | slot: {item['slot']}")
        lines.append(f"    +{edge} {item['final_target']}")
        lines.append(f"       loader: {item['loader_condition']}")
        lines.append('')
    lines.append('```')
    lines.append('')
    lines.append('### Per-entry conditions')
    lines.append('')
    lines.append('| # | kind | source | slot | file value | initializer | final target | load bias needed | loader condition |')
    lines.append('|---:|---|---|---|---|---|---|:---:|---|')
    for i, item in enumerate(report['evidence'], 1):
        def clean(text: str | None) -> str:
            return (text or '-').replace('|', '\\|').replace('\n', ' ')
        lines.append(f"| {i} | {clean(item['kind'])} | {clean(item['source'])} | "
                     f"{clean(item['slot'])} | {clean(item['file_value'])} | "
                     f"{clean(item['initializer'])} | {clean(item['final_target'])} | "
                     f"{'yes' if item['requires_load_bias'] else 'no'} | "
                     f"{clean(item['loader_condition'])} |")
    if report['limitations']:
        lines.append('')
        lines.append('### Limits')
        lines.append('')
        lines.extend(f"- {x}" for x in report['limitations'])
    return '\n'.join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('elf', help='ELF file to inspect; it is read, never loaded or executed')
    ap.add_argument('--json', action='store_true', help='emit JSON')
    ap.add_argument('--markdown', action='store_true', help='emit an evidence-graph Markdown section')
    args = ap.parse_args(argv)
    try:
        report = build_report(args.elf)
    except Exception as exc:
        print(f'probe: {exc}', file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.markdown:
        print(render_markdown(report))
    else:
        print(render_text(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
