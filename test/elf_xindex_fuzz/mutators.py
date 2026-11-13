"""Deterministic, relationship-level mutators.

Each mutator clones a legal :class:`~test.elf_xindex_fuzz.builder.Template`
and changes exactly one structural fact: a count, a link target, a table
length or an index value. Mutators never resize the underlying blob, so
the fixed sample size is preserved and a changed byte offset always maps
back to a named header field.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable

from .builder import (
    DECOY_SECTION,
    EXPECTED_TARGET_SECTION,
    IDX_DATA,
    IDX_DECOY,
    IDX_SHNDX,
    IDX_SYMTAB,
    SECTION_COUNT,
    SYM_TARGET,
    SYMBOL_COUNT,
    Template,
    build_template,
)


@dataclass(frozen=True)
class Mutant:
    name: str
    mode: str
    data: bytes
    changed_field: str
    field_range: tuple[int, int]
    expected: str  # 'ok' | 'reject'
    detail: str


MutatorFn = Callable[[Template], None]


def make_custom_mutant(mode: str, name: str, fields: str | tuple[str, ...],
                       expected: str, detail: str,
                       mutate: MutatorFn) -> Mutant:
    """Build a one-off mutant from an inline mutation callback.

    Exposed for tests that need a relationship break not covered by the
    fixed mutator list. ``fields`` names the header field(s) the callback
    changes; the first one defines the protected minimization window.
    """
    return _make(mode, name, fields, expected, detail, mutate)


def _make(mode: str, name: str, fields: str | tuple[str, ...],
          expected: str, detail: str,
          mutate: MutatorFn) -> Mutant:
    template = build_template(mode)
    mutate(template)
    if isinstance(fields, str):
        fields = (fields,)
    if fields[0].startswith('symtab['):
        # Direct st_shndx patch; its range is derived from the symtab blob.
        sym_off, _ = template.layout['symtab']
        base = sym_off + SYM_TARGET * 16 + 14
        field_range = (base, base + 2)
    else:
        ref = template.refs[fields[0]]
        field_range = (ref.offset, ref.offset + ref.size)
    return Mutant(name=name, mode=mode, data=bytes(template.data),
                  changed_field='/'.join(fields), field_range=field_range,
                  expected=expected, detail=detail)


# --- Count mutations (e_shnum / section zero sh_size) ----------------------

def mutate_shnum_zero(mode: str) -> Mutant:
    """Force e_shnum to 0 without the section-zero escape being valid."""
    def apply(template: Template) -> None:
        template.set_u16('e_shnum', 0)
        if mode == 'extended':
            # Break the real count in section zero as well: parser would
            # derive 0 sections instead of SECTION_COUNT.
            template.set_u32('shdr0.sh_size', 0)
    return _make(mode, 'shnum_zero', ('e_shnum', 'shdr0.sh_size'), 'reject',
                 'section count collapses to zero', apply)


def mutate_shnum_too_small(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        if mode == 'extended':
            template.set_u32('shdr0.sh_size', IDX_DATA)
        else:
            template.set_u16('e_shnum', IDX_DATA)
    return _make(mode, 'shnum_too_small', ('e_shnum', 'shdr0.sh_size'), 'reject',
                 f'count {IDX_DATA} hides the symtab/shndx sections', apply)


def mutate_shnum_huge(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        if mode == 'extended':
            template.set_u32('shdr0.sh_size', 0x10000)
        else:
            template.set_u16('e_shnum', 0xFFFE)
    return _make(mode, 'shnum_huge', ('e_shnum', 'shdr0.sh_size'), 'reject',
                 'count runs past the section header table', apply)


# --- shstrndx mutations -----------------------------------------------------

def mutate_shstrndx_bad(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        if mode == 'extended':
            # Point section zero's sh_link at a non-STRTAB section.
            template.set_u32('shdr0.sh_link', IDX_DATA)
        else:
            template.set_u16('e_shstrndx', IDX_DATA)
    return _make(mode, 'shstrndx_wrong_type', ('e_shstrndx', 'shdr0.sh_link'),
                 'reject', 'name string table index names a PROGBITS section',
                 apply)


def mutate_shstrndx_oor(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        if mode == 'extended':
            template.set_u32('shdr0.sh_link', 0xFFFF)
        else:
            template.set_u16('e_shstrndx', 0xFFFE)
    return _make(mode, 'shstrndx_out_of_range', ('e_shstrndx', 'shdr0.sh_link'),
                 'reject', 'name string table index is beyond the table',
                 apply)


# --- Link target mutations --------------------------------------------------

def mutate_shndx_link_decoy(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        template.set_u32(f'shdr{IDX_SHNDX}.sh_link', IDX_DECOY)
    return _make(mode, 'shndx_link_to_decoy', 'shdr5.sh_link', 'reject',
                 'SHNDX points at the decoy PROGBITS section, not the symtab',
                 apply)


def mutate_shndx_link_oor(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        template.set_u32(f'shdr{IDX_SHNDX}.sh_link', SECTION_COUNT + 9)
    return _make(mode, 'shndx_link_out_of_range', 'shdr5.sh_link', 'reject',
                 'SHNDX link names a section number that does not exist',
                 apply)


def mutate_symtab_link_type(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        # Repoint the symbol table's string-table link at the SHNDX section.
        template.set_u32(f'shdr{IDX_SYMTAB}.sh_link', IDX_SHNDX)
    return _make(mode, 'symtab_link_wrong_type', 'shdr4.sh_link', 'reject',
                 'symtab string link names a non-STRTAB section', apply)


# --- SHT_SYMTAB_SHNDX length mutations --------------------------------------

def mutate_shndx_short(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        # Header claims one word fewer than the symbol table needs.
        template.set_u32(f'shdr{IDX_SHNDX}.sh_size',
                         (SYMBOL_COUNT - 1) * 4)
    return _make(mode, 'shndx_short_table', 'shdr5.sh_size', 'reject',
                 'extended index table shorter than the symbol count', apply)


def mutate_shndx_long(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        template.set_u32(f'shdr{IDX_SHNDX}.sh_size',
                         (SYMBOL_COUNT + 1) * 4)
    return _make(mode, 'shndx_long_table', 'shdr5.sh_size', 'reject',
                 'extended index table longer than the symbol count', apply)


def mutate_shndx_bad_entsize(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        template.set_u32(f'shdr{IDX_SHNDX}.sh_entsize', 8)
    return _make(mode, 'shndx_bad_entsize', 'shdr5.sh_entsize', 'reject',
                 'extended index entry size is no longer Elf32_Word', apply)


# --- Index value mutations --------------------------------------------------

def mutate_xindex_to_decoy(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        template.set_u32(f'shndx.slot{SYM_TARGET}', DECOY_SECTION)
    return _make(mode, 'xindex_points_at_decoy', f'shndx.slot{SYM_TARGET}',
                 'ok', 'legal index, but membership must become the decoy',
                 apply)


def mutate_xindex_oor(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        template.set_u32(f'shndx.slot{SYM_TARGET}', 0xFFFF)
    return _make(mode, 'xindex_out_of_range', f'shndx.slot{SYM_TARGET}',
                 'reject', 'extended index names a section that does not exist',
                 apply)


def mutate_symbol_drops_xindex(mode: str) -> Mutant:
    def apply(template: Template) -> None:
        # Overwrite only the symbol's st_shndx halfword (last two bytes of
        # Elf_Sym) with an ordinary, existing section while the SHNDX table
        # remains present but unused.
        sym_off, _ = template.layout['symtab']
        st_shndx_off = sym_off + SYM_TARGET * 16 + 14
        struct.pack_into('<H', template.data, st_shndx_off,
                         EXPECTED_TARGET_SECTION)
    return _make(mode, 'symbol_drops_xindex', 'symtab[2].st_shndx', 'ok',
                 'symbol uses a direct index; extended table goes unused',
                 apply)


MUTATORS: tuple[Callable[[str], Mutant], ...] = (
    mutate_shnum_zero,
    mutate_shnum_too_small,
    mutate_shnum_huge,
    mutate_shstrndx_bad,
    mutate_shstrndx_oor,
    mutate_shndx_link_decoy,
    mutate_shndx_link_oor,
    mutate_symtab_link_type,
    mutate_shndx_short,
    mutate_shndx_long,
    mutate_shndx_bad_entsize,
    mutate_xindex_to_decoy,
    mutate_xindex_oor,
    mutate_symbol_drops_xindex,
)


def all_mutants() -> list[Mutant]:
    """Every mutator applied to both legal representations."""
    return [mutator(mode)
            for mode in ('normal', 'extended')
            for mutator in MUTATORS]
