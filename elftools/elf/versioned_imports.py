#------------------------------------------------------------------------------
# elftools: elf/versioned_imports.py
#
# Versioned import inventory: which external dynamic symbols this ELF file
# requires, at which symbol/version indices, together with the version name
# and the shared library that supplies it.
#
# Every fact is derived from the parsed file itself (dynsym, .gnu.version /
# DT_VERSYM and .gnu.version_r / DT_VERNEED). Version definitions
# (.gnu.version_d / DT_VERDEF) are never treated as import requirements, and
# nothing is guessed from libraries installed on the host.
#
# This code is in the public domain
#------------------------------------------------------------------------------
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypedDict

from ..common.exceptions import ELFError
from ..common.utils import struct_parse
from .dynamic import DynamicSegment
from .gnuversions import GNUVerNeedSection, GNUVerSymSection

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .elffile import ELFFile

# Special VERSYM indices from the gABI (VER_NDX_*).
VER_NDX_LOCAL = 0
VER_NDX_GLOBAL = 1
VER_NDX_LORESERVE = 0xFF00
# GNU versioning stores the hidden flag in the high bit of the 16-bit entry.
VERSYM_HIDDEN_BIT = 0x8000
VERSYM_INDEX_MASK = 0x7FFF


class ImportOffsets(TypedDict, total=False):
    """ File offsets backing a single versioned import record.

        Every value is a byte offset into the parsed stream. Sources that do
        not exist (for example because section headers were stripped) simply
        do not appear. A string offset points at the first byte of the string
        inside the dynamic string table, not at the table itself.
    """
    dynsym: int           # Elf_Sym entry of the imported symbol
    dynstr: int           # symbol name string in the dynamic string table
    versym: int           # Elf_Versym entry holding the version index
    verneed: int          # Elf_Verneed entry naming the needed library
    vernaux: int          # Elf_Vernaux entry naming the required version
    vernaux_name: int     # version name string in the dynamic string table
    verneed_file: int     # library name string in the dynamic string table


class VersionedImport(TypedDict, total=False):
    """ One imported dynamic symbol and the version it requires.

        ``reasons`` is always present (possibly empty) and explains every
        piece of information that could not be resolved and why.
    """
    symbol_index: int                  # index in the dynamic symbol table
    name: str                          # symbol name from dynstr
    binding: str | int                 # STB_* symbol binding
    version_index: int | str | None    # index after removing the hidden bit,
                                       # or VER_NDX_LOCAL/VER_NDX_GLOBAL
    version_name: str | None           # version required from the dependency
    library: str | None                # library file name supplying it
    hidden: bool                       # GNU version-hidden (0x8000) bit
    offsets: ImportOffsets             # file offsets of each source record
    reasons: list[str]                 # unresolved / degraded information


@dataclass
class _TableSource:
    """ Where the dynsym/VERSYM/VERNEED tables live.

        ``mode`` is 'sections' when section headers drive the walk and
        'dynamic' when the tables were recovered from PT_DYNAMIC only.
    """
    mode: str
    dynsym: Any
    dynsym_count: int
    dynstr: Any
    dynstr_offset: int | None
    versym_offset: int | None
    versym_entsize: int
    verneed_offset: int | None
    verneed_count: int
    notes: list[str] = field(default_factory=list)


@dataclass
class _Requirement:
    """ One VERNEED auxiliary entry (a named version of a needed library). """
    index: int
    name: str | None
    library: str | None
    verneed_offset: int
    vernaux_offset: int
    vernaux_name_offset: int | None
    verneed_file_offset: int | None
    error: str | None = None


class VersionedImports:
    """ Build an inventory of versioned external symbols for an ELF file.

        Section headers are preferred. When the file has none, the dynamic
        symbol table, VERSYM and VERNEED are recovered from the PT_DYNAMIC
        segment and its DT_* tags. Information that cannot be recovered is
        reported per record in ``reasons`` and globally in :attr:`notes`; it
        is never reconstructed from version definitions or host libraries.
    """

    def __init__(self, elffile: ELFFile) -> None:
        self.elffile = elffile
        self.stream = elffile.stream
        self.structs = elffile.structs
        self._source = self._locate_tables()
        # Parse VERNEED eagerly so that chain/duplicate diagnostics land in
        # notes even when a caller reads notes before iterating imports.
        self._requirements = self._parse_verneed()

    # -- public API ---------------------------------------------------------

    @property
    def mode(self) -> str:
        """ 'sections' when section headers were used, else 'dynamic'. """
        return self._source.mode

    @property
    def notes(self) -> list[str]:
        """ Whole-file caveats, e.g. a missing DT_VERSYM or DT_VERNEED. """
        return list(self._source.notes)

    def iter_imports(self) -> Iterator[VersionedImport]:
        """ Yield one :class:`VersionedImport` per imported dynamic symbol.

            Imported symbols are dynsym entries with section index SHN_UNDEF
            (undefined here and satisfied at run time by a dependency).
            Symbols defined in this file are skipped even when versioned.
        """
        source = self._source
        for symbol_index in range(source.dynsym_count):
            symbol = source.dynsym.get_symbol(symbol_index)
            if not self._is_undefined(symbol):
                continue
            yield self._build_record(symbol_index, symbol)

    def get_imports(self) -> list[VersionedImport]:
        """ Return :meth:`iter_imports` results as a list. """
        return list(self.iter_imports())

    def get_version_requirements(self) -> dict[int, dict[str, Any]]:
        """ Map every VERNEED version index found in the file to its data.

            Values carry the version name, supplying library, file offsets of
            the backing Verneed/Vernaux records and any parse error. This is
            the raw requirement table, independent of which symbols use it.
            Indices >= 0 only; global parse problems live in :attr:`notes`.
        """
        return {
            req.index: {
                'name': req.name,
                'library': req.library,
                'verneed': req.verneed_offset,
                'vernaux': req.vernaux_offset,
                'vernaux_name': req.vernaux_name_offset,
                'verneed_file': req.verneed_file_offset,
                'error': req.error,
            }
            for req in self._requirements.values()
        }

    # -- table location -----------------------------------------------------

    def _locate_tables(self) -> _TableSource:
        if self.elffile.num_sections() > 0:
            source = self._locate_from_sections()
            if source is not None:
                return source
        return self._locate_from_dynamic()

    def _locate_from_sections(self) -> _TableSource | None:
        versym = next(
            (section for section in self.elffile.iter_sections()
             if isinstance(section, GNUVerSymSection)),
            None)
        if versym is None:
            # Without a VERSYM section the dynamic-segment path can still list
            # undefined symbols while explicitly reporting the missing table.
            return None

        # sh_link of the VERSYM section identifies its dynamic symbol table,
        # so this stays correct even if another symbol table is present.
        dynsym = versym.symboltable
        dynstr = dynsym.stringtable
        source = _TableSource(
            mode='sections',
            dynsym=dynsym,
            dynsym_count=dynsym.num_symbols(),
            dynstr=dynstr,
            dynstr_offset=dynstr['sh_offset'],
            versym_offset=versym['sh_offset'],
            versym_entsize=(versym['sh_entsize']
                            or self.structs.Elf_Versym.sizeof()),
            verneed_offset=None,
            verneed_count=0,
        )
        verneed = next(
            (section for section in self.elffile.iter_sections()
             if isinstance(section, GNUVerNeedSection)
             and section['sh_link'] == dynsym['sh_link']),
            None)
        if verneed is None:
            source.notes.append(
                'no SHT_GNU_verneed section linked to the dynamic string '
                'table: required version names and libraries cannot be '
                'resolved')
        else:
            source.verneed_offset = verneed['sh_offset']
            source.verneed_count = verneed.num_versions()
        return source

    def _locate_from_dynamic(self) -> _TableSource:
        dynamic = next(
            (segment for segment in self.elffile.iter_segments()
             if isinstance(segment, DynamicSegment)),
            None)
        if dynamic is None:
            # A relocatable object or other non-dynamic file has no imports
            # to inventory. Report an empty source rather than failing, so
            # callers can treat "no dynamic table" like "no imports".
            return _TableSource(
                mode='dynamic',
                dynsym=None,
                dynsym_count=0,
                dynstr=None,
                dynstr_offset=None,
                versym_offset=None,
                versym_entsize=self.structs.Elf_Versym.sizeof(),
                verneed_offset=None,
                verneed_count=0,
                notes=['no PT_DYNAMIC segment: the file has no dynamic '
                       'symbol table and therefore no versioned imports'])

        notes: list[str] = []
        if self.elffile.num_sections() == 0:
            notes.append(
                'section header table absent (e_shnum=0): tables recovered '
                'from PT_DYNAMIC tags; section-level metadata is unavailable')

        _, symtab_offset = dynamic.get_table_offset('DT_SYMTAB')
        if symtab_offset is None:
            raise ELFError('PT_DYNAMIC has no DT_SYMTAB')
        try:
            symbol_count = dynamic.num_symbols()
        except ELFError as exc:
            raise ELFError(f'cannot size DT_SYMTAB: {exc}') from exc

        versym_ptr, versym_offset = dynamic.get_table_offset('DT_VERSYM')
        if versym_ptr is None:
            notes.append(
                'DT_VERSYM absent: symbol version indices are unavailable')
        elif versym_offset is None:
            notes.append(
                f'DT_VERSYM points at unmappable address {versym_ptr:#x}: '
                'symbol version indices are unavailable')

        verneed_ptr, verneed_offset = dynamic.get_table_offset('DT_VERNEED')
        verneed_count = 0
        if verneed_ptr is None:
            notes.append(
                'DT_VERNEED absent: required version names and libraries '
                'are unavailable')
        elif verneed_offset is None:
            notes.append(
                f'DT_VERNEED points at unmappable address {verneed_ptr:#x}: '
                'required version names and libraries are unavailable')
        else:
            count_tag = next(dynamic.iter_tags('DT_VERNEEDNUM'), None)
            if count_tag is None:
                notes.append(
                    'DT_VERNEEDNUM absent: VERNEED entry count unknown, '
                    'walking until the first unparseable entry')
            else:
                verneed_count = count_tag['d_val']

        dynstr = dynamic._get_stringtable()
        return _TableSource(
            mode='dynamic',
            dynsym=dynamic,
            dynsym_count=symbol_count,
            dynstr=dynstr,
            dynstr_offset=getattr(dynstr, '_table_offset', None),
            versym_offset=versym_offset,
            versym_entsize=self.structs.Elf_Versym.sizeof(),
            verneed_offset=verneed_offset,
            verneed_count=verneed_count,
            notes=notes,
        )

    # -- per-symbol processing ---------------------------------------------

    def _build_record(self, symbol_index: int, symbol: Any) -> VersionedImport:
        source = self._source
        reasons: list[str] = []
        offsets = ImportOffsets()

        dynsym_offset = self._dynsym_entry_offset(symbol_index)
        if dynsym_offset is not None:
            offsets['dynsym'] = dynsym_offset
            if symbol['st_name'] and source.dynstr_offset is not None:
                offsets['dynstr'] = (
                    source.dynstr_offset + symbol['st_name'])

        version_index, hidden = self._read_versym(
            symbol_index, offsets, reasons)

        record = VersionedImport(
            symbol_index=symbol_index,
            name=symbol.name,
            binding=self._symbol_binding(symbol),
            version_index=version_index,
            version_name=None,
            library=None,
            hidden=hidden,
            offsets=offsets,
            reasons=reasons,
        )

        if isinstance(version_index, int):
            if version_index >= VER_NDX_LORESERVE:
                # The reason was recorded while reading the VERSYM entry.
                pass
            else:
                self._resolve_named_version(record, version_index)
        elif version_index is None:
            record['reasons'].append(
                'unversioned import: the symbol requires no specific version')
        else:
            record['reasons'].append(
                f'{version_index} is a special/reserved index, not a named '
                'version')
        return record

    def _read_versym(
        self,
        symbol_index: int,
        offsets: ImportOffsets,
        reasons: list[str],
    ) -> tuple[int | str | None, bool]:
        source = self._source
        if source.versym_offset is None:
            reasons.append('no VERSYM table: version index not recorded')
            return None, False

        entry_offset = (
            source.versym_offset + symbol_index * source.versym_entsize)
        if not self._in_file(entry_offset, source.versym_entsize):
            reasons.append(
                f'VERSYM entry for symbol {symbol_index} is outside the '
                'file: version index unreadable')
            return None, False

        offsets['versym'] = entry_offset
        raw = struct_parse(
            self.structs.Elf_Versym, self.stream,
            stream_pos=entry_offset)['ndx']
        # The struct enum names the special indices (VER_NDX_*); every other
        # value is handed back as the raw integer (Enum _default_=Pass).
        if isinstance(raw, str):
            # Named special/reserved indices carry no hidden bit and never
            # name an importable version.
            return raw, False
        # The hidden flag lives in bit 15. Recognise the reserved index range
        # on the full 16-bit value first, so the hidden bit never drags a
        # reserved index (0xff00..0xffff) down into the normal range.
        hidden = bool(raw & VERSYM_HIDDEN_BIT)
        if raw == VER_NDX_LOCAL:
            return 'VER_NDX_LOCAL', hidden
        if raw == VER_NDX_GLOBAL:
            return 'VER_NDX_GLOBAL', hidden
        if raw >= VER_NDX_LORESERVE:
            reasons.append(
                f'reserved VERSYM index {raw:#06x} (VER_NDX_LORESERVE '
                'range): not a named version')
            return raw, hidden
        return raw & VERSYM_INDEX_MASK, hidden

    def _resolve_named_version(
        self,
        record: VersionedImport,
        version_index: int,
    ) -> None:
        requirement = self._requirements.get(version_index)
        if requirement is None:
            record['reasons'].append(
                f'no VERNEED auxiliary records version index {version_index}: '
                'the required version name and library cannot be resolved')
            return

        if requirement.name is not None:
            record['version_name'] = requirement.name
        else:
            record['reasons'].append(
                'version name string could not be read from dynstr')
        if requirement.library is not None:
            record['library'] = requirement.library
        else:
            record['reasons'].append(
                'needed library name could not be read from dynstr')
        if requirement.error:
            record['reasons'].append(requirement.error)

        offsets = record['offsets']
        offsets['verneed'] = requirement.verneed_offset
        offsets['vernaux'] = requirement.vernaux_offset
        if requirement.vernaux_name_offset is not None:
            offsets['vernaux_name'] = requirement.vernaux_name_offset
        if requirement.verneed_file_offset is not None:
            offsets['verneed_file'] = requirement.verneed_file_offset

    # -- VERNEED walking ----------------------------------------------------

    def _parse_verneed(self) -> dict[int, _Requirement]:
        """ Parse every VERNEED entry, surviving broken auxiliary chains.

            Returns a map of vna_other index -> _Requirement. The first
            occurrence of a duplicated index wins, matching the linker's
            table layout; later duplicates are reported in :attr:`notes`.
        """
        requirements: dict[int, _Requirement] = {}
        source = self._source
        if source.verneed_offset is None:
            return requirements

        dynstr_base = source.dynstr_offset
        cursor = source.verneed_offset
        # With no DT_VERNEEDNUM the count is unknown; bound the walk by file
        # size so a broken vn_next chain cannot loop or run off the end.
        remaining = source.verneed_count if source.verneed_count > 0 else None
        entry_number = 0
        while remaining is None or entry_number < remaining:
            if not self._in_file(cursor, self.structs.Elf_Verneed.sizeof()):
                if remaining is not None:
                    source.notes.append(
                        f'Verneed entry {entry_number} at {cursor:#x} is '
                        'outside the file; remaining entries not parsed')
                break

            verneed_offset = cursor
            try:
                verneed = struct_parse(
                    self.structs.Elf_Verneed, self.stream,
                    stream_pos=cursor)
            except ELFError as exc:
                source.notes.append(
                    f'Verneed entry {entry_number} at {cursor:#x} is '
                    f'malformed: {exc}; remaining entries not parsed')
                break

            if verneed['vn_version'] != 1:
                source.notes.append(
                    f'Verneed entry {entry_number} at {cursor:#x} has '
                    f"unsupported vn_version={verneed['vn_version']}; "
                    'skipped')
                cursor = self._next_verneed(cursor, verneed['vn_next'])
                entry_number += 1
                continue

            library, library_name_offset = self._read_dynstr(
                verneed['vn_file'], dynstr_base)
            aux_cursor = cursor + verneed['vn_aux']
            self._walk_vernaux(
                requirements, verneed_offset, aux_cursor,
                verneed['vn_cnt'], library, library_name_offset, dynstr_base)

            cursor = self._next_verneed(cursor, verneed['vn_next'])
            entry_number += 1

        return requirements

    def _walk_vernaux(
        self,
        requirements: dict[int, _Requirement],
        verneed_offset: int,
        aux_cursor: int,
        aux_count: int,
        library: str | None,
        library_name_offset: int | None,
        dynstr_base: int | None,
    ) -> None:
        for aux_number in range(max(aux_count, 0)):
            if not self._in_file(aux_cursor,
                                 self.structs.Elf_Vernaux.sizeof()):
                self._source.notes.append(
                    f'Vernaux entry {aux_number} of Verneed at '
                    f'{verneed_offset:#x} is outside the file at '
                    f'{aux_cursor:#x}; auxiliary chain truncated')
                return
            vernaux_offset = aux_cursor
            try:
                vernaux = struct_parse(
                    self.structs.Elf_Vernaux, self.stream,
                    stream_pos=aux_cursor)
            except ELFError as exc:
                self._source.notes.append(
                    f'Vernaux entry {aux_number} at {aux_cursor:#x} is '
                    f'malformed: {exc}; auxiliary chain truncated')
                return

            name, name_offset = self._read_dynstr(
                vernaux['vna_name'], dynstr_base)
            index = vernaux['vna_other']
            error = None
            if name is None:
                error = 'version name string is missing or outside dynstr'
            requirement = _Requirement(
                index=index,
                name=name,
                library=library,
                verneed_offset=verneed_offset,
                vernaux_offset=vernaux_offset,
                vernaux_name_offset=name_offset,
                verneed_file_offset=library_name_offset,
                error=error,
            )
            if index in requirements:
                self._source.notes.append(
                    f'duplicate vna_other index {index} at '
                    f'{vernaux_offset:#x}: first VERNEED definition wins')
            else:
                requirements[index] = requirement

            vna_next = vernaux['vna_next']
            if vna_next == 0:
                if aux_number + 1 < aux_count:
                    self._source.notes.append(
                        f'Vernaux chain of Verneed at {verneed_offset:#x} '
                        f'terminates after {aux_number + 1} of {aux_count} '
                        'declared entries')
                return
            next_cursor = aux_cursor + vna_next
            if (next_cursor <= aux_cursor
                    or not self._in_file(next_cursor,
                                         self.structs.Elf_Vernaux.sizeof())):
                self._source.notes.append(
                    f'Vernaux vna_next chain from {aux_cursor:#x} leaves '
                    'the file or does not advance; chain truncated')
                return
            aux_cursor = next_cursor

    def _next_verneed(self, cursor: int, vn_next: int) -> int:
        # Returning stream_len ends the outer walk cleanly.
        if vn_next == 0:
            return self.elffile.stream_len
        next_cursor = cursor + vn_next
        if next_cursor <= cursor or next_cursor >= self.elffile.stream_len:
            return self.elffile.stream_len
        return next_cursor

    # -- helpers ------------------------------------------------------------

    def _read_dynstr(
        self,
        strtab_offset: int,
        dynstr_base: int | None,
    ) -> tuple[str | None, int | None]:
        if dynstr_base is None:
            return None, None
        absolute = dynstr_base + strtab_offset
        if not self._in_file(absolute, 1):
            return None, absolute
        try:
            value = self._source.dynstr.get_string(strtab_offset)
        except ELFError:
            return None, absolute
        if not value:
            return None, absolute
        return value, absolute

    def _dynsym_entry_offset(self, symbol_index: int) -> int | None:
        source = self._source
        if source.mode == 'sections':
            section = source.dynsym
            entsize = section['sh_entsize'] or self.structs.Elf_Sym.sizeof()
            return section['sh_offset'] + symbol_index * entsize
        _, table_offset = source.dynsym.get_table_offset('DT_SYMTAB')
        if table_offset is None:
            return None
        return table_offset + symbol_index * self.structs.Elf_Sym.sizeof()

    def _in_file(self, offset: int, size: int) -> bool:
        return (0 <= offset and size >= 0
                and offset + size <= self.elffile.stream_len)

    @staticmethod
    def _is_undefined(symbol: Any) -> bool:
        shndx = symbol['st_shndx']
        return shndx == 'SHN_UNDEF' or shndx == 0

    @staticmethod
    def _symbol_binding(symbol: Any) -> str | int:
        info = symbol['st_info']
        binding = info.get('bind') if hasattr(info, 'get') else None
        return binding if binding is not None else info


def iter_versioned_imports(elffile: ELFFile) -> Iterator[VersionedImport]:
    """ Convenience wrapper around :class:`VersionedImports`. """
    yield from VersionedImports(elffile).iter_imports()
