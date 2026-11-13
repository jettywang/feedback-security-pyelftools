#-------------------------------------------------------------------------------
# elftools: elf/relocation.py
#
# ELF relocations
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from functools import cached_property
from typing import IO, TYPE_CHECKING, Any, NamedTuple, Protocol

from ..common.construct_utils import ULEB128
from ..common.exceptions import ELFParseError, ELFRelocationError
from ..common.utils import elf_assert, struct_parse
from ..construct import Container
from .enums import (
    ENUM_RELOC_TYPE_AARCH64,
    ENUM_RELOC_TYPE_ARM,
    ENUM_RELOC_TYPE_BPF,
    ENUM_RELOC_TYPE_LOONGARCH,
    ENUM_RELOC_TYPE_MIPS,
    ENUM_RELOC_TYPE_PPC64,
    ENUM_RELOC_TYPE_RISCV,
    ENUM_RELOC_TYPE_S390X,
    ENUM_RELOC_TYPE_i386,
    ENUM_RELOC_TYPE_x64,
)
from .sections import Section, SymbolTableSection

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from .elffile import ELFFile
    from .segments import Segment


class Relocation:
    """ Relocation object - representing a single relocation entry. Allows
        dictionary-like access to the entry's fields.

        Can be either a REL or RELA relocation.
    """
    def __init__(self, entry: Container, elffile: ELFFile) -> None:
        self.entry = entry
        self.elffile = elffile

    def is_RELA(self) -> bool:
        """ Is this a RELA relocation? If not, it's REL.
        """
        return 'r_addend' in self.entry

    def __getitem__(self, name: str) -> Any:
        """ Dict-like access to entries
        """
        return self.entry[name]

    def __repr__(self) -> str:
        return '<Relocation ({}): {}>'.format(
                'RELA' if self.is_RELA() else 'REL',
                self.entry)

    def __str__(self) -> str:
        return self.__repr__()


class RelocationTable:
    """ Shared functionality between relocation sections and relocation tables
    """

    def __init__(
        self,
        elffile: ELFFile,
        offset: int,
        size: int,
        is_rela: bool,
    ) -> None:
        self._stream = elffile.stream
        self._elffile = elffile
        self._elfstructs = elffile.structs
        self._size = size
        self._offset = offset
        self._is_rela = is_rela

        if is_rela:
            self.entry_struct = self._elfstructs.Elf_Rela
        else:
            self.entry_struct = self._elfstructs.Elf_Rel

        self.entry_size = self.entry_struct.sizeof()

    def is_RELA(self) -> bool:
        """ Is this a RELA relocation section? If not, it's REL.
        """
        return self._is_rela

    def num_relocations(self) -> int:
        """ Number of relocations in the section
        """
        return self._size // self.entry_size

    def get_relocation(self, n: int) -> Relocation:
        """ Get the relocation at index #n from the section (Relocation object)
        """
        entry_offset = self._offset + n * self.entry_size
        entry = struct_parse(
            self.entry_struct,
            self._stream,
            stream_pos=entry_offset)
        return Relocation(entry, self._elffile)

    def iter_relocations(self) -> Iterator[Relocation]:
        """ Yield all the relocations in the section
        """
        for i in range(self.num_relocations()):
            yield self.get_relocation(i)


class RelocationSection(Section, RelocationTable):
    """ ELF relocation section. Serves as a collection of Relocation entries.
    """
    def __init__(self, header: Container, name: str, elffile: ELFFile) -> None:
        Section.__init__(self, header, name, elffile)
        RelocationTable.__init__(self, self.elffile,
            self['sh_offset'], self['sh_size'], header['sh_type'] == 'SHT_RELA')

        elf_assert(header['sh_type'] in ('SHT_REL', 'SHT_RELA'),
            'Unknown relocation type section')
        elf_assert(header['sh_entsize'] == self.entry_size,
            'Expected sh_entsize of {} section to be {}'.format(
                header['sh_type'], self.entry_size))


class RelrEntry(NamedTuple):
    """ A single word from a RELR table, retained as provenance for the
        relocations it expands to.
    """
    index: int
    offset: int
    value: int
    is_bitmap: bool
    # Bit number in the bitmap whose set bit produced this relocation. Bit 0
    # is the tag bit and is never used for a target; anchors use None.
    bitmap_bit: int | None


class RelrExpandedRelocation(NamedTuple):
    """ One relocation produced by expanding a RELR table.

        target_address is the virtual address whose pointer is relocated. It
        is not a file offset. file_offset is the corresponding offset in the
        file when target_address has exactly one file-backed mapping.

        addend is the pointer-sized word stored at the target address (RELR,
        like REL, keeps its addend in place). It is None when the word cannot
        be read unambiguously; status explains why. mapped_offsets lists the
        distinct file offsets of the PT_LOAD mappings that fully contain the
        target word. An addend is reported only when those mappings agree.
    """
    target_address: int
    addend: int | None
    status: str
    file_offset: int | None
    source: RelrEntry
    mapped_offsets: tuple[int, ...]

    # Exactly one PT_LOAD provides a readable file-backed word.
    STATUS_FILE = 'file'
    # The target lies in the zero-filled part of a PT_LOAD (p_memsz > p_filesz).
    STATUS_ZERO_FILL = 'zero_fill'
    # Part of the pointer-sized target is in a PT_LOAD's file-backed range and
    # part is beyond it, so no complete word can be read.
    STATUS_PARTIAL_MAPPING = 'partial_mapping'
    # More than one PT_LOAD maps the target. file_offset and addend are set
    # only when every mapping selects the same readable file-backed word.
    STATUS_MULTIPLE_MAPPINGS = 'multiple_mappings'
    # No PT_LOAD maps the complete target word.
    STATUS_UNMAPPED = 'unmapped'
    # A mapping exists, but the word extends past the end of the file.
    STATUS_OUTSIDE_FILE = 'outside_file'

    @property
    def r_offset(self) -> int:
        """ The target virtual address, matching Relocation's field name.
        """
        return self.target_address

    @property
    def target(self) -> int:
        """ Alias for target_address.
        """
        return self.target_address

    @property
    def original_addend(self) -> int | None:
        """ The addend as stored at the target address, before relocation.
        """
        return self.addend

    @property
    def relr_entry(self) -> int:
        """ The original RELR word that produced this relocation.
        """
        return self.source.value

    @property
    def relr_entry_offset(self) -> int:
        """ File offset of the original RELR word.
        """
        return self.source.offset

    @property
    def relr_entry_index(self) -> int:
        """ Index of the original RELR word in the table.
        """
        return self.source.index


class RelrRelocationTable:
    """ RELR compressed relocation table. This stores relative relocations
        in a compressed format. An entry with an even value serves as an
        'anchor' that defines a base address. Following this entry are one or
        more bitmaps for consecutive addresses after the anchor which determine
        if the corresponding relocation exists (if the bit is 1) or if it is
        skipped. Addends are stored at the respective addresses (as in REL
        relocations).
    """

    def __init__(self, elffile: ELFFile, offset: int | None, size: int,
                 entrysize: int) -> None:
        self._elffile = elffile
        self._offset = offset
        self._size = size
        self._relr_struct = self._elffile.structs.Elf_Relr
        self._entrysize = self._relr_struct.sizeof()
        self._address_size = self._elffile.structs.Elf_addr('').sizeof()

        elf_assert(self._entrysize == entrysize,
            f'Expected RELR entry size to be {self._entrysize}, got {entrysize}')

    def _iter_relr_entries(self) -> Iterator[tuple[RelrEntry, int]]:
        """ Decode the table into (provenance entry, target address) pairs.

            An anchor yields only its own relocation. Each set bit in a bitmap
            yields one relocation whose target is computed from the preceding
            anchor, using this table's word size.
        """
        # DT_RELRSZ may be zero, and a dynamic table whose address has no
        # PT_LOAD file mapping has no offset. Either way there is nothing to
        # decode.
        offset = self._offset
        if offset is None or self._size <= 0:
            return

        # Bit 0 of a bitmap entry is the tag that distinguishes it from an
        # anchor, so each bitmap describes (word_bits - 1) addresses.
        bitmap_capacity = 8 * self._entrysize - 1
        limit = offset + self._size
        base: int | None = None
        index = 0
        relr = offset
        while relr + self._entrysize <= limit:
            entry = struct_parse(self._relr_struct,
                                 self._elffile.stream,
                                 stream_pos=relr)
            value: int = entry['r_offset']
            if (value & 1) == 0:
                # An anchor supplies the address of its own relocation and
                # the base for the bitmaps that follow.
                source = RelrEntry(index, relr, value, False, None)
                yield source, value
                base = value + self._address_size
            else:
                elf_assert(base is not None, 'RELR bitmap without base address')
                assert base is not None
                # Skip the tag bit; bit i then selects base + i * address
                # size for i in 0..bitmap_capacity-1. Empty bitmaps only
                # advance the base.
                for bit in range(1, bitmap_capacity + 1):
                    if value & (1 << bit):
                        source = RelrEntry(index, relr, value, True, bit)
                        yield source, base + (bit - 1) * self._address_size
                base += bitmap_capacity * self._address_size
            relr += self._entrysize
            index += 1

    def _load_segments(self) -> list[Segment]:
        return list(self._elffile.iter_segments(type='PT_LOAD'))

    @staticmethod
    def _file_length(elffile: ELFFile) -> int:
        stream = elffile.stream
        pos = stream.tell()
        stream.seek(0, 2)
        length = stream.tell()
        stream.seek(pos)
        return length

    def _read_addend(self, file_offset: int, file_length: int) -> int | None:
        if file_offset < 0 or file_offset + self._address_size > file_length:
            return None
        stream = self._elffile.stream
        try:
            stream.seek(file_offset)
        except (OverflowError, ValueError):
            return None
        if len(stream.read(self._address_size)) != self._address_size:
            return None
        try:
            return struct_parse(
                self._elffile.structs.Elf_addr(''),
                stream,
                stream_pos=file_offset)
        except ELFParseError:
            # The range was checked above; treat any remaining parse failure
            # (for example, a malformed stream) as an unreadable addend rather
            # than aborting expansion of the rest of the table.
            return None

    def _classify_target(
        self,
        target_address: int,
        loads: list[Segment],
        file_length: int,
    ) -> tuple[str, int | None, int | None, tuple[int, ...]]:
        """ Map a target virtual address to file bytes and read its addend.

            Only PT_LOAD file ranges are used; the virtual address is never
            treated as a file offset.
        """
        end_address = target_address + self._address_size
        containing = [
            segment for segment in loads
            if (target_address >= segment['p_vaddr'] and
                end_address <= segment['p_vaddr'] + segment['p_memsz'])
        ]
        if not containing:
            return (RelrExpandedRelocation.STATUS_UNMAPPED, None, None, ())

        file_offsets = []
        for segment in containing:
            file_end = segment['p_vaddr'] + segment['p_filesz']
            if end_address <= file_end:
                file_offsets.append(
                    target_address - segment['p_vaddr'] + segment['p_offset'])
        mapped_offsets = tuple(sorted(set(file_offsets)))

        if len(containing) > 1:
            # Multiple mappings describe the same virtual word. If any of
            # them is zero-filled, or they select different file bytes, there
            # is no single original addend to report. Only agreement between
            # all mappings makes the word meaningful.
            unambiguous = (
                len(file_offsets) == len(containing) and
                len(mapped_offsets) == 1)
            file_offset = mapped_offsets[0] if unambiguous else None
            addend = (self._read_addend(file_offset, file_length)
                      if file_offset is not None else None)
            if addend is None and unambiguous:
                return (RelrExpandedRelocation.STATUS_OUTSIDE_FILE,
                        file_offset, None, mapped_offsets)
            return (RelrExpandedRelocation.STATUS_MULTIPLE_MAPPINGS,
                    file_offset, addend, mapped_offsets)

        if not file_offsets:
            # The target begins in file-backed bytes but the word crosses into
            # the zero-filled tail. The addend is not fully present in the
            # file even though the address is mapped.
            segment = containing[0]
            if target_address < segment['p_vaddr'] + segment['p_filesz']:
                return (RelrExpandedRelocation.STATUS_PARTIAL_MAPPING,
                        target_address - segment['p_vaddr'] + segment['p_offset'],
                        None, ())
            return (RelrExpandedRelocation.STATUS_ZERO_FILL, None, None, ())

        file_offset = file_offsets[0]
        addend = self._read_addend(file_offset, file_length)
        if addend is None:
            return (RelrExpandedRelocation.STATUS_OUTSIDE_FILE,
                    file_offset, None, mapped_offsets)
        return (RelrExpandedRelocation.STATUS_FILE,
                file_offset, addend, mapped_offsets)

    def iter_expanded_relocations(self) -> Iterator[RelrExpandedRelocation]:
        """ Yield every relocation encoded by this table with provenance.

            Each result identifies the original RELR word, the target virtual
            address and, when readable, the in-place addend. Targets that are
            not backed by a single file-mapped PT_LOAD range are reported
            rather than guessed.
        """
        loads = self._load_segments()
        file_length = self._file_length(self._elffile)
        for source, target in self._iter_relr_entries():
            status, file_offset, addend, mapped_offsets = self._classify_target(
                target, loads, file_length)
            yield RelrExpandedRelocation(
                target_address=target,
                addend=addend,
                status=status,
                file_offset=file_offset,
                source=source,
                mapped_offsets=mapped_offsets)

    def iter_relocations(self) -> Iterator[Relocation]:
        """ Yield all the relocations in the section

            This is the legacy Relocation interface. Use
            iter_expanded_relocations() for the originating RELR entry and
            target mapping details.
        """
        for _source, target in self._iter_relr_entries():
            yield Relocation(Container(r_offset=target), self._elffile)

    def num_expanded_relocations(self) -> int:
        """ Number of relocations after expanding the compressed table
        """
        return len(self._cached_expanded_relocations)

    def get_expanded_relocation(self, n: int) -> RelrExpandedRelocation:
        """ Get the expanded relocation at index #n
        """
        return self._cached_expanded_relocations[n]

    @cached_property
    def _cached_expanded_relocations(self) -> list[RelrExpandedRelocation]:
        return list(self.iter_expanded_relocations())

    def num_relocations(self) -> int:
        """ Number of relocations in the section
        """
        return len(self._cached_relocations)

    def get_relocation(self, n: int) -> Relocation:
        """ Get the relocation at index #n from the section (Relocation object)
        """
        return self._cached_relocations[n]

    @cached_property
    def _cached_relocations(self) -> list[Relocation]:
        return list(self.iter_relocations())


class RelrRelocationSection(Section, RelrRelocationTable):
    """ ELF RELR relocation section. Serves as a collection of RELR relocation entries.
    """
    def __init__(self, header: Container, name: str, elffile: ELFFile) -> None:
        Section.__init__(self, header, name, elffile)
        RelrRelocationTable.__init__(self, self.elffile,
            self['sh_offset'], self['sh_size'], self['sh_entsize'])


# Recipe bytesize of a relocation that patches a ULEB128 encoded value
_ULEB128_BYTESIZE = 0


class _RelocationFunction(Protocol):
    def __call__(self, value: int, sym_value: int, offset: int, addend: int = 0) -> int: ...


def _reloc_calc_identity(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return value


def _reloc_calc_sym_plus_value(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return sym_value + value + addend


def _reloc_calc_sym_plus_value_pcrel(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return sym_value + value - offset


def _reloc_calc_sym_plus_addend(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return sym_value + addend


def _reloc_calc_sym_plus_addend_pcrel(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return sym_value + addend - offset


def _reloc_calc_value_minus_sym_addend(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return value - sym_value - addend


def _arm_reloc_calc_sym_plus_value_pcrel(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return sym_value // 4 + value - offset // 4


def _bpf_64_32_reloc_calc_sym_plus_addend(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return (sym_value + addend) // 8 - 1


def _riscv_reloc_calc_set6(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return (value & 0xc0) | ((sym_value + addend) & 0x3f)


def _riscv_reloc_calc_sub6(value: int, sym_value: int, offset: int, addend: int = 0) -> int:
    return (value & 0xc0) | ((value - sym_value - addend) & 0x3f)


class RelocationHandler:
    """ Applies a supported subset of ELF relocations to section data,
        primarily for reading DWARF sections.

        Symbol values come directly from the linked symbol table's st_value
        fields. This handler does not perform runtime symbol resolution,
        account for load addresses, or implement general dynamic linking.
    """
    def __init__(self, elffile: ELFFile) -> None:
        self.elffile = elffile

    def find_relocations_for_section(self, section: Section) -> RelocationSection | None:
        """ Given a section, find the relocation section for it in the ELF
            file. Return a RelocationSection object, or None if none was
            found.
        """
        # sh_info identifies the target section; names need not be unique.
        # A zero index means no target section (e.g. for dynamic relocations).
        for relsection in self.elffile.iter_sections():
            if (isinstance(relsection, RelocationSection) and
                    relsection['sh_info'] != 0 and
                    self.elffile.get_section(relsection['sh_info']) == section):
                return relsection
        return None

    def apply_section_relocations(
        self,
        stream: IO[bytes],
        reloc_section: RelocationSection,
    ) -> None:
        """ Apply reloc_section's relocations in place to a stream containing
            the target section's data, starting at stream offset 0. The stream
            must support reading, writing, and seeking.

            Each r_offset is used directly as a position within this stream,
            matching section-relative offsets in relocatable (ET_REL) files.
            The target section's offset within the ELF file is not added.
            Virtual addresses in executable/shared-object dynamic relocations
            are not translated to stream offsets by this API.
        """
        # The symbol table associated with this relocation section
        symtab = self.elffile.get_section(reloc_section['sh_link'])
        assert isinstance(symtab, SymbolTableSection)
        for reloc in reloc_section.iter_relocations():
            self._do_apply_relocation(stream, reloc, symtab)

    def _do_apply_relocation(
        self,
        stream: IO[bytes],
        reloc: Relocation,
        symtab: SymbolTableSection,
    ) -> None:
        arch = self.elffile.get_machine_arch()
        reloc_type = reloc['r_info_type']

        # NONE has no target field and needs no symbol lookup. MIPS64 packs
        # up to three operations into one entry; r_info_type is only the first.
        # If a later operation is non-NONE, let the unsupported combination
        # raise an error below instead of silently skipping the entire entry.
        is_mips_composed = arch == 'MIPS' and (
            reloc.entry.get('r_type2', 0) != 0 or reloc.entry.get('r_type3', 0) != 0)
        if reloc_type in self._RELOCATION_NONE_TYPES.get(arch, ()) and not is_mips_composed:
            return

        # Preparations for performing the relocation: obtain the value of
        # the symbol mentioned in the relocation, as well as the relocation
        # recipe which tells us how to actually perform it.
        # All peppered with some sanity checking.
        if reloc['r_info_sym'] >= symtab.num_symbols():
            raise ELFRelocationError(
                'Invalid symbol reference in relocation: index {}'.format(reloc['r_info_sym']))
        sym_value = symtab.get_symbol(reloc['r_info_sym'])['st_value']

        recipe = None

        if arch == 'x86':
            if reloc.is_RELA():
                raise ELFRelocationError(
                    f'Unexpected RELA relocation for x86: {reloc}')
            recipe = self._RELOCATION_RECIPES_X86.get(reloc_type, None)
        elif arch == 'x64':
            if not reloc.is_RELA():
                raise ELFRelocationError(
                    f'Unexpected REL relocation for x64: {reloc}')
            recipe = self._RELOCATION_RECIPES_X64.get(reloc_type, None)
        elif arch == 'MIPS':
            if reloc.is_RELA():
                if (
                    reloc_type == ENUM_RELOC_TYPE_MIPS['R_MIPS_64']
                    and (
                        reloc['r_type2'] != 0
                        or reloc['r_type3'] != 0
                        or reloc['r_ssym'] != 0
                    )
                ):
                    raise ELFRelocationError(
                        f'Multiple relocations in R_MIPS_64 are not implemented: {reloc}')
                recipe = self._RELOCATION_RECIPES_MIPS_RELA.get(reloc_type, None)
            else:
                recipe = self._RELOCATION_RECIPES_MIPS_REL.get(reloc_type, None)
        elif arch == 'ARM':
            if reloc.is_RELA():
                raise ELFRelocationError(
                    f'Unexpected RELA relocation for ARM: {reloc}')
            recipe = self._RELOCATION_RECIPES_ARM.get(reloc_type, None)
        elif arch == 'AArch64':
            recipe = self._RELOCATION_RECIPES_AARCH64.get(reloc_type, None)
        elif arch == '64-bit PowerPC':
            recipe = self._RELOCATION_RECIPES_PPC64.get(reloc_type, None)
        elif arch == 'IBM S/390':
            recipe = self._RELOCATION_RECIPES_S390X.get(reloc_type, None)
        elif arch == 'Linux BPF - in-kernel virtual machine':
            recipe = self._RELOCATION_RECIPES_EBPF.get(reloc_type, None)
        elif arch == 'LoongArch':
            if not reloc.is_RELA():
                raise ELFRelocationError(
                    f'Unexpected REL relocation for LoongArch: {reloc}')
            recipe = self._RELOCATION_RECIPES_LOONGARCH.get(reloc_type, None)
        elif arch == 'RISC-V':
            if not reloc.is_RELA():
                raise ELFRelocationError(
                    f'Unexpected REL relocation for RISC-V: {reloc}')
            recipe = self._RELOCATION_RECIPES_RISCV.get(reloc_type, None)

        if recipe is None:
            # Avoid a circular import through descriptions -> dynamic -> relocation.
            from .descriptions import describe_reloc_type

            name = describe_reloc_type(reloc_type, self.elffile)
            detail = f'{reloc_type} ({name})' if name.startswith('R_') else str(reloc_type)
            raise ELFRelocationError(
                    f'Unsupported relocation type: {detail} for {arch}')

        # So now we have everything we need to actually perform the relocation.
        # Let's get to it:

        if recipe.bytesize == _ULEB128_BYTESIZE:
            self._do_apply_uleb128_relocation(stream, reloc, recipe, sym_value)
            return

        # 0. Find out which struct we're going to be using to read this value
        #    from the stream and write it back.
        if recipe.bytesize == 4:
            value_struct = self.elffile.structs.Elf_word('')
        elif recipe.bytesize == 8:
            value_struct = self.elffile.structs.Elf_word64('')
        elif recipe.bytesize == 1:
            value_struct = self.elffile.structs.Elf_byte('')
        elif recipe.bytesize == 2:
            value_struct = self.elffile.structs.Elf_half('')
        else:
            raise ELFRelocationError(f'Invalid bytesize {recipe.bytesize} for relocation')

        # 1. Read the value from the stream (with correct size and endianness)
        original_value = struct_parse(
            value_struct,
            stream,
            stream_pos=reloc['r_offset'])
        # 2. Apply the relocation to the value, acting according to the recipe
        relocated_value = recipe.calc_func(
            value=original_value,
            sym_value=sym_value,
            offset=reloc['r_offset'],
            addend=reloc['r_addend'] if recipe.has_addend else 0)
        # 3. Write the relocated value back into the stream
        stream.seek(reloc['r_offset'])

        # Make sure the relocated value fits back by wrapping it around. This
        # looks like a problem, but it seems to be the way this is done in
        # binutils too.
        relocated_value = relocated_value % (2 ** (recipe.bytesize * 8))
        value_struct.build_stream(relocated_value, stream)

    def _do_apply_uleb128_relocation(
        self,
        stream: IO[bytes],
        reloc: Relocation,
        recipe: _RELOCATION_RECIPE_TYPE,
        sym_value: int,
    ) -> None:
        # The relocated value is written back in the same number of bytes as
        # the original encoding, as ld does, so the data that follows it does
        # not move.
        original_value = struct_parse(ULEB128(''), stream, stream_pos=reloc['r_offset'])
        length = stream.tell() - reloc['r_offset']
        relocated_value = recipe.calc_func(
            value=original_value,
            sym_value=sym_value,
            offset=reloc['r_offset'],
            addend=reloc['r_addend'] if recipe.has_addend else 0)
        relocated_value %= 2 ** (7 * length)
        encoded = bytearray()
        for i in range(length):
            byte = relocated_value & 0x7f
            relocated_value >>= 7
            if i < length - 1:
                byte |= 0x80
            encoded.append(byte)
        stream.seek(reloc['r_offset'])
        stream.write(encoded)

    # NONE relocations are handled before symbol lookup or target access, so
    # they do not have recipes describing a field to read and write.
    _RELOCATION_NONE_TYPES: Mapping[str, tuple[int, ...]] = {
        'x86': (ENUM_RELOC_TYPE_i386['R_386_NONE'],),
        'x64': (ENUM_RELOC_TYPE_x64['R_X86_64_NONE'],),
        'MIPS': (ENUM_RELOC_TYPE_MIPS['R_MIPS_NONE'],),
        'ARM': (ENUM_RELOC_TYPE_ARM['R_ARM_NONE'],),
        # The AArch64 ABI accepts both 0 and the historical value 256.
        'AArch64': (0, ENUM_RELOC_TYPE_AARCH64['R_AARCH64_NONE']),
        '64-bit PowerPC': (ENUM_RELOC_TYPE_PPC64['R_PPC64_NONE'],),
        'IBM S/390': (ENUM_RELOC_TYPE_S390X['R_390_NONE'],),
        'Linux BPF - in-kernel virtual machine': (ENUM_RELOC_TYPE_BPF['R_BPF_NONE'],),
        'LoongArch': (ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_NONE'],),
        'RISC-V': (ENUM_RELOC_TYPE_RISCV['R_RISCV_NONE'],),
    }

    # Other relocations are represented by "recipes". Each recipe specifies:
    #  bytesize: The number of bytes to read (and write back) to the section.
    #            This is the unit of data on which relocation is performed.
    #            _ULEB128_BYTESIZE marks a ULEB128 encoded value, which keeps
    #            the length it already has.
    #  has_addend: Does this relocation have an extra addend?
    #  calc_func: A function that performs the relocation on an extracted
    #             value, and returns the updated value.
    #
    class _RELOCATION_RECIPE_TYPE(NamedTuple):
        bytesize: int
        has_addend: bool
        calc_func: _RelocationFunction

    _RELOCATION_RECIPES_ARM: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_ARM['R_ARM_ABS32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_ARM['R_ARM_CALL']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_arm_reloc_calc_sym_plus_value_pcrel),
    }

    _RELOCATION_RECIPES_AARCH64: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_AARCH64['R_AARCH64_ABS64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_AARCH64['R_AARCH64_ABS32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_AARCH64['R_AARCH64_PREL32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend_pcrel),
    }

    # https://dmz-portal.mips.com/wiki/MIPS_relocation_types
    _RELOCATION_RECIPES_MIPS_REL: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_MIPS['R_MIPS_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_reloc_calc_sym_plus_value),
    }
    _RELOCATION_RECIPES_MIPS_RELA: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_MIPS['R_MIPS_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_MIPS['R_MIPS_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
    }

    _RELOCATION_RECIPES_PPC64: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_PPC64['R_PPC64_ADDR32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_PPC64['R_PPC64_REL32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend_pcrel),
        ENUM_RELOC_TYPE_PPC64['R_PPC64_ADDR64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
    }

    _RELOCATION_RECIPES_X86: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_i386['R_386_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_i386['R_386_PC32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_reloc_calc_sym_plus_value_pcrel),
        # The location of a thread-local variable in the debug sections of an
        # object file: its offset in its TLS section, as objdump applies it.
        ENUM_RELOC_TYPE_i386['R_386_TLS_LDO_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False,
            calc_func=_reloc_calc_sym_plus_value),
    }

    _RELOCATION_RECIPES_X64: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_x64['R_X86_64_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_x64['R_X86_64_PC32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend_pcrel),
        ENUM_RELOC_TYPE_x64['R_X86_64_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_x64['R_X86_64_32S']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        # The location of a thread-local variable in the debug sections of an
        # object file: its offset in its TLS section, as objdump applies it.
        ENUM_RELOC_TYPE_x64['R_X86_64_DTPOFF32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_x64['R_X86_64_DTPOFF64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
    }

    # https://www.kernel.org/doc/html/latest/bpf/llvm_reloc.html#different-relocation-types
    _RELOCATION_RECIPES_EBPF: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_BPF['R_BPF_64_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=False, calc_func=_reloc_calc_identity),
        ENUM_RELOC_TYPE_BPF['R_BPF_64_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=False, calc_func=_bpf_64_32_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_BPF['R_BPF_64_NODYLD32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False, calc_func=_reloc_calc_identity),
        ENUM_RELOC_TYPE_BPF['R_BPF_64_ABS64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=False, calc_func=_reloc_calc_identity),
        ENUM_RELOC_TYPE_BPF['R_BPF_64_ABS32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=False, calc_func=_reloc_calc_identity),
    }

    # https://github.com/loongson/la-abi-specs/blob/release/laelf.adoc
    _RELOCATION_RECIPES_LOONGARCH: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_ADD8']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_SUB8']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_ADD16']: _RELOCATION_RECIPE_TYPE(
            bytesize=2, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_SUB16']: _RELOCATION_RECIPE_TYPE(
            bytesize=2, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_ADD32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_SUB32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_ADD64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_SUB64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_32_PCREL']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend_pcrel),
        ENUM_RELOC_TYPE_LOONGARCH['R_LARCH_64_PCREL']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend_pcrel),
    }

    # https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc#relocations
    # Linker relaxation can still change code size, so a difference between
    # two labels is emitted as a pair of relocations, ADD and SUB, or SET and
    # SUB, applied one after the other to the same place.
    _RELOCATION_RECIPES_RISCV: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_RISCV['R_RISCV_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_32_PCREL']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend_pcrel),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_ADD8']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True, calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_ADD16']: _RELOCATION_RECIPE_TYPE(
            bytesize=2, has_addend=True, calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_ADD32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_ADD64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_value),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB8']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB16']: _RELOCATION_RECIPE_TYPE(
            bytesize=2, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB6']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True, calc_func=_riscv_reloc_calc_sub6),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SET6']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True, calc_func=_riscv_reloc_calc_set6),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SET8']: _RELOCATION_RECIPE_TYPE(
            bytesize=1, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SET16']: _RELOCATION_RECIPE_TYPE(
            bytesize=2, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SET32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SET_ULEB128']: _RELOCATION_RECIPE_TYPE(
            bytesize=_ULEB128_BYTESIZE, has_addend=True,
            calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_RISCV['R_RISCV_SUB_ULEB128']: _RELOCATION_RECIPE_TYPE(
            bytesize=_ULEB128_BYTESIZE, has_addend=True,
            calc_func=_reloc_calc_value_minus_sym_addend),
    }

    _RELOCATION_RECIPES_S390X: Mapping[int, _RELOCATION_RECIPE_TYPE] = {
        ENUM_RELOC_TYPE_S390X['R_390_32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
        ENUM_RELOC_TYPE_S390X['R_390_PC32']: _RELOCATION_RECIPE_TYPE(
            bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend_pcrel),
        ENUM_RELOC_TYPE_S390X['R_390_64']: _RELOCATION_RECIPE_TYPE(
            bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
    }

