#-------------------------------------------------------------------------------
# elftools: dwarf/lineprogram.py
#
# DWARF line number program
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import copy
import os
import posixpath
from bisect import bisect_left
from functools import cached_property
from typing import IO, TYPE_CHECKING, Any, NamedTuple

from ..common.exceptions import DWARFError
from ..common.utils import bytes2str, struct_parse
from .constants import DW_LNE, DW_LNS

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..construct.lib.container import Container
    from .structs import DWARFStructs


# LineProgramEntry - an entry in the line program.
# A line program is a sequence of encoded entries. Some of these entries add a
# new LineState (mapping between line and address), and some don't.
#
# command:
#   The command/opcode - always numeric. For standard commands - it's the opcode
#   that can be matched with one of the DW_LNS constants. For extended commands
#   it's the extended opcode that can be matched with one of the DW_LNE
#   constants. For special commands, it's the opcode itself.
#
# args:
#   A list of decoded arguments of the command.
#
# is_extended:
#   Since extended commands are encoded by a zero followed by an extended
#   opcode, and these extended opcodes overlap with other opcodes, this
#   flag is needed to mark that the command has an extended opcode.
#
# state:
#   For commands that add a new state, it's the relevant LineState object.
#   For commands that don't add a new state, it's None.
#
class LineProgramEntry(NamedTuple):
    command: int
    is_extended: bool
    args: list[int]
    state: LineState | None


class LineState:
    """ Represents a line program state (or a "row" in the matrix
        describing debug location information for addresses).
        The instance variables of this class are the "state machine registers"
        described in section 6.2.2 of DWARFv3
    """
    def __init__(self, default_is_stmt: int) -> None:
        self.address = 0
        self.file = 1
        self.line = 1
        self.column = 0
        self.op_index = 0
        self.is_stmt = default_is_stmt
        self.basic_block = False
        self.end_sequence = False
        self.prologue_end = False
        self.epilogue_begin = False
        self.isa = 0
        self.discriminator = 0

    def __repr__(self) -> str:
        return '\n'.join((
            f'<LineState {id(self):x}:',
            f'  address = 0x{self.address:x}',
            *(
                f'  {attr} = {getattr(self, attr)}'
                for attr in ('file', 'line', 'column', 'is_stmt', 'basic_block',
                    'end_sequence', 'prologue_end', 'epilogue_begin', 'isa',
                    'discriminator')
            ),
            '>',
        ))


# LineTableEntry - one row of the line table, re-indexed for address lookup.
#
# The decoded line program is a state machine: only entries that emit a new
# state are matrix rows, and a row with end_sequence set is a boundary marker
# rather than a source location. This class keeps the emitted row together
# with the half-open address interval [address, end_address) for which the
# row's source location is valid according to DWARF section 6.2.5.2.
#
# Rows that share an address (common in optimized code, where several line
# table records - different files, lines, columns or discriminators - are
# emitted at the same machine address) all have a non-empty interval only if
# the address advances later on. The last row at a given address owns the
# interval; earlier duplicates have address == end_address and can therefore
# only be matched by an exact-address query.
#
# state:
#   The LineState row emitted by the line program. Never an end_sequence
#   boundary marker.
#
# end_address:
#   Address of the row that ends this row's interval. It is the address of
#   the next emitted row within the same sequence, or the address carried by
#   the sequence's end_sequence marker. Equal to state.address when the row
#   is followed by another row at the same address.
#
# sequence_index:
#   Zero-based index of the sequence (the run of rows terminated by an
#   end_sequence marker) this row belongs to.
class LineTableEntry(NamedTuple):
    state: LineState
    end_address: int
    sequence_index: int


# Why a lookup matched a particular line table row. Exact matches take
# precedence over interval matches: a query address that is itself a row
# address returns every row emitted at that address, including duplicate rows
# whose interval is empty, and never the row that merely covers the address
# through its interval.
LINE_MATCH_EXACT = 'exact'
LINE_MATCH_RANGE = 'range'


class LineProgram:
    """ Builds a "line table", which is essentially the matrix described
        in section 6.2 of DWARFv3. It's a list of LineState objects,
        sorted by increasing address, so it can be used to obtain the
        state information for each address.
    """
    def __init__(
        self,
        header: Container,
        stream: IO[bytes],
        structs: DWARFStructs,
        program_start_offset: int,
        program_end_offset: int,
    ) -> None:
        """
            header:
                The header of this line program. Note: LineProgram may modify
                its header by appending file entries if DW_LNE.define_file
                instructions are encountered.

            stream:
                The stream this program can be read from.

            structs:
                A DWARFStructs instance suitable for this line program

            program_{start|end}_offset:
                Offset in the debug_line section stream where this program
                starts (the actual program, after the header), and where it
                ends.
                The actual range includes start but not end: [start, end - 1]
        """
        self.stream = stream
        self.header = header
        self.structs = structs
        self.program_start_offset = program_start_offset
        self.program_end_offset = program_end_offset

    def get_entries(self) -> list[LineProgramEntry]:
        """ Get the decoded entries for this line program. Return a list of
            LineProgramEntry objects.
            Note that this contains more information than absolutely required
            for the line table. The line table can be easily extracted from
            the list of entries by looking only at entries with non-None
            state. The extra information is mainly for the purposes of display
            with readelf and debugging.
        """
        return self._decode_line_program

    @cached_property
    def line_table(self) -> list[LineTableEntry]:
        """ Get the line table re-indexed for address lookup.

            Returns a list of LineTableEntry objects, one per emitted matrix
            row (end_sequence boundary markers are excluded). Each entry
            records the half-open address interval [address, end_address) in
            which its source location is valid and the index of the sequence
            it belongs to.

            The list keeps the program's emission order. Several entries may
            share an address; only the last of them can have a non-empty
            interval. Sequences are kept strictly separate: an
            end_sequence marker ends the previous sequence and the state
            machine reset starts a fresh one, so intervals can never span a
            sequence boundary or borrow state from a previous sequence.
        """
        table: list[LineTableEntry] = []
        sequence_index = 0
        pending: list[LineState] = []

        def flush(sequence_end: int) -> None:
            # Assign every pending row the address of the row that follows it
            # as the end of its interval. Rows sharing an address get an empty
            # interval, which is what keeps exact-address duplicates reachable.
            for position, row in enumerate(pending):
                end_address = (
                    pending[position + 1].address
                    if position + 1 < len(pending)
                    else sequence_end)
                table.append(LineTableEntry(row, end_address, sequence_index))

        for entry in self._decode_line_program:
            state = entry.state
            if state is None:
                continue
            if state.end_sequence:
                # The end_sequence row is a boundary marker: its address is
                # one past the last instruction of the sequence and its other
                # registers are meaningless, so it is not itself a location.
                flush(state.address)
                pending = []
                sequence_index += 1
            else:
                pending.append(state)

        # Be tolerant of a truncated program that has no end_sequence marker:
        # the trailing rows are still usable for exact-address lookups.
        if pending:
            flush(pending[-1].address)
        return table

    def lookup_address(self, address: int) -> list[tuple[LineTableEntry, str]]:
        """ Find all line table rows in this program that describe address.

            Returns a list of (LineTableEntry, reason) pairs, in emission
            order. The reason is one of:
              - LINE_MATCH_EXACT: the row's own address equals the queried
                address. Every row emitted at the address is returned,
                including duplicate rows with different files, lines, columns
                or discriminators and rows with an empty interval.
              - LINE_MATCH_RANGE: the address falls inside the row's
                half-open interval [address, end_address). At most one row
                per sequence can match this way, and it is only returned when
                no row is emitted exactly at the queried address.

            The result is computed from the indexed line table alone, so
            repeatedly querying addresses in any order always gives the same
            answer. Rows from a previous sequence can never match an address
            of a later one: each sequence is bounded by its own
            end_sequence marker.
        """
        table = self.line_table
        # First row whose address is greater than the queried address; all
        # candidates are at or before this insertion point.
        insertion = bisect_left(
            table, address + 1, key=lambda entry: entry.state.address)

        exact: list[tuple[LineTableEntry, str]] = []
        range_matches: list[tuple[LineTableEntry, str]] = []
        for entry in table[:insertion]:
            if entry.state.address == address:
                exact.append((entry, LINE_MATCH_EXACT))
            elif entry.state.address < address < entry.end_address:
                range_matches.append((entry, LINE_MATCH_RANGE))

        # Exact matches win outright: an address that is itself a row address
        # is never also attributed to the rows whose intervals contain it.
        if exact:
            return exact
        return range_matches

    def filename_for_state(self, state: LineState) -> str | None:
        """ Resolve the source file name recorded by a LineState row.

            The file index stored in the row is interpreted against the
            header's file table, which already includes files appended by
            DW_LNE.define_file while the program was decoded. File and
            directory indices are 1-based before DWARFv5 and 0-based in
            DWARFv5. Returns None when the row carries no usable file index
            or the file table does not contain it.
        """
        header = self.header
        file_entries = header['file_entry']
        file_index = state.file - (1 if header.version < 5 else 0)
        if not 0 <= file_index < len(file_entries):
            return None

        file_entry = file_entries[file_index]
        name = file_entry.name
        if name is None:
            return None
        name = bytes2str(name)

        directories: Sequence[Any] = header.get('include_directory', ())
        dir_index = file_entry['dir_index']
        if header.version < 5:
            if dir_index == 0:
                return name
            dir_index -= 1
        if not 0 <= dir_index < len(directories):
            return name
        return posixpath.join(bytes2str(directories[dir_index]), name)

    #------ PRIVATE ------#

    def __getitem__(self, name: str) -> Any:
        """ Implement dict-like access to header entries
        """
        return self.header[name]

    @cached_property
    def _decode_line_program(self) -> list[LineProgramEntry]:
        entries = []
        state = LineState(self.header['default_is_stmt'])

        def add_entry_new_state(cmd: int, args: list[int], is_extended: bool = False) -> None:
            # Add an entry that sets a new state.
            # After adding, clear some state registers.
            entries.append(LineProgramEntry(
                cmd, is_extended, args, copy.copy(state)))
            state.discriminator = 0
            state.basic_block = False
            state.prologue_end = False
            state.epilogue_begin = False

        def add_entry_old_state(cmd: int, args: list[int], is_extended: bool = False) -> None:
            # Add an entry that doesn't visibly set a new state
            entries.append(LineProgramEntry(cmd, is_extended, args, None))

        offset = self.program_start_offset
        while offset < self.program_end_offset:
            opcode: int = struct_parse(
                self.structs.the_Dwarf_uint8,
                self.stream,
                offset)

            # As an exercise in avoiding premature optimization, if...elif
            # chains are used here for standard and extended opcodes instead
            # of dispatch tables. This keeps the code much cleaner. Besides,
            # the majority of instructions in a typical program are special
            # opcodes anyway.
            if opcode >= self.header['opcode_base']:
                # Special opcode (follow the recipe in 6.2.5.1)
                maximum_operations_per_instruction: int = self['maximum_operations_per_instruction']
                adjusted_opcode: int = opcode - self['opcode_base']
                operation_advance: int = adjusted_opcode // self['line_range']
                address_addend: int = (
                    self['minimum_instruction_length'] *
                        ((state.op_index + operation_advance) //
                          maximum_operations_per_instruction))
                state.address += address_addend
                state.op_index = (state.op_index + operation_advance) % maximum_operations_per_instruction
                line_addend: int = self['line_base'] + (adjusted_opcode % self['line_range'])
                state.line += line_addend
                add_entry_new_state(
                    opcode, [line_addend, address_addend, state.op_index])
            elif opcode == 0:
                # Extended opcode: start with a zero byte, followed by
                # instruction size and the instruction itself.
                inst_len: int = struct_parse(self.structs.the_Dwarf_uleb128,
                                        self.stream)
                ex_opcode: int = struct_parse(self.structs.the_Dwarf_uint8,
                                         self.stream)

                if ex_opcode == DW_LNE.end_sequence:
                    state.end_sequence = True
                    state.is_stmt = 0
                    add_entry_new_state(ex_opcode, [], is_extended=True)
                    # reset state
                    state = LineState(self.header['default_is_stmt'])
                elif ex_opcode == DW_LNE.set_address:
                    operand: int = struct_parse(self.structs.the_Dwarf_target_addr,
                                           self.stream)
                    state.address = operand
                    add_entry_old_state(ex_opcode, [operand], is_extended=True)
                elif ex_opcode == DW_LNE.define_file:
                    operand = struct_parse(
                        self.structs.Dwarf_lineprog_file_entry, self.stream)
                    self['file_entry'].append(operand)
                    add_entry_old_state(ex_opcode, [operand], is_extended=True)
                elif ex_opcode == DW_LNE.set_discriminator:
                    operand = struct_parse(self.structs.the_Dwarf_uleb128,
                                           self.stream)
                    state.discriminator = operand
                else:
                    # Unknown, but need to roll forward the stream because the
                    # length is specified. Seek forward inst_len - 1 because
                    # we've already read the extended opcode, which takes part
                    # in the length.
                    self.stream.seek(inst_len - 1, os.SEEK_CUR)
            else: # 0 < opcode < opcode_base
                # Standard opcode
                if opcode == DW_LNS.copy:
                    add_entry_new_state(opcode, [])
                elif opcode == DW_LNS.advance_pc:
                    operand = struct_parse(self.structs.the_Dwarf_uleb128,
                                           self.stream)
                    address_addend = (
                        operand * self.header['minimum_instruction_length'])
                    state.address += address_addend
                    add_entry_old_state(opcode, [address_addend])
                elif opcode == DW_LNS.advance_line:
                    operand = struct_parse(self.structs.the_Dwarf_sleb128,
                                           self.stream)
                    state.line += operand
                elif opcode == DW_LNS.set_file:
                    operand = struct_parse(self.structs.the_Dwarf_uleb128,
                                           self.stream)
                    state.file = operand
                    add_entry_old_state(opcode, [operand])
                elif opcode == DW_LNS.set_column:
                    operand = struct_parse(self.structs.the_Dwarf_uleb128,
                                           self.stream)
                    state.column = operand
                    add_entry_old_state(opcode, [operand])
                elif opcode == DW_LNS.negate_stmt:
                    state.is_stmt = not state.is_stmt
                    add_entry_old_state(opcode, [])
                elif opcode == DW_LNS.set_basic_block:
                    state.basic_block = True
                    add_entry_old_state(opcode, [])
                elif opcode == DW_LNS.const_add_pc:
                    adjusted_opcode = 255 - self['opcode_base']
                    address_addend = ((adjusted_opcode // self['line_range']) *
                                      self['minimum_instruction_length'])
                    state.address += address_addend
                    add_entry_old_state(opcode, [address_addend])
                elif opcode == DW_LNS.fixed_advance_pc:
                    operand = struct_parse(self.structs.the_Dwarf_uint16,
                                           self.stream)
                    state.address += operand
                    add_entry_old_state(opcode, [operand])
                elif opcode == DW_LNS.set_prologue_end:
                    state.prologue_end = True
                    add_entry_old_state(opcode, [])
                elif opcode == DW_LNS.set_epilogue_begin:
                    state.epilogue_begin = True
                    add_entry_old_state(opcode, [])
                elif opcode == DW_LNS.set_isa:
                    operand = struct_parse(self.structs.the_Dwarf_uleb128,
                                           self.stream)
                    state.isa = operand
                    add_entry_old_state(opcode, [operand])
                else:
                    raise DWARFError(f"Invalid standard line program opcode: {opcode}")
            offset = self.stream.tell()
        return entries
