#-------------------------------------------------------------------------------
# elftools tests
#
# A tiny DWARF line number program generator. The point of these tests is to
# exercise pyelftools' address lookup against hand-controlled line tables -
# duplicate addresses, adjacent sequences, discriminators and files appended
# from within the program - without having to compile a large program.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from io import BytesIO
from typing import NamedTuple

from elftools.dwarf.constants import DW_LNE, DW_LNS
from elftools.dwarf.lineprogram import LineProgram
from elftools.dwarf.structs import DWARFStructs


def uleb128(value: int) -> bytes:
    if value < 0:
        raise ValueError('uleb128 expects a non-negative integer')
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def sleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        sign_bit = byte & 0x40
        if (value == 0 and not sign_bit) or (value == -1 and sign_bit):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


class FileSpec(NamedTuple):
    name: str
    dir_index: int = 0
    mtime: int = 0
    length: int = 0


class LineTableBuilder:
    """ Builds a DWARF version 3/4 line program in an in-memory stream.

        Rows are emitted with absolute addresses, which keeps generated
        programs short and makes the expected address intervals obvious. A
        fresh sequence is started with end_sequence followed by set_address,
        mirroring what compilers emit for disjoint code regions.
    """
    def __init__(
        self,
        files: list[FileSpec],
        *,
        version: int = 4,
        directories: list[str] | None = None,
        default_is_stmt: int = 1,
        line_base: int = -5,
        line_range: int = 14,
        opcode_base: int = 10,
    ) -> None:
        if version >= 5:
            raise ValueError('the builder only covers the legacy v3/v4 format')
        self.version = version
        self.files = list(files)
        self.directories = directories or []
        self.default_is_stmt = default_is_stmt
        self.line_base = line_base
        self.line_range = line_range
        self.opcode_base = opcode_base
        # Standard opcode lengths indexed by opcode - 1, for opcode_base 10
        # (opcodes 1..9): copy and the flag-setting opcodes take no operands.
        self.standard_opcode_lengths = [0, 1, 1, 1, 1, 0, 0, 0, 1]
        self._body = bytearray()
        # Mirror of the line register, so rows can be specified with
        # absolute line numbers even across end_sequence state resets.
        self._current_line = 1

    #-- primitives --------------------------------------------------------#

    def set_address(self, address: int) -> 'LineTableBuilder':
        payload = bytes([DW_LNE.set_address]) + address.to_bytes(4, 'little')
        self._body += b'\x00' + uleb128(len(payload)) + payload
        return self

    def set_file(self, file_index: int) -> 'LineTableBuilder':
        self._body += bytes([DW_LNS.set_file]) + uleb128(file_index)
        return self

    def set_column(self, column: int) -> 'LineTableBuilder':
        self._body += bytes([DW_LNS.set_column]) + uleb128(column)
        return self

    def advance_line(self, line_delta: int) -> 'LineTableBuilder':
        self._body += bytes([DW_LNS.advance_line]) + sleb128(line_delta)
        return self

    def set_line(self, line: int) -> 'LineTableBuilder':
        # The line register starts at 1; advance_line is the only way to move
        # it, so an absolute line is reached relative to the current value.
        self.advance_line(line - self._current_line)
        self._current_line = line
        return self

    def next_row(
        self,
        address: int,
        line_delta: int,
        *,
        file: int = 1,
        column: int = 0,
    ) -> 'LineTableBuilder':
        # Emit a row using a relative line advance, exercising DW_LNS
        # .advance_line directly instead of the absolute set_line helper.
        self.set_address(address)
        self.set_file(file)
        if column:
            self.set_column(column)
        self.advance_line(line_delta)
        self._current_line += line_delta
        self.copy()
        return self

    def set_discriminator(self, discriminator: int) -> 'LineTableBuilder':
        payload = bytes([DW_LNE.set_discriminator]) + uleb128(discriminator)
        self._body += b'\x00' + uleb128(len(payload)) + payload
        return self

    def copy(self) -> 'LineTableBuilder':
        self._body += bytes([DW_LNS.copy])
        return self

    def define_file(self, spec: FileSpec) -> 'LineTableBuilder':
        # DW_LNE.define_file appends a file to the header's file table while
        # the line program itself is being executed.
        payload = (
            bytes([DW_LNE.define_file])
            + spec.name.encode() + b'\x00'
            + uleb128(spec.dir_index)
            + uleb128(spec.mtime)
            + uleb128(spec.length))
        self._body += b'\x00' + uleb128(len(payload)) + payload
        return self

    def end_sequence(self) -> 'LineTableBuilder':
        payload = bytes([DW_LNE.end_sequence])
        self._body += b'\x00' + uleb128(len(payload)) + payload
        # The state machine resets all registers after end_sequence.
        self._current_line = 1
        return self

    #-- row helpers -------------------------------------------------------#

    def row(
        self,
        address: int,
        line: int,
        *,
        file: int = 1,
        column: int = 0,
        discriminator: int = 0,
    ) -> 'LineTableBuilder':
        self.set_address(address)
        self.set_file(file)
        if column:
            self.set_column(column)
        if discriminator:
            self.set_discriminator(discriminator)
        self.set_line(line)
        self.copy()
        return self

    #-- assembly ----------------------------------------------------------#

    def _file_entry(self, spec: FileSpec) -> bytes:
        return (
            spec.name.encode() + b'\x00'
            + uleb128(spec.dir_index)
            + uleb128(spec.mtime)
            + uleb128(spec.length))

    def build(self) -> LineProgram:
        # An empty directory list, like an empty file list, is a single NULL
        # terminator in the legacy header format.
        directories = (
            b''.join(d.encode() + b'\x00' for d in self.directories) + b'\x00')
        files = b''.join(self._file_entry(spec) for spec in self.files) + b'\x00'
        parameters = bytes([
            1,                      # minimum_instruction_length
        ])
        if self.version >= 4:
            parameters += bytes([1])  # maximum_operations_per_instruction
        parameters += bytes([
            self.default_is_stmt,
            self.line_base & 0xFF,
            self.line_range,
            self.opcode_base,
        ])
        header_body = (
            parameters
            + bytes(self.standard_opcode_lengths)
            + directories
            + files)

        # unit_length counts the bytes following the initial length field:
        # version, the header_length field, the header body and the program.
        initial_length = 2 + 4 + len(header_body) + len(self._body)
        header_bytes = (
            initial_length.to_bytes(4, 'little')
            + self.version.to_bytes(2, 'little')
            + len(header_body).to_bytes(4, 'little')
            + header_body)

        program_bytes = bytes(self._body)
        # The stream contains header plus program, exactly like the real
        # .debug_line section; LineProgram reads opcodes starting at the
        # offset right after the header.
        stream = BytesIO(header_bytes + program_bytes)
        structs = DWARFStructs(
            little_endian=True, dwarf_format=32, address_size=4)
        # The header itself is parsed from the same bytes blob, as in the
        # existing line program tests.
        header = structs.Dwarf_lineprog_header.parse(header_bytes)
        program_start = len(header_bytes)
        return LineProgram(
            header, stream, structs,
            program_start,
            program_start + len(program_bytes))
