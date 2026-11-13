#-------------------------------------------------------------------------------
# elftools tests: end-to-end variable location resolution on a synthetic ELF.
#
# The object is generated purely in Python (see _synth_elf.py) so the exact
# DWARF location lists and expressions are controlled by the test. These tests
# exercise the whole path: ELF -> DWARF DIE -> location-list selection for an
# instruction address -> restricted, hosted evaluation.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
import os
import sys
import unittest
from io import BytesIO

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.getcwd())

from elftools.elf.elffile import ELFFile
from elftools.dwarf.locationlists import LocationParser
from elftools.dwarf.location_eval import (
    EvalReason,
    LocationContext,
    LocationEvalError,
    PieceKind,
    VariableLocator,
)

from _synth_elf import VarSpec, build_elf64_dwarf4, sleb


def make_locator(blob):
    elffile = ELFFile(BytesIO(blob))
    dwarfinfo = elffile.get_dwarf_info()
    parser = LocationParser(dwarfinfo.location_lists())
    return VariableLocator(parser), elffile, dwarfinfo


def variable_dies(dwarfinfo):
    out = {}
    for cu in dwarfinfo.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag == 'DW_TAG_variable':
                out[die.attributes['DW_AT_name'].value.decode()] = die
    return out


class TestSyntheticVariableLocation(unittest.TestCase):
    def setUp(self):
        # One variable that moves between a register and a stack slot, and an
        # inline-expression variable that stays in a fixed register.
        moving = [
            (0x1000, 0x1008, bytes([0x55])),                  # DW_OP_reg5
            (0x1008, 0x1010, bytes([0x91]) + sleb(-16)),     # DW_OP_fbreg -16
        ]
        blob = build_elf64_dwarf4([
            VarSpec('moving', moving),
            VarSpec('fixed', bytes([0x54])),                 # DW_OP_reg4
        ])
        self.locator, _elffile, dwarfinfo = make_locator(blob)
        self.dies = variable_dies(dwarfinfo)
        self.memory = {0x2000: (0xDEADBEEF).to_bytes(8, 'little')}

    def _context(self, *, registers=None, frame_base=0x2010, memory=None):
        registers = registers if registers is not None else {}

        def read_register(number):
            if number not in registers:
                raise KeyError(number)
            return registers[number]

        return LocationContext(
            read_register=read_register,
            read_memory=memory,
            frame_base=frame_base,
        )

    def test_variable_moves_register_to_memory_across_ranges(self):
        ctx = self._context(memory=self.memory.get)
        first = self.locator.locate(self.dies['moving'], 0x1004, ctx)
        self.assertEqual(first.pieces[0].kind, PieceKind.REGISTER)
        self.assertEqual(first.pieces[0].register, 5)

        second = self.locator.locate(self.dies['moving'], 0x1009, ctx)
        self.assertEqual(second.pieces[0].kind, PieceKind.MEMORY)
        self.assertEqual(second.pieces[0].address, 0x2000)

    def test_range_boundaries_are_half_open(self):
        ctx = self._context(memory=self.memory.get)
        # 0x1008 belongs to the second range, not the first.
        at_boundary = self.locator.locate(self.dies['moving'], 0x1008, ctx)
        self.assertEqual(at_boundary.pieces[0].kind, PieceKind.MEMORY)
        # Past the last range there is no covering expression.
        with self.assertRaises(LocationEvalError) as caught:
            self.locator.locate(self.dies['moving'], 0x1010, ctx)
        self.assertEqual(caught.exception.reason,
                         EvalReason.MALFORMED_EXPRESSION)

    def test_inline_expression_applies_at_any_address(self):
        ctx = self._context()
        for address in (0x1000, 0x5555):
            result = self.locator.locate(
                self.dies['fixed'], address, ctx)
            self.assertEqual(result.pieces[0].kind, PieceKind.REGISTER)
            self.assertEqual(result.pieces[0].register, 4)

    def test_materialize_reads_value_and_records_memory_range(self):
        ctx = self._context(memory=self.memory.get)
        result = self.locator.materialize(
            self.dies['moving'], 0x1009, ctx)
        self.assertEqual(result.pieces[0].kind, PieceKind.VALUE)
        self.assertEqual(result.pieces[0].value, 0xDEADBEEF)
        self.assertEqual(len(result.memory_accesses), 1)
        access = result.memory_accesses[0]
        self.assertEqual((access.address, access.size, access.available),
                         (0x2000, 8, True))

    def test_locate_does_not_read_variable_value(self):
        # Locate with no memory reader must still succeed: locating the stack
        # slot only computes its address; it never dereferences it.
        ctx = self._context(memory=None)
        result = self.locator.locate(self.dies['moving'], 0x1009, ctx)
        self.assertEqual(result.pieces[0].kind, PieceKind.MEMORY)
        self.assertEqual(result.memory_accesses, [])

    def test_materialize_without_memory_reader_is_typed_error(self):
        ctx = self._context(memory=None)
        with self.assertRaises(LocationEvalError) as caught:
            self.locator.materialize(self.dies['moving'], 0x1009, ctx)
        self.assertEqual(caught.exception.reason, EvalReason.MISSING_MEMORY)

    def test_missing_frame_base_is_context_error(self):
        ctx = LocationContext()  # nothing provided
        with self.assertRaises(LocationEvalError) as caught:
            self.locator.locate(self.dies['moving'], 0x1009, ctx)
        self.assertEqual(caught.exception.reason, EvalReason.MISSING_CONTEXT)


class TestSyntheticFragmentedVariable(unittest.TestCase):
    def setUp(self):
        # A 16-byte variable split into two 8-byte register pieces.
        fragmented = [
            (0x3000, 0x3010,
             bytes([0x50, 0x93, 0x08, 0x51, 0x93, 0x08])),
        ]
        blob = build_elf64_dwarf4(
            [VarSpec('pair', fragmented)], cu_low_pc=0x3000)
        self.locator, _elffile, dwarfinfo = make_locator(blob)
        self.die = variable_dies(dwarfinfo)['pair']

    def test_two_pieces_preserve_location_not_value(self):
        result = self.locator.locate(
            self.die, 0x3004, LocationContext())
        self.assertEqual(len(result.pieces), 2)
        self.assertTrue(
            all(p.kind == PieceKind.REGISTER for p in result.pieces))
        self.assertEqual([p.register for p in result.pieces], [0, 1])
        self.assertTrue(all(p.value is None for p in result.pieces))
        self.assertFalse(result.is_value)

    def test_materialize_composes_register_values(self):
        ctx = LocationContext(
            read_register=lambda n: {0: 0x1111, 1: 0x2222}[n])
        result = self.locator.materialize(self.die, 0x3004, ctx)
        self.assertEqual([p.value for p in result.pieces],
                         [0x1111, 0x2222])

    def test_partial_context_failure_names_missing_register(self):
        # Only register 0 is known; the second piece cannot be materialized.
        ctx = LocationContext(read_register=lambda n: {0: 0x1111}[n])
        with self.assertRaises(LocationEvalError) as caught:
            self.locator.materialize(self.die, 0x3004, ctx)
        self.assertEqual(caught.exception.reason,
                         EvalReason.MISSING_REGISTER)
        self.assertIn('1', caught.exception.detail)


class TestSyntheticStackValue(unittest.TestCase):
    def setUp(self):
        # constu 1234; stack_value -> the variable *is* the value 1234.
        expression = bytes([0x10, 0xD2, 0x09, 0x9F])
        blob = build_elf64_dwarf4(
            [VarSpec('constant', expression)])
        self.locator, _elffile, dwarfinfo = make_locator(blob)
        self.die = variable_dies(dwarfinfo)['constant']

    def test_stack_value_is_distinct_from_location(self):
        result = self.locator.locate(self.die, 0x1000, LocationContext())
        self.assertTrue(result.is_value)
        self.assertEqual(result.pieces[0].kind, PieceKind.VALUE)
        self.assertEqual(result.pieces[0].value, 1234)
        # No target memory or register access is required.
        self.assertEqual(result.memory_accesses, [])


if __name__ == '__main__':
    unittest.main()
