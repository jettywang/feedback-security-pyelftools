#-------------------------------------------------------------------------------
# elftools tests: restricted DWARF location-expression evaluator.
#
# These tests drive LocationExpressionEvaluator directly with hand-built
# DWARF expression bytes, covering registers, constants, address arithmetic,
# dereferences, piece / bit_piece, the location-vs-value distinction, the
# memory-access log, and every documented non-evaluable reason.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
import os
import sys
import unittest

sys.path.insert(0, os.getcwd())

from elftools.dwarf.structs import DWARFStructs
from elftools.dwarf.dwarf_expr import DW_OP_name2opcode
from elftools.dwarf.location_eval import (
    EvalReason,
    LocationContext,
    LocationEvalError,
    LocationExpressionEvaluator,
    PieceKind,
    select_expression,
)


def op(name: str) -> int:
    return DW_OP_name2opcode[name]


class Mem:
    """A tiny addressable memory that also records served ranges."""

    def __init__(self, contents):
        self._contents = dict(contents)
        self.reads = []

    def __call__(self, address, size):
        self.reads.append((address, size))
        if address not in self._contents:
            raise LookupError(address)
        return self._contents[address][:size]


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
        shifted = value >> 7
        if (shifted == 0 and not (byte & 0x40)) or (
                shifted == -1 and (byte & 0x40)):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)
        value = shifted


def addr(value: int) -> bytes:
    return value.to_bytes(8, 'little')


def constu(value: int) -> bytes:
    return bytes([op('DW_OP_constu')]) + uleb(value)


def consts(value: int) -> bytes:
    return bytes([op('DW_OP_consts')]) + sleb(value)


def lit(number: int) -> bytes:
    return bytes([DW_OP_name2opcode[f'DW_OP_lit{number}']])


class EvaluatorTestBase(unittest.TestCase):
    structs = DWARFStructs(
        little_endian=True, dwarf_format=32, address_size=8)

    def eval(self, expression, context=None):
        if isinstance(expression, (bytes, bytearray)):
            expression = bytes(expression)
        else:
            expression = bytes(expression)
        return LocationExpressionEvaluator(
            self.structs, expression, context or LocationContext())

    def assertReason(self, reason, expression, context=None,
                     materialize=False):
        ev = self.eval(expression, context)
        with self.assertRaises(LocationEvalError) as caught:
            ev.materialize() if materialize else ev.locate()
        self.assertEqual(caught.exception.reason, reason)
        return caught.exception


class TestRegisterAndMemoryLocations(EvaluatorTestBase):
    def test_reg_family_is_symbolic_register_location(self):
        # DW_OP_reg5: variable is *in* register 5; the register is not read.
        result = self.eval([op('DW_OP_reg5')]).locate()
        self.assertEqual(len(result.pieces), 1)
        piece = result.pieces[0]
        self.assertEqual(piece.kind, PieceKind.REGISTER)
        self.assertEqual(piece.register, 5)
        self.assertFalse(result.is_value)
        # No memory and no register access happened for a plain location.
        self.assertEqual(result.memory_accesses, [])

    def test_regx_symbolic(self):
        result = self.eval([op('DW_OP_regx'), 17]).locate()
        self.assertEqual(result.pieces[0].kind, PieceKind.REGISTER)
        self.assertEqual(result.pieces[0].register, 17)

    def test_breg_plus_offset_needs_register_and_yields_address(self):
        ctx = LocationContext(read_register=lambda n: {5: 0x1000}[n])
        # DW_OP_breg5, +8
        result = self.eval([0x75, 0x08], ctx).locate()
        piece = result.pieces[0]
        self.assertEqual(piece.kind, PieceKind.MEMORY)
        self.assertEqual(piece.address, 0x1008)
        # A breg-derived value is an address, not the variable's value.
        self.assertFalse(result.is_value)

    def test_breg_missing_register_is_reported(self):
        def boom(reg):
            raise KeyError(reg)
        self.assertReason(
            EvalReason.MISSING_REGISTER, [0x75, 0x08],
            LocationContext(read_register=boom))

    def test_no_register_reader_at_all(self):
        self.assertReason(EvalReason.MISSING_REGISTER, [0x75, 0x00])

    def test_bregx(self):
        ctx = LocationContext(read_register=lambda n: 0x2000 if n == 9 else 0)
        result = self.eval(
            [op('DW_OP_bregx'), 9] + list(sleb(-16)), ctx).locate()
        self.assertEqual(result.pieces[0].address, 0x1FF0)

    def test_fbreg_uses_frame_base(self):
        ctx = LocationContext(frame_base=0x4000)
        result = self.eval(
            [op('DW_OP_fbreg')] + list(sleb(-24)), ctx).locate()
        self.assertEqual(result.pieces[0].kind, PieceKind.MEMORY)
        self.assertEqual(result.pieces[0].address, 0x3FE8)

    def test_fbreg_without_frame_base_is_context_error(self):
        self.assertReason(EvalReason.MISSING_CONTEXT,
                          [op('DW_OP_fbreg'), 0])

    def test_deref_reads_and_logs_memory(self):
        mem = Mem({0x3000: (0x1122334455667788).to_bytes(8, 'little')})
        ctx = LocationContext(read_memory=mem)
        expression = (bytes([op('DW_OP_addr')]) + addr(0x3000) +
                      bytes([op('DW_OP_deref')]))
        result = self.eval(expression, ctx).locate()
        # After deref the top is the loaded word used as a value.
        self.assertEqual(result.pieces[0].kind, PieceKind.VALUE)
        self.assertEqual(result.pieces[0].value, 0x1122334455667788)
        self.assertEqual(mem.reads, [(0x3000, 8)])
        self.assertEqual(result.memory_accesses[0].address, 0x3000)
        self.assertTrue(result.memory_accesses[0].available)

    def test_deref_missing_memory_is_logged_unavailable(self):
        def boom(address, size):
            raise LookupError(address)
        ctx = LocationContext(read_memory=boom)
        expression = (bytes([op('DW_OP_addr')]) + addr(0x5000) +
                      bytes([op('DW_OP_deref')]))
        ev = self.eval(expression, ctx)
        with self.assertRaises(LocationEvalError) as caught:
            ev.locate()
        self.assertEqual(caught.exception.reason, EvalReason.MISSING_MEMORY)
        self.assertEqual(ev._memory_accesses[0].address, 0x5000)
        self.assertFalse(ev._memory_accesses[0].available)

    def test_deref_size(self):
        mem = Mem({0x6000: bytes([0x78, 0x56, 0x34, 0x12])})
        ctx = LocationContext(read_memory=mem)
        expression = (bytes([op('DW_OP_addr')]) + addr(0x6000) +
                      bytes([op('DW_OP_deref_size'), 4]))
        result = self.eval(expression, ctx).locate()
        self.assertEqual(result.pieces[0].value, 0x12345678)
        self.assertEqual(mem.reads, [(0x6000, 4)])


class TestConstantsAndArithmetic(EvaluatorTestBase):
    def test_lit_and_constu_are_values_not_locations(self):
        result = self.eval([op('DW_OP_lit7')]).locate()
        self.assertEqual(result.pieces[0].kind, PieceKind.VALUE)
        self.assertEqual(result.pieces[0].value, 7)
        self.assertTrue(result.is_value is False)  # literal, no stack_value

        result = self.eval([op('DW_OP_constu'), 42]).locate()
        self.assertEqual(result.pieces[0].value, 42)

    def test_stack_value_marks_actual_value(self):
        # constu 99; stack_value => the *value* 99.
        expression = [op('DW_OP_constu'), 99, op('DW_OP_stack_value')]
        result = self.eval(expression).locate()
        self.assertTrue(result.is_value)
        self.assertEqual(result.pieces[0].kind, PieceKind.VALUE)
        self.assertEqual(result.pieces[0].value, 99)

    def test_address_plus_uconst(self):
        ctx = LocationContext(read_register=lambda n: 0x100)
        expression = [0x70, 0x00, op('DW_OP_plus_uconst'), 0x20]
        result = self.eval(expression, ctx).locate()
        self.assertEqual(result.pieces[0].address, 0x120)

    def test_plus_minus_mul(self):
        # lit3 + lit4 = 7
        self.assertEqual(
            self.eval([op('DW_OP_lit3'), op('DW_OP_lit4'),
                       op('DW_OP_plus')]).locate().pieces[0].value, 7)
        # lit10 - lit3 = 7
        self.assertEqual(
            self.eval([op('DW_OP_lit10'), op('DW_OP_lit3'),
                       op('DW_OP_minus')]).locate().pieces[0].value, 7)
        # lit3 * lit5 = 15
        self.assertEqual(
            self.eval([op('DW_OP_lit3'), op('DW_OP_lit5'),
                       op('DW_OP_mul')]).locate().pieces[0].value, 15)

    def test_signed_div_truncates_toward_zero(self):
        # consts -7 ; lit2 ; div -> -3 (truncation toward zero)
        expression = ([op('DW_OP_consts')] + list(sleb(-7)) +
                      [op('DW_OP_lit2'), op('DW_OP_div')])
        self.assertEqual(
            self.eval(expression).locate().pieces[0].value,
            (-3) & ((1 << 64) - 1))

    def test_division_by_zero(self):
        expression = [op('DW_OP_lit5'), op('DW_OP_lit0'),
                      op('DW_OP_div')]
        self.assertReason(EvalReason.DIVISION_BY_ZERO, expression)

    def test_mod_by_zero(self):
        expression = [op('DW_OP_lit5'), op('DW_OP_lit0'),
                      op('DW_OP_mod')]
        self.assertReason(EvalReason.DIVISION_BY_ZERO, expression)

    def test_shifts_and_bitops(self):
        # lit1 ; constu 4 ; shl -> 16
        shl = lit(1) + constu(4) + bytes([op('DW_OP_shl')])
        self.assertEqual(self.eval(shl).locate().pieces[0].value, 16)
        # constu 16 ; lit4 ; shr -> 1
        shr = constu(16) + lit(4) + bytes([op('DW_OP_shr')])
        self.assertEqual(self.eval(shr).locate().pieces[0].value, 1)
        # consts -8 ; lit1 ; shra -> -4
        shra = consts(-8) + lit(1) + bytes([op('DW_OP_shra')])
        self.assertEqual(self.eval(shra).locate().pieces[0].value,
                         (-4) & ((1 << 64) - 1))
        # and / or / xor
        self.assertEqual(
            self.eval([op('DW_OP_lit3'), op('DW_OP_lit5'),
                       op('DW_OP_and')]).locate().pieces[0].value, 1)

    def test_shift_amount_out_of_word(self):
        expression = lit(1) + constu(64) + bytes([op('DW_OP_shl')])
        self.assertReason(EvalReason.VALUE_OUT_OF_RANGE, expression)

    def test_compares_produce_0_or_1(self):
        self.assertEqual(
            self.eval([op('DW_OP_lit3'), op('DW_OP_lit3'),
                       op('DW_OP_eq')]).locate().pieces[0].value, 1)
        self.assertEqual(
            self.eval([op('DW_OP_lit2'), op('DW_OP_lit3'),
                       op('DW_OP_lt')]).locate().pieces[0].value, 1)
        self.assertEqual(
            self.eval([op('DW_OP_lit2'), op('DW_OP_lit3'),
                       op('DW_OP_ne')]).locate().pieces[0].value, 1)

    def test_stack_manipulation(self):
        # lit1 lit2 over -> stack 1,2,1 ; drop drop leaves 1
        expression = [op('DW_OP_lit1'), op('DW_OP_lit2'),
                      op('DW_OP_over'), op('DW_OP_drop'), op('DW_OP_drop')]
        self.assertEqual(
            self.eval(expression).locate().pieces[0].value, 1)

    def test_underflow_on_binop(self):
        self.assertReason(EvalReason.STACK_UNDERFLOW, [op('DW_OP_plus')])

    def test_underflow_on_stack_value(self):
        self.assertReason(EvalReason.STACK_UNDERFLOW,
                          [op('DW_OP_stack_value')])

    def test_malformed_empty_expression(self):
        self.assertReason(EvalReason.MALFORMED_EXPRESSION, [])

    def test_malformed_two_leftover_entries(self):
        expression = [op('DW_OP_lit1'), op('DW_OP_lit2')]
        self.assertReason(EvalReason.MALFORMED_EXPRESSION, expression)


class TestUnsupportedAndContext(EvaluatorTestBase):
    def test_unknown_branch_opcode(self):
        # DW_OP_bra is a control-flow opcode and must not be executed.
        self.assertReason(EvalReason.UNSUPPORTED_OP,
                          [op('DW_OP_bra'), 0, 0])

    def test_skip_unsupported(self):
        self.assertReason(EvalReason.UNSUPPORTED_OP,
                          [op('DW_OP_skip'), 0, 0])

    def test_tls_unsupported(self):
        self.assertReason(EvalReason.UNSUPPORTED_OP,
                          [op('DW_OP_form_tls_address')])

    def test_call_unsupported(self):
        self.assertReason(EvalReason.UNSUPPORTED_OP,
                          [op('DW_OP_call4'), 0, 0, 0, 0])

    def test_cfa_needs_context(self):
        self.assertReason(EvalReason.MISSING_CONTEXT,
                          [op('DW_OP_call_frame_cfa')])

    def test_cfa_with_context(self):
        ctx = LocationContext(cfa=0x7000)
        result = self.eval([op('DW_OP_call_frame_cfa')], ctx).locate()
        self.assertEqual(result.pieces[0].address, 0x7000)

    def test_object_address_needs_context(self):
        self.assertReason(EvalReason.MISSING_CONTEXT,
                          [op('DW_OP_push_object_address')])

    def test_addrx_needs_resolver(self):
        self.assertReason(EvalReason.MISSING_CONTEXT,
                          [op('DW_OP_addrx'), 0])

    def test_addrx_resolved(self):
        ctx = LocationContext(resolve_addr=lambda index: 0x8000 + index)
        result = self.eval([op('DW_OP_addrx'), 2], ctx).locate()
        self.assertEqual(result.pieces[0].address, 0x8002)

    def test_uninit_is_not_a_value(self):
        self.assertReason(EvalReason.NOT_A_VALUE,
                          [op('DW_OP_GNU_uninit')])


class TestPieces(EvaluatorTestBase):
    def test_two_register_pieces(self):
        # reg3 piece(4) reg4 piece(4)
        expression = [op('DW_OP_reg3'), op('DW_OP_piece'), 4,
                      op('DW_OP_reg4'), op('DW_OP_piece'), 4]
        result = self.eval(expression).locate()
        self.assertEqual([p.kind for p in result.pieces],
                         [PieceKind.REGISTER, PieceKind.REGISTER])
        self.assertEqual([p.register for p in result.pieces], [3, 4])
        self.assertEqual([p.size for p in result.pieces], [4, 4])

    def test_split_register_and_memory_piece(self):
        ctx = LocationContext(read_register=lambda n: 0x9000)
        # reg0 piece(8); fbreg 0 piece(8)
        expression = [op('DW_OP_reg0'), op('DW_OP_piece'), 8,
                      op('DW_OP_fbreg'), 0, op('DW_OP_piece'), 8]
        ctx.frame_base = 0xAB00
        result = self.eval(expression, ctx).locate()
        self.assertEqual(result.pieces[0].kind, PieceKind.REGISTER)
        self.assertEqual(result.pieces[1].kind, PieceKind.MEMORY)
        self.assertEqual(result.pieces[1].address, 0xAB00)

    def test_materialize_register_piece_reads_register(self):
        ctx = LocationContext(
            read_register=lambda n: {3: 0x01020304, 4: 0x05060708}[n])
        expression = [op('DW_OP_reg3'), op('DW_OP_piece'), 4,
                      op('DW_OP_reg4'), op('DW_OP_piece'), 4]
        result = self.eval(expression, ctx).materialize()
        self.assertEqual([p.value for p in result.pieces],
                         [0x01020304, 0x05060708])
        # Register-only materialization touches no memory.
        self.assertEqual(result.memory_accesses, [])

    def test_materialize_memory_piece_logs_range(self):
        mem = Mem({0x100: (0xCAFE).to_bytes(8, 'little')})
        ctx = LocationContext(
            frame_base=0x100, read_memory=mem)
        expression = [op('DW_OP_fbreg'), 0, op('DW_OP_piece'), 8]
        result = self.eval(expression, ctx).materialize()
        self.assertEqual(result.pieces[0].value, 0xCAFE)
        self.assertEqual(mem.reads, [(0x100, 8)])

    def test_materialize_with_missing_register_piece_reports_reason(self):
        def boom(reg):
            raise KeyError(reg)
        ctx = LocationContext(read_register=boom)
        expression = [op('DW_OP_reg3'), op('DW_OP_piece'), 4]
        self.assertReason(EvalReason.MISSING_REGISTER, expression,
                          ctx, materialize=True)

    def test_bit_piece_from_value(self):
        # constu 0xAABB ; bit_piece(size=8, offset=8) -> 0xAA
        expression = (constu(0xAABB) +
                      bytes([op('DW_OP_bit_piece'), 8, 8]))
        result = self.eval(expression).locate()
        self.assertEqual(result.pieces[0].kind, PieceKind.VALUE)
        self.assertEqual(result.pieces[0].value, 0xAA)
        self.assertEqual(result.pieces[0].bit_size, 8)
        self.assertEqual(result.pieces[0].bit_offset, 8)

    def test_bit_piece_from_register_keeps_location(self):
        # reg2 ; bit_piece(size=4, offset=0): stays a register description with
        # a bit window until the value is materialized.
        expression = [op('DW_OP_reg2'), op('DW_OP_bit_piece'), 4, 0]
        result = self.eval(expression).locate()
        piece = result.pieces[0]
        self.assertEqual(piece.kind, PieceKind.REGISTER)
        self.assertEqual(piece.register, 2)
        self.assertEqual(piece.bit_size, 4)
        ctx = LocationContext(read_register=lambda n: 0b1011)
        materialized = self.eval(expression, ctx).materialize()
        self.assertEqual(materialized.pieces[0].value, 0b1011 & 0b1111)

    def test_locate_then_materialize_on_same_evaluator(self):
        memory = {0x100: (0xCAFE).to_bytes(8, 'little')}
        ctx = LocationContext(
            frame_base=0x100, read_memory=lambda a, s: memory[a])
        evaluator = self.eval(
            bytes([op('DW_OP_fbreg'), 0]), ctx)
        location = evaluator.locate()
        self.assertEqual(location.pieces[0].address, 0x100)
        # A second evaluation must not inherit stack/piece state from the first.
        materialized = evaluator.materialize()
        self.assertEqual(materialized.pieces[0].value, 0xCAFE)
        self.assertEqual(len(materialized.pieces), 1)

    def test_implicit_value(self):
        blob = bytes([0x01, 0x02, 0x03, 0x04])
        expression = [op('DW_OP_implicit_value'), len(blob)] + list(blob)
        result = self.eval(expression).locate()
        piece = result.pieces[0]
        self.assertEqual(piece.kind, PieceKind.IMPLICIT)
        self.assertEqual(piece.implicit, blob)
        self.assertTrue(result.is_value)

    def test_bit_piece_from_memory_reads_containing_bytes(self):
        # fbreg 0 (frame base 0x2000); bit_piece(size=8, offset=8) reads the
        # two bytes that contain the field and extracts the high byte.
        store = bytes([0x77, 0x88])
        ctx = LocationContext(
            frame_base=0x2000, read_memory=lambda address, size: store[:size])
        expression = bytes([op('DW_OP_fbreg'), 0,
                            op('DW_OP_bit_piece'), 8, 8])
        result = self.eval(expression, ctx).materialize()
        self.assertEqual(result.pieces[0].value, 0x88)
        self.assertEqual(result.memory_accesses[0].size, 2)

    def test_mixed_register_and_memory_pieces_log_only_memory(self):
        memory = {0x1000: (0xAAAA).to_bytes(8, 'little')}
        ctx = LocationContext(
            read_register=lambda number: {3: 0x1234}[number],
            frame_base=0x1000,
            read_memory=lambda address, size: memory[address])
        # reg3 piece(8); fbreg 0 piece(8)
        expression = bytes([op('DW_OP_reg3'), op('DW_OP_piece'), 8,
                            op('DW_OP_fbreg'), 0,
                            op('DW_OP_piece'), 8])
        result = self.eval(expression, ctx).materialize()
        self.assertEqual([piece.value for piece in result.pieces],
                         [0x1234, 0xAAAA])
        self.assertEqual(len(result.memory_accesses), 1)
        self.assertEqual(result.memory_accesses[0].address, 0x1000)


class TestWordWidthAndEndianness(unittest.TestCase):
    structs32 = DWARFStructs(
        little_endian=True, dwarf_format=32, address_size=4)
    structs_be32 = DWARFStructs(
        little_endian=False, dwarf_format=32, address_size=4)

    def test_operand_wider_than_target_word_is_rejected(self):
        # const8u of 2**32 does not fit a 4-byte target; adding it must fail
        # with an explicit out-of-range reason rather than silently truncating.
        big = (1 << 32).to_bytes(8, 'little')
        expression = (bytes([DW_OP_name2opcode['DW_OP_lit0'],
                             DW_OP_name2opcode['DW_OP_const8u']]) + big +
                      bytes([op('DW_OP_plus')]))
        evaluator = LocationExpressionEvaluator(
            self.structs32, expression, LocationContext())
        with self.assertRaises(LocationEvalError) as caught:
            evaluator.locate()
        self.assertEqual(caught.exception.reason,
                         EvalReason.VALUE_OUT_OF_RANGE)

    def test_same_operand_fits_wider_target(self):
        big = (1 << 32).to_bytes(8, 'little')
        expression = (bytes([DW_OP_name2opcode['DW_OP_lit0'],
                             DW_OP_name2opcode['DW_OP_const8u']]) + big +
                      bytes([op('DW_OP_plus')]))
        structs64 = DWARFStructs(
            little_endian=True, dwarf_format=32, address_size=8)
        result = LocationExpressionEvaluator(
            structs64, expression, LocationContext()).locate()
        self.assertEqual(result.pieces[0].value, 1 << 32)

    def test_32bit_deref_uses_four_byte_word(self):
        memory = {0x4000: (0xCAFEBABE).to_bytes(4, 'little')}
        expression = (bytes([op('DW_OP_addr')]) +
                      (0x4000).to_bytes(4, 'little') +
                      bytes([op('DW_OP_deref')]))
        result = LocationExpressionEvaluator(
            self.structs32, expression,
            LocationContext(read_memory=lambda a, s: memory[a])).materialize()
        self.assertEqual(result.pieces[0].value, 0xCAFEBABE)
        self.assertEqual(result.memory_accesses[0].size, 4)

    def test_big_endian_deref(self):
        memory = {0x5000: bytes([0xDE, 0xAD, 0xBE, 0xEF])}
        expression = (bytes([op('DW_OP_addr')]) +
                      (0x5000).to_bytes(4, 'big') +
                      bytes([op('DW_OP_deref')]))
        result = LocationExpressionEvaluator(
            self.structs_be32, expression,
            LocationContext(read_memory=lambda a, s: memory[a])).materialize()
        self.assertEqual(result.pieces[0].value, 0xDEADBEEF)

    def test_implicit_value_carries_bytes_and_value(self):
        blob = bytes([1, 2, 3, 4])
        expression = bytes([op('DW_OP_implicit_value'), len(blob)]) + blob
        result = LocationExpressionEvaluator(
            self.structs_be32, expression, LocationContext()).locate()
        piece = result.pieces[0]
        self.assertEqual(piece.kind, PieceKind.IMPLICIT)
        self.assertEqual(piece.implicit, blob)
        self.assertEqual(piece.value, 0x01020304)


class TestSelector(unittest.TestCase):
    def _entry(self, begin, end, expr, absolute=False):
        from elftools.dwarf.locationlists import (
            LocationEntry, BaseAddressEntry)
        if begin is None:  # base-address entry
            return BaseAddressEntry(0, 0, base_address=end)
        return LocationEntry(0, 0, begin, end, list(expr), absolute)

    def test_picks_half_open_range(self):
        expr_a = bytes([0x55])
        expr_b = bytes([0x56])
        locations = [
            self._entry(0x1000, 0x1008, expr_a),
            self._entry(0x1008, 0x1010, expr_b),
        ]
        self.assertEqual(
            select_expression(locations, 0x1007).expression, expr_a)
        self.assertEqual(
            select_expression(locations, 0x1008).expression, expr_b)
        self.assertIsNone(select_expression(locations, 0x1010))

    def test_relative_entries_apply_base_address(self):
        expr = bytes([0x57])
        locations = [
            self._entry(None, 0x2000, b''),       # base address = 0x2000
            self._entry(0x10, 0x18, expr),        # relative -> 0x2010..0x2018
        ]
        selected = select_expression(locations, 0x2014)
        self.assertEqual(selected.expression, expr)
        self.assertEqual(selected.matched_begin, 0x2010)
        self.assertEqual(selected.matched_end, 0x2018)

    def test_default_location_used_when_no_range_matches(self):
        default_expr = bytes([0x53])
        locations = [
            self._entry(0x1000, 0x1008, bytes([0x55])),
            self._entry(-1, -1, default_expr),
        ]
        selected = select_expression(locations, 0x9999)
        self.assertTrue(selected.is_default)
        self.assertEqual(selected.expression, default_expr)

    def test_bare_location_expr_applies_everywhere(self):
        from elftools.dwarf.locationlists import LocationExpr
        selected = select_expression(LocationExpr(bytes([0x54])), 0x1234)
        self.assertEqual(selected.expression, bytes([0x54]))
        self.assertFalse(selected.is_default)


if __name__ == '__main__':
    unittest.main()
