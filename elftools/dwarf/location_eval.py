#-------------------------------------------------------------------------------
# elftools: dwarf/location_eval.py
#
# Restricted evaluation of DWARF location expressions.
#
# This module turns a location expression (already decoded by DWARFExprParser)
# into either a concrete *location description* (where a variable lives: a
# register, a memory address, or a composition of pieces) or its *value*.
#
# It never executes the target program and never interprets arbitrary bytes as
# Python code: every opcode is handled by an explicit, closed dispatch table.
# The evaluator is "hosted" - it has no access to the firmware itself.
# Register contents, frame base / CFA values, target memory and target-address
# resolution are supplied by the caller through a LocationContext. When
# something the expression needs is not provided, evaluation raises
# LocationEvalError carrying a machine-readable EvalReason rather than
# guessing.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, NamedTuple

from .dwarf_expr import DWARFExprParser, DW_OP_name2opcode
from .locationlists import (
    BaseAddressEntry,
    LocationEntry,
    LocationExpr,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from .dwarf_expr import DWARFExprOp
    from .locationlists import LocationParser as _LocationParserType
    from .structs import DWARFStructs


class EvalReason(str, Enum):
    """Machine-readable reasons an expression could not be fully evaluated."""

    # An opcode the restricted evaluator deliberately does not implement
    # (control flow, TLS, entry values, calls, type conversions, ...).
    UNSUPPORTED_OP = 'unsupported_operation'
    # Not enough values on the DWARF evaluation stack for an opcode.
    STACK_UNDERFLOW = 'stack_underflow'
    # An operand/result does not fit the target machine word width.
    VALUE_OUT_OF_RANGE = 'value_out_of_range'
    # Division or modulo by zero.
    DIVISION_BY_ZERO = 'division_by_zero'
    # The expression needs a register the caller did not provide.
    MISSING_REGISTER = 'missing_register'
    # The expression needs memory the caller did not provide / cannot read.
    MISSING_MEMORY = 'missing_memory'
    # fbreg / call_frame_cfa / push_object_address / addrx / constx needs a
    # provider the caller did not configure.
    MISSING_CONTEXT = 'missing_context'
    # The expression finished with an unexpected number of stack entries.
    MALFORMED_EXPRESSION = 'malformed_expression'
    # A piece references bits the evaluator cannot describe from this source.
    PIECE_UNSUPPORTED = 'piece_unsupported'
    # A value was requested for something that has no value (e.g. uninit).
    NOT_A_VALUE = 'not_a_value'


class LocationEvalError(Exception):
    """Raised when a location expression cannot be (fully) evaluated.

    ``reason`` is one of :class:`EvalReason`; ``detail`` is a human readable
    explanation including the offending opcode/offset when known.
    """

    def __init__(self, reason: EvalReason, detail: str) -> None:
        super().__init__(f'{reason.value}: {detail}')
        self.reason = reason
        self.detail = detail


@dataclass
class LocationContext:
    """Host services required to evaluate an expression.

    Every field is optional. ``read_register`` maps a DWARF register number to
    its unsigned integer contents and raises ``KeyError`` when the register is
    unavailable. ``read_memory`` maps ``(address, size)`` to ``size`` raw bytes
    and raises ``LookupError`` when the range is unreadable. The evaluator
    converts those into typed :class:`LocationEvalError`s.

    Attributes:
        read_register:    DWARF register number -> unsigned integer contents.
        read_memory:      (address, size) -> ``size`` raw target bytes.
        frame_base:       value for DW_OP_fbreg (enclosing frame base).
        cfa:              value for DW_OP_call_frame_cfa.
        object_address:   value for DW_OP_push_object_address.
        resolve_addr:     .debug_addr index -> target address (DW_OP_addrx /
                          DW_OP_GNU_addr_index).
        resolve_const:    index -> constant (DW_OP_constx /
                          DW_OP_GNU_const_index).
    """

    read_register: Callable[[int], int] | None = None
    read_memory: Callable[[int, int], bytes] | None = None
    frame_base: int | None = None
    cfa: int | None = None
    object_address: int | None = None
    resolve_addr: Callable[[int], int] | None = None
    resolve_const: Callable[[int], int] | None = None


class MemoryAccess(NamedTuple):
    """A single target-memory read performed during evaluation.

    ``available`` is False when the caller could not serve the read; the read
    is still recorded so callers can see every range that was attempted.
    """

    address: int
    size: int
    available: bool


class PieceKind(str, Enum):
    REGISTER = 'register'
    MEMORY = 'memory'
    VALUE = 'value'        # an actual value, not a storage address
    IMPLICIT = 'implicit'  # literal bytes carried by the DWARF itself


@dataclass
class LocationPiece:
    """One piece of a (possibly fragmented) variable.

    Meaning of fields by ``kind``:
        * REGISTER -> ``register`` set; bit fields narrow it when it came from
          DW_OP_bit_piece.
        * MEMORY   -> ``address`` is the computed byte address; ``size`` is
          the number of bytes occupied.
        * VALUE    -> ``value`` holds a materialized integer (only present in
          the result of materialize(), or for stack_value / literal pieces).
        * IMPLICIT -> ``implicit`` holds literal bytes from
          DW_OP_implicit_value.
    """

    kind: PieceKind
    size: int | None = None
    register: int | None = None
    address: int | None = None
    value: int | None = None
    implicit: bytes | None = None
    bit_offset: int = 0
    bit_size: int | None = None


@dataclass
class LocationResult:
    """Outcome of evaluating one location expression.

    ``pieces`` always holds at least one entry - even a scalar variable is
    represented as a one-piece list so callers have a single code path.
    ``memory_accesses`` records every target memory range touched, in order.
    ``is_value`` distinguishes "the variable lives at ..." from "the variable's
    value is ..." (DW_OP_stack_value / DW_OP_implicit_value).
    """

    pieces: list[LocationPiece]
    memory_accesses: list[MemoryAccess] = field(default_factory=list)
    is_value: bool = False


@dataclass
class _Entry:
    """A DWARF stack value plus evaluation bookkeeping.

    ``is_register`` marks a symbolic "variable is in this register" entry from
    DW_OP_reg*/DW_OP_regx (as opposed to a register's *contents* from
    DW_OP_breg*). ``is_value`` marks a computed value rather than a storage
    address. ``implicit`` carries literal bytes for implicit_value.
    """

    value: int
    bit_width: int
    is_register: bool = False
    is_value: bool = False
    implicit: bytes | None = None

    def clone(self) -> _Entry:
        return _Entry(self.value, self.bit_width, self.is_register,
                      self.is_value, self.implicit)


# Opcode boundary constants for the lit/reg/breg families.
_LIT0 = DW_OP_name2opcode['DW_OP_lit0']
_REG0 = DW_OP_name2opcode['DW_OP_reg0']
_BREG0 = DW_OP_name2opcode['DW_OP_breg0']


def _op(name: str) -> int:
    return DW_OP_name2opcode[name]


def _signed(value: int, bit_width: int) -> int:
    """Interpret the low ``bit_width`` bits of value as a signed integer."""
    mask = (1 << bit_width) - 1
    value &= mask
    sign_bit = 1 << (bit_width - 1)
    return value - (1 << bit_width) if value & sign_bit else value


class LocationExpressionEvaluator:
    """Evaluate one DWARF location expression against a hosted context.

    Construct one per expression, then call :meth:`locate` (storage
    description) and/or :meth:`materialize` (actual value). Both share the
    same memory-access log. The evaluator is reusable across those calls but
    does not retain state between different expressions.
    """

    def __init__(
        self,
        structs: DWARFStructs,
        expression: bytes | Sequence[int],
        context: LocationContext,
    ) -> None:
        self._structs = structs
        self._parser = DWARFExprParser(structs)
        self._expression = bytes(expression)
        self._context = context
        self._addr_size = structs.address_size
        self._word_bits = structs.address_size * 8
        self._word_mask = (1 << self._word_bits) - 1
        self._memory_accesses: list[MemoryAccess] = []
        self._stack: list[_Entry] = []
        self._pieces: list[LocationPiece] = []
        self._is_value = False

    #-- public API ---------------------------------------------------------
    def locate(self) -> LocationResult:
        """Return the storage description without reading the variable itself.

        Memory needed to *compute an address* (explicit derefs) is read and
        logged; the bytes that make up the variable's value are not read here.
        """
        self._evaluate()
        pieces = list(self._pieces) if self._pieces else self._terminal()
        return LocationResult(pieces, list(self._memory_accesses),
                              self._is_value)

    def materialize(self) -> LocationResult:
        """Read the variable's value from its backing store.

        Register and memory locations are read through the context; literal /
        implicit / stack values are passed through. Every backing-store read is
        appended to the memory-access log.
        """
        self._evaluate()
        source = self._pieces if self._pieces else self._terminal()
        pieces = [self._materialize_piece(piece) for piece in source]
        return LocationResult(pieces, list(self._memory_accesses),
                              self._is_value)

    #-- driver -------------------------------------------------------------
    def _evaluate(self) -> None:
        # Reset per-evaluation state so locate()/materialize() can be called
        # more than once on the same evaluator without accumulating state.
        self._stack = []
        self._pieces = []
        self._memory_accesses = []
        self._is_value = False
        for parsed in self._parser.parse_expr(self._expression):
            handler = self._HANDLERS.get(parsed.op)
            if handler is None:
                raise LocationEvalError(
                    EvalReason.UNSUPPORTED_OP,
                    f'{parsed.op_name} (opcode 0x{parsed.op:02x}) at '
                    f'expression offset {parsed.offset} is not supported by '
                    f'the restricted evaluator')
            handler(self, parsed)

    def _terminal(self) -> list[LocationPiece]:
        if len(self._stack) != 1:
            raise LocationEvalError(
                EvalReason.MALFORMED_EXPRESSION,
                f'expression ended with {len(self._stack)} stack entries; '
                f'expected exactly one')
        return [self._entry_to_piece(self._stack[0], None)]

    #-- stack helpers ------------------------------------------------------
    def _push(self, entry: _Entry) -> None:
        self._stack.append(entry)

    def _pop(self, op_name: str) -> _Entry:
        if not self._stack:
            raise LocationEvalError(
                EvalReason.STACK_UNDERFLOW,
                f'{op_name} popped from an empty stack')
        return self._stack.pop()

    def _pop2(self, op_name: str) -> tuple[_Entry, _Entry]:
        if len(self._stack) < 2:
            raise LocationEvalError(
                EvalReason.STACK_UNDERFLOW,
                f'{op_name} requires two stack entries')
        rhs = self._stack.pop()
        lhs = self._stack.pop()
        return lhs, rhs

    def _mask(self, value: int) -> int:
        return value & self._word_mask

    def _guard_word_width(self, entry: _Entry, op_name: str) -> None:
        if entry.bit_width > self._word_bits:
            raise LocationEvalError(
                EvalReason.VALUE_OUT_OF_RANGE,
                f'{op_name}: operand of {entry.bit_width} bits exceeds the '
                f'{self._word_bits}-bit target word')

    def _read_register(self, register: int, op_name: str) -> int:
        if self._context.read_register is None:
            raise LocationEvalError(
                EvalReason.MISSING_REGISTER,
                f'{op_name} needs register {register} but no register reader '
                f'was provided')
        try:
            return int(self._context.read_register(register)) & self._word_mask
        except KeyError as exc:
            raise LocationEvalError(
                EvalReason.MISSING_REGISTER,
                f'{op_name}: register {register} is unavailable ({exc})'
            ) from exc

    def _read_memory(self, address: int, size: int, op_name: str) -> int:
        address &= self._word_mask
        if self._context.read_memory is None:
            self._memory_accesses.append(MemoryAccess(address, size, False))
            raise LocationEvalError(
                EvalReason.MISSING_MEMORY,
                f'{op_name} needs {size} byte(s) at 0x{address:x} but no '
                f'memory reader was provided')
        try:
            data = self._context.read_memory(address, size)
        except LookupError as exc:
            self._memory_accesses.append(MemoryAccess(address, size, False))
            raise LocationEvalError(
                EvalReason.MISSING_MEMORY,
                f'{op_name}: {size} byte(s) at 0x{address:x} are unreadable '
                f'({exc})') from exc
        if len(data) != size:
            self._memory_accesses.append(MemoryAccess(address, size, False))
            raise LocationEvalError(
                EvalReason.MISSING_MEMORY,
                f'{op_name}: expected {size} byte(s) at 0x{address:x}, got '
                f'{len(data)}')
        self._memory_accesses.append(MemoryAccess(address, size, True))
        return int.from_bytes(data, byteorder=self._endianness())

    def _endianness(self) -> str:
        return 'little' if self._structs.little_endian else 'big'

    def _require(self, value: object, what: str, op_name: str) -> None:
        if value is None:
            raise LocationEvalError(
                EvalReason.MISSING_CONTEXT,
                f'{op_name} requires {what}, which was not provided')

    #-- arithmetic ---------------------------------------------------------
    def _unary(self, op: DWARFExprOp,
               fn: Callable[[int], int]) -> None:
        entry = self._pop(op.op_name)
        self._guard_word_width(entry, op.op_name)
        result = self._mask(fn(entry.value))
        self._push(_Entry(result, self._word_bits, is_value=entry.is_value))

    def _binop(self, op: DWARFExprOp,
               fn: Callable[[int, int], int],
               signed: bool = False) -> None:
        lhs, rhs = self._pop2(op.op_name)
        self._guard_word_width(lhs, op.op_name)
        self._guard_word_width(rhs, op.op_name)
        left = _signed(lhs.value, lhs.bit_width) if signed else lhs.value
        right = _signed(rhs.value, rhs.bit_width) if signed else rhs.value
        result = fn(left, right)
        if not (0 <= result <= self._word_mask) and not signed:
            raise LocationEvalError(
                EvalReason.VALUE_OUT_OF_RANGE,
                f'{op.op_name}: result {result} does not fit the '
                f'{self._word_bits}-bit target word')
        self._push(_Entry(self._mask(result), self._word_bits,
                          is_value=(lhs.is_value or rhs.is_value)))

    def _signed_div(self, op: DWARFExprOp) -> None:
        lhs, rhs = self._pop2(op.op_name)
        self._guard_word_width(lhs, op.op_name)
        self._guard_word_width(rhs, op.op_name)
        divisor = _signed(rhs.value, rhs.bit_width)
        if divisor == 0:
            raise LocationEvalError(EvalReason.DIVISION_BY_ZERO,
                                    'DW_OP_div: division by zero')
        # DWARF: truncation toward zero.
        quotient = int(_signed(lhs.value, lhs.bit_width) / divisor)
        self._push(_Entry(self._mask(quotient), self._word_bits,
                          is_value=(lhs.is_value or rhs.is_value)))

    def _signed_mod(self, op: DWARFExprOp) -> None:
        lhs, rhs = self._pop2(op.op_name)
        self._guard_word_width(lhs, op.op_name)
        self._guard_word_width(rhs, op.op_name)
        divisor = _signed(rhs.value, rhs.bit_width)
        if divisor == 0:
            raise LocationEvalError(EvalReason.DIVISION_BY_ZERO,
                                    'DW_OP_mod: modulo by zero')
        remainder = _signed(lhs.value, lhs.bit_width) - (
            int(_signed(lhs.value, lhs.bit_width) / divisor) * divisor)
        self._push(_Entry(self._mask(remainder), self._word_bits,
                          is_value=(lhs.is_value or rhs.is_value)))

    def _shift(self, op: DWARFExprOp, logical: bool) -> None:
        lhs, rhs = self._pop2(op.op_name)
        self._guard_word_width(lhs, op.op_name)
        amount = rhs.value
        if amount >= self._word_bits:
            raise LocationEvalError(
                EvalReason.VALUE_OUT_OF_RANGE,
                f'{op.op_name}: shift amount {amount} exceeds the '
                f'{self._word_bits}-bit target word')
        if logical:
            if op.op == _op('DW_OP_shl'):
                result = lhs.value << amount
            else:  # DW_OP_shr: logical right shift
                result = lhs.value >> amount
            if not 0 <= result <= self._word_mask:
                raise LocationEvalError(
                    EvalReason.VALUE_OUT_OF_RANGE,
                    f'{op.op_name}: result does not fit the target word')
        else:  # DW_OP_shra: arithmetic right shift; result may be negative
            result = _signed(lhs.value, lhs.bit_width) >> amount
        self._push(_Entry(self._mask(result), self._word_bits,
                          is_value=lhs.is_value))

    def _compare(self, op: DWARFExprOp,
                 fn: Callable[[int, int], bool]) -> None:
        lhs, rhs = self._pop2(op.op_name)
        self._guard_word_width(lhs, op.op_name)
        self._guard_word_width(rhs, op.op_name)
        signed = op.op_name in ('DW_OP_le', 'DW_OP_lt', 'DW_OP_ge',
                                'DW_OP_gt')
        left = _signed(lhs.value, lhs.bit_width) if signed else lhs.value
        right = _signed(rhs.value, rhs.bit_width) if signed else rhs.value
        self._push(_Entry(1 if fn(left, right) else 0, self._word_bits,
                          is_value=True))

    #-- pieces -------------------------------------------------------------
    def _entry_to_piece(self, entry: _Entry,
                        byte_size: int | None) -> LocationPiece:
        bit_size = byte_size * 8 if byte_size is not None else None
        if entry.implicit is not None:
            implicit_value = int.from_bytes(
                entry.implicit, byteorder=self._endianness())
            return LocationPiece(
                kind=PieceKind.IMPLICIT, size=len(entry.implicit),
                value=implicit_value, implicit=entry.implicit,
                bit_size=bit_size or len(entry.implicit) * 8)
        if entry.is_register:
            return LocationPiece(
                kind=PieceKind.REGISTER, size=byte_size,
                register=entry.value,
                bit_size=bit_size or self._word_bits)
        if entry.is_value:
            return LocationPiece(
                kind=PieceKind.VALUE, size=byte_size, value=entry.value,
                bit_size=bit_size or self._word_bits)
        return LocationPiece(
            kind=PieceKind.MEMORY,
            size=byte_size or self._addr_size,
            address=entry.value & self._word_mask,
            bit_size=bit_size or self._word_bits)

    def _consume_piece(self, op: DWARFExprOp) -> _Entry | None:
        if len(self._stack) > 1:
            raise LocationEvalError(
                EvalReason.PIECE_UNSUPPORTED,
                f'{op.op_name}: {len(self._stack)} live stack entries at a '
                f'piece boundary is not representable')
        return self._stack.pop() if self._stack else None

    def _op_piece(self, op: DWARFExprOp) -> None:
        byte_size = op.args[0]
        entry = self._consume_piece(op)
        if entry is None:
            self._pieces.append(LocationPiece(
                kind=PieceKind.VALUE, size=byte_size, value=None,
                bit_size=byte_size * 8 if byte_size else None))
            return
        piece = self._entry_to_piece(entry, byte_size)
        self._pieces.append(piece)

    def _op_bit_piece(self, op: DWARFExprOp) -> None:
        bit_size, bit_offset = op.args
        byte_size = (bit_size + bit_offset + 7) // 8 if bit_size else None
        entry = self._consume_piece(op)
        if entry is None:
            self._pieces.append(LocationPiece(
                kind=PieceKind.VALUE, size=byte_size, value=None,
                bit_offset=bit_offset, bit_size=bit_size))
            return
        if entry.implicit is not None:
            container = int.from_bytes(entry.implicit,
                                       byteorder=self._endianness())
            extracted = (container >> bit_offset) & (
                (1 << bit_size) - 1) if bit_size else 0
            self._pieces.append(LocationPiece(
                kind=PieceKind.VALUE, size=byte_size, value=extracted,
                bit_offset=bit_offset, bit_size=bit_size))
            return
        if entry.is_value:
            extracted = (entry.value >> bit_offset) & (
                (1 << bit_size) - 1) if bit_size else 0
            self._pieces.append(LocationPiece(
                kind=PieceKind.VALUE, size=byte_size, value=extracted,
                bit_offset=bit_offset, bit_size=bit_size))
            return
        # Register or memory source: keep the location and record the bit
        # window; materialize() applies it after reading the container.
        piece = self._entry_to_piece(entry, byte_size)
        piece.bit_offset = bit_offset
        piece.bit_size = bit_size
        self._pieces.append(piece)

    def _materialize_piece(self, piece: LocationPiece) -> LocationPiece:
        if piece.kind in (PieceKind.IMPLICIT, PieceKind.VALUE):
            return piece
        if piece.kind is PieceKind.REGISTER:
            raw = self._read_register(piece.register, 'piece register read')
            raw = self._apply_bit_window(raw, piece)
            return LocationPiece(
                kind=PieceKind.VALUE, size=piece.size, value=raw,
                bit_offset=piece.bit_offset, bit_size=piece.bit_size)
        size = piece.size or self._addr_size
        raw = self._read_memory(piece.address, size, 'piece memory read')
        raw = self._apply_bit_window(raw, piece)
        return LocationPiece(
            kind=PieceKind.VALUE, size=size, value=raw,
            bit_offset=piece.bit_offset, bit_size=piece.bit_size)

    @staticmethod
    def _apply_bit_window(value: int, piece: LocationPiece) -> int:
        if piece.bit_size is None:
            return value
        shifted = value >> piece.bit_offset
        return shifted & ((1 << piece.bit_size) - 1) if piece.bit_size else 0

    #-- opcode handlers ----------------------------------------------------
    def _op_addr(self, op: DWARFExprOp) -> None:
        self._push(_Entry(op.args[0] & self._word_mask, self._word_bits))

    def _op_const_sized(self, op: DWARFExprOp) -> None:
        widths = {
            _op('DW_OP_const1u'): 8, _op('DW_OP_const1s'): 8,
            _op('DW_OP_const2u'): 16, _op('DW_OP_const2s'): 16,
            _op('DW_OP_const4u'): 32, _op('DW_OP_const4s'): 32,
            _op('DW_OP_const8u'): 64, _op('DW_OP_const8s'): 64,
        }
        self._push(_Entry(op.args[0] & ((1 << widths[op.op]) - 1),
                          widths[op.op], is_value=True))

    def _op_constu(self, op: DWARFExprOp) -> None:
        self._push(_Entry(op.args[0] & self._word_mask, self._word_bits,
                          is_value=True))

    def _op_consts(self, op: DWARFExprOp) -> None:
        self._push(_Entry(self._mask(op.args[0]), self._word_bits,
                          is_value=True))

    def _op_lit(self, op: DWARFExprOp) -> None:
        self._push(_Entry(op.op - _LIT0, 8, is_value=True))

    def _op_reg(self, op: DWARFExprOp) -> None:
        # Symbolic register location: the register is intentionally NOT read.
        self._push(_Entry(op.op - _REG0, self._word_bits, is_register=True))

    def _op_regx(self, op: DWARFExprOp) -> None:
        self._push(_Entry(op.args[0], self._word_bits, is_register=True))

    def _op_breg(self, op: DWARFExprOp) -> None:
        base = self._read_register(op.op - _BREG0, op.op_name)
        self._push(_Entry(self._mask(base + op.args[0]), self._word_bits))

    def _op_bregx(self, op: DWARFExprOp) -> None:
        register, offset = op.args
        base = self._read_register(register, op.op_name)
        self._push(_Entry(self._mask(base + offset), self._word_bits))

    def _op_fbreg(self, op: DWARFExprOp) -> None:
        self._require(self._context.frame_base, 'a frame base', op.op_name)
        self._push(_Entry(
            self._mask(self._context.frame_base + op.args[0]),
            self._word_bits))

    def _op_cfa(self, op: DWARFExprOp) -> None:
        self._require(self._context.cfa, 'the CFA', op.op_name)
        self._push(_Entry(self._mask(self._context.cfa), self._word_bits))

    def _op_object_address(self, op: DWARFExprOp) -> None:
        self._require(self._context.object_address, 'the object address',
                      op.op_name)
        self._push(_Entry(self._mask(self._context.object_address),
                          self._word_bits))

    def _op_addrx(self, op: DWARFExprOp) -> None:
        self._require(self._context.resolve_addr,
                      'a .debug_addr index resolver', op.op_name)
        self._push(_Entry(
            self._mask(self._context.resolve_addr(op.args[0])),
            self._word_bits))

    def _op_constx(self, op: DWARFExprOp) -> None:
        self._require(self._context.resolve_const,
                      'a constant-index resolver', op.op_name)
        self._push(_Entry(
            self._mask(self._context.resolve_const(op.args[0])),
            self._word_bits, is_value=True))

    def _op_deref(self, op: DWARFExprOp) -> None:
        entry = self._pop(op.op_name)
        value = self._read_memory(entry.value & self._word_mask,
                                  self._addr_size, op.op_name)
        # A dereference yields the *value* stored at the address, not another
        # storage address.
        self._push(_Entry(value, self._word_bits, is_value=True))

    def _op_deref_size(self, op: DWARFExprOp) -> None:
        size = op.args[0]
        if not 1 <= size <= self._addr_size:
            raise LocationEvalError(
                EvalReason.VALUE_OUT_OF_RANGE,
                f'{op.op_name}: size {size} is outside the target word')
        entry = self._pop(op.op_name)
        value = self._read_memory(entry.value & self._word_mask, size,
                                  op.op_name)
        self._push(_Entry(value, size * 8, is_value=True))

    def _op_plus_uconst(self, op: DWARFExprOp) -> None:
        entry = self._pop(op.op_name)
        self._push(_Entry(
            self._mask(entry.value + op.args[0]), self._word_bits,
            is_register=entry.is_register, is_value=entry.is_value))

    def _op_implicit_value(self, op: DWARFExprOp) -> None:
        blob = bytes(op.args[0])
        self._push(_Entry(
            int.from_bytes(blob, byteorder=self._endianness()),
            len(blob) * 8, is_value=True, implicit=blob))
        self._is_value = True

    def _op_stack_value(self, op: DWARFExprOp) -> None:
        entry = self._pop(op.op_name)
        self._push(_Entry(entry.value, entry.bit_width, is_register=False,
                          is_value=True))
        self._is_value = True

    def _op_nop(self, op: DWARFExprOp) -> None:
        return

    def _op_uninit(self, op: DWARFExprOp) -> None:
        raise LocationEvalError(
            EvalReason.NOT_A_VALUE,
            f'{op.op_name}: the variable is uninitialized at this location')

    def _op_dup(self, op: DWARFExprOp) -> None:
        if not self._stack:
            raise LocationEvalError(EvalReason.STACK_UNDERFLOW,
                                    'DW_OP_dup on an empty stack')
        self._stack.append(self._stack[-1].clone())

    def _op_drop(self, op: DWARFExprOp) -> None:
        self._pop(op.op_name)

    def _op_over(self, op: DWARFExprOp) -> None:
        if len(self._stack) < 2:
            raise LocationEvalError(EvalReason.STACK_UNDERFLOW,
                                    'DW_OP_over needs two stack entries')
        self._stack.append(self._stack[-2].clone())

    def _op_pick(self, op: DWARFExprOp) -> None:
        index = op.args[0]
        if index >= len(self._stack):
            raise LocationEvalError(
                EvalReason.STACK_UNDERFLOW,
                f'DW_OP_pick index {index} exceeds stack depth '
                f'{len(self._stack)}')
        self._stack.append(self._stack[-1 - index].clone())

    def _op_swap(self, op: DWARFExprOp) -> None:
        if len(self._stack) < 2:
            raise LocationEvalError(EvalReason.STACK_UNDERFLOW,
                                    'DW_OP_swap needs two stack entries')
        self._stack[-1], self._stack[-2] = (self._stack[-2], self._stack[-1])

    def _op_rot(self, op: DWARFExprOp) -> None:
        if len(self._stack) < 3:
            raise LocationEvalError(EvalReason.STACK_UNDERFLOW,
                                    'DW_OP_rot needs three stack entries')
        self._stack[-3], self._stack[-2], self._stack[-1] = (
            self._stack[-2], self._stack[-1], self._stack[-3])


def _build_handlers() -> dict[int, Callable]:
    e = LocationExpressionEvaluator
    table: dict[int, Callable] = {
        _op('DW_OP_addr'): e._op_addr,
        _op('DW_OP_const1u'): e._op_const_sized,
        _op('DW_OP_const1s'): e._op_const_sized,
        _op('DW_OP_const2u'): e._op_const_sized,
        _op('DW_OP_const2s'): e._op_const_sized,
        _op('DW_OP_const4u'): e._op_const_sized,
        _op('DW_OP_const4s'): e._op_const_sized,
        _op('DW_OP_const8u'): e._op_const_sized,
        _op('DW_OP_const8s'): e._op_const_sized,
        _op('DW_OP_constu'): e._op_constu,
        _op('DW_OP_consts'): e._op_consts,
        _op('DW_OP_regx'): e._op_regx,
        _op('DW_OP_fbreg'): e._op_fbreg,
        _op('DW_OP_bregx'): e._op_bregx,
        _op('DW_OP_piece'): e._op_piece,
        _op('DW_OP_deref_size'): e._op_deref_size,
        _op('DW_OP_nop'): e._op_nop,
        _op('DW_OP_push_object_address'): e._op_object_address,
        _op('DW_OP_call_frame_cfa'): e._op_cfa,
        _op('DW_OP_bit_piece'): e._op_bit_piece,
        _op('DW_OP_implicit_value'): e._op_implicit_value,
        _op('DW_OP_stack_value'): e._op_stack_value,
        _op('DW_OP_addrx'): e._op_addrx,
        _op('DW_OP_constx'): e._op_constx,
        _op('DW_OP_GNU_addr_index'): e._op_addrx,
        _op('DW_OP_GNU_const_index'): e._op_constx,
        _op('DW_OP_GNU_uninit'): e._op_uninit,
        _op('DW_OP_dup'): e._op_dup,
        _op('DW_OP_drop'): e._op_drop,
        _op('DW_OP_over'): e._op_over,
        _op('DW_OP_pick'): e._op_pick,
        _op('DW_OP_swap'): e._op_swap,
        _op('DW_OP_rot'): e._op_rot,
        _op('DW_OP_deref'): e._op_deref,
        _op('DW_OP_abs'): lambda s, o: s._unary(o, abs),
        _op('DW_OP_neg'): lambda s, o: s._unary(o, lambda v: -v),
        _op('DW_OP_not'): lambda s, o: s._unary(o, lambda v: ~v),
        _op('DW_OP_and'): lambda s, o: s._binop(o, lambda a, b: a & b),
        _op('DW_OP_div'): e._signed_div,
        _op('DW_OP_minus'): lambda s, o: s._binop(o, lambda a, b: a - b),
        _op('DW_OP_mod'): e._signed_mod,
        _op('DW_OP_mul'): lambda s, o: s._binop(o, lambda a, b: a * b),
        _op('DW_OP_or'): lambda s, o: s._binop(o, lambda a, b: a | b),
        _op('DW_OP_plus'): lambda s, o: s._binop(o, lambda a, b: a + b),
        _op('DW_OP_plus_uconst'): e._op_plus_uconst,
        _op('DW_OP_shl'): lambda s, o: s._shift(o, logical=True),
        _op('DW_OP_shr'): lambda s, o: s._shift(o, logical=True),
        _op('DW_OP_shra'): lambda s, o: s._shift(o, logical=False),
        _op('DW_OP_xor'): lambda s, o: s._binop(o, lambda a, b: a ^ b),
        _op('DW_OP_eq'): lambda s, o: s._compare(o, lambda a, b: a == b),
        _op('DW_OP_ge'): lambda s, o: s._compare(o, lambda a, b: a >= b),
        _op('DW_OP_gt'): lambda s, o: s._compare(o, lambda a, b: a > b),
        _op('DW_OP_le'): lambda s, o: s._compare(o, lambda a, b: a <= b),
        _op('DW_OP_lt'): lambda s, o: s._compare(o, lambda a, b: a < b),
        _op('DW_OP_ne'): lambda s, o: s._compare(o, lambda a, b: a != b),
    }
    for index in range(32):
        table[0x30 + index] = e._op_lit
        table[0x50 + index] = e._op_reg
        table[0x70 + index] = e._op_breg
    return table


LocationExpressionEvaluator._HANDLERS = _build_handlers()


#-----------------------------------------------------------------------------
# Choosing the expression that applies at a given instruction address
#-----------------------------------------------------------------------------
@dataclass
class SelectedExpression:
    """The location expression selected for an instruction address.

    ``expression`` is the raw DWARF expression bytes to feed to an evaluator.
    ``is_default`` marks a DW_LLE_default_location chosen because no range
    matched. When nothing applies, :func:`select_expression` returns None.
    """

    expression: bytes
    is_default: bool = False
    matched_begin: int | None = None
    matched_end: int | None = None


def select_expression(
    location: LocationExpr | list[object],
    address: int,
    initial_base: int = 0,
) -> SelectedExpression | None:
    """Pick the location expression valid at ``address``.

    ``location`` is whatever ``LocationParser.parse_from_attribute`` returns:
    a :class:`~elftools.dwarf.locationlists.LocationExpr` (a single
    expression, valid everywhere) or a list of
    :class:`~elftools.dwarf.locationlists.LocationEntry` /
    :class:`~elftools.dwarf.locationlists.BaseAddressEntry` objects.

    Selection follows the DWARF rules: a running base address is updated by
    base-address entries, relative range entries are added to that base, and a
    half-open range ``[begin, end)`` matches when ``begin <= address < end``. A
    default-location entry (begin == end == -1) is used only if no concrete
    range matches.
    """
    # A bare LocationExpr applies at every PC.
    if hasattr(location, 'loc_expr') and not isinstance(location, list):
        return SelectedExpression(expression=bytes(location.loc_expr))

    if not isinstance(location, list):
        return None

    base_address = initial_base
    default: bytes | None = None
    for entry in location:
        if isinstance(entry, BaseAddressEntry):
            base_address = entry.base_address
            continue
        if not isinstance(entry, LocationEntry):
            # LocationViewPair and friends carry no selectable expression.
            continue

        begin = entry.begin_offset
        end = entry.end_offset
        if begin == -1 and end == -1:
            # DW_LLE_default_location
            default = bytes(entry.loc_expr)
            continue
        if not entry.is_absolute:
            begin += base_address
            end += base_address
        if begin <= address < end:
            return SelectedExpression(
                expression=bytes(entry.loc_expr),
                is_default=False,
                matched_begin=begin,
                matched_end=end)

    if default is not None:
        return SelectedExpression(expression=default, is_default=True)
    return None


#-----------------------------------------------------------------------------
# High-level helper bridging pyelftools DIEs and the evaluator
#-----------------------------------------------------------------------------
if TYPE_CHECKING:
    from .die import DIE


class VariableLocator:
    """Resolve a variable's location/value at an instruction address.

    This glues three pieces together: pyelftools' :class:`LocationParser`
    (attribute -> expression or location list), :func:`select_expression`
    (pick the expression for a given PC) and
    :class:`LocationExpressionEvaluator` (restricted, hosted evaluation).

    The locator never opens or runs the firmware; all target access goes
    through the caller-supplied :class:`LocationContext`.
    """

    def __init__(self, location_parser: _LocationParserType) -> None:
        self._location_parser = location_parser

    def parse_attribute(self, die: DIE):
        """Return the parsed location information held by a DIE.

        Returns a LocationExpr or a location-list entry list, or None if the
        DIE has no DW_AT_location attribute.
        """
        attr = die.attributes.get('DW_AT_location')
        if attr is None:
            return None
        version = die.cu['version']
        if not self._location_parser.attribute_has_location(attr, version):
            return None
        return self._location_parser.parse_from_attribute(attr, version, die)

    def locate(
        self,
        die: DIE,
        address: int,
        context: LocationContext,
    ) -> LocationResult:
        """Describe where the variable in ``die`` is stored at ``address``."""
        return self._resolve(die, address, context, materialize=False)

    def materialize(
        self,
        die: DIE,
        address: int,
        context: LocationContext,
    ) -> LocationResult:
        """Read the variable's value at ``address`` via the hosted context."""
        return self._resolve(die, address, context, materialize=True)

    def _resolve(
        self,
        die: DIE,
        address: int,
        context: LocationContext,
        materialize: bool,
    ) -> LocationResult:
        parsed = self.parse_attribute(die)
        if parsed is None:
            raise LocationEvalError(
                EvalReason.MALFORMED_EXPRESSION,
                'DIE has no DW_AT_location location information')
        selected = select_expression(parsed, address)
        if selected is None:
            raise LocationEvalError(
                EvalReason.MALFORMED_EXPRESSION,
                f'no location expression covers address 0x{address:x}')
        evaluator = LocationExpressionEvaluator(
            die.cu.structs, selected.expression, context)
        return evaluator.materialize() if materialize else evaluator.locate()
