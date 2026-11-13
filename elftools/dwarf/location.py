#-------------------------------------------------------------------------------
# elftools: dwarf/location.py
#
# Address-to-source lookup on top of the decoded DWARF line number programs.
#
# An optimized program can have more than one line table record for one
# machine address: duplicate rows may differ in file, line, column or
# discriminator, and the line programs of distinct compilation units may
# describe overlapping address ranges. The helpers in this module therefore
# return every matching row as a LocationCandidate carrying the reason the
# row matched, instead of picking a single row.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from ..common.utils import bytes2str
from .lineprogram import LINE_MATCH_EXACT, LINE_MATCH_RANGE, LineProgram

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .compileunit import CompileUnit


__all__ = [
    'LINE_MATCH_EXACT',
    'LINE_MATCH_RANGE',
    'LocationCandidate',
    'describe_location_candidate',
    'source_locations_for_address',
    'source_locations_for_lineprogram',
]


# LocationCandidate - one source location that a machine address may map to.
#
# cu:
#   The CompileUnit the line program belongs to, or None when the lookup is
#   performed on a standalone LineProgram with no CU attached.
#
# filename:
#   Resolved source file name, or None if the row's file index cannot be
#   resolved against the line program header.
#
# line, column:
#   Source line and column recorded by the matching line table row.
#
# discriminator:
#   DWARF discriminator of the row; nonzero discriminators distinguish blocks
#   assigned to the same source line on a duplicated address.
#
# address, end_address:
#   The half-open interval [address, end_address) for which the row is valid.
#   end_address == address marks a duplicate row reachable only through an
#   exact-address match.
#
# sequence_index:
#   Index of the sequence (the run of rows terminated by an end_sequence
#   marker) the row belongs to inside its line program.
#
# match_reason:
#   LINE_MATCH_EXACT when a row is emitted at the queried address, otherwise
#   LINE_MATCH_RANGE when the address falls inside the row's interval.
class LocationCandidate(NamedTuple):
    cu: CompileUnit | None
    filename: str | None
    line: int
    column: int
    discriminator: int
    address: int
    end_address: int
    sequence_index: int
    match_reason: str


def source_locations_for_lineprogram(
    line_program: LineProgram,
    address: int,
    cu: CompileUnit | None = None,
) -> tuple[LocationCandidate, ...]:
    """ Return all location candidates for an address within one line program.

        The line program's sequence-aware index does all the work: rows from
        a sequence already terminated by an end_sequence marker can never be
        reused, duplicate rows at the same address are all retained, and the
        result depends only on the address, so queries may be issued in any
        order without affecting later results.
    """
    return tuple(
        LocationCandidate(
            cu=cu,
            filename=line_program.filename_for_state(entry.state),
            line=entry.state.line,
            column=entry.state.column,
            discriminator=entry.state.discriminator,
            address=entry.state.address,
            end_address=entry.end_address,
            sequence_index=entry.sequence_index,
            match_reason=reason)
        for entry, reason in line_program.lookup_address(address))


def source_locations_for_address(
    line_programs: Iterable[tuple[CompileUnit | None, LineProgram]],
    address: int,
) -> tuple[LocationCandidate, ...]:
    """ Return all location candidates for an address across line programs.

        line_programs is an iterable of (compile unit, line program) pairs;
        the compile unit may be None for a standalone line program. Every
        program is queried independently, so overlapping compilation unit
        ranges simply contribute additional candidates rather than hiding one
        another. Candidates are returned in input order; within each program
        they follow line program emission order. The output for a given set
        of programs is deterministic and independent of query history.
    """
    candidates: list[LocationCandidate] = []
    for cu, line_program in line_programs:
        candidates.extend(
            source_locations_for_lineprogram(line_program, address, cu))
    return tuple(candidates)


def describe_location_candidate(candidate: LocationCandidate) -> str:
    """ Format a LocationCandidate as a compact human-readable string.

        Mainly useful for diagnostics and for tools that previously printed a
        single file/line pair.
    """
    cu_name = _cu_name(candidate.cu)
    source = candidate.filename if candidate.filename is not None else '<unknown>'
    text = f'{source}:{candidate.line}:{candidate.column}'
    if candidate.discriminator:
        text += f' discriminator={candidate.discriminator}'
    text += (
        f' [{candidate.match_reason} '
        f'0x{candidate.address:x}-0x{candidate.end_address:x}'
        f' seq={candidate.sequence_index}]')
    if cu_name is not None:
        text = f'CU {cu_name}: {text}'
    return text


def _cu_name(cu: CompileUnit | None) -> str | None:
    if cu is None:
        return None
    try:
        name = cu.get_top_DIE().attributes['DW_AT_name'].value
    except (KeyError, AttributeError):
        return f'0x{cu.cu_offset:x}'
    if isinstance(name, bytes):
        return bytes2str(name)
    return name
