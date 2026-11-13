#-------------------------------------------------------------------------------
# elftools tests
#
# Address-to-source lookup on synthetic DWARF line number programs. The line
# tables are generated in-process by line_table_builder, so the tricky cases
# for optimized code - duplicate addresses, end_sequence resets, adjacent
# sequences, discriminators and files appended from the program - can be
# exercised deterministically without compiling a large program.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from elftools.dwarf.lineprogram import LINE_MATCH_EXACT, LINE_MATCH_RANGE
from elftools.dwarf.location import (
    describe_location_candidate,
    source_locations_for_address,
    source_locations_for_lineprogram,
)
from elftools.elf.elffile import ELFFile

from line_table_builder import FileSpec, LineTableBuilder


SAMPLE_ELF = os.path.join(
    os.path.dirname(__file__), '..', 'examples', 'sample_exe64.elf')


class FakeCU:
    """ Minimal stand-in for a CompileUnit in cross-CU aggregation tests.
    """
    def __init__(self, offset):
        self.cu_offset = offset

    def get_top_DIE(self):
        # No DW_AT_name: describe_location_candidate falls back to the offset.
        raise KeyError('DW_AT_name')


class TestAddressLocation(unittest.TestCase):
    def _build_two_sequences(self):
        # Sequence 0 starts with two rows at the same address (an optimized
        # block with a discriminator), followed by an advancing row.
        # Sequence 1 is an adjacent, separately terminated sequence.
        return (
            LineTableBuilder([FileSpec('a.c'), FileSpec('b.c')])
            .row(0x100, 10, file=1, column=1)
            .row(0x100, 11, file=2, column=2, discriminator=3)
            .row(0x110, 12, column=2)
            .end_sequence()
            .row(0x200, 20, column=1)
            .row(0x210, 21, column=1)
            .end_sequence()
            .build())

    def test_line_table_indexes_intervals_and_sequences(self):
        lp = self._build_two_sequences()
        table = lp.line_table

        # Two end_sequence markers were emitted, but they are boundary rows
        # and must not appear in the indexed table.
        self.assertEqual(len(table), 5)
        self.assertEqual(
            [entry.sequence_index for entry in table],
            [0, 0, 0, 1, 1])

        # Intervals are half-open and computed within each sequence. The first
        # duplicate row has an empty interval; the second one owns [0x100,
        # 0x110). The end_sequence address (0x110) bounds the last row.
        self.assertEqual(
            [(hex(entry.state.address), hex(entry.end_address))
             for entry in table],
            [('0x100', '0x100'),
             ('0x100', '0x110'),
             ('0x110', '0x110'),
             ('0x200', '0x210'),
             ('0x210', '0x210')])

        # end_sequence rows never leak into the table.
        decoded_states = [
            entry.state for entry in lp.get_entries()
            if entry.state is not None]
        self.assertTrue(
            all(not entry.state.end_sequence for entry in table))
        self.assertTrue(any(state.end_sequence for state in decoded_states))

    def test_duplicate_address_returns_every_row(self):
        lp = self._build_two_sequences()
        candidates = source_locations_for_lineprogram(lp, 0x100)

        # Both rows emitted at 0x100 survive; neither first nor last wins.
        self.assertEqual(len(candidates), 2)
        self.assertEqual(
            [(c.filename, c.line, c.column, c.discriminator)
             for c in candidates],
            [('a.c', 10, 1, 0),
             ('b.c', 11, 2, 3)])
        self.assertTrue(
            all(c.match_reason == LINE_MATCH_EXACT for c in candidates))
        # The earlier duplicate has an empty interval but is still reachable.
        self.assertEqual(candidates[0].address, candidates[0].end_address)
        self.assertEqual(candidates[1].end_address, 0x110)

    def test_exact_match_takes_precedence_over_range(self):
        lp = self._build_two_sequences()

        # 0x108 sits inside the interval owned by the second 0x100 row, but
        # no row is emitted at 0x108, so it is a range match.
        range_candidates = source_locations_for_lineprogram(lp, 0x108)
        self.assertEqual(len(range_candidates), 1)
        self.assertEqual(range_candidates[0].match_reason, LINE_MATCH_RANGE)
        self.assertEqual(range_candidates[0].line, 11)
        self.assertEqual(
            (range_candidates[0].address, range_candidates[0].end_address),
            (0x100, 0x110))

        # An exact row address must never also report the covering row.
        exact_candidates = source_locations_for_lineprogram(lp, 0x110)
        self.assertEqual(len(exact_candidates), 1)
        self.assertEqual(
            exact_candidates[0].match_reason, LINE_MATCH_EXACT)
        self.assertEqual(exact_candidates[0].line, 12)

    def test_end_sequence_resets_state_between_sequences(self):
        lp = self._build_two_sequences()

        # Addresses past the first sequence's end_sequence boundary (0x110)
        # and before the second sequence starts (0x200) match nothing: the
        # previous sequence's rows must not be reused.
        self.assertEqual(
            source_locations_for_lineprogram(lp, 0x150), ())
        self.assertEqual(
            source_locations_for_lineprogram(lp, 0x110 + 0),
            source_locations_for_lineprogram(lp, 0x110))

        # The second sequence is indexed independently.
        candidates = source_locations_for_lineprogram(lp, 0x205)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].line, 20)
        self.assertEqual(candidates[0].sequence_index, 1)
        self.assertEqual(
            (candidates[0].address, candidates[0].end_address),
            (0x200, 0x210))

        # One past the final end_sequence address is outside every sequence.
        self.assertEqual(
            source_locations_for_lineprogram(lp, 0x300), ())

    def test_discriminator_is_preserved(self):
        lp = self._build_two_sequences()
        candidates = source_locations_for_lineprogram(lp, 0x100)
        discriminators = {c.discriminator for c in candidates}
        self.assertEqual(discriminators, {0, 3})
        described = [describe_location_candidate(c) for c in candidates]
        self.assertTrue(
            any('discriminator=3' in text for text in described))
        self.assertTrue(
            all('seq=0' in text for text in described))

    def test_define_file_extends_header_file_table(self):
        # Only one file exists in the header; the program appends a second
        # file with DW_LNE.define_file and then emits a row referencing it.
        lp = (
            LineTableBuilder([FileSpec('header.c')])
            .row(0x100, 30, file=1)
            .define_file(FileSpec('appended.c'))
            .row(0x110, 31, file=2)
            .end_sequence()
            .build())

        # Decoding the program runs DW_LNE.define_file and appends the new
        # file entry to the header's file table.
        lp.get_entries()
        self.assertEqual(
            [entry.name for entry in lp.header['file_entry']],
            [b'header.c', b'appended.c'])

        candidates = source_locations_for_lineprogram(lp, 0x110)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].filename, 'appended.c')
        self.assertEqual(candidates[0].line, 31)

    def test_lookup_order_does_not_change_results(self):
        lp = self._build_two_sequences()
        addresses = [0x100, 0x108, 0x110, 0x150, 0x200, 0x205, 0x210, 0x300]

        baseline = {
            addr: source_locations_for_lineprogram(lp, addr)
            for addr in addresses}

        # Repeated, shuffled queries must return identical candidate tuples:
        # the index is built once and lookups hold no mutable state.
        rng = random.Random(20261113)
        for _ in range(10):
            shuffled = addresses[:]
            rng.shuffle(shuffled)
            for addr in shuffled:
                self.assertEqual(
                    source_locations_for_lineprogram(lp, addr),
                    baseline[addr])

        # The indexed table itself is cached and identical on repeated access.
        self.assertIs(lp.line_table, lp.line_table)

    def test_overlapping_compilation_units_both_contribute(self):
        first = (
            LineTableBuilder([FileSpec('one.c')])
            .row(0x500, 40, column=1)
            .row(0x510, 41, column=1)
            .end_sequence()
            .build())
        second = (
            LineTableBuilder([FileSpec('two.c')])
            .row(0x500, 77, column=3)
            .row(0x520, 78, column=3)
            .end_sequence()
            .build())
        cu_one = FakeCU(0x1000)
        cu_two = FakeCU(0x2000)

        candidates = source_locations_for_address(
            [(cu_one, first), (cu_two, second)], 0x500)

        # Both CUs describe 0x500; overlapping ranges must not hide either.
        self.assertEqual(len(candidates), 2)
        self.assertEqual(
            [c.cu.cu_offset for c in candidates],
            [0x1000, 0x2000])
        self.assertEqual(
            [c.filename for c in candidates], ['one.c', 'two.c'])
        self.assertEqual(
            [c.line for c in candidates], [40, 77])
        self.assertTrue(
            all(c.match_reason == LINE_MATCH_EXACT for c in candidates))

        # An address covered only through an interval still reports the CU
        # that owns the interval.
        covered = source_locations_for_address(
            [(cu_one, first), (cu_two, second)], 0x518)
        self.assertEqual(len(covered), 1)
        self.assertIs(covered[0].cu, cu_two)
        self.assertEqual(covered[0].match_reason, LINE_MATCH_RANGE)

        # Program order, like query order, must not alter the candidates.
        swapped = source_locations_for_address(
            [(cu_two, second), (cu_one, first)], 0x500)
        self.assertEqual(
            [(c.cu.cu_offset, c.line) for c in swapped],
            [(0x2000, 77), (0x1000, 40)])
        self.assertEqual(
            sorted((c.cu.cu_offset, c.line) for c in swapped),
            sorted((c.cu.cu_offset, c.line) for c in candidates))

    def test_standalone_program_has_no_cu(self):
        lp = self._build_two_sequences()
        candidates = source_locations_for_lineprogram(lp, 0x200)
        self.assertEqual(len(candidates), 1)
        self.assertIsNone(candidates[0].cu)
        self.assertEqual(candidates[0].sequence_index, 1)

    def test_describe_candidate_formats_all_fields(self):
        first = (
            LineTableBuilder([FileSpec('one.c')])
            .row(0x500, 40, column=1)
            .end_sequence()
            .build())
        candidate = source_locations_for_address(
            [(FakeCU(0x1ABC), first)], 0x500)[0]
        text = describe_location_candidate(candidate)
        self.assertIn('CU 0x1abc', text)
        self.assertIn('one.c:40:1', text)
        self.assertIn('exact', text)
        self.assertIn('seq=0', text)

    def test_synthetic_program_is_self_consistent(self):
        # Guard against generator drift: the decoded program must contain
        # exactly the rows and boundaries that were requested.
        lp = self._build_two_sequences()
        states = [
            entry.state for entry in lp.get_entries()
            if entry.state is not None]
        self.assertEqual(
            [(state.address, state.line, state.end_sequence)
             for state in states],
            [(0x100, 10, False),
             (0x100, 11, False),
             (0x110, 12, False),
             (0x110, 12, True),
             (0x200, 20, False),
             (0x210, 21, False),
             (0x210, 21, True)])

    def test_builder_supports_version_3_header(self):
        # Version 3 headers have no maximum_operations_per_instruction field;
        # the builder must emit a parseable header for that format too.
        lp = (
            LineTableBuilder([FileSpec('old.c')], version=3)
            .row(0x10, 7)
            .end_sequence()
            .build())
        self.assertEqual(lp.header.version, 3)
        candidates = source_locations_for_lineprogram(lp, 0x10)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].filename, 'old.c')
        self.assertEqual(candidates[0].line, 7)

    def test_relative_line_advance_and_directory_join(self):
        lp = (
            LineTableBuilder(
                [FileSpec('src.c', dir_index=1)],
                directories=['/home/user/project'])
            .row(0x100, 50)
            .next_row(0x104, 3, column=2)
            .end_sequence()
            .build())

        states = [
            entry.state for entry in lp.get_entries()
            if entry.state is not None and not entry.state.end_sequence]
        self.assertEqual([state.line for state in states], [50, 53])

        candidates = source_locations_for_lineprogram(lp, 0x104)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0].filename, '/home/user/project/src.c')
        self.assertEqual(candidates[0].column, 2)


@unittest.skipUnless(os.path.exists(SAMPLE_ELF), 'sample ELF unavailable')
class TestSampleELFIntegration(unittest.TestCase):
    def test_matches_legacy_single_result_example(self):
        # The dwarf_decode_address example reports z.c:3 for this address in
        # the sample executable; the new candidate API must agree.
        with open(SAMPLE_ELF, 'rb') as f:
            dwarfinfo = ELFFile(f).get_dwarf_info()
            candidates = dwarfinfo.source_locations_for_address(0x400503)

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate.filename, 'z.c')
        self.assertEqual(candidate.line, 3)
        self.assertEqual(candidate.match_reason, LINE_MATCH_RANGE)
        self.assertTrue(candidate.address <= 0x400503 < candidate.end_address)


if __name__ == '__main__':
    unittest.main()
