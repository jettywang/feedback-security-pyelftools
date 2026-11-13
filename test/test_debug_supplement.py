#-------------------------------------------------------------------------------
# elftools tests
#
# Caller-driven matching of supplementary debug information. The fixtures
# under test/testfiles_for_unittests/debug_supplement are rebuilt with
# build_fixtures.sh (Clang targeting x86_64 ELF, no GNU binutils required).
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import os
import shutil
import unittest
from typing import IO

from elftools.elf.debugsupplement import (
    DebugCandidate,
    DebugInfoResolver,
    EvidenceOutcome,
    RelationKind,
    collect_dwo_file_ids,
    collect_skeleton_dwo_ids,
    extract_build_id,
)
from elftools.elf.elffile import ELFFile

FIXTURE_DIR = os.path.join(
    'test', 'testfiles_for_unittests', 'debug_supplement')

REQUIRED_FIXTURES = (
    'debuglink_primary.o',
    'program_full.debug',
    'program_wrong.debug',
    'buildid_primary.o',
    'buildid_companion.debug',
    'random_name.debug',
    'split_program.o',
    'split_program.dwo',
    'split_other.o',
    'split_other.dwo',
    'split_program_v4.o',
    'split_program_v4.dwo',
    'cycle_primary.o',
    'cycle_a.debug',
    'cycle_b.debug',
    'not_elf.bin',
)


def fixtures_available() -> bool:
    """ Whether the prebuilt fixture set is present next to this test.
    """
    return all(
        os.path.exists(os.path.join(FIXTURE_DIR, name))
        for name in REQUIRED_FIXTURES)


@unittest.skipUnless(
    fixtures_available(),
    'debug-supplement fixtures missing; run build_fixtures.sh with a Clang '
    'able to target x86_64-linux-gnu')
class TestDebugSupplementMatching(unittest.TestCase):
    """ Identity-verified matching of caller-provided candidate files.
    """

    def setUp(self) -> None:
        self._streams: list[IO[bytes]] = []

    def tearDown(self) -> None:
        for stream in self._streams:
            stream.close()

    def path(self, name: str) -> str:
        return os.path.join(FIXTURE_DIR, name)

    def candidate(
        self,
        label: str,
        name: str,
        hint: str | None = None,
    ) -> DebugCandidate:
        stream = open(self.path(name), 'rb')  # noqa: SIM115
        self._streams.append(stream)
        return DebugCandidate(
            label=label, stream=stream, referenced_name=hint)

    def open_elf(self, name: str) -> ELFFile:
        stream = open(self.path(name), 'rb')  # noqa: SIM115
        self._streams.append(stream)
        return ELFFile(stream)

    #-- .gnu_debuglink CRC -------------------------------------------------#

    def test_debuglink_rejects_right_name_wrong_crc(self) -> None:
        primary = self.open_elf('debuglink_primary.o')
        resolver = DebugInfoResolver(primary, [
            self.candidate(
                'same-name-wrong-crc', 'program_wrong.debug',
                hint='program_full.debug'),
        ])
        result = resolver.resolve_debuglink()

        self.assertFalse(result.resolved)
        outcomes = {
            evidence.candidate_label: evidence.outcome
            for evidence in result.evidence}
        # The basename match is recorded, but only as a non-authoritative hint.
        self.assertEqual(
            outcomes['same-name-wrong-crc'],
            EvidenceOutcome.REJECTED_WRONG_IDENTIFIER)
        self.assertIn(
            EvidenceOutcome.NAME_ONLY_HINT,
            [evidence.outcome for evidence in result.evidence])
        crc_evidence = next(
            evidence for evidence in result.evidence
            if evidence.outcome is EvidenceOutcome.REJECTED_WRONG_IDENTIFIER)
        self.assertNotEqual(crc_evidence.expected, crc_evidence.observed)

    def test_debuglink_accepts_verified_candidate(self) -> None:
        primary = self.open_elf('debuglink_primary.o')
        resolver = DebugInfoResolver(primary, [
            self.candidate(
                'same-name-wrong-crc', 'program_wrong.debug',
                hint='program_full.debug'),
            self.candidate(
                'verified-companion', 'program_full.debug',
                hint='program_full.debug'),
        ])
        result = resolver.resolve_debuglink()

        self.assertTrue(result.resolved)
        self.assertEqual(result.matched_label, 'verified-companion')
        matched = next(
            evidence for evidence in result.evidence
            if evidence.outcome is EvidenceOutcome.MATCHED)
        self.assertEqual(matched.relation, RelationKind.DEBUGLINK_CRC)
        self.assertEqual(matched.expected, matched.observed)

    def test_only_verified_debuglink_companion_explains_addresses(self) -> None:
        primary = self.open_elf('debuglink_primary.o')

        # With only the wrong-CRC candidate, no address may be explained.
        unresolved = DebugInfoResolver(primary, [
            self.candidate(
                'same-name-wrong-crc', 'program_wrong.debug',
                hint='program_full.debug'),
        ]).resolve_debuglink()
        self.assertIsNone(unresolved.matched_stream)
        self.assertEqual(
            explain_subprograms(unresolved.matched_stream),
            'unresolved')

        # The verified companion carries the subprogram address ranges.
        resolved = DebugInfoResolver(primary, [
            self.candidate(
                'same-name-wrong-crc', 'program_wrong.debug',
                hint='program_full.debug'),
            self.candidate(
                'verified-companion', 'program_full.debug',
                hint='program_full.debug'),
        ]).resolve_debuglink()
        subprograms = explain_subprograms(resolved.matched_stream)
        assert isinstance(subprograms, dict)
        self.assertIn(b'addNumbers', subprograms)
        self.assertIn(b'main', subprograms)
        for low_pc, size in subprograms.values():
            self.assertIsInstance(low_pc, int)
            self.assertGreater(size, 0)

    #-- NT_GNU_BUILD_ID ----------------------------------------------------#

    def test_build_id_matches_different_basename(self) -> None:
        primary = self.open_elf('buildid_primary.o')
        expected = extract_build_id(primary)
        assert expected is not None
        self.assertEqual(expected.hex(), '8877665544332211')

        resolver = DebugInfoResolver(primary, [
            self.candidate('decoy', 'random_name.debug'),
            self.candidate(
                'companion', 'buildid_companion.debug',
                hint='unexpected-basename.debug'),
        ])
        result = resolver.resolve_build_id()

        self.assertTrue(result.resolved)
        self.assertEqual(result.matched_label, 'companion')
        decoy = next(
            evidence for evidence in result.evidence
            if evidence.candidate_label == 'decoy'
            and evidence.outcome is EvidenceOutcome.REJECTED_WRONG_IDENTIFIER)
        self.assertEqual(decoy.expected, expected.hex())
        self.assertEqual(decoy.observed, '00ffeeddccbbaa99')

    def test_build_id_unresolved_without_identical_id(self) -> None:
        primary = self.open_elf('buildid_primary.o')
        resolver = DebugInfoResolver(primary, [
            self.candidate('decoy', 'random_name.debug'),
        ])
        result = resolver.resolve_build_id()
        self.assertFalse(result.resolved)
        self.assertEqual(
            explain_subprograms(result.matched_stream), 'unresolved')

    #-- split DWARF DWO ID -------------------------------------------------#

    def test_dwo_id_matching_dwarf5(self) -> None:
        primary = self.open_elf('split_program.o')
        expected_ids = collect_skeleton_dwo_ids(primary)
        self.assertEqual(len(expected_ids), 1)

        resolver = DebugInfoResolver(primary, [
            self.candidate(
                'foreign-dwo', 'split_other.dwo',
                hint='split_program.dwo'),
            self.candidate(
                'program-dwo', 'split_program.dwo',
                hint='split_program.dwo'),
        ])
        result = resolver.resolve_dwo()

        self.assertTrue(result.resolved)
        self.assertEqual(result.matched_label, 'program-dwo')
        rejected = next(
            evidence for evidence in result.evidence
            if evidence.candidate_label == 'foreign-dwo')
        self.assertEqual(
            rejected.outcome, EvidenceOutcome.REJECTED_WRONG_IDENTIFIER)
        # The rejected foreign DWO keeps its own DWO ID as observed evidence.
        observed_ids = collect_dwo_file_ids(
            self.open_elf('split_other.dwo'))
        assert rejected.observed is not None
        self.assertIn(
            f'0x{observed_ids[0]:x}', rejected.observed)

    def test_dwo_id_matching_dwarf4_gnu_extension(self) -> None:
        primary = self.open_elf('split_program_v4.o')
        expected = set(collect_skeleton_dwo_ids(primary))
        observed = set(
            collect_dwo_file_ids(self.open_elf('split_program_v4.dwo')))
        self.assertEqual(expected, observed)

        resolver = DebugInfoResolver(primary, [
            self.candidate(
                'foreign-dwo', 'split_other.dwo',
                hint='split_program_v4.dwo'),
            self.candidate(
                'program-dwo', 'split_program_v4.dwo',
                hint='split_program_v4.dwo'),
        ])
        result = resolver.resolve_dwo()
        self.assertTrue(result.resolved)
        self.assertEqual(result.matched_label, 'program-dwo')
        self.assertEqual(
            [label for label, _ in result.matches], ['program-dwo'])

    def test_dwo_unresolved_with_wrong_identifier(self) -> None:
        primary = self.open_elf('split_program.o')
        resolver = DebugInfoResolver(primary, [
            self.candidate(
                'foreign-dwo', 'split_other.dwo',
                hint='split_program.dwo'),
        ])
        result = resolver.resolve_dwo()
        self.assertFalse(result.resolved)
        self.assertIsNone(result.matched_stream)

    #-- duplicates, cycles and malformed input -----------------------------#

    def test_duplicate_candidates_create_single_relationship(self) -> None:
        primary = self.open_elf('buildid_primary.o')
        resolver = DebugInfoResolver(primary, [
            self.candidate('first', 'buildid_companion.debug'),
            self.candidate('second', 'buildid_companion.debug'),
            self.candidate('third', 'buildid_companion.debug'),
        ])
        result = resolver.resolve_build_id()

        self.assertEqual(result.matched_label, 'first')
        duplicate_labels = [
            evidence.candidate_label for evidence in result.evidence
            if evidence.outcome is EvidenceOutcome.REJECTED_DUPLICATE]
        self.assertEqual(duplicate_labels, ['second', 'third'])
        self.assertEqual(len(result.matches), 1)
        self.assertEqual(len(result.accepted_digests), 1)

    def test_cycle_candidate_does_not_block_distinct_match(self) -> None:
        primary = self.open_elf('buildid_primary.o')
        resolver = DebugInfoResolver(
            primary,
            [
                self.candidate(
                    'buildid_primary.o', 'buildid_companion.debug'),
                self.candidate(
                    'valid-companion', 'buildid_companion.debug'),
            ],
            primary_label='buildid_primary.o')
        result = resolver.resolve_build_id()

        cycle = next(
            evidence for evidence in result.evidence
            if evidence.outcome is EvidenceOutcome.REJECTED_CYCLE)
        self.assertEqual(cycle.candidate_label, 'buildid_primary.o')
        self.assertEqual(result.matched_label, 'valid-companion')

    def test_mutual_supplementary_references_terminate(self) -> None:
        primary = self.open_elf('cycle_primary.o')
        resolver = DebugInfoResolver(
            primary,
            [
                self.candidate(
                    'cycle_a.debug', 'cycle_a.debug',
                    hint='cycle_a.debug'),
                self.candidate('cycle_b.debug', 'cycle_b.debug'),
            ],
            primary_label='cycle_primary.o')
        report = resolver.resolve_supplementary_chain(max_depth=8)

        # The first hop is verified through the debuglink CRC.
        self.assertEqual(
            report.results[RelationKind.DEBUGLINK_CRC].matched_label,
            'cycle_a.debug')
        # The A -> B -> A loop is recorded as cycle evidence and terminates.
        supplementary = report.results[RelationKind.SUPPLEMENTARY]
        self.assertTrue(
            any(evidence.outcome is EvidenceOutcome.REJECTED_CYCLE
                for evidence in supplementary.evidence))
        self.assertIsNotNone(supplementary.matched_label)

    def test_non_elf_candidate_is_rejected_with_evidence(self) -> None:
        primary = self.open_elf('buildid_primary.o')
        resolver = DebugInfoResolver(primary, [
            self.candidate('garbage', 'not_elf.bin'),
            self.candidate('companion', 'buildid_companion.debug'),
        ])
        result = resolver.resolve_build_id()

        bad = next(
            evidence for evidence in result.evidence
            if evidence.candidate_label == 'garbage')
        self.assertEqual(bad.outcome, EvidenceOutcome.REJECTED_BAD_ELF)
        self.assertEqual(result.matched_label, 'companion')

    def test_duplicate_labels_are_rejected(self) -> None:
        primary = self.open_elf('buildid_primary.o')
        with self.assertRaises(ValueError):
            DebugInfoResolver(primary, [
                self.candidate('same-label', 'buildid_companion.debug'),
                self.candidate('same-label', 'random_name.debug'),
            ])

    #-- evidence audit trail -----------------------------------------------#

    def test_report_records_every_decision(self) -> None:
        primary = self.open_elf('debuglink_primary.o')
        resolver = DebugInfoResolver(primary, [
            self.candidate(
                'wrong', 'program_wrong.debug',
                hint='program_full.debug'),
            self.candidate(
                'right', 'program_full.debug',
                hint='program_full.debug'),
        ])
        report = resolver.resolve_all()

        labels = {
            evidence.candidate_label for evidence in report.all_evidence()}
        self.assertEqual(labels, {'wrong', 'right'})
        # Relations without an identifier are absent, not silently invented.
        self.assertNotIn(RelationKind.BUILD_ID, report.results)
        self.assertNotIn(RelationKind.DWO_ID, report.results)
        self.assertEqual(
            report.matched_labels(), ['right'])


def explain_subprograms(stream: IO[bytes] | None) -> dict[bytes, tuple[int, int]] | str:
    """ Use a matched supplement's DWARF data to explain subprogram ranges.

        Returns the sentinel string ``'unresolved'`` when no verified
        supplement is available, so missing information is never hidden.
    """
    if stream is None:
        return 'unresolved'
    stream.seek(0)
    elf = ELFFile(stream)
    if not elf.has_dwarf_info(True):
        return 'unresolved'
    dwarf_info = elf.get_dwarf_info(follow_links=False)
    subprograms: dict[bytes, tuple[int, int]] = {}
    for cu in dwarf_info.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != 'DW_TAG_subprogram':
                continue
            attributes = die.attributes
            name_attr = attributes.get('DW_AT_name')
            low_attr = attributes.get('DW_AT_low_pc')
            high_attr = attributes.get('DW_AT_high_pc')
            if name_attr is None or low_attr is None or high_attr is None:
                continue
            if high_attr.form == 'DW_FORM_addr':
                size = high_attr.value - low_attr.value
            else:
                size = high_attr.value
            subprograms[name_attr.value] = (low_attr.value, size)
    return subprograms or 'unresolved'


class TestFixtureBuildScript(unittest.TestCase):
    """ The fixture set is rebuilt through a documented, Clang-only script.
    """

    @unittest.skipUnless(
        shutil.which('clang'), 'clang is required to rebuild fixtures')
    @unittest.skipUnless(
        os.path.isdir(FIXTURE_DIR),
        'debug-supplement fixture directory is missing')
    def test_build_script_exists(self) -> None:
        script = os.path.join(FIXTURE_DIR, 'build_fixtures.sh')
        self.assertTrue(os.path.isfile(script))


if __name__ == '__main__':
    unittest.main()
