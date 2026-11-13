#-------------------------------------------------------------------------------
# Structured fuzz tests for ELF extended section indices.
#
# The fixtures are tiny hand-laid-out ELF32 objects (see
# test/elf_xindex_fuzz/) rather than random byte blobs. They exercise the
# e_shnum / e_shstrndx escape forms and symbol SHN_XINDEX resolution,
# mutating one structural relationship at a time.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
import struct
import unittest
from io import BytesIO

from elftools.common.exceptions import ELFError, ELFParseError
from elftools.elf.constants import SHN_INDICES
from elftools.elf.elffile import ELFFile

from test.elf_xindex_fuzz.builder import (
    DECOY_SECTION,
    EHDR_SIZE,
    EXPECTED_TARGET_SECTION,
    IDX_SHNDX,
    IDX_SYMTAB,
    SECTION_COUNT,
    SHN_XINDEX,
    SYM_TARGET,
    build_template,
)
from test.elf_xindex_fuzz.harness import (
    FUZZ_SEED,
    FUZZ_TRIALS,
    build_empty_symtab_no_shndx_template,
    build_empty_xindex_template,
    expected_layout_size,
    minimize_failure,
    parse_outcome,
    run_all_mutants_once,
    run_structured_fuzz,
    truncate_template,
)
from test.elf_xindex_fuzz.mutators import (
    make_custom_mutant,
    mutate_shndx_bad_entsize,
    mutate_shndx_link_oor,
    mutate_symbol_drops_xindex,
    mutate_xindex_to_decoy,
)
from test.elf_xindex_fuzz.oracle import (
    naive_resolve_memberships,
    resolve_memberships,
)

FIXED_SAMPLE_SIZE = expected_layout_size()


def _symbol_shndx(symbol) -> int:
    value = symbol['st_shndx']
    if isinstance(value, str):
        return int(getattr(SHN_INDICES, value))
    return int(value)


class TestLegalRepresentations(unittest.TestCase):
    def test_fixed_sample_size_and_seed(self):
        # Both representations must keep the same fixed size so fuzz offsets
        # stay comparable across modes and reruns.
        normal = build_template('normal')
        extended = build_template('extended')
        self.assertEqual(len(normal.data), FIXED_SAMPLE_SIZE)
        self.assertEqual(len(extended.data), FIXED_SAMPLE_SIZE)
        self.assertEqual(FUZZ_TRIALS, 64)
        self.assertEqual(FUZZ_SEED, 0x5EC10)

    def test_extended_header_forms(self):
        normal = build_template('normal')
        extended = build_template('extended')
        self.assertEqual(normal.get_u16('e_shnum'), SECTION_COUNT)
        self.assertEqual(extended.get_u16('e_shnum'), 0)
        self.assertEqual(extended.get_u32('shdr0.sh_size'), SECTION_COUNT)
        self.assertEqual(extended.get_u16('e_shstrndx'), int(SHN_XINDEX))
        self.assertEqual(extended.get_u32('shdr0.sh_link'),
                         normal.get_u16('e_shstrndx'))

    def test_legal_forms_resolve_identically(self):
        results = {
            mode: resolve_memberships(bytes(build_template(mode).data))
            for mode in ('normal', 'extended')
        }
        for result in results.values():
            self.assertEqual(result['num_sections'], SECTION_COUNT)
        self.assertEqual(results['normal']['shstrndx'],
                         results['extended']['shstrndx'])
        self.assertEqual(results['normal']['memberships'],
                         results['extended']['memberships'])
        target = results['normal']['memberships'][SYM_TARGET]
        self.assertEqual(target, EXPECTED_TARGET_SECTION)
        self.assertNotEqual(target, DECOY_SECTION)

    def test_pyelftools_native_parse_agrees(self):
        for mode in ('normal', 'extended'):
            with self.subTest(mode=mode):
                data = bytes(build_template(mode).data)
                result = resolve_memberships(data)
                elf = ELFFile(BytesIO(data))
                self.assertEqual(elf.num_sections(), result['num_sections'])
                self.assertEqual(elf.get_shstrndx(), result['shstrndx'])
                shndx = elf.get_section(IDX_SHNDX)
                self.assertEqual(shndx.get_section_index(SYM_TARGET),
                                 EXPECTED_TARGET_SECTION)


class TestStructuredMutants(unittest.TestCase):
    def test_every_mutant_matches_its_expected_verdict(self):
        rows = run_all_mutants_once()
        self.assertEqual(len(rows), 28)  # 14 mutators x 2 representations
        for mutant, verdict, observed in rows:
            with self.subTest(mutant=mutant.name, mode=mutant.mode):
                self.assertEqual(verdict, mutant.expected,
                                 msg=f'{mutant.name}: {observed}')

    def test_corrupt_link_never_lands_on_existing_section(self):
        # The decoy is a real, reachable section; every relationship the
        # oracle rejects must raise instead of attributing the symbol to it.
        for mutant, verdict, _ in run_all_mutants_once():
            if mutant.expected != 'reject':
                continue
            with self.subTest(mutant=mutant.name, mode=mutant.mode):
                with self.assertRaises(ELFError):
                    resolve_memberships(mutant.data)

    def test_legal_redirect_changes_membership_to_decoy(self):
        for mode in ('normal', 'extended'):
            with self.subTest(mode=mode):
                mutant = mutate_xindex_to_decoy(mode)
                verdict, _, _ = parse_outcome(mutant.data)
                self.assertEqual(verdict, 'ok')
                result = resolve_memberships(mutant.data)
                self.assertEqual(result['memberships'][SYM_TARGET],
                                 DECOY_SECTION)

    def test_symbol_dropping_xindex_uses_direct_index(self):
        for mode in ('normal', 'extended'):
            with self.subTest(mode=mode):
                mutant = mutate_symbol_drops_xindex(mode)
                result = resolve_memberships(mutant.data)
                self.assertEqual(result['memberships'][SYM_TARGET],
                                 EXPECTED_TARGET_SECTION)


class TestTruncationAndTypes(unittest.TestCase):
    def test_truncated_section_header_table_rejected(self):
        template = build_template('normal')
        shoff = template.get_u32('e_shoff')
        # Cut inside the section header table, before the SHNDX header.
        cut = shoff + IDX_SHNDX * 40 + 10
        data = truncate_template('normal', cut)
        elf = ELFFile(BytesIO(data))
        # Construction is lazy; walking the declared sections is what hits
        # the truncated header and must fail closed.
        with self.assertRaises(ELFParseError):
            list(elf.iter_sections())

    def test_truncation_at_many_points_fails_closed(self):
        # No truncation point may escape ELFError: the parser must reject
        # instead of returning partial memberships.
        for cut in range(EHDR_SIZE, FIXED_SAMPLE_SIZE, 7):
            with self.subTest(cut=cut):
                verdict, _, _ = parse_outcome(
                    truncate_template('extended', cut))
                self.assertEqual(verdict, 'reject')

    def test_wrong_section_type_rejected(self):
        def break_type(template):
            template.set_u32(f'shdr{IDX_SHNDX}.sh_type', 1)

        mutant = make_custom_mutant(
            'normal', 'shndx_wrong_type', 'shdr5.sh_type',
            'reject', 'SHNDX section retyped to PROGBITS',
            break_type)
        with self.assertRaises(ELFError):
            resolve_memberships(mutant.data)

    def test_entsize_mismatch_rejected(self):
        mutant = mutate_shndx_bad_entsize('extended')
        with self.assertRaises(ELFError):
            resolve_memberships(mutant.data)


class TestLegalEmptyTables(unittest.TestCase):
    def test_empty_xindex_table_with_null_symbol_only(self):
        template = build_empty_xindex_template()
        result = resolve_memberships(bytes(template.data))
        self.assertEqual(result['num_sections'], SECTION_COUNT)
        self.assertEqual(result['memberships'], [0])

    def test_empty_symtab_without_shndx_section(self):
        # No SHN_XINDEX symbol exists, so a null-only symbol table parses
        # even though no extended index section is advertised.
        template = build_empty_symtab_no_shndx_template()
        elf = ELFFile(BytesIO(bytes(template.data)))
        symtab = elf.get_section(IDX_SYMTAB)
        self.assertEqual(symtab.num_symbols(), 1)
        self.assertEqual(_symbol_shndx(symtab.get_symbol(0)), 0)


class TestMinimizationAndReport(unittest.TestCase):
    def test_minimized_failure_keeps_layout_and_mutation(self):
        mutant = mutate_shndx_link_oor('extended')
        minimized, access_range = minimize_failure(mutant.data,
                                                   mutant.field_range)
        # Length and offsets are preserved; only irrelevant bytes are zeroed.
        self.assertEqual(len(minimized), len(mutant.data))
        field_lo, field_hi = mutant.field_range
        mutated_value = struct.unpack_from(
            '<I', mutant.data, field_lo)[0].to_bytes(4, 'little')
        self.assertEqual(minimized[field_lo:field_hi], mutated_value)
        # The ELF header and section header table survive untouched.
        self.assertEqual(minimized[:EHDR_SIZE], mutant.data[:EHDR_SIZE])
        shoff = build_template('normal').layout['shdr_table'][0]
        self.assertEqual(minimized[shoff:], mutant.data[shoff:])
        # Some irrelevant content must actually have been zeroed.
        self.assertLess(sum(minimized), sum(mutant.data))
        verdict, _, _ = parse_outcome(minimized)
        self.assertEqual(verdict, 'reject')
        self.assertIsNotNone(access_range)
        range_lo, range_hi = access_range
        self.assertGreaterEqual(range_lo, 0)
        self.assertLessEqual(range_hi, len(minimized))

    def test_fuzz_run_is_deterministic_and_clean(self):
        first = run_structured_fuzz()
        second = run_structured_fuzz()
        self.assertTrue(first.ok, msg=first.render())
        self.assertEqual(len(first.failures), len(second.failures))

    def test_report_records_full_access_envelope(self):
        result = resolve_memberships(bytes(build_template('normal').data))
        lo, hi = result['access_range']
        self.assertEqual((lo, hi), (0, FIXED_SAMPLE_SIZE))


class TestNaiveResolverIsCaught(unittest.TestCase):
    def test_naive_xindex_ignorance_changes_membership(self):
        # Deliberate-bug self-test: the defective resolver ignores the
        # extended index table, so it must disagree with the reference on
        # every SHN_XINDEX symbol.
        for mode in ('normal', 'extended'):
            data = bytes(build_template(mode).data)
            correct = resolve_memberships(data)
            naive = naive_resolve_memberships(data)
            self.assertNotEqual(correct['memberships'], naive['memberships'])
            self.assertEqual(naive['memberships'][SYM_TARGET],
                             int(SHN_INDICES.SHN_XINDEX))
            self.assertEqual(correct['memberships'][SYM_TARGET],
                             EXPECTED_TARGET_SECTION)

    def test_suite_invariant_flags_the_naive_resolver(self):
        data = bytes(build_template('extended').data)
        naive = naive_resolve_memberships(data)
        with self.assertRaises(AssertionError):
            assert naive['memberships'][SYM_TARGET] == EXPECTED_TARGET_SECTION


if __name__ == '__main__':
    unittest.main()
