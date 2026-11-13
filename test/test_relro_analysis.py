#-------------------------------------------------------------------------------
# elftools tests
#
# Per-slot static RELRO analysis.  The ELF inputs are hand-crafted by
# test/make_relro_fixtures.py (no compiler/linker needed) and rebuilt into a
# temporary directory here, so the test stays self contained and deterministic.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from make_relro_fixtures import (  # noqa: E402
    GOT_VADDR,
    GOTPLT_VADDR,
    build_elf,
    write_file,
)

# Import the example as a module; it lives under examples/.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'examples'))
import elf_relro_analysis as relro  # noqa: E402


def _analyze(data, **kwargs):
    from io import BytesIO
    return relro.analyze_relro(BytesIO(data), **kwargs)


def _slot_map(result):
    return {slot.address: slot for slot in result.slots}


class TestRelroFixtures(unittest.TestCase):
    def test_fixtures_parse_with_and_without_sections(self):
        for mode in ('partial', 'full', 'rounded'):
            for stripped in (False, True):
                with self.subTest(mode=mode, stripped=stripped):
                    result = _analyze(
                        build_elf(mode, strip_sections=stripped))
                    # Five relocation target slots in every crafted file.
                    self.assertEqual(len(result.slots), 5)
                    self.assertTrue(result.has_relro_segment)

    def test_full_relro_protects_every_slot(self):
        result = _analyze(build_elf('full'))
        self.assertTrue(result.now_binding)
        self.assertEqual(result.now_sources,
                         ['DT_FLAGS DF_BIND_NOW', 'DT_BIND_NOW'])
        self.assertEqual(result.conflicts, [])
        for slot in result.slots:
            self.assertEqual(slot.verdict, relro.PROTECTED,
                             msg=f'{slot.address:#x}: {slot.verdict}')

    def test_partial_relro_reports_conflict_conservatively(self):
        result = _analyze(build_elf('partial'))
        self.assertFalse(result.now_binding)
        # One conflicted page covering .got/.got.plt.
        self.assertEqual(len(result.conflicts), 1)
        (conflict_page, conflict_end, seg_start, seg_end,
         overlap_start, overlap_end) = result.conflicts[0]
        self.assertEqual(conflict_page, 0x400000)
        self.assertEqual(conflict_end, 0x401000)
        self.assertEqual((overlap_start, overlap_end),
                         (0x400fc0, 0x401000))
        self.assertEqual(seg_end, 0x40114c)
        for slot in result.slots:
            self.assertEqual(slot.verdict, relro.CONSERVATIVE_CONFLICT)
        # The JUMP_SLOT entries additionally record the lazy-binding reason.
        jump_slots = [slot for slot in result.slots if slot.is_jump_slot]
        self.assertEqual(len(jump_slots), 2)
        for slot in jump_slots:
            self.assertTrue(
                any('lazy binding' in reason for reason in slot.reasons))

    def test_rounded_relro_distinct_verdicts(self):
        result = _analyze(build_elf('rounded'))
        self.assertTrue(result.now_binding)
        self.assertEqual(result.conflicts, [])
        slots = _slot_map(result)
        # The two .got slots and the first .got.plt relative slot below the
        # declared end are directly inside the declared RELRO region.
        self.assertEqual(slots[GOT_VADDR + 0x00].verdict, relro.PROTECTED)
        self.assertEqual(slots[GOT_VADDR + 0x08].verdict, relro.PROTECTED)
        # Slots at or past the declared end are protected only by rounding.
        self.assertEqual(slots[GOTPLT_VADDR + 0x00].verdict,
                         relro.PROTECTED_PAGE_ROUNDED)
        self.assertEqual(slots[GOTPLT_VADDR + 0x08].verdict,
                         relro.PROTECTED_PAGE_ROUNDED)
        self.assertEqual(slots[GOTPLT_VADDR + 0x10].verdict,
                         relro.PROTECTED_PAGE_ROUNDED)

    def test_got_vs_gotplt_classification(self):
        result = _analyze(build_elf('full'))
        slots = _slot_map(result)
        self.assertEqual(slots[GOT_VADDR].section_name, '.got')
        self.assertFalse(slots[GOT_VADDR].in_got_plt)
        self.assertEqual(slots[GOTPLT_VADDR + 0x08].section_name, '.got.plt')
        self.assertTrue(slots[GOTPLT_VADDR + 0x08].in_got_plt)
        self.assertTrue(slots[GOTPLT_VADDR + 0x08].is_jump_slot)
        self.assertFalse(slots[GOT_VADDR].is_jump_slot)

    def test_stripped_sample_uses_segment_only_fallback(self):
        result = _analyze(build_elf('full', strip_sections=True))
        # No section names are available, but the dynamic tags still drive the
        # relocation lookup and JUMP_SLOT entries infer .got.plt membership.
        for slot in result.slots:
            self.assertEqual(slot.section_name, '')
        jump_slots = [slot for slot in result.slots if slot.is_jump_slot]
        self.assertEqual(len(jump_slots), 2)
        for slot in jump_slots:
            self.assertTrue(slot.in_got_plt)
            self.assertIn('DT_JMPREL', slot.table)
        self.assertEqual(len(result.slots), 5)

    def test_now_override_changes_lazy_verdict(self):
        # Without NOW, the full-RELRO layout would still protect its slots;
        # forcing lazy flips JUMP_SLOT verdicts to writable.
        lazy = _analyze(build_elf('full'), assume_now=False)
        self.assertFalse(lazy.now_binding)
        for slot in lazy.slots:
            if slot.is_jump_slot:
                self.assertEqual(slot.verdict, relro.WRITABLE_LAZY)
            else:
                self.assertEqual(slot.verdict, relro.PROTECTED)
        # Forcing NOW onto a lazy file removes the lazy-binding verdict, but
        # the partial layout still loses to its mapping conflict.
        forced = _analyze(build_elf('partial'), assume_now=True)
        self.assertTrue(forced.now_binding)
        self.assertTrue(
            any('overridden' in warning for warning in forced.warnings))
        for slot in forced.slots:
            self.assertEqual(slot.verdict, relro.CONSERVATIVE_CONFLICT)

    def test_page_size_changes_effective_range(self):
        small = _analyze(build_elf('full'), page_size=0x1000)
        large = _analyze(build_elf('full'), page_size=0x10000)
        self.assertEqual(small.region.effective_end, 0x401000)
        self.assertEqual(large.region.effective_end, 0x410000)
        # A larger page makes the following writable mapping conflict.
        self.assertEqual(small.conflicts, [])
        self.assertTrue(large.conflicts)

    def test_invalid_page_size_rejected(self):
        with self.assertRaises(ValueError):
            _analyze(build_elf('full'), page_size=3000)

    def test_unknown_base_is_flagged(self):
        result = _analyze(build_elf('full'))
        self.assertFalse(result.base_known)
        self.assertTrue(
            any('unknown base' in warning for warning in result.warnings))

    def test_explicit_base_shifts_absolute_addresses(self):
        base = 0x7f0000000000
        result = _analyze(build_elf('full'), base=base)
        self.assertTrue(result.base_known)
        self.assertEqual(result.base, base)
        d_start, d_end = result.region.absolute_declared
        self.assertEqual(d_start, base + 0x400000)
        self.assertEqual(d_end, base + 0x401000)
        self.assertEqual(result.slots[0].address, 0x400f00)  # stored relative

    def test_unaligned_base_warns(self):
        result = _analyze(build_elf('full'), base=0x1234)
        self.assertTrue(
            any('not' in warning and 'aligned' in warning
                for warning in result.warnings))

    def test_conflict_report_applies_load_bias(self):
        base = 0x7f0000000000
        text = relro.format_analysis(
            _analyze(build_elf('partial'), base=base))
        self.assertIn(f'{base + 0x400000:#x}', text)
        self.assertIn('mapping conflicts', text)

    def test_report_mentions_static_only_disclaimer(self):
        text = relro.format_analysis(_analyze(build_elf('full')))
        self.assertIn('static analysis only', text)
        self.assertIn('PT_GNU_RELRO', text)
        self.assertIn('R_X86_64_JUMP_SLOT', text)

    def test_no_relro_segment_leaves_slots_writable(self):
        result = _analyze(build_elf('full', include_relro=False))
        self.assertFalse(result.has_relro_segment)
        self.assertIsNone(result.region)
        self.assertEqual(result.conflicts, [])
        for slot in result.slots:
            self.assertEqual(slot.verdict, relro.NO_RELRO)
            self.assertTrue(
                any('PT_GNU_RELRO' in reason for reason in slot.reasons))

    def test_relr_section_is_handled(self):
        # A real shared object using SHT_RELR must not require r_info_type and
        # should classify each expanded entry as a relative relocation.
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'testfiles_for_unittests', 'lib_relro.so.elf')
        with open(path, 'rb') as stream:
            result = relro.analyze_relro(stream)
        relr_slots = [slot for slot in result.slots
                      if slot.reloc_type == 'RELR (relative)']
        self.assertTrue(relr_slots)
        for slot in relr_slots:
            self.assertFalse(slot.is_jump_slot)
            self.assertEqual(slot.symbol, '')

    def test_write_and_reopen_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'relro_full.elf')
            write_file(path, 'full')
            with open(path, 'rb') as stream:
                result = relro.analyze_relro(stream)
        self.assertEqual(len(result.slots), 5)
        self.assertTrue(result.now_binding)


if __name__ == '__main__':
    unittest.main()
