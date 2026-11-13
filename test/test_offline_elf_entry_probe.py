"""Regression tests for tools/offline_elf_entry_probe.

The probe is a standalone prototype, so it is imported by path rather than as
part of the installed elftools package.
"""

import importlib.util
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROBE_PATH = os.path.join(ROOT, 'tools', 'offline_elf_entry_probe', 'probe.py')
FIXTURES = os.path.join(ROOT, 'tools', 'offline_elf_entry_probe', 'fixtures')


def load_probe():
    spec = importlib.util.spec_from_file_location('offline_elf_entry_probe', PROBE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


probe = load_probe()


def report(name):
    return probe.build_report(os.path.join(FIXTURES, name))


def by_kind(rep, kind):
    return [item for item in rep['evidence'] if item['kind'] == kind]


class TestPieRela(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rep = report('pie-rela.so')
        cls.ev = cls.rep['evidence']

    def test_no_absolute_runtime_addresses(self):
        # ET_DYN entries must remain expressions; a concrete absolute target
        # would require guessing the load bias.
        for item in self.ev:
            if item['kind'] == 'entry':
                self.assertTrue(item['requires_load_bias'])
                self.assertIn('B + ', item['final_target'])
        for item in by_kind(self.rep, 'relative'):
            self.assertTrue(item['requires_load_bias'])
            self.assertIn('B + ', item['final_target'])
            self.assertNotRegex(item['final_target'], r'^0x[0-9a-f]+$')

    def test_irelative_keeps_resolver_and_result_distinct(self):
        items = by_kind(self.rep, 'irelative')
        self.assertTrue(items)
        for item in items:
            self.assertEqual(item['address_form'], 'resolver-result')
            self.assertIn('call B + ', item['final_target'])
            self.assertIn('resolver return value', item['final_target'])
            # The resolver entry must not be presented as the final function.
            self.assertIn('resolver', item['final_target'])
            self.assertIn('unknown', item['confidence'].lower())
        init = [i for i in by_kind(self.rep, 'init-array') if i['initializer']]
        self.assertTrue(any('IRELATIVE' in i['initializer'] for i in init))

    def test_rela_addend_comes_from_explicit_field(self):
        for item in by_kind(self.rep, 'relative'):
            self.assertIn('RELA', item['source'])
            self.assertIn('r_addend=', item['file_value'])
            self.assertNotIn('in-place', item['file_value'])

    def test_relative_symbol_is_not_a_target_contribution(self):
        # r_info_sym=2 points at not_ifunc, but RELATIVE ignores it.
        decoys = [i for i in by_kind(self.rep, 'relative')
                  if 'not_ifunc' in i['source']]
        self.assertEqual(len(decoys), 1)
        self.assertIn('B + 0x1040', decoys[0]['final_target'])
        self.assertIn('ignored', ' '.join(decoys[0]['notes']))

    def test_ifunc_symbol_and_reference_are_separate_evidence(self):
        syms = by_kind(self.rep, 'ifunc-symbol')
        self.assertEqual(len(syms), 1)
        self.assertIn('STT_GNU_IFUNC', syms[0]['file_value'])
        self.assertIn('resolver', syms[0]['final_target'])
        refs = by_kind(self.rep, 'ifunc-reference')
        self.assertEqual(len(refs), 1)
        self.assertIn('GLOB_DAT', refs[0]['source'])
        self.assertEqual(refs[0]['address_form'], 'resolver-result')

    def test_arrays_are_slots_not_final_calls(self):
        self.assertEqual(len(by_kind(self.rep, 'preinit-array-inapplicable')), 1)
        self.assertEqual(len(by_kind(self.rep, 'init-array')), 2)
        self.assertEqual(len(by_kind(self.rep, 'fini-array')), 1)
        for item in by_kind(self.rep, 'init-array'):
            self.assertIn('raw file word', item['file_value'])
            self.assertIn('slot is both an array element and a relocation target',
                          item['notes'])

    def test_preinit_is_demoted_for_a_dso(self):
        # Both fixtures are ET_DYN shared objects, so DT_PREINIT_ARRAY must
        # not be reported as an applicable startup callback.
        items = by_kind(self.rep, 'preinit-array-inapplicable')
        self.assertEqual(len(items), 1)
        self.assertIn('not honored', ' '.join(items[0]['notes']))
        self.assertFalse(by_kind(self.rep, 'preinit-array'))


class TestStrippedRel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rep = report('stripped-rel.so')

    def test_sections_absent_but_dynamic_tables_used(self):
        self.assertFalse(self.rep['section_headers']['available'])
        self.assertEqual(self.rep['section_headers']['count'], 0)
        self.assertEqual(self.rep['dynamic']['provenance'], 'PT_DYNAMIC segment')
        self.assertTrue(self.rep['dynamic']['tags'])
        # The only addresses available are dynamic tag values; they are
        # parser VAs, not runtime addresses.
        tables = self.rep['dynamic']['table_addresses']
        self.assertEqual(tables['DT_REL'], '0x1190')
        self.assertEqual(tables['DT_INIT_ARRAY'], '0x1184')
        self.assertEqual(tables['DT_PREINIT_ARRAY'], '0x1180')

    def test_rel_addend_is_in_place(self):
        rels = by_kind(self.rep, 'relative')
        self.assertTrue(rels)
        for item in rels:
            self.assertIn('in-place REL word', item['file_value'])
            self.assertNotIn('r_addend=', item['file_value'])
            self.assertIn('R_386_RELATIVE', item['source'])

    def test_stripped_ifunc_symbol_is_recovered_from_dt_symtab(self):
        syms = by_kind(self.rep, 'ifunc-symbol')
        self.assertEqual(len(syms), 1)
        self.assertIn('DT_SYMTAB', syms[0]['source'])
        self.assertIn('resolver', syms[0]['final_target'])

    def test_irelative_uses_inplace_word(self):
        item = by_kind(self.rep, 'irelative')[0]
        self.assertIn('[*0x1188]=0x1020', item['file_value'])
        self.assertIn('call B + 0x1020', item['final_target'])

    def test_no_section_names_are_invented(self):
        for item in self.rep['evidence']:
            self.assertNotIn('section .rela', item['source'])
            self.assertNotIn('section .init_array', item['source'])


class TestNegativeAddend(unittest.TestCase):
    def test_negative_addend_stays_symbolic(self):
        rep = report('negative-addend.so')
        rels = by_kind(rep, 'relative')
        neg = [r for r in rels if '-0x20' in r['file_value']]
        self.assertEqual(len(neg), 1)
        self.assertIn('B - 0x20', neg[0]['final_target'])
        self.assertTrue(neg[0]['requires_load_bias'])


class TestNoLoadSideEffects(unittest.TestCase):
    def test_probe_imports_no_loading_or_execution_modules(self):
        import ast
        with open(PROBE_PATH, encoding='utf-8') as f:
            tree = ast.parse(f.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split('.')[0])
        forbidden = {'ctypes', 'subprocess', 'mmap', 'multiprocessing'}
        self.assertFalse(imported & forbidden, imported & forbidden)

    def test_probe_has_no_execution_calls(self):
        import ast
        with open(PROBE_PATH, encoding='utf-8') as f:
            tree = ast.parse(f.read())
        forbidden = {'system', 'execv', 'execve', 'posix_spawn', 'dlopen', 'fork', 'run'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.func is not None:
                name = getattr(node.func, 'attr', None) or getattr(node.func, 'id', None)
                self.assertNotIn(name, forbidden)

    def test_fixture_generator_has_no_external_build_steps(self):
        import ast
        gen = os.path.join(ROOT, 'tools', 'offline_elf_entry_probe',
                           'make_fixtures.py')
        with open(gen, encoding='utf-8') as f:
            tree = ast.parse(f.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split('.')[0])
        self.assertFalse(imported & {'subprocess', 'ctypes', 'mmap'})


