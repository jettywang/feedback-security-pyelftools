#------------------------------------------------------------------------------
# elftools tests
#
# Tests for the versioned import inventory (elftools.elf.versioned_imports).
# Real fixtures cover section-header and PT_DYNAMIC-only parsing; the small
# synthetic builder in test/synthetic_elf.py covers crafted edge cases.
#
# This code is in the public domain
#------------------------------------------------------------------------------
import os
import struct
import unittest
from io import BytesIO

from elftools.elf.elffile import ELFFile
from elftools.elf.versioned_imports import (
    VersionedImports,
    iter_versioned_imports,
)
from test.synthetic_elf import (
    STB_GLOBAL,
    STB_WEAK,
    SyntheticELFBuilder,
    SyntheticSymbol,
    SyntheticVersion,
)

FIXTURES = os.path.join('test', 'testfiles_for_unittests')
VERSIONED_LIB = os.path.join(FIXTURES, 'lib_versioned64.so.elf')
STRIPPED_LIB = os.path.join(FIXTURES, 'aarch64_super_stripped.elf')


def _open(path):
    return open(path, 'rb')


class TestRealFixtures(unittest.TestCase):

    def test_section_header_mode_inventory(self):
        with _open(VERSIONED_LIB) as stream:
            vi = VersionedImports(ELFFile(stream))
            self.assertEqual(vi.mode, 'sections')
            self.assertEqual(vi.notes, [])

            by_name = {}
            for record in vi.get_imports():
                by_name.setdefault(record['name'], []).append(record)

            puts = by_name['puts'][0]
            self.assertEqual(puts['symbol_index'], 3)
            self.assertEqual(puts['version_index'], 5)
            self.assertEqual(puts['version_name'], 'GLIBC_2.2.5')
            self.assertEqual(puts['library'], 'libc.so.6')
            self.assertFalse(puts['hidden'])
            self.assertEqual(puts['reasons'], [])

            stack_chk = by_name['__stack_chk_fail'][0]
            self.assertEqual(stack_chk['version_name'], 'GLIBC_2.4')
            self.assertEqual(stack_chk['library'], 'libc.so.6')

            gzoffset = by_name['gzoffset'][0]
            self.assertEqual(gzoffset['version_name'], 'ZLIB_1.2.3.5')
            self.assertEqual(gzoffset['library'], 'libz.so.1')

            # Two undefined symbols can share one version requirement.
            self.assertEqual(
                by_name['__cxa_finalize'][0]['version_name'], 'GLIBC_2.2.5')

    def test_version_definitions_are_not_imports(self):
        # function1/function2/VER_* are defined in the file and versioned via
        # verdef; they must never surface as import requirements.
        with _open(VERSIONED_LIB) as stream:
            vi = VersionedImports(ELFFile(stream))
            for record in vi.get_imports():
                self.assertNotIn(record['name'],
                                 ('function1', 'function2',
                                  'function1_ver1_1'))
                # Every resolved import must come from a VERNEED library,
                # never from a version definition of this file.
                if record['version_name'] is not None:
                    self.assertIsNotNone(record['library'])

    def test_special_indices(self):
        with _open(VERSIONED_LIB) as stream:
            vi = VersionedImports(ELFFile(stream))
            locals_ = [r for r in vi.get_imports()
                       if r['version_index'] == 'VER_NDX_LOCAL']
            self.assertTrue(locals_)
            for record in locals_:
                self.assertIsNone(record['version_name'])
                self.assertIsNone(record['library'])
                self.assertTrue(
                    any('special' in reason for reason in record['reasons']))

    def test_offsets_point_at_backing_bytes(self):
        with _open(VERSIONED_LIB) as stream:
            data = stream.read()
        with _open(VERSIONED_LIB) as stream:
            vi = VersionedImports(ELFFile(stream))
            for record in vi.get_imports():
                offsets = record['offsets']
                self.assertIn('dynsym', offsets)
                self.assertIn('versym', offsets)
                if record['name']:
                    offset = offsets['dynstr']
                    self.assertEqual(
                        data[offset:offset + len(record['name'])],
                        record['name'].encode())
                if record['version_name'] is not None:
                    offset = offsets['vernaux_name']
                    self.assertEqual(
                        data[offset:offset + len(record['version_name'])],
                        record['version_name'].encode())
                    offset = offsets['verneed_file']
                    self.assertEqual(
                        data[offset:offset + len(record['library'])],
                        record['library'].encode())

    def test_dynamic_mode_super_stripped_fixture(self):
        with _open(STRIPPED_LIB) as stream:
            vi = VersionedImports(ELFFile(stream))
            self.assertEqual(vi.mode, 'dynamic')
            self.assertTrue(
                any('e_shnum=0' in note for note in vi.notes))

            records = [r for r in vi.get_imports() if r['name']]
            self.assertEqual(
                sorted(r['name'] for r in records),
                ['__gmon_start__', '__libc_start_main', 'abort'])
            for record in records:
                if record['version_index'] == 'VER_NDX_LOCAL':
                    # Weak, unversioned import: no named requirement.
                    self.assertIsNone(record['version_name'])
                    continue
                self.assertEqual(record['version_name'], 'GLIBC_2.17')
                self.assertEqual(record['library'], 'libc.so.6')
                self.assertEqual(record['reasons'], [])
                # Dynamic mode still reports concrete file offsets.
                for key in ('dynsym', 'dynstr', 'versym', 'verneed',
                            'vernaux', 'vernaux_name', 'verneed_file'):
                    self.assertIn(key, record['offsets'])

    def test_dynamic_mode_requirement_table(self):
        with _open(STRIPPED_LIB) as stream:
            vi = VersionedImports(ELFFile(stream))
            requirements = vi.get_version_requirements()
        self.assertEqual(requirements[2]['name'], 'GLIBC_2.17')
        self.assertEqual(requirements[2]['library'], 'libc.so.6')
        self.assertIsNone(requirements[2]['error'])

    def test_convenience_iterator(self):
        with _open(VERSIONED_LIB) as stream:
            records = list(iter_versioned_imports(ELFFile(stream)))
            self.assertTrue(records)
            self.assertTrue(
                all('symbol_index' in r for r in records))

    def test_non_dynamic_object_has_empty_inventory(self):
        relocatable = os.path.join(FIXTURES, 'compressed_64.o')
        with _open(relocatable) as stream:
            vi = VersionedImports(ELFFile(stream))
        self.assertEqual(vi.get_imports(), [])
        self.assertEqual(vi.get_version_requirements(), {})
        self.assertTrue(
            any('no PT_DYNAMIC' in note for note in vi.notes))


class TestSyntheticELFs(unittest.TestCase):

    def _build(self, symbols, requirements, **tweaks):
        builder = SyntheticELFBuilder(symbols, requirements)
        for name, value in tweaks.items():
            setattr(builder, name, value)
        return ELFFile(builder.build())

    def test_same_name_requires_two_versions(self):
        symbols = [
            SyntheticSymbol('foo', version_index=3),
            SyntheticSymbol('foo', version_index=4, hidden=True),
        ]
        requirements = [
            SyntheticVersion('libfoo.so.1',
                             [('FOO_1.0', 3), ('FOO_2.0', 4)])]
        vi = VersionedImports(self._build(symbols, requirements))
        foo = [r for r in vi.get_imports() if r['name'] == 'foo']
        self.assertEqual(len(foo), 2)
        first, second = foo
        self.assertEqual(first['symbol_index'], 1)
        self.assertEqual(first['version_index'], 3)
        self.assertEqual(first['version_name'], 'FOO_1.0')
        self.assertFalse(first['hidden'])
        self.assertEqual(second['symbol_index'], 2)
        self.assertEqual(second['version_index'], 4)
        self.assertEqual(second['version_name'], 'FOO_2.0')
        self.assertTrue(second['hidden'])
        # Same dynstr offset (duplicate name), distinct versym/vernaux.
        self.assertEqual(first['offsets']['dynstr'],
                         second['offsets']['dynstr'])
        self.assertNotEqual(first['offsets']['versym'],
                            second['offsets']['versym'])
        self.assertNotEqual(first['offsets']['vernaux'],
                            second['offsets']['vernaux'])

    def test_offsets_of_dual_version_records(self):
        symbols = [
            SyntheticSymbol('foo', version_index=3),
            SyntheticSymbol('foo', version_index=4),
        ]
        requirements = [
            SyntheticVersion('libfoo.so.1',
                             [('FOO_1.0', 3), ('FOO_2.0', 4)])]
        elf = self._build(symbols, requirements)
        data = elf.stream.getvalue()
        vi = VersionedImports(elf)
        for record in vi.get_imports():
            if record['name'] != 'foo':
                continue
            offsets = record['offsets']
            self.assertEqual(
                data[offsets['dynstr']:offsets['dynstr'] + 3], b'foo')
            self.assertEqual(
                data[offsets['vernaux_name']:
                     offsets['vernaux_name'] + len(record['version_name'])],
                record['version_name'].encode())
            self.assertEqual(
                data[offsets['verneed_file']:
                     offsets['verneed_file'] + len(record['library'])],
                record['library'].encode())

    def test_stripped_recovery_for_dual_versions(self):
        symbols = [
            SyntheticSymbol('foo', version_index=3),
            SyntheticSymbol('foo', version_index=4),
        ]
        requirements = [
            SyntheticVersion('libfoo.so.1',
                             [('FOO_1.0', 3), ('FOO_2.0', 4)])]
        elf = self._build(symbols, requirements,
                          include_section_headers=False)
        self.assertEqual(elf.num_sections(), 0)
        vi = VersionedImports(elf)
        self.assertEqual(vi.mode, 'dynamic')
        foo = [r for r in vi.get_imports() if r['name'] == 'foo']
        self.assertEqual([r['version_name'] for r in foo],
                         ['FOO_1.0', 'FOO_2.0'])
        self.assertTrue(
            all(r['library'] == 'libfoo.so.1' and not r['reasons']
                for r in foo))

    def test_broken_vernaux_chain(self):
        symbols = [
            SyntheticSymbol('foo', version_index=3),
            SyntheticSymbol('bar', version_index=4),
        ]
        requirements = [
            SyntheticVersion('libfoo.so.1',
                             [('FOO_1.0', 3), ('FOO_2.0', 4)])]
        vi = VersionedImports(self._build(
            symbols, requirements, break_vernaux_chain=True))
        self.assertTrue(
            any('terminates after 1 of 2' in note for note in vi.notes))
        bar = next(r for r in vi.get_imports() if r['name'] == 'bar')
        self.assertIsNone(bar['version_name'])
        self.assertIsNone(bar['library'])
        self.assertTrue(
            any('cannot be resolved' in reason for reason in bar['reasons']))
        # The reachable first auxiliary still resolves cleanly.
        foo = next(r for r in vi.get_imports() if r['name'] == 'foo')
        self.assertEqual(foo['version_name'], 'FOO_1.0')
        self.assertEqual(foo['reasons'], [])

    def test_broken_verneed_chain(self):
        symbols = [
            SyntheticSymbol('alib', version_index=2),
            SyntheticSymbol('blib', version_index=3),
        ]
        requirements = [
            SyntheticVersion('liba.so.1', [('A_1.0', 2)]),
            SyntheticVersion('libb.so.1', [('B_7.0', 3)]),
        ]
        vi = VersionedImports(self._build(
            symbols, requirements, break_verneed_chain=True))
        # The second Verneed is unreachable because the first claims to be
        # the end of the chain; its symbol stays unresolved.
        records = {r['name']: r for r in vi.get_imports() if r['name']}
        self.assertEqual(records['alib']['version_name'], 'A_1.0')
        self.assertIsNone(records['blib']['version_name'])
        self.assertTrue(
            any('cannot be resolved' in reason
                for reason in records['blib']['reasons']))

    def test_duplicate_vna_other_keeps_first(self):
        symbols = [
            SyntheticSymbol('foo', version_index=3),
            SyntheticSymbol('bar', version_index=4),
        ]
        requirements = [
            SyntheticVersion('libfoo.so.1',
                             [('FOO_1.0', 3), ('FOO_2.0', 4)])]
        vi = VersionedImports(self._build(
            symbols, requirements, duplicate_vna_other=3))
        self.assertTrue(
            any('duplicate vna_other index 3' in note
                for note in vi.notes))
        resolved = vi.get_version_requirements()
        self.assertNotIn(4, resolved)
        self.assertEqual(resolved[3]['name'], 'FOO_1.0')
        bar = next(r for r in vi.get_imports() if r['name'] == 'bar')
        self.assertTrue(
            any('cannot be resolved' in reason for reason in bar['reasons']))

    def test_missing_verneednum_still_walks_entries(self):
        symbols = [SyntheticSymbol('foo', version_index=3)]
        requirements = [
            SyntheticVersion('libfoo.so.1', [('FOO_1.0', 3)])]
        vi = VersionedImports(self._build(
            symbols, requirements, drop_verneednum=True,
            include_section_headers=False))
        self.assertTrue(
            any('DT_VERNEEDNUM absent' in note for note in vi.notes))
        foo = next(r for r in vi.get_imports() if r['name'] == 'foo')
        self.assertEqual(foo['version_name'], 'FOO_1.0')
        self.assertEqual(foo['library'], 'libfoo.so.1')

    def test_two_libraries(self):
        symbols = [
            SyntheticSymbol('alib', version_index=2),
            SyntheticSymbol('blib', version_index=3),
        ]
        requirements = [
            SyntheticVersion('liba.so.1', [('A_1.0', 2)]),
            SyntheticVersion('libb.so.1', [('B_7.0', 3)]),
        ]
        vi = VersionedImports(self._build(symbols, requirements))
        records = {r['name']: r for r in vi.get_imports() if r['name']}
        self.assertEqual(records['alib']['library'], 'liba.so.1')
        self.assertEqual(records['alib']['version_name'], 'A_1.0')
        self.assertEqual(records['blib']['library'], 'libb.so.1')
        self.assertEqual(records['blib']['version_name'], 'B_7.0')

    def test_weak_unversioned_global(self):
        symbols = [
            SyntheticSymbol('weakie', bind=STB_WEAK,
                            version_index='VER_NDX_GLOBAL')]
        requirements = [
            SyntheticVersion('liba.so.1', [('A_1.0', 2)])]
        vi = VersionedImports(self._build(symbols, requirements))
        weakie = next(r for r in vi.get_imports()
                      if r['name'] == 'weakie')
        self.assertEqual(weakie['binding'], 'STB_WEAK')
        self.assertEqual(weakie['version_index'], 'VER_NDX_GLOBAL')
        self.assertIsNone(weakie['version_name'])
        self.assertTrue(weakie['reasons'])

    def test_reserved_version_index(self):
        symbols = [SyntheticSymbol('weird', version_index=0xff02)]
        requirements = [
            SyntheticVersion('liba.so.1', [('A_1.0', 2)])]
        vi = VersionedImports(self._build(symbols, requirements))
        weird = next(r for r in vi.get_imports()
                     if r['name'] == 'weird')
        self.assertEqual(weird['version_index'], 0xff02)
        self.assertIsNone(weird['version_name'])
        self.assertIsNone(weird['library'])
        self.assertTrue(
            any('VER_NDX_LORESERVE' in reason
                for reason in weird['reasons']))
        # A reserved index must not be looked up as a VERNEED requirement.
        self.assertNotIn('vernaux', weird['offsets'])

    def test_named_reserved_eliminate_index(self):
        # 0xff01 is decoded by the struct enum as VER_NDX_ELIMINATE.
        symbols = [SyntheticSymbol('gone', version_index=0xff01)]
        requirements = [
            SyntheticVersion('liba.so.1', [('A_1.0', 2)])]
        vi = VersionedImports(self._build(symbols, requirements))
        gone = next(r for r in vi.get_imports() if r['name'] == 'gone')
        self.assertEqual(gone['version_index'], 'VER_NDX_ELIMINATE')
        self.assertIsNone(gone['version_name'])
        self.assertTrue(gone['reasons'])

    def test_hidden_bit_does_not_change_resolution(self):
        symbols = [SyntheticSymbol('hid', version_index=3, hidden=True)]
        requirements = [
            SyntheticVersion('libfoo.so.1', [('FOO_1.0', 3)])]
        vi = VersionedImports(self._build(symbols, requirements))
        hid = next(r for r in vi.get_imports() if r['name'] == 'hid')
        self.assertTrue(hid['hidden'])
        self.assertEqual(hid['version_index'], 3)
        self.assertEqual(hid['version_name'], 'FOO_1.0')

    def test_binding_field_values(self):
        symbols = [
            SyntheticSymbol('g', bind=STB_GLOBAL, version_index=2),
            SyntheticSymbol('w', bind=STB_WEAK, version_index=2),
        ]
        requirements = [
            SyntheticVersion('liba.so.1', [('A_1.0', 2)])]
        vi = VersionedImports(self._build(symbols, requirements))
        bindings = {r['name']: r['binding']
                    for r in vi.get_imports() if r['name']}
        self.assertEqual(bindings, {'g': 'STB_GLOBAL', 'w': 'STB_WEAK'})

    def test_unmappable_versym_address_is_reported(self):
        symbols = [SyntheticSymbol('foo', version_index=3)]
        requirements = [
            SyntheticVersion('libfoo.so.1', [('FOO_1.0', 3)])]
        builder = SyntheticELFBuilder(symbols, requirements)
        builder.include_section_headers = False
        data = bytearray(builder.build().getvalue())
        elf = ELFFile(BytesIO(data))
        dynamic = next(segment for segment in elf.iter_segments()
                       if segment['p_type'] == 'PT_DYNAMIC')
        cursor = dynamic['p_offset']
        while True:
            tag, _ = struct.unpack_from('<QQ', data, cursor)
            if tag == 0x6FFFFFF0:  # DT_VERSYM
                struct.pack_into('<Q', data, cursor + 8, 0x99999999)
                break
            if tag == 0:
                self.fail('DT_VERSYM tag not found')
            cursor += 16

        vi = VersionedImports(ELFFile(BytesIO(data)))
        self.assertTrue(
            any('unmappable address' in note for note in vi.notes))
        foo = next(r for r in vi.get_imports() if r['name'] == 'foo')
        self.assertIsNone(foo['version_index'])
        self.assertIsNone(foo['version_name'])
        self.assertTrue(
            any('no VERSYM table' in reason for reason in foo['reasons']))


if __name__ == '__main__':
    unittest.main()
