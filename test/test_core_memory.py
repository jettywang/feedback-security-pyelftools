"""Tests for address-to-mapping queries over ELF core files.

The central fixture is a core built entirely in memory.  It deliberately mixes
NT_FILE mappings that are not backed by bytes with PT_LOAD segments that are,
so that "the address was mapped" and "the core has those bytes" cannot be
confused.
"""
import io
import unittest
from unittest.mock import patch

from elftools.common.exceptions import ELFError
from elftools.construct import Container
from elftools.elf.core_memory import CoreFile
from elftools.elf.elffile import ELFFile
from elftools.elf.structs import ELFStructs

PAGE = 0x1000


def _structs(elfclass=64, little_endian=True):
    structs = ELFStructs(elfclass=elfclass, little_endian=little_endian)
    structs.create_basic_structs()
    structs.create_advanced_structs('ET_CORE', 'EM_X86_64', 'ELFOSABI_SYSV')
    return structs


def _align(data, alignment=4):
    return data + b'\0' * ((-len(data)) % alignment)


def make_core(*, segments, nt_file_notes, elfclass=64, little_endian=True,
              extra_notes=()):
    """Build an ELF core in memory.

    ``segments`` is a sequence of ``(p_type, vaddr, memsz, data_or_None,
    unused_offset)``.  File offsets are assigned sequentially so the fixture
    never has to guess them.  A ``PT_LOAD`` gets ``p_filesz`` from the data
    length; a ``PT_NOTE`` gets the bodies from ``nt_file_notes`` and
    ``extra_notes``.
    """
    structs = _structs(elfclass, little_endian)
    ehdr_size = structs.Elf_Ehdr.sizeof()
    phdr_size = structs.Elf_Phdr.sizeof()

    payloads = list(extra_notes)
    for page_size, entries in nt_file_notes:
        desc = structs.Elf_Nt_File.build(Container(
            num_map_entries=len(entries),
            page_size=page_size,
            Elf_Nt_File_Entry=[
                Container(vm_start=start, vm_end=end, page_offset=page_offset)
                for start, end, page_offset, _ in entries],
            filename=[name for _, _, _, name in entries]))
        payloads.append((b'CORE', 0x46494c45, desc))

    note_bytes = b''
    for name, n_type, desc in payloads:
        name_bytes = name + b'\0'
        nhdr = structs.Elf_Nhdr.build(Container(
            n_namesz=len(name_bytes), n_descsz=len(desc), n_type=n_type))
        note_bytes += nhdr + _align(name_bytes) + _align(desc)
    note_bytes = _align(note_bytes)

    headers = []
    blobs = []
    file_cursor = ehdr_size + phdr_size * len(segments)
    for p_type, vaddr, memsz, data, _requested_offset in segments:
        if p_type == 'PT_NOTE':
            offset, filesz, blob = file_cursor, len(note_bytes), note_bytes
        elif data is None:
            offset, filesz, blob = file_cursor, 0, b''
        else:
            offset, filesz, blob = file_cursor, len(data), data
        headers.append(Container(
            p_type=p_type, p_flags=4, p_offset=offset, p_vaddr=vaddr,
            p_paddr=vaddr, p_filesz=filesz, p_memsz=memsz, p_align=PAGE))
        blobs.append((offset, blob))
        file_cursor += filesz

    image = bytearray(file_cursor)
    for offset, blob in blobs:
        if blob:
            image[offset:offset + len(blob)] = blob

    ehdr = structs.Elf_Ehdr.build(Container(
        e_ident=Container(
            EI_MAG=[0x7f, 0x45, 0x4c, 0x46],
            EI_CLASS='ELFCLASS64' if elfclass == 64 else 'ELFCLASS32',
            EI_DATA='ELFDATA2LSB' if little_endian else 'ELFDATA2MSB',
            EI_VERSION='EV_CURRENT', EI_OSABI='ELFOSABI_SYSV', EI_ABIVERSION=0),
        e_type='ET_CORE',
        e_machine='EM_X86_64' if elfclass == 64 else 'EM_386',
        e_version='EV_CURRENT', e_entry=0, e_phoff=ehdr_size, e_shoff=0,
        e_flags=0, e_ehsize=ehdr_size, e_phentsize=phdr_size,
        e_phnum=len(headers), e_shentsize=0, e_shnum=0, e_shstrndx=0))
    image[0:len(ehdr)] = ehdr
    for index, header in enumerate(headers):
        ph = structs.Elf_Phdr.build(header)
        phoff = ehdr_size + index * phdr_size
        image[phoff:phoff + len(ph)] = ph
    return bytes(image)


class CoreFixture:
    """A synthetic core mixing mappings, gaps, headers-only data and overlaps.

    Virtual layout:

      0x400000 - 0x402000   /tmp/one       two mapped pages, first page saved
      0x500000 - 0x501000   anonymous      saved
      0x600000 - 0x601000   /tmp/header_only  mapped, no saved bytes
      0x700000 - 0x702000   /tmp/two       file page offset 5, both pages saved
      0x800000 - 0x802000   deleted name, only the first 16 bytes saved
      0x900000 - 0x901000   /tmp/overlap, saved by two PT_LOAD segments
    """
    def __init__(self):
        self.image = make_core(
            segments=[
                ('PT_NOTE', 0, 0, None, 0),
                ('PT_LOAD', 0x400000, 0x2000, b'A' * PAGE, 0),
                ('PT_LOAD', 0x401000, PAGE, None, 0),
                ('PT_LOAD', 0x500000, 0x1000, b'B' * PAGE, 0),
                ('PT_LOAD', 0x600000, 0x1000, None, 0),
                ('PT_LOAD', 0x700000, 0x2000, b'C' * (2 * PAGE), 0),
                ('PT_LOAD', 0x800000, 0x2000, b'D' * 16, 0),
                ('PT_LOAD', 0x900000, 0x1000, b'E' * PAGE, 0),
                ('PT_LOAD', 0x900000, 0x1000, b'F' * PAGE, 0),
            ],
            nt_file_notes=[(PAGE, [
                (0x400000, 0x402000, 0, b'/tmp/one'),
                (0x710000, 0x710000, 0, b'/tmp/one'),
                (0x600000, 0x601000, 0, b'/tmp/header_only'),
                (0x700000, 0x702000, 5, b'/tmp/two'),
                (0x800000, 0x802000, 0, b'/tmp/gone (deleted)'),
                (0x900000, 0x901000, 0, b'/tmp/overlap'),
                (0x900000, 0x901000, 0, b'/tmp/overlap-other'),
            ])])

    def open(self):
        return ELFFile(io.BytesIO(self.image))

    def core(self):
        return self.open().get_core_file()


class TestSyntheticCore(unittest.TestCase):
    def setUp(self):
        self.fixture = CoreFixture()
        self.core = self.fixture.core()

    def test_page_unit_offsets_become_byte_offsets(self):
        mapping = self.core.mappings[3]
        self.assertEqual(mapping.page_offset, 5)
        self.assertEqual(mapping.page_size, PAGE)
        self.assertEqual(mapping.file_offset, 5 * PAGE)
        self.assertEqual(mapping.vm_size, 2 * PAGE)
        self.assertEqual(mapping.file_offset_for(0x701023), 6 * PAGE + 0x23)

    def test_three_addresses_separate_mapping_from_content(self):
        mapped_and_present = self.core.resolve(0x400123)
        self.assertEqual(mapped_and_present.kind, 'file')
        self.assertEqual(mapped_and_present.source, ('nt_file', 'pt_load'))
        self.assertEqual(mapped_and_present.file_name, '/tmp/one')
        self.assertTrue(mapped_and_present.has_memory_content)
        self.assertEqual(mapped_and_present.readable.status, 'present')
        self.assertEqual(mapped_and_present.readable.start, 0x400123)
        self.assertEqual(mapped_and_present.readable.end, 0x401000)
        self.assertEqual(self.core.read(0x400123, 2).data, b'AA')

        # The second mapped page has NT_FILE provenance, but the core stored
        # only the first page of the PT_LOAD segment.
        mapped_without_content = self.core.resolve(0x401100)
        self.assertEqual(mapped_without_content.kind, 'file')
        self.assertEqual(mapped_without_content.source, ('nt_file', 'pt_load'))
        self.assertFalse(mapped_without_content.has_memory_content)
        self.assertEqual(mapped_without_content.readable.status, 'not_present')
        self.assertIsNone(mapped_without_content.readable.end)
        self.assertEqual(self.core.read(0x401100, 4).available, 0)

        unmapped = self.core.resolve(0x550000)
        self.assertEqual(unmapped.kind, 'anonymous')
        self.assertEqual(unmapped.source, ())
        self.assertEqual(unmapped.readable.status, 'unavailable')
        self.assertFalse(unmapped.has_memory_content)

    def test_content_range_stops_at_preserved_bytes(self):
        result = self.core.resolve(0x700010)
        self.assertEqual(result.readable.status, 'present')
        self.assertEqual(result.readable.end, 0x700000 + 2 * PAGE)
        self.assertEqual(self.core.read(0x700010, 4).data, b'CCCC')

    def test_partial_read_has_explicit_status_and_prefix(self):
        result = self.core.read(0x800004, 0x20)
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.available, 12)
        self.assertIsNone(result.data)
        full = self.core.read(0x800000, 16)
        self.assertEqual(full.status, 'present')
        self.assertEqual(full.data, b'D' * 16)

    def test_deleted_name_is_kept_as_evidence(self):
        deleted, = self.core.find_candidates('/tmp/gone (deleted)')
        self.assertTrue(deleted.deleted)
        self.assertEqual(deleted.original_name, '/tmp/gone')
        self.assertEqual(deleted.raw_name, b'/tmp/gone (deleted)')
        self.assertEqual(self.core.find_candidates('/tmp/gone'), ())

    def test_header_only_segment_is_known_but_has_no_bytes(self):
        result = self.core.resolve(0x600000)
        self.assertEqual(result.kind, 'file')
        self.assertEqual(result.file_name, '/tmp/header_only')
        self.assertEqual([(load.index, load.filesz) for load in result.loads],
                         [(4, 0)])
        self.assertEqual(result.readable.status, 'not_present')
        self.assertFalse(result.has_memory_content)

    def test_overlapping_segments_are_not_disambiguated(self):
        result = self.core.resolve(0x900010)
        self.assertEqual(len(result.loads), 2)
        self.assertEqual(result.readable.status, 'not_unique')
        self.assertIsNone(result.readable.end)
        read = self.core.read(0x900010, 4)
        self.assertEqual(read.status, 'not_unique')
        self.assertIsNone(read.data)
        self.assertEqual(len(read.candidates), 2)

    def test_overlapping_mappings_return_candidates_not_a_path(self):
        result = self.core.resolve(0x900010)
        self.assertEqual(result.kind, 'file')
        self.assertIsNone(result.file_name)
        self.assertEqual(result.candidate_names,
                         ('/tmp/overlap', '/tmp/overlap-other'))
        self.assertEqual(len(result.mappings), 2)

    def test_anonymous_but_present_memory(self):
        result = self.core.resolve(0x500123)
        self.assertEqual(result.kind, 'anonymous')
        self.assertIsNone(result.file_name)
        self.assertEqual(result.source, ('pt_load',))
        self.assertTrue(result.has_memory_content)
        self.assertEqual(self.core.read(0x500123, 2).data, b'BB')

    def test_zero_length_mapping_entry_is_not_extended(self):
        self.assertEqual(self.core.resolve(0x710000).mappings, ())

    def test_mapping_loads_reports_intersection_not_content(self):
        loads = self.core.mapping_loads(self.core.mappings[0])
        self.assertEqual([load.index for load in loads], [1, 2])

    def test_names_never_open_local_files(self):
        with patch('builtins.open', side_effect=AssertionError('must not open')):
            core = self.fixture.core()
            for address in (0x400123, 0x600000, 0x800000, 0x900010):
                core.resolve(address)

    def test_read_is_bounded_to_the_file(self):
        image = make_core(segments=[('PT_LOAD', 0x1000, 0x1000, b'abc', 0)],
                          nt_file_notes=[])
        structs = _structs()
        phoff = structs.Elf_Ehdr.sizeof()
        ph_size = structs.Elf_Phdr.sizeof()
        ph = structs.Elf_Phdr.parse(image[phoff:phoff + ph_size])
        ph.p_filesz = 0x10000
        image = image[:phoff] + structs.Elf_Phdr.build(ph) + image[phoff + ph_size:]
        core = ELFFile(io.BytesIO(image)).get_core_file()
        with self.assertRaises(ELFError):
            core.read(0x1000, 4)

    def test_requires_core_file(self):
        image = bytearray(self.fixture.image)
        structs = _structs()
        ehdr = structs.Elf_Ehdr.parse(bytes(image))
        ehdr.e_type = 'ET_EXEC'
        rebuilt = structs.Elf_Ehdr.build(ehdr)
        image[0:len(rebuilt)] = rebuilt
        with self.assertRaises(ELFError):
            CoreFile(ELFFile(io.BytesIO(bytes(image))))
        self.assertEqual(self.fixture.open()['e_type'], 'ET_CORE')

    def test_adjacent_segments_are_read_as_one_run(self):
        image = make_core(
            segments=[('PT_NOTE', 0, 0, None, 0),
                      ('PT_LOAD', 0x1000, 0x1000, b'ab', 0),
                      ('PT_LOAD', 0x1002, 0x1000, b'cd', 0)],
            nt_file_notes=[])
        core = ELFFile(io.BytesIO(image)).get_core_file()
        read = core.read(0x1000, 3)
        self.assertEqual(read.status, 'present')
        self.assertEqual(read.data, b'abc')
        self.assertEqual(read.candidates, (1, 2))
        self.assertEqual(core.resolve(0x1001).readable.end, 0x1004)

    def test_identical_duplicate_segments_are_not_ambiguous(self):
        image = bytearray(make_core(
            segments=[('PT_NOTE', 0, 0, None, 0),
                      ('PT_LOAD', 0x1000, 0x1000, b'abcd', 0),
                      ('PT_LOAD', 0x1000, 0x1000, b'abcd', 0)],
            nt_file_notes=[]))
        structs = _structs()
        ehdr_size = structs.Elf_Ehdr.sizeof()
        ph_size = structs.Elf_Phdr.sizeof()
        # Make the second PT_LOAD header byte-identical to the first.
        first = bytes(image[ehdr_size:ehdr_size + ph_size])
        image[ehdr_size + ph_size:ehdr_size + 2 * ph_size] = first
        core = ELFFile(io.BytesIO(bytes(image))).get_core_file()
        self.assertEqual(len(core.loads), 1)
        result = core.resolve(0x1000)
        self.assertEqual(result.readable.status, 'present')
        self.assertEqual(core.read(0x1000, 4).data, b'abcd')

    def test_range_stops_before_an_overlap(self):
        image = make_core(
            segments=[('PT_NOTE', 0, 0, None, 0),
                      ('PT_LOAD', 0x1000, 0x1000, b'ab', 0),
                      ('PT_LOAD', 0x1002, 0x1000, b'cd', 0),
                      ('PT_LOAD', 0x1003, 0x1000, b'ef', 0)],
            nt_file_notes=[])
        core = ELFFile(io.BytesIO(image)).get_core_file()
        # Byte 0x1003 has two sources, so a range covering it is not unique.
        read = core.read(0x1000, 4)
        self.assertEqual(read.status, 'not_unique')
        self.assertEqual(read.available, 3)
        self.assertEqual(len(read.candidates), 2)
        self.assertIsNone(read.data)

    def test_range_stops_at_a_gap(self):
        image = make_core(
            segments=[('PT_NOTE', 0, 0, None, 0),
                      ('PT_LOAD', 0x1000, 0x1000, b'ab', 0),
                      ('PT_LOAD', 0x1005, 0x1000, b'cd', 0)],
            nt_file_notes=[])
        core = ELFFile(io.BytesIO(image)).get_core_file()
        read = core.read(0x1000, 4)
        self.assertEqual(read.status, 'partial')
        self.assertEqual(read.available, 2)

    def test_readable_range_truncates_before_a_later_overlap(self):
        image = make_core(
            segments=[('PT_NOTE', 0, 0, None, 0),
                      ('PT_LOAD', 0x1000, 0x1000, b'abcd', 0),
                      ('PT_LOAD', 0x1002, 0x1000, b'wxyz', 0)],
            nt_file_notes=[])
        core = ELFFile(io.BytesIO(image)).get_core_file()
        # 0x1000 and 0x1001 are unique; 0x1002 has two sources.
        result = core.resolve(0x1000)
        self.assertEqual(result.readable.status, 'present')
        self.assertEqual(result.readable.end, 0x1002)
        self.assertEqual(core.read(0x1000, 2).data, b'ab')
        self.assertEqual(core.read(0x1000, 3).status, 'not_unique')

    def test_multiple_nt_file_notes_keep_per_note_page_sizes(self):
        image = make_core(
            segments=[('PT_NOTE', 0, 0, None, 0),
                      ('PT_LOAD', 0x1000, 0x1000, b'abcd', 0)],
            nt_file_notes=[
                (4096, [(0x1000, 0x2000, 0, b'/a')]),
                (65536, [(0x1000, 0x2000, 1, b'/b')])])
        core = ELFFile(io.BytesIO(image)).get_core_file()
        self.assertTrue(core.multiple_nt_file_notes)
        self.assertEqual(core.nt_file_note_count, 2)
        self.assertIsNone(core.page_size)  # notes disagree
        self.assertEqual([m.page_size for m in core.mappings], [4096, 65536])
        self.assertEqual([m.file_offset for m in core.mappings], [0, 65536])
        result = core.resolve(0x1000)
        self.assertIsNone(result.file_name)
        self.assertEqual(result.candidate_names, ('/a', '/b'))

    def test_malformed_nt_file_descriptor_is_rejected(self):
        structs = _structs()
        # Two entries but only one filename: the note parser must reject this
        # rather than let CoreFile invent a second name.
        desc = structs.Elf_Nt_File.build(Container(
            num_map_entries=2, page_size=PAGE,
            Elf_Nt_File_Entry=[
                Container(vm_start=0x1000, vm_end=0x2000, page_offset=0),
                Container(vm_start=0x2000, vm_end=0x3000, page_offset=1)],
            filename=[b'/only-name', b'/missing']))
        desc = desc[:-len(b'/missing\0')]
        image = make_core(
            segments=[('PT_NOTE', 0, 0, None, 0),
                      ('PT_LOAD', 0x1000, 0x1000, b'abcd', 0)],
            nt_file_notes=[],
            extra_notes=[(b'CORE', 0x46494c45, desc)])
        with self.assertRaises(ELFError):
            ELFFile(io.BytesIO(image)).get_core_file()

    def test_negative_size_is_rejected(self):
        with self.assertRaises(ValueError):
            self.core.read(0x400000, -1)

    def test_non_positive_page_size_keeps_raw_offset(self):
        image = make_core(
            segments=[('PT_NOTE', 0, 0, None, 0),
                      ('PT_LOAD', 0x1000, 0x1000, b'x' * PAGE, 0)],
            nt_file_notes=[(0, [(0x1000, 0x2000, 7, b'/tmp/bad-page')])])
        mapping, = ELFFile(io.BytesIO(image)).get_core_file().mappings
        self.assertIsNone(mapping.file_offset)
        self.assertEqual(mapping.page_offset, 7)
        self.assertIsNone(mapping.file_offset_for(0x1000))


class TestRealCore(unittest.TestCase):
    def test_real_core_mapping_and_content(self):
        with open('test/testfiles_for_unittests/core_linux64.elf', 'rb') as f:
            core = ELFFile(f).get_core_file()
            self.assertEqual(core.page_size, PAGE)
            self.assertEqual(len(core.mappings), 10)
            present = core.resolve(0x7fa4593ae010)
            self.assertEqual(present.kind, 'file')
            self.assertEqual(present.file_name,
                             '/lib/x86_64-linux-gnu/libc-2.23.so')
            self.assertEqual(present.readable.status, 'present')
            header_only = core.resolve(0x7fa45956d010)
            self.assertEqual(header_only.kind, 'file')
            self.assertEqual(header_only.readable.status, 'not_present')
            self.assertFalse(header_only.has_memory_content)

    def test_real_core_32bit(self):
        with open('test/testfiles_for_unittests/core_linux32.elf', 'rb') as f:
            core = ELFFile(f).get_core_file()
            self.assertEqual(core.page_size, PAGE)
            self.assertEqual(core.mappings[2].page_offset, 1)
            self.assertEqual(core.mappings[2].file_offset, PAGE)
            self.assertEqual(core.resolve(0x56624000).readable.status, 'present')


if __name__ == '__main__':
    unittest.main()
