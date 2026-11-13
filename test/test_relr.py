#-------------------------------------------------------------------------------
# elftools tests
#
# Andreas Ziegler (andreas.ziegler@fau.de)
# This code is in the public domain
#-------------------------------------------------------------------------------
# The lib_relro.so.elf file was generated as follows (on Debian 11):
# $ cat lib_relro.c
# int retfunc(){ return 1; }
# int (*ptr1)() = retfunc;
# int (*ptr2)() = retfunc;
# <...>
# int (*ptr100)() = retfunc;
# $ clang-12 -c -o lib_relro.o -fPIC lib_relro.c
# $ ld.lld-12 -o lib_relro.so.elf --pack-dyn-relocs=relr --shared -Bsymbolic-functions lib_relro.o
#
# The synthetic fixtures below are built in memory. They deliberately use a
# non-zero load base so that file offsets cannot be confused with virtual
# addresses.

import os
import unittest
from io import BytesIO

from elftools.construct import Container
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelrExpandedRelocation
from elftools.elf.structs import ELFStructs

SHSTRTAB = b'\x00.dynstr\x00.relr.dyn\x00.dynamic\x00.shstrtab\x00'
DYNAMIC_TAGS = 6


class SyntheticRelrFile:
    """ Build a small ET_DYN ELF containing a RELR table.

        The first PT_LOAD covers the file from offset 0 at BASE. Extra
        segments allow tests to create overlapping mappings and targets whose
        file range extends past the end of the file.
    """

    BASE = 0x400000

    def __init__(self, elfclass=64, little_endian=True, slot_values=(),
                 relr_words=(), extra_segments=(), zero_fill=0,
                 with_sections=True):
        self.elfclass = elfclass
        self.little_endian = little_endian
        self.machine = 'EM_X86_64' if elfclass == 64 else 'EM_386'
        self.structs = ELFStructs(
            elfclass=elfclass, little_endian=little_endian)
        self.structs.create_basic_structs()
        self.structs.create_advanced_structs(
            'ET_DYN', self.machine, 'ELFOSABI_SYSV')

        self.addr_size = self.structs.Elf_addr('').sizeof()
        self.ehsize = self.structs.Elf_Ehdr.sizeof()
        self.phentsize = self.structs.Elf_Phdr.sizeof()
        self.shentsize = self.structs.Elf_Shdr.sizeof()
        self.dynsize = self.structs.Elf_Dyn.sizeof()

        self.slot_values = tuple(slot_values)
        self.relr_words = tuple(relr_words)
        self.extra_segments = tuple(extra_segments)
        self.zero_fill = zero_fill
        self.with_sections = with_sections

        self.phnum = 2 + len(self.extra_segments)
        self.slots_off = self._align(self.ehsize + self.phnum * self.phentsize)
        self.relr_off = self._align(
            self.slots_off + len(self.slot_values) * self.addr_size)
        self.dyn_off = self._align(
            self.relr_off + len(self.relr_words) * self.addr_size)
        self.dynstr_off = self._align(self.dyn_off + DYNAMIC_TAGS * self.dynsize)
        self.shstr_off = self._align(self.dynstr_off + 1)
        self.payload_end = self._align(self.shstr_off + len(SHSTRTAB))
        if with_sections:
            self.shoff = self._align(self.payload_end)
            self.shnum = 5
            self.file_len = self.shoff + self.shnum * self.shentsize
        else:
            self.shoff = 0
            self.shnum = 0
            self.file_len = self.payload_end

    @staticmethod
    def _align(value):
        return (value + 7) & ~7

    def slot_address(self, index):
        return self.BASE + self.slots_off + index * self.addr_size

    def address(self, file_offset):
        return self.BASE + file_offset

    def _dynamic_tags(self):
        tags = [
            ('DT_RELR', self.address(self.relr_off)),
            ('DT_RELRSZ', len(self.relr_words) * self.addr_size),
            ('DT_RELRENT', self.addr_size),
            ('DT_STRTAB', self.address(self.dynstr_off)),
            ('DT_STRSZ', 1),
        ]
        return tags + [('DT_NULL', 0)]

    def build(self):
        out = bytearray(self.file_len)

        def put(offset, data):
            out[offset:offset + len(data)] = data

        ident = Container(
            EI_MAG=[0x7f, ord('E'), ord('L'), ord('F')],
            EI_CLASS=f'ELFCLASS{self.elfclass}',
            EI_DATA='ELFDATA2LSB' if self.little_endian else 'ELFDATA2MSB',
            EI_VERSION='EV_CURRENT',
            EI_OSABI='ELFOSABI_SYSV',
            EI_ABIVERSION=0)
        ehdr = Container(
            e_ident=ident, e_type='ET_DYN', e_machine=self.machine,
            e_version='EV_CURRENT', e_entry=0, e_phoff=self.ehsize,
            e_shoff=self.shoff, e_flags=0, e_ehsize=self.ehsize,
            e_phentsize=self.phentsize, e_phnum=self.phnum,
            e_shentsize=self.shentsize, e_shnum=self.shnum,
            e_shstrndx=4 if self.with_sections else 0)
        put(0, self.structs.Elf_Ehdr.build(ehdr))

        segments = [
            ('PT_LOAD', 6, 0, self.BASE, self.payload_end,
             self.payload_end + self.zero_fill),
            ('PT_DYNAMIC', 6, self.dyn_off, self.address(self.dyn_off),
             DYNAMIC_TAGS * self.dynsize, DYNAMIC_TAGS * self.dynsize),
        ]
        for vaddr, offset, filesz, memsz in self.extra_segments:
            if callable(offset):
                offset = offset(self)
            segments.append(
                ('PT_LOAD', 6, offset, vaddr, filesz, memsz))
        for i, (ptype, flags, offset, vaddr, filesz, memsz) in enumerate(
                segments):
            put(self.ehsize + i * self.phentsize,
                self.structs.Elf_Phdr.build(Container(
                    p_type=ptype, p_flags=flags, p_offset=offset,
                    p_vaddr=vaddr, p_paddr=vaddr, p_filesz=filesz,
                    p_memsz=memsz, p_align=8)))

        addr_struct = self.structs.Elf_addr('')
        put(self.slots_off, b''.join(
            addr_struct.build(value) for value in self.slot_values))
        put(self.relr_off, b''.join(
            addr_struct.build(value) for value in self.relr_words))
        put(self.dyn_off, b''.join(
            self.structs.Elf_Dyn.build(Container(
                d_tag=tag, d_val=value, d_ptr=value))
            for tag, value in self._dynamic_tags()))
        put(self.dynstr_off, b'\0')
        put(self.shstr_off, SHSTRTAB)

        if self.with_sections:
            put(self.shoff, b''.join(self._section_headers()))
        return bytes(out)

    def _section_headers(self):
        def header(name_offset, sh_type, sh_flags, sh_addr, sh_offset, size,
                   sh_link=0, sh_entsize=0):
            return self.structs.Elf_Shdr.build(Container(
                sh_name=name_offset, sh_type=sh_type, sh_flags=sh_flags,
                sh_addr=sh_addr, sh_offset=sh_offset, sh_size=size,
                sh_link=sh_link, sh_info=0,
                sh_addralign=self.addr_size, sh_entsize=sh_entsize))

        return [
            header(0, 'SHT_NULL', 0, 0, 0, 0),
            header(SHSTRTAB.index(b'.dynstr'), 'SHT_STRTAB', 0, 0,
                   self.dynstr_off, 1),
            header(SHSTRTAB.index(b'.relr.dyn'), 'SHT_RELR', 2,
                   self.address(self.relr_off), self.relr_off,
                   len(self.relr_words) * self.addr_size,
                   sh_entsize=self.addr_size),
            header(SHSTRTAB.index(b'.dynamic'), 'SHT_DYNAMIC', 2,
                   self.address(self.dyn_off), self.dyn_off,
                   DYNAMIC_TAGS * self.dynsize, sh_link=1,
                   sh_entsize=self.dynsize),
            header(SHSTRTAB.index(b'.shstrtab'), 'SHT_STRTAB', 0, 0,
                   self.shstr_off, len(SHSTRTAB)),
        ]


def _expanded_signature(relocations):
    return [
        (reloc.target_address, reloc.addend, reloc.status, reloc.file_offset,
         reloc.mapped_offsets, reloc.source)
        for reloc in relocations
    ]


class TestRelr(unittest.TestCase):

    def test_num_relocations(self):
        """ Verify we can get the number of relocations in a RELR relocation
            section.
        """
        path = os.path.join('test', 'testfiles_for_unittests',
                            'lib_relro.so.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            relr_section = elf.get_section_by_name('.relr.dyn')
            self.assertIsNotNone(relr_section)
            self.assertEqual(relr_section.num_relocations(), 100)

    def test_get_relocation(self):
        """ Verify we can get a specific RELR relocation.
        """
        path = os.path.join('test', 'testfiles_for_unittests',
                            'lib_relro.so.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            relr_section = elf.get_section_by_name('.relr.dyn')
            self.assertIsNotNone(relr_section)
            reloc = relr_section.get_relocation(n=0)
            self.assertEqual(reloc['r_offset'], 0x4540)
            reloc = relr_section.get_relocation(n=65)
            self.assertEqual(reloc['r_offset'], 0x4748)

            dynamic_section = elf.get_section_by_name('.dynamic')
            self.assertIsNotNone(dynamic_section)
            dynamic_relr = dynamic_section.get_relocation_tables()
            self.assertIsNotNone(dynamic_relr)
            self.assertIsNotNone(dynamic_relr['RELR'])
            reloc = dynamic_relr['RELR'].get_relocation(n=0)
            self.assertEqual(reloc['r_offset'], 0x4540)
            reloc = dynamic_relr['RELR'].get_relocation(n=65)
            self.assertEqual(reloc['r_offset'], 0x4748)

    def test_expanded_relocations_from_sample(self):
        """ The expanded view must retain the legacy offsets and expose the
            in-place addend of the real sample.
        """
        path = os.path.join('test', 'testfiles_for_unittests',
                            'lib_relro.so.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            relr_section = elf.get_section_by_name('.relr.dyn')
            expanded = list(relr_section.iter_expanded_relocations())
            legacy = list(relr_section.iter_relocations())
            self.assertEqual(len(expanded), 100)
            self.assertEqual(
                [reloc['r_offset'] for reloc in legacy],
                [reloc.target_address for reloc in expanded])
            for reloc in expanded:
                self.assertEqual(reloc.status, RelrExpandedRelocation.STATUS_FILE)
                self.assertEqual(reloc.addend, 0x2490)
            # The sample has one anchor and two bitmaps: the anchor itself,
            # 63 addresses from the first bitmap, then 36 from the second.
            self.assertEqual(
                [reloc.relr_entry_index for reloc in expanded],
                [0] + [1] * 63 + [2] * 36)
            self.assertEqual(expanded[0].relr_entry, 0x4540)
            self.assertEqual(expanded[0].file_offset, 0x1540)

    def test_hand_listed_bitmap_addresses(self):
        """ Compare the expansion of consecutive and empty bitmaps against a
            manually listed address set, for every class and byte order.
        """
        for elfclass in (32, 64):
            # An anchor relocates its own address. Each following bitmap entry
            # has bit 0 set as a tag and describes (word_bits - 1) addresses.
            capacity = 8 * (elfclass // 8) - 1
            bitmap1 = 1 | (1 << 1) | (1 << 2) | (1 << 12)
            bitmap2 = 1 | (1 << 1) | (1 << 2)
            empty_bitmap = 1
            # This bitmap directly follows the empty one, so its target
            # proves that the empty bitmap advanced the base by a full word.
            bitmap3 = 1 | (1 << 1)
            # Four spans of bitmaps must fit within the slot table.
            slots_needed = 1 + 4 * capacity + 1
            anchor_slot2 = slots_needed - 2

            for little_endian in (True, False):
                # Two passes: the table layout depends only on the number of
                # words, so placeholders determine the addresses used below.
                placeholder = SyntheticRelrFile(
                    elfclass, little_endian,
                    slot_values=range(slots_needed),
                    relr_words=(0,) * 6)
                words = (
                    placeholder.slot_address(0), bitmap1, bitmap2,
                    empty_bitmap, bitmap3,
                    placeholder.slot_address(anchor_slot2))
                fixture = SyntheticRelrFile(
                    elfclass, little_endian,
                    slot_values=range(slots_needed),
                    relr_words=words)
                data = fixture.build()
                expected_slots = [
                    0,
                    1,
                    2,
                    12,
                    1 + capacity,
                    2 + capacity,
                    1 + 3 * capacity,
                    anchor_slot2,
                ]
                expected = [fixture.slot_address(slot) for slot in expected_slots]

                with self.subTest(elfclass=elfclass, little_endian=little_endian):
                    elf = ELFFile(BytesIO(data))
                    relr_section = elf.get_section_by_name('.relr.dyn')
                    expanded = list(relr_section.iter_expanded_relocations())
                    self.assertEqual(
                        [reloc.target_address for reloc in expanded], expected)
                    self.assertEqual(
                        [reloc['r_offset'] for reloc in
                         relr_section.iter_relocations()], expected)
                    for index, reloc in enumerate(expanded):
                        if index in (0, len(expected) - 1):
                            self.assertFalse(reloc.source.is_bitmap)
                            self.assertIsNone(reloc.source.bitmap_bit)
                        else:
                            self.assertTrue(reloc.source.is_bitmap)
                        slot = expected_slots[index]
                        self.assertEqual(reloc.addend, slot)
                        self.assertEqual(reloc.status,
                                         RelrExpandedRelocation.STATUS_FILE)
                        self.assertEqual(
                            reloc.file_offset,
                            fixture.slots_off + slot * fixture.addr_size)
                        self.assertEqual(reloc.mapped_offsets,
                                         (reloc.file_offset,))

                    # The empty entry itself contributes no relocation; the
                    # following bitmap starts one full-word span later.
                    self.assertEqual(
                        [reloc.source.index for reloc in expanded],
                        [0, 1, 1, 1, 2, 2, 4, 5])
                    self.assertEqual(
                        [reloc.source.bitmap_bit for reloc in expanded],
                        [None, 1, 2, 12, 1, 2, 1, None])

                    self.assertEqual(relr_section.num_expanded_relocations(),
                                     len(expected))
                    for index, reloc in enumerate(expanded):
                        self.assertEqual(
                            relr_section.get_expanded_relocation(index), reloc)

    def test_bitmap_provenance(self):
        """ The original word and the set bit are retained for each target.
        """
        first_word = SyntheticRelrFile(
            slot_values=range(4),
            relr_words=(0,) * 2)
        fixture = SyntheticRelrFile(
            slot_values=range(4),
            relr_words=(first_word.slot_address(0),
                        1 | (1 << 1) | (1 << 3)))
        with ELFFile(BytesIO(fixture.build())) as elf:
            expanded = list(
                elf.get_section_by_name('.relr.dyn').iter_expanded_relocations())
        self.assertEqual([reloc.relr_entry_index for reloc in expanded],
                         [0, 1, 1])
        self.assertEqual([reloc.source.bitmap_bit for reloc in expanded],
                         [None, 1, 3])
        self.assertEqual([reloc.relr_entry for reloc in expanded],
                         [fixture.slot_address(0), 0b1011, 0b1011])
        self.assertEqual(
            [reloc.relr_entry_offset for reloc in expanded],
            [fixture.relr_off] +
            [fixture.relr_off + fixture.addr_size] * 2)
        self.assertEqual([reloc.target_address for reloc in expanded],
                         [fixture.slot_address(0), fixture.slot_address(1),
                          fixture.slot_address(3)])

    def test_target_statuses(self):
        """ Zero-filled, overlapping, unmapped and past-EOF targets are
        reported without treating the virtual address as a file offset.
        """
        for elfclass in (32, 64):
            step = elfclass // 8
            for little_endian in (True, False):
                # Slot 0 is mapped by two PT_LOADs below, slot 1 is ordinary.
                placeholder = SyntheticRelrFile(
                    elfclass, little_endian,
                    slot_values=(0x11223344, 0x55667788),
                    relr_words=(0,) * 6,
                    zero_fill=0x100,
                    extra_segments=(
                        (0x600000, lambda builder: builder.dynstr_off,
                         step, step),
                        (0x800000,
                         lambda builder: builder.file_len - 2, 0x100, 0x100),
                    ))
                payload_end = placeholder.payload_end
                zero_target = placeholder.address(payload_end + 0x20)
                partial_target = placeholder.address(payload_end - 2)
                unmapped_target = placeholder.BASE + 0x500000
                outside_target = placeholder.BASE + 0x600000
                multiple_target = placeholder.slot_address(0)
                normal_target = placeholder.slot_address(1)
                fixture = SyntheticRelrFile(
                    elfclass, little_endian,
                    slot_values=(0x11223344, 0x55667788),
                    relr_words=(
                        zero_target, partial_target, unmapped_target,
                        outside_target, multiple_target, normal_target),
                    zero_fill=0x100,
                    extra_segments=(
                        # A second mapping of slot 0, at unrelated file content.
                        (multiple_target, lambda builder: builder.dynstr_off,
                         step, step),
                        # The mapping claims file bytes that run past EOF.
                        (outside_target,
                         lambda builder: builder.file_len - 2, 0x100, 0x100),
                    ))
                data = fixture.build()

                with self.subTest(elfclass=elfclass,
                                  little_endian=little_endian):
                    elf = ELFFile(BytesIO(data))
                    expanded = list(
                        elf.get_section_by_name(
                            '.relr.dyn').iter_expanded_relocations())
                    self.assertEqual(len(expanded), 6)

                    zero = expanded[0]
                    self.assertEqual(zero.status,
                                     RelrExpandedRelocation.STATUS_ZERO_FILL)
                    self.assertIsNone(zero.addend)
                    self.assertIsNone(zero.file_offset)

                    partial = expanded[1]
                    self.assertEqual(
                        partial.status,
                        RelrExpandedRelocation.STATUS_PARTIAL_MAPPING)
                    self.assertIsNone(partial.addend)
                    self.assertEqual(partial.file_offset, payload_end - 2)

                    unmapped = expanded[2]
                    self.assertEqual(
                        unmapped.status,
                        RelrExpandedRelocation.STATUS_UNMAPPED)
                    self.assertIsNone(unmapped.addend)
                    self.assertIsNone(unmapped.file_offset)
                    self.assertEqual(unmapped.mapped_offsets, ())

                    outside = expanded[3]
                    self.assertEqual(
                        outside.status,
                        RelrExpandedRelocation.STATUS_OUTSIDE_FILE)
                    self.assertIsNone(outside.addend)
                    self.assertEqual(outside.file_offset, fixture.file_len - 2)

                    multiple = expanded[4]
                    self.assertEqual(
                        multiple.status,
                        RelrExpandedRelocation.STATUS_MULTIPLE_MAPPINGS)
                    self.assertIsNone(multiple.addend)
                    self.assertEqual(len(multiple.mapped_offsets), 2)
                    self.assertIn(fixture.slots_off, multiple.mapped_offsets)
                    self.assertIn(fixture.dynstr_off, multiple.mapped_offsets)

                    normal = expanded[5]
                    self.assertEqual(normal.status,
                                     RelrExpandedRelocation.STATUS_FILE)
                    self.assertEqual(normal.addend, 0x55667788)
                    self.assertEqual(
                        normal.file_offset, fixture.slots_off + step)
                    # A non-zero load base makes the distinction explicit.
                    self.assertNotEqual(normal.file_offset,
                                        normal.target_address)

    @staticmethod
    def _fixture_with_bitmaps(elfclass, little_endian, slots):
        """ Build a fixture whose anchors point at real slots, so that the
            same expansion can be compared across entry points.
        """
        layout = SyntheticRelrFile(
            elfclass, little_endian, slot_values=range(slots),
            relr_words=(0,) * 3)
        anchor1 = layout.slot_address(0)
        anchor2 = layout.slot_address(slots - 2)
        return SyntheticRelrFile(
            elfclass, little_endian, slot_values=range(slots),
            relr_words=(anchor1, 1 | (1 << 1) | (1 << 2), anchor2))

    def test_multiple_mappings_with_agreeing_file_bytes(self):
        """ Overlapping mappings that select the same file bytes permit one
            unambiguous addend; a zero-filled overlapping mapping does not.
        """
        layout = SyntheticRelrFile(
            slot_values=(0xdeadbeef,), relr_words=(0,) * 1,
            extra_segments=((0, 0, 0, 0),))
        target = layout.slot_address(0)

        agree = SyntheticRelrFile(
            slot_values=(0xdeadbeef,), relr_words=(target,),
            extra_segments=(
                (target, lambda builder: builder.slots_off,
                 layout.addr_size, layout.addr_size),))
        with ELFFile(BytesIO(agree.build())) as elf:
            reloc = next(elf.get_section_by_name(
                '.relr.dyn').iter_expanded_relocations())
        self.assertEqual(reloc.status,
                         RelrExpandedRelocation.STATUS_MULTIPLE_MAPPINGS)
        self.assertEqual(reloc.mapped_offsets, (agree.slots_off,))
        self.assertEqual(reloc.file_offset, agree.slots_off)
        self.assertEqual(reloc.addend, 0xdeadbeef)

        # The second mapping is zero-filled: no single addend.
        disagree = SyntheticRelrFile(
            slot_values=(0xdeadbeef,), relr_words=(target,),
            extra_segments=(
                (target, lambda builder: builder.slots_off,
                 0, layout.addr_size + 0x100),))
        with ELFFile(BytesIO(disagree.build())) as elf:
            reloc = next(elf.get_section_by_name(
                '.relr.dyn').iter_expanded_relocations())
        self.assertEqual(reloc.status,
                         RelrExpandedRelocation.STATUS_MULTIPLE_MAPPINGS)
        self.assertIsNone(reloc.addend)
        self.assertIsNone(reloc.file_offset)
        self.assertEqual(reloc.mapped_offsets, (disagree.slots_off,))

    def test_section_and_dynamic_entry_points_agree(self):
        """ The section, dynamic section and dynamic segment entry points must
        produce the same expansion.
        """
        fixtures = [
            self._fixture_with_bitmaps(64, True, 8),
            self._fixture_with_bitmaps(32, False, 8),
        ]
        for fixture in fixtures:
            with self.subTest(elfclass=fixture.elfclass,
                              little_endian=fixture.little_endian):
                with ELFFile(BytesIO(fixture.build())) as elf:
                    section = elf.get_section_by_name('.relr.dyn')
                    dynamic_section = elf.get_section_by_name('.dynamic')
                    dynamic_segment = next(
                        elf.iter_segments(type='PT_DYNAMIC'))

                    from_section = _expanded_signature(
                        section.iter_expanded_relocations())
                    from_dynamic_section = _expanded_signature(
                        dynamic_section.get_relocation_tables()[
                            'RELR'].iter_expanded_relocations())
                    from_dynamic_segment = _expanded_signature(
                        dynamic_segment.get_relocation_tables()[
                            'RELR'].iter_expanded_relocations())
                    self.assertGreater(len(from_section), 1)
                    self.assertEqual(from_section, from_dynamic_section)
                    self.assertEqual(from_section, from_dynamic_segment)
                    self.assertEqual({entry[2] for entry in from_section},
                                     {RelrExpandedRelocation.STATUS_FILE})

    def test_dynamic_segment_without_sections(self):
        """ A stripped file still expands RELR through PT_DYNAMIC.
        """
        placeholder = SyntheticRelrFile(
            slot_values=range(4), relr_words=(0,) * 2, with_sections=False)
        fixture = SyntheticRelrFile(
            slot_values=range(4),
            relr_words=(placeholder.slot_address(0),
                        1 | (1 << 1) | (1 << 2)),
            with_sections=False)
        expected = [fixture.slot_address(slot) for slot in (0, 1, 2)]
        with ELFFile(BytesIO(fixture.build())) as elf:
            self.assertEqual(elf.num_sections(), 0)
            dynamic_segment = next(elf.iter_segments(type='PT_DYNAMIC'))
            expanded = list(
                dynamic_segment.get_relocation_tables()[
                    'RELR'].iter_expanded_relocations())
            self.assertEqual([reloc.target_address for reloc in expanded],
                             expected)
            self.assertEqual([reloc.addend for reloc in expanded],
                             [0, 1, 2])
            self.assertEqual(
                [reloc.file_offset for reloc in expanded],
                [fixture.slots_off,
                 fixture.slots_off + fixture.addr_size,
                 fixture.slots_off + 2 * fixture.addr_size])
            self.assertEqual({reloc.status for reloc in expanded},
                             {RelrExpandedRelocation.STATUS_FILE})


if __name__ == '__main__':
    unittest.main()
