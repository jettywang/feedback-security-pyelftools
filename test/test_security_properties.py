# -------------------------------------------------------------------------------
# test/test_security_properties.py
#
# False-positive-resistant tests for the static CET/BTI/PAC declaration
# auditor in security_note_audit.py.
#
# These tests never search an ELF for a constant byte pattern.  Every fixture
# is a fully formed ELF object whose PT_NOTE segment and SHT_NOTE section are
# decoded through pyelftools' real NOTE machinery.  A small in-memory ELF
# builder gives exact control over architecture, endianness, 32/64-bit
# alignment, property types, feature bits, descriptor truncation and byte
# mutations.
#
# The three verdict classes exercised below are:
#
#   ENABLED        a well-formed note declares the mitigation bit
#   ABSENT         a well-formed note (or none) does not declare it
#   UNDETERMINED   malformed/ambiguous input; neither claim is safe
#
# A static declaration cannot prove runtime enforcement.  The note only records
# what the toolchain emitted; the kernel, loader and CPU may ignore, downgrade
# or reject it.  See test_static_declaration_is_not_runtime_proof for the
# explicit argument.
#
# This code is in the public domain.
# -------------------------------------------------------------------------------
from __future__ import annotations

import os
import struct
import unittest
from io import BytesIO

from security_note_audit import (
    AARCH64_FEATURE_1_BTI,
    AARCH64_FEATURE_1_PAC,
    GNU_PROPERTY_AARCH64_FEATURE_1_AND,
    GNU_PROPERTY_X86_FEATURE_1_AND,
    MITIGATIONS,
    Verdict,
    audit_bytes,
)

# Machine values from the ELF spec (e_machine).
EM_386 = 3
EM_X86_64 = 62
EM_AARCH64 = 183
EM_RISCV = 243

PT_NOTE = 4
SHT_NOTE = 7
NT_GNU_PROPERTY_TYPE_0 = 5

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
READELF_CORPUS = os.path.join(_TEST_DIR, "testfiles_for_readelf")
UNITTEST_CORPUS = os.path.join(_TEST_DIR, "testfiles_for_unittests")


# -------------------------------------------------------------------------------
# Minimal in-memory ELF builder.  It emits a real Ehdr, one PT_NOTE program
# header and one SHT_NOTE section pointing at the same note bytes, so every
# test exercises both the segment and the section decoding paths.
# -------------------------------------------------------------------------------
def _round_up(value: int, alignment: int) -> int:
    return value + (-value) % alignment


def gnu_property_note(
    entries: list[tuple[int, bytes]],
    *,
    big_endian: bool = False,
    descriptor_truncate: int = 0,
    note_name: bytes = b"GNU\0",
    note_type: int = NT_GNU_PROPERTY_TYPE_0,
    property_alignment: int = 8,
) -> bytes:
    """Build the raw bytes of one NT_GNU_PROPERTY_TYPE_0 note.

    entries is a list of (pr_type, pr_data).  Property entries use the
    native word alignment (4 bytes for ELF32, 8 for ELF64), matching the
    GNU property note layout.
    """
    endian = ">" if big_endian else "<"
    descriptor = bytearray()
    for pr_type, pr_data in entries:
        header = struct.pack(endian + "II", pr_type, len(pr_data))
        entry = header + pr_data
        entry += b"\0" * ((-len(entry)) % property_alignment)
        descriptor += entry
    if descriptor_truncate:
        descriptor = descriptor[:-descriptor_truncate]

    name_field = note_name + b"\0" * ((-len(note_name)) % 4)
    nhdr = struct.pack(endian + "III", len(note_name), len(descriptor), note_type)
    return nhdr + name_field + bytes(descriptor)


def build_elf(
    note: bytes,
    *,
    elfclass: int = 64,
    machine: int = EM_X86_64,
    big_endian: bool = False,
    with_pt_note: bool = True,
    with_sht_note: bool = True,
) -> bytes:
    endian = ">" if big_endian else "<"
    data_encoding = 2 if big_endian else 1

    if elfclass == 64:
        ehsize = 64
        phentsize = 56
        shentsize = 64
        phnum = 1 if with_pt_note else 0
        note_off = ehsize + phnum * phentsize
        blob = bytearray(ehsize)
        blob[0:16] = b"\x7fELF" + bytes([2, data_encoding, 1, 0]) + b"\0" * 8
        struct.pack_into(
            endian + "HHIQQQIHHHHHH",
            blob,
            16,
            1,
            machine,
            1,
            0,
            ehsize if phnum else 0,
            0,
            0,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            2 if with_sht_note else 0,
            0,
        )
        if with_pt_note:
            # ELF64 Phdr: type,flags,offset,vaddr,paddr,filesz,memsz,align
            blob += struct.pack(
                endian + "IIQQQQQQ", PT_NOTE, 0, note_off, 0, 0, len(note), len(note), 4
            )
        blob += note
        if with_sht_note:
            shoff = len(blob)
            blob += b"\0" * shentsize
            blob += struct.pack(
                endian + "IIQQQQIIQQ",
                0,
                SHT_NOTE,
                2,
                0,
                note_off,
                len(note),
                0,
                0,
                8,
                0,
            )
            struct.pack_into(endian + "Q", blob, 40, shoff)
        return bytes(blob)

    # ELF32 Ehdr field offsets: e_type16 e_machine18 e_version20 e_entry24
    # e_phoff28 e_shoff32 e_flags36, halfword fields from offset 40.
    ehsize = 52
    phentsize = 32
    shentsize = 40
    phnum = 1 if with_pt_note else 0
    phoff = ehsize
    note_off = phoff + phnum * phentsize
    blob = bytearray(ehsize)
    blob[0:16] = b"\x7fELF" + bytes([1, data_encoding, 1, 0]) + b"\0" * 8
    struct.pack_into(endian + "HHI", blob, 16, 1, machine, 1)
    struct.pack_into(endian + "I", blob, 24, 0)
    struct.pack_into(endian + "II", blob, 28, phoff if phnum else 0, 0)
    struct.pack_into(endian + "I", blob, 36, 0)
    struct.pack_into(
        endian + "HHHHHH",
        blob,
        40,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        2 if with_sht_note else 0,
        0,
    )
    if with_pt_note:
        # ELF32 Phdr: type,offset,vaddr,paddr,filesz,memsz,flags,align
        blob += struct.pack(
            endian + "IIIIIIII", PT_NOTE, note_off, 0, 0, len(note), len(note), 0, 4
        )
    blob += note
    if with_sht_note:
        shoff = len(blob)
        blob += b"\0" * shentsize
        blob += struct.pack(
            endian + "IIIIIIIIII", 0, SHT_NOTE, 2, 0, note_off, len(note), 0, 0, 8, 0
        )
        struct.pack_into(endian + "I", blob, 32, shoff)
    return bytes(blob)


def feature_word(
    pr_type: int, value: int, *, big_endian: bool = False
) -> tuple[int, bytes]:
    endian = ">" if big_endian else "<"
    return pr_type, struct.pack(endian + "I", value)


def x86_note(value: int, **kwargs: object) -> bytes:
    return gnu_property_note(
        [
            feature_word(
                GNU_PROPERTY_X86_FEATURE_1_AND,
                value,
                big_endian=bool(kwargs.get("big_endian", False)),
            )
        ],
        big_endian=bool(kwargs.get("big_endian", False)),
        property_alignment=int(kwargs.get("property_alignment", 8)),
    )


def aarch64_note(value: int, *, big_endian: bool = False) -> bytes:
    return gnu_property_note(
        [
            feature_word(
                GNU_PROPERTY_AARCH64_FEATURE_1_AND, value, big_endian=big_endian
            )
        ],
        big_endian=big_endian,
    )


class TestSyntheticFixturesAreRealElf(unittest.TestCase):
    """The builder must produce objects pyelftools decodes as genuine ELF."""

    def test_64bit_fixture_decodes_through_both_note_paths(self) -> None:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import NoteSection
        from elftools.elf.segments import NoteSegment

        data = build_elf(x86_note(0x1), elfclass=64, machine=EM_X86_64)
        with ELFFile(BytesIO(data)) as elf:
            self.assertEqual(elf.elfclass, 64)
            self.assertEqual(elf["e_machine"], "EM_X86_64")
            note_sections = [
                s for s in elf.iter_sections() if isinstance(s, NoteSection)
            ]
            note_segments = [
                g for g in elf.iter_segments() if isinstance(g, NoteSegment)
            ]
            self.assertEqual(len(note_sections), 1)
            self.assertEqual(len(note_segments), 1)
            section_props = [
                (p.pr_type, p.pr_data)
                for n in note_sections[0].iter_notes()
                for p in n.n_desc
            ]
            segment_props = [
                (p.pr_type, p.pr_data)
                for n in note_segments[0].iter_notes()
                for p in n.n_desc
            ]
            expected = [("GNU_PROPERTY_X86_FEATURE_1_AND", 1)]
            self.assertEqual(section_props, expected)
            self.assertEqual(segment_props, expected)

    def test_32bit_fixture_uses_four_byte_property_alignment(self) -> None:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import NoteSection

        # On ELF32 a 4-byte feature word plus 8-byte header is exactly 12
        # bytes, which is already 4-byte aligned; on ELF64 it would need
        # 4 bytes of padding.
        note = gnu_property_note(
            [feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x1)], property_alignment=4
        )
        data = build_elf(note, elfclass=32, machine=EM_386)
        with ELFFile(BytesIO(data)) as elf:
            self.assertEqual(elf.elfclass, 32)
            sections = [s for s in elf.iter_sections() if isinstance(s, NoteSection)]
            props = [
                (p.pr_type, p.pr_datasz, p.pr_data)
                for n in sections[0].iter_notes()
                for p in n.n_desc
            ]
            self.assertEqual(props, [("GNU_PROPERTY_X86_FEATURE_1_AND", 4, 1)])

    def test_big_endian_aarch64_fixture(self) -> None:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import NoteSection

        note = aarch64_note(
            AARCH64_FEATURE_1_BTI | AARCH64_FEATURE_1_PAC, big_endian=True
        )
        data = build_elf(note, elfclass=64, machine=EM_AARCH64, big_endian=True)
        with ELFFile(BytesIO(data)) as elf:
            self.assertFalse(elf.little_endian)
            self.assertEqual(elf["e_machine"], "EM_AARCH64")
            section = next(s for s in elf.iter_sections() if isinstance(s, NoteSection))
            props = [
                (p.pr_type, p.pr_data) for n in section.iter_notes() for p in n.n_desc
            ]
            self.assertEqual(props, [("GNU_PROPERTY_AARCH64_FEATURE_1_AND", 3)])

    def test_segment_only_note_path_is_audited(self) -> None:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import NoteSection
        from elftools.elf.segments import NoteSegment

        # Stripped objects can carry PT_NOTE without any SHT_NOTE section.
        data = build_elf(x86_note(0x3), machine=EM_X86_64, with_sht_note=False)
        with ELFFile(BytesIO(data)) as elf:
            self.assertEqual(
                [s for s in elf.iter_sections() if isinstance(s, NoteSection)],
                [],
            )
            self.assertEqual(
                len([g for g in elf.iter_segments() if isinstance(g, NoteSegment)]),
                1,
            )
        report = audit_bytes(data)
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ENABLED)

    def test_section_only_note_path_is_audited(self) -> None:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import NoteSection
        from elftools.elf.segments import NoteSegment

        # Relocatable objects can have an SHT_NOTE section and no PT_NOTE.
        data = build_elf(
            x86_note(0x3, property_alignment=8),
            machine=EM_X86_64,
            with_pt_note=False,
        )
        with ELFFile(BytesIO(data)) as elf:
            self.assertEqual(
                len([g for g in elf.iter_segments() if isinstance(g, NoteSegment)]),
                0,
            )
            self.assertEqual(
                len([s for s in elf.iter_sections() if isinstance(s, NoteSection)]),
                1,
            )
        report = audit_bytes(data)
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ENABLED)


class TestDeclarationMatrix(unittest.TestCase):
    """Three-way matrix: ENABLED / ABSENT / UNDETERMINED."""

    # -- ENABLED -----------------------------------------------------------
    def test_x86_ibt_and_shstk_enabled_64bit(self) -> None:
        report = audit_bytes(build_elf(x86_note(0x3), machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ENABLED)
        self.assertEqual(report.malformed, [])

    def test_x86_ibt_only_enabled_shstk_absent_same_word(self) -> None:
        # Bit 1 (IBT) set, bit 2 (SHSTK) clear: the two mitigations sharing
        # one feature word must be evaluated independently.
        report = audit_bytes(build_elf(x86_note(0x1), machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ABSENT)

    def test_aarch64_bti_and_pac_enabled_big_endian(self) -> None:
        note = aarch64_note(
            AARCH64_FEATURE_1_BTI | AARCH64_FEATURE_1_PAC, big_endian=True
        )
        report = audit_bytes(build_elf(note, machine=EM_AARCH64, big_endian=True))
        self.assertEqual(report.verdict("aarch64-bti"), Verdict.ENABLED)
        self.assertEqual(report.verdict("aarch64-pac"), Verdict.ENABLED)

    def test_32bit_x86_enabled_path(self) -> None:
        report = audit_bytes(
            build_elf(x86_note(0x2, property_alignment=4), elfclass=32, machine=EM_386)
        )
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ABSENT)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ENABLED)

    def test_real_aarch64_corpus_declares_bti_and_pac(self) -> None:
        report = audit_bytes(
            _read(os.path.join(READELF_CORPUS, "aarch64-pac-bti.so.elf"))
        )
        self.assertEqual(report.machine, "EM_AARCH64")
        self.assertEqual(report.verdict("aarch64-bti"), Verdict.ENABLED)
        self.assertEqual(report.verdict("aarch64-pac"), Verdict.ENABLED)
        self.assertEqual(report.malformed, [])

    def test_real_x86_corpus_declares_cet(self) -> None:
        report = audit_bytes(
            _read(os.path.join(READELF_CORPUS, "note_gnu_property.elf"))
        )
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ENABLED)

    # -- ABSENT ------------------------------------------------------------
    def test_no_property_note_means_absent(self) -> None:
        # An ELF with NOTE headers but an empty note region carries no
        # property declaration at all.
        empty_note = b""
        data = build_elf(empty_note, machine=EM_X86_64)
        report = audit_bytes(data)
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ABSENT)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ABSENT)

    def test_property_note_without_feature_word_is_absent(self) -> None:
        # STACK_SIZE (type 1) is a valid property but says nothing about CET.
        note = gnu_property_note([(1, struct.pack("<Q", 0x123000))])
        report = audit_bytes(build_elf(note, machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ABSENT)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ABSENT)
        self.assertEqual(report.malformed, [])

    def test_feature_word_present_but_bit_clear_is_absent(self) -> None:
        report = audit_bytes(build_elf(x86_note(0x0), machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ABSENT)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ABSENT)

    def test_real_32bit_binary_without_property_note_is_absent(self) -> None:
        report = audit_bytes(_read(os.path.join(READELF_CORPUS, "exe_simple32.elf")))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ABSENT)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ABSENT)

    # -- Architecture boundary: same number, wrong architecture -----------
    def test_aarch64_property_type_does_not_enable_x86_cet(self) -> None:
        # 0xC0000000 is GNU_PROPERTY_AARCH64_FEATURE_1_AND.  Placing that
        # number on an x86-64 object must never read as IBT/SHSTK, even though
        # the x86 FEATURE_1_AND type 0xC0000002 shares its high bits.
        note = gnu_property_note(
            [feature_word(GNU_PROPERTY_AARCH64_FEATURE_1_AND, 0x3)]
        )
        report = audit_bytes(build_elf(note, machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ABSENT)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ABSENT)

    def test_x86_property_type_does_not_enable_aarch64_bti(self) -> None:
        note = gnu_property_note([feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x3)])
        report = audit_bytes(build_elf(note, machine=EM_AARCH64))
        self.assertEqual(report.verdict("aarch64-bti"), Verdict.ABSENT)
        self.assertEqual(report.verdict("aarch64-pac"), Verdict.ABSENT)

    def test_aarch64_word_under_riscv_machine_is_conservative(self) -> None:
        # AArch64 and RISC-V both use property type 0xC0000000, but the bit
        # semantics differ.  An AArch64 BTI|PAC word (0x3) carries bit 0x2,
        # which is undefined for RISC-V FEATURE_1 (only bit 0x1 = BTI).  The
        # auditor must not certify RISC-V BTI; the uninterpreted bit forces an
        # undetermined verdict rather than a false "enabled".
        note = gnu_property_note(
            [feature_word(GNU_PROPERTY_AARCH64_FEATURE_1_AND, 0x3)]
        )
        report = audit_bytes(build_elf(note, machine=EM_RISCV))
        self.assertNotEqual(report.verdict("riscv-bti"), Verdict.ENABLED)
        self.assertEqual(report.verdict("riscv-bti"), Verdict.UNDETERMINED)

    def test_riscv_bti_bit_alone_is_enabled(self) -> None:
        # The same property number with only the RISC-V-defined BTI bit is a
        # legitimate RISC-V declaration.
        note = gnu_property_note(
            [feature_word(GNU_PROPERTY_AARCH64_FEATURE_1_AND, 0x1)]
        )
        report = audit_bytes(build_elf(note, machine=EM_RISCV))
        self.assertEqual(report.verdict("riscv-bti"), Verdict.ENABLED)

    def test_in_architecture_mitigations_are_not_applicable(self) -> None:
        report = audit_bytes(build_elf(x86_note(0x3), machine=EM_X86_64))
        for name in ("aarch64-bti", "aarch64-pac", "riscv-bti"):
            result = report.results[name]
            self.assertFalse(result.applicable)
            self.assertEqual(result.verdict, Verdict.ABSENT)

    # -- UNDETERMINED: malformed or ambiguous ------------------------------
    def test_truncated_feature_descriptor_is_undetermined(self) -> None:
        # The feature entry claims four data bytes but the descriptor is cut
        # so they are missing.
        note = gnu_property_note(
            [feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x3)], descriptor_truncate=4
        )
        report = audit_bytes(build_elf(note, machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.UNDETERMINED)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.UNDETERMINED)
        self.assertTrue(report.malformed)

    def test_truncated_property_header_is_undetermined(self) -> None:
        # A complete feature entry followed by four orphan bytes that cannot
        # form the mandatory 8-byte pr_type/pr_datasz header.
        good = gnu_property_note([feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x1)])
        # Strip the GNU note framing (12-byte Nhdr + 4-byte aligned name) and
        # append an unparseable tail, then re-frame the raw descriptor.
        descriptor = good[16:] + struct.pack("<I", GNU_PROPERTY_X86_FEATURE_1_AND)
        raw = _wrap_raw_descriptor(descriptor)
        report = audit_bytes(build_elf(raw, machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.UNDETERMINED)
        # Either pyelftools' own decoder rejects the overrun first, or the
        # auditor's explicit bounds walk flags the incomplete header.
        self.assertTrue(report.malformed)
        self.assertTrue(
            any(
                "truncated property header" in m or "decoder failed" in m
                for m in report.malformed
            )
        )

    def test_feature_entry_wrong_size_is_not_evidence(self) -> None:
        # FEATURE_1_AND must be exactly four bytes.  A structurally valid but
        # 8-byte entry cannot be interpreted as a feature word, so the
        # mitigation is simply not declared (ABSENT), not malformed.
        note = gnu_property_note(
            [
                (GNU_PROPERTY_X86_FEATURE_1_AND, struct.pack("<II", 0x3, 0x0)),
            ]
        )
        report = audit_bytes(build_elf(note, machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ABSENT)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ABSENT)
        self.assertEqual(report.malformed, [])

    def test_conflicting_feature_words_are_undetermined(self) -> None:
        # Two AND entries disagree (IBT set vs clear).  The link-time AND
        # rule would clear IBT, but contradictory producer metadata must not be
        # silently collapsed into either answer.
        note = gnu_property_note(
            [
                feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x3),
                feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x2),
            ]
        )
        report = audit_bytes(build_elf(note, machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.UNDETERMINED)
        # SHSTK is set in both, yet the entry conflict still forces caution.
        self.assertEqual(report.verdict("x86-shstk"), Verdict.UNDETERMINED)
        self.assertTrue(
            any("conflicting" in r for r in report.results["x86-ibt"].reasons)
        )

    def test_duplicate_identical_feature_words_remain_enabled(self) -> None:
        note = gnu_property_note(
            [
                feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x3),
                feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x3),
            ]
        )
        report = audit_bytes(build_elf(note, machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ENABLED)

    def test_unknown_feature_bit_forces_undetermined(self) -> None:
        # Bit 0x10 is not part of the known x86 FEATURE_1 mask.  A future
        # toolchain using it must not let us certify the legacy bits blindly.
        report = audit_bytes(build_elf(x86_note(0x13), machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.UNDETERMINED)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.UNDETERMINED)
        self.assertTrue(
            any("unknown bit" in r for r in report.results["x86-ibt"].reasons)
        )

    def test_unknown_aarch64_bit_forces_undetermined(self) -> None:
        # BTI set plus an unknown high bit in the AArch64 feature word.
        value = AARCH64_FEATURE_1_BTI | 0x80000000
        report = audit_bytes(build_elf(aarch64_note(value), machine=EM_AARCH64))
        self.assertEqual(report.verdict("aarch64-bti"), Verdict.UNDETERMINED)
        self.assertEqual(report.verdict("aarch64-pac"), Verdict.UNDETERMINED)

    def test_non_gnu_note_owner_is_ignored(self) -> None:
        # The numeric note type 5 only means NT_GNU_PROPERTY_TYPE_0 inside the
        # "GNU" owner namespace.  Another owner's type-5 note is not evidence.
        note = gnu_property_note(
            [feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x3)], note_name=b"XXXX\0"
        )
        report = audit_bytes(build_elf(note, machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ABSENT)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ABSENT)

    def test_unknown_note_type_is_ignored(self) -> None:
        note = gnu_property_note(
            [feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x3)], note_type=0x12345
        )
        report = audit_bytes(build_elf(note, machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ABSENT)


def _wrap_raw_descriptor(descriptor: bytes, *, big_endian: bool = False) -> bytes:
    """Frame an arbitrary descriptor inside a GNU property note header."""
    endian = ">" if big_endian else "<"
    name = b"GNU\0"
    return (
        struct.pack(endian + "III", len(name), len(descriptor), NT_GNU_PROPERTY_TYPE_0)
        + name
        + descriptor
    )


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


class TestMutationAssertionsFail(unittest.TestCase):
    """A correct enabled verdict must collapse once the evidence is mutated.

    Each test takes a genuinely ENABLED object, flips one decoded field,
    and asserts that the original enabled assertion no longer holds.
    """

    def _enabled_x86(self) -> bytes:
        return build_elf(x86_note(0x3), machine=EM_X86_64)

    def test_endianness_mutation_invalidates_feature_value(self) -> None:
        # Build a big-endian note but label the ELF little-endian (and vice
        # versa): the decoder then reads the feature word byte-swapped.
        note_be = gnu_property_note(
            [feature_word(GNU_PROPERTY_X86_FEATURE_1_AND, 0x3, big_endian=True)],
            big_endian=True,
        )
        mismatched = build_elf(note_be, machine=EM_X86_64, big_endian=False)
        report = audit_bytes(mismatched)
        # The byte-swapped 0x03000000 contains unknown bits and no IBT/SHSTK,
        # so it cannot remain ENABLED.
        self.assertNotEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        self.assertNotEqual(report.verdict("x86-shstk"), Verdict.ENABLED)

    def test_architecture_mutation_invalidates_verdict(self) -> None:
        data = bytearray(self._enabled_x86())
        # e_machine sits at Ehdr offset 18 (two bytes, little-endian).
        original_machine = struct.unpack_from("<H", data, 18)[0]
        self.assertEqual(original_machine, EM_X86_64)
        struct.pack_into("<H", data, 18, EM_AARCH64)
        report = audit_bytes(bytes(data))
        self.assertEqual(report.machine, "EM_AARCH64")
        # The x86-specific property no longer applies to the new machine.
        self.assertNotEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        self.assertNotEqual(report.verdict("x86-shstk"), Verdict.ENABLED)
        # And it must not accidentally satisfy the AArch64 checks.
        self.assertNotEqual(report.verdict("aarch64-bti"), Verdict.ENABLED)

    def test_property_type_mutation_invalidates_verdict(self) -> None:
        data = bytearray(self._enabled_x86())
        # The note begins after Ehdr(64)+Phdr(56); the property pr_type is
        # 12 (Nhdr) + 4 (name) bytes into the note.
        pr_type_off = 64 + 56 + 12 + 4
        self.assertEqual(
            struct.unpack_from("<I", data, pr_type_off)[0],
            GNU_PROPERTY_X86_FEATURE_1_AND,
        )
        struct.pack_into("<I", data, pr_type_off, 0xDEADBEEF)
        report = audit_bytes(bytes(data))
        self.assertNotEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        self.assertNotEqual(report.verdict("x86-shstk"), Verdict.ENABLED)

    def test_feature_bit_mutation_clears_enabled(self) -> None:
        data = bytearray(self._enabled_x86())
        value_off = 64 + 56 + 12 + 4 + 8
        self.assertEqual(struct.unpack_from("<I", data, value_off)[0], 0x3)
        struct.pack_into("<I", data, value_off, 0x0)
        report = audit_bytes(bytes(data))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ABSENT)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ABSENT)

    def test_descriptor_size_mutation_to_truncated_is_undetermined(self) -> None:
        data = bytearray(self._enabled_x86())
        # n_descsz is the second word of the Nhdr at the note start.
        descsz_off = 64 + 56 + 4
        original = struct.unpack_from("<I", data, descsz_off)[0]
        struct.pack_into("<I", data, descsz_off, original - 4)
        report = audit_bytes(bytes(data))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.UNDETERMINED)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.UNDETERMINED)

    def test_unmutated_fixture_still_enabled_guard(self) -> None:
        # Control case proving the mutation tests start from a true ENABLED.
        report = audit_bytes(self._enabled_x86())
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        self.assertEqual(report.verdict("x86-shstk"), Verdict.ENABLED)


class TestRealCorpusIntegration(unittest.TestCase):
    """End-to-end checks against checked-in ELF objects."""

    def test_note_after_gnu_property_still_decodes(self) -> None:
        path = os.path.join(UNITTEST_CORPUS, "note_after_gnu_property", "main.elf")
        report = audit_bytes(_read(path))
        # The object carries a well-formed property note followed by another
        # note; the auditor must not treat the trailing note as properties.
        self.assertEqual(report.malformed, [])

    def test_segment_padding_file_is_clean(self) -> None:
        path = os.path.join(UNITTEST_CORPUS, "note_with_segment_padding", "main.elf")
        report = audit_bytes(_read(path))
        self.assertEqual(report.malformed, [])

    def test_every_mitigation_has_a_spec(self) -> None:
        names = {spec.name for spec in MITIGATIONS}
        self.assertEqual(
            names, {"x86-ibt", "x86-shstk", "aarch64-bti", "aarch64-pac", "riscv-bti"}
        )


class TestStaticDeclarationIsNotRuntimeProof(unittest.TestCase):
    """Documents why the static verdict is a declaration, not enforcement."""

    def test_report_only_describes_static_bytes(self) -> None:
        report = audit_bytes(build_elf(x86_note(0x3), machine=EM_X86_64))
        self.assertEqual(report.verdict("x86-ibt"), Verdict.ENABLED)
        # The report carries no runtime state: no kernel/loader/CPU signal is
        # observable from the file, so ENABLED means "declared" only.
        self.assertFalse(hasattr(report, "runtime_enforced"))


if __name__ == "__main__":
    unittest.main()
