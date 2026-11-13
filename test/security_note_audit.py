# -------------------------------------------------------------------------------
# test/security_note_audit.py
#
# Conservative static auditor for control-flow mitigation declarations stored
# in the GNU property note (.note.gnu.property / PT_GNU_PROPERTY).
#
# The auditor never pattern-matches raw bytes for a constant.  It drives the
# real pyelftools NOTE decoder (PT_NOTE segments and SHT_NOTE sections), then
# walks each NT_GNU_PROPERTY_TYPE_0 descriptor with explicit bounds checks so
# that truncated or contradictory descriptors cannot produce an "enabled"
# verdict.  Results are three-valued:
#
#   ENABLED        the mitigation bit is declared set in a well-formed note
#   ABSENT         a well-formed note (or no property note at all) declares it
#                  without the bit
#   UNDETERMINED   the file is ambiguous or malformed; claiming either way
#                  would be a false positive or a false negative
#
# A static declaration is only a claim by the producer of the object.  It does
# not prove that the kernel, dynamic loader or CPU actually enforce the
# mitigation at runtime; see test_security_properties.py for details.
#
# This code is in the public domain.
# -------------------------------------------------------------------------------
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from elftools.common.exceptions import ELFError
from elftools.elf.enums import (
    ENUM_GNU_PROPERTY_X86_FEATURE_1_FLAGS,
    ENUM_NOTE_GNU_PROPERTY_TYPE,
)
from elftools.elf.sections import NoteSection
from elftools.elf.segments import NoteSegment

if TYPE_CHECKING:
    from elftools.elf.elffile import ELFFile

NT_GNU_PROPERTY_TYPE_0 = 5

# Numeric identifiers for the processor-specific GNU property types.  Keeping
# the numbers here (rather than only the enum names) lets the auditor reason
# about a property even when pyelftools leaves the type un-decoded.
GNU_PROPERTY_X86_FEATURE_1_AND = 0xC0000002
GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xC0000000
GNU_PROPERTY_RISCV_FEATURE_1_AND = 0xC0000000

# Every processor feature-1 AND property defined by the psABIs carries a
# single 4-byte word.
FEATURE_WORD_SIZE = 4

# Known feature-1 bits per architecture.  Anything outside these masks in a
# feature word is an unknown, forward-compatible bit and forces caution.
X86_FEATURE_1_KNOWN_MASK = (
    ENUM_GNU_PROPERTY_X86_FEATURE_1_FLAGS["GNU_PROPERTY_X86_FEATURE_1_IBT"]
    | ENUM_GNU_PROPERTY_X86_FEATURE_1_FLAGS["GNU_PROPERTY_X86_FEATURE_1_SHSTK"]
    | ENUM_GNU_PROPERTY_X86_FEATURE_1_FLAGS["GNU_PROPERTY_X86_FEATURE_1_LAM_U48"]
    | ENUM_GNU_PROPERTY_X86_FEATURE_1_FLAGS["GNU_PROPERTY_X86_FEATURE_1_LAM_U57"]
)
AARCH64_FEATURE_1_BTI = 0x1
AARCH64_FEATURE_1_PAC = 0x2
AARCH64_FEATURE_1_KNOWN_MASK = AARCH64_FEATURE_1_BTI | AARCH64_FEATURE_1_PAC
RISCV_FEATURE_1_BTI = 0x1
RISCV_FEATURE_1_KNOWN_MASK = RISCV_FEATURE_1_BTI


class Verdict(str, Enum):
    """Three-valued result for a single mitigation on one ELF object."""

    ENABLED = "enabled"
    ABSENT = "absent"
    UNDETERMINED = "undetermined"


@dataclass(frozen=True)
class MitigationSpec:
    """Architecture-scoped location of one mitigation's declaration bit."""

    name: str
    machines: frozenset[str]
    property_type: int
    bit: int
    known_mask: int


# The same numeric property type and the same feature-bit number mean
# different things on different architectures.  A bit is only meaningful
# through the architecture-specific spec below.
MITIGATIONS: tuple[MitigationSpec, ...] = (
    MitigationSpec(
        name="x86-ibt",
        machines=frozenset({"EM_386", "EM_X86_64"}),
        property_type=GNU_PROPERTY_X86_FEATURE_1_AND,
        bit=ENUM_GNU_PROPERTY_X86_FEATURE_1_FLAGS["GNU_PROPERTY_X86_FEATURE_1_IBT"],
        known_mask=X86_FEATURE_1_KNOWN_MASK,
    ),
    MitigationSpec(
        name="x86-shstk",
        machines=frozenset({"EM_386", "EM_X86_64"}),
        property_type=GNU_PROPERTY_X86_FEATURE_1_AND,
        bit=ENUM_GNU_PROPERTY_X86_FEATURE_1_FLAGS["GNU_PROPERTY_X86_FEATURE_1_SHSTK"],
        known_mask=X86_FEATURE_1_KNOWN_MASK,
    ),
    MitigationSpec(
        name="aarch64-bti",
        machines=frozenset({"EM_AARCH64"}),
        property_type=GNU_PROPERTY_AARCH64_FEATURE_1_AND,
        bit=AARCH64_FEATURE_1_BTI,
        known_mask=AARCH64_FEATURE_1_KNOWN_MASK,
    ),
    MitigationSpec(
        name="aarch64-pac",
        machines=frozenset({"EM_AARCH64"}),
        property_type=GNU_PROPERTY_AARCH64_FEATURE_1_AND,
        bit=AARCH64_FEATURE_1_PAC,
        known_mask=AARCH64_FEATURE_1_KNOWN_MASK,
    ),
    MitigationSpec(
        name="riscv-bti",
        machines=frozenset({"EM_RISCV"}),
        property_type=GNU_PROPERTY_RISCV_FEATURE_1_AND,
        bit=RISCV_FEATURE_1_BTI,
        known_mask=RISCV_FEATURE_1_KNOWN_MASK,
    ),
)


@dataclass
class FeatureWord:
    """One decoded feature-1 AND property entry."""

    property_type: int
    value: int
    source: str
    note_index: int


@dataclass
class MitigationResult:
    mitigation: str
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    applicable: bool = True


@dataclass
class AuditReport:
    machine: str
    elfclass: int
    little_endian: bool
    results: dict[str, MitigationResult]
    malformed: list[str] = field(default_factory=list)

    def verdict(self, mitigation: str) -> Verdict:
        return self.results[mitigation].verdict


def _note_locations(elffile: ELFFile) -> list[tuple[str, int, int, object]]:
    """Collect every NOTE-bearing section and segment without duplicates.

    Returns (label, offset, size, note_holder) tuples.  A note that lives
    in both a PT_NOTE segment and an SHT_NOTE section over the same bytes
    is only scanned once, but both locations are recorded so callers can
    see the declaration is reachable through both views.
    """
    locations: list[tuple[str, int, int, object]] = []
    seen: set[tuple[int, int]] = set()

    for section in elffile.iter_sections():
        if isinstance(section, NoteSection):
            key = (section["sh_offset"], section["sh_size"])
            seen.add(key)
            label_name = section.name or "<unnamed SHT_NOTE>"
            locations.append(
                (
                    f"section:{label_name}",
                    section["sh_offset"],
                    section["sh_size"],
                    section,
                )
            )

    for segment in elffile.iter_segments():
        if isinstance(segment, NoteSegment):
            key = (segment["p_offset"], segment["p_filesz"])
            if key not in seen:
                locations.append(
                    (
                        f"segment:{segment['p_type']}",
                        segment["p_offset"],
                        segment["p_filesz"],
                        segment,
                    )
                )
    return locations


def _property_type_number(pr_type: object) -> int:
    """Return the numeric pr_type even when pyelftools decoded it to a name."""
    if isinstance(pr_type, int):
        return pr_type
    name = str(pr_type)
    value = ENUM_NOTE_GNU_PROPERTY_TYPE.get(name)
    if value is None:  # pragma: no cover - defensive, names come from the enum
        raise ValueError(f"undecodable property type {pr_type!r}")
    return value


def _decode_feature_words(
    elffile: ELFFile,
    descriptor: bytes,
    source: str,
    note_index: int,
    malformed: list[str],
) -> list[FeatureWord]:
    """Walk a property descriptor with explicit bounds checking.

    pyelftools already decodes the note framing and Elf_Prop entries, but
    this independent walk re-validates every pr_type/pr_datasz header and
    every 4-byte feature word against the descriptor bounds.  A descriptor
    that overruns, has a mis-sized feature entry, or leaves trailing bytes
    is reported as malformed rather than trusted.
    """
    words: list[FeatureWord] = []
    endian = "<" if elffile.little_endian else ">"
    # Property entries are aligned to the native word size: 4 bytes on ILP32,
    # 8 bytes on LP64.
    entry_align = 4 if elffile.elfclass == 32 else 8
    offset = 0
    size = len(descriptor)

    while offset < size:
        if size - offset < 8:
            malformed.append(f"{source}: truncated property header at byte {offset}")
            return words
        pr_type, pr_datasz = struct.unpack_from(endian + "II", descriptor, offset)
        data_start = offset + 8
        data_end = data_start + pr_datasz
        if data_end > size:
            malformed.append(
                f"{source}: property 0x{pr_type:08x} descriptor overruns "
                f"note (needs {pr_datasz} bytes at offset {data_start}, "
                f"have {size - data_start})"
            )
            return words
        if pr_datasz == FEATURE_WORD_SIZE:
            (value,) = struct.unpack_from(endian + "I", descriptor, data_start)
            words.append(FeatureWord(pr_type, value, source, note_index))
        # Non-feature properties (STACK_SIZE, NO_COPY_ON_PROTECTED, unknown
        # vendor entries) are skipped; their sizes still drive the walk.
        next_offset = data_end
        if entry_align > 1:
            padding = (-next_offset) % entry_align
            next_offset += padding
        if next_offset <= offset:  # pragma: no cover - pure defensive guard
            malformed.append(f"{source}: non-advancing property at {offset}")
            return words
        offset = next_offset

    if offset != size:
        malformed.append(
            f"{source}: {offset - size} trailing bytes after property walk"
        )
    return words


def _collect_evidence(
    elffile: ELFFile,
) -> tuple[list[FeatureWord], list[str], int]:
    """Decode every GNU property note through the real NOTE machinery."""
    words: list[FeatureWord] = []
    malformed: list[str] = []
    property_note_count = 0

    for source, _offset, _size, holder in _note_locations(elffile):
        try:
            notes = list(holder.iter_notes())
        except ELFError as exc:
            # pyelftools raises (e.g. FieldError wrapped in ELFParseError) when
            # a property entry claims bytes the descriptor does not contain.
            malformed.append(f"{source}: note decoder failed: {exc}")
            continue

        for note_index, note in enumerate(notes):
            if note.get("n_name") != "GNU":
                continue
            n_type = note["n_type"]
            if n_type != "NT_GNU_PROPERTY_TYPE_0" and n_type != NT_GNU_PROPERTY_TYPE_0:
                continue
            property_note_count += 1
            descriptor = note["n_descdata"]
            # Cross-check the structured view against the raw descriptor.
            try:
                structured = list(note["n_desc"])
            except ELFError as exc:
                malformed.append(f"{source}: property decoder failed: {exc}")
                continue
            words.extend(
                _decode_feature_words(
                    elffile, descriptor, source, note_index, malformed
                )
            )
            _cross_check_structured(structured, descriptor, source, malformed)

    return words, malformed, property_note_count


def _cross_check_structured(
    structured: list[object],
    descriptor: bytes,
    source: str,
    malformed: list[str],
) -> None:
    """Confirm the high-level Elf_Prop view stays inside the descriptor."""
    for prop in structured:
        pr_type = _property_type_number(prop.pr_type)  # type: ignore[attr-defined]
        pr_datasz = int(prop.pr_datasz)  # type: ignore[attr-defined]
        if pr_datasz > len(descriptor):
            malformed.append(
                f"{source}: structured property 0x{pr_type:08x} size "
                f"{pr_datasz} exceeds descriptor {len(descriptor)}"
            )


# Numeric property types that each architecture's psABI assigns a feature
# meaning to.  The same number (0xC0000000) is a feature word on AArch64 and
# RISC-V but an unrelated entry elsewhere, so validity is per architecture.
_ARCH_FEATURE_TYPES: dict[str, set[int]] = {}
# Union of every feature bit an architecture documents.  AArch64 and RISC-V
# reuse the same property number, so the machine-specific mask decides whether
# set bits are interpretable rather than the MitigationSpec alone.
_ARCH_KNOWN_MASKS: dict[str, int] = {}
for _spec in MITIGATIONS:
    for _machine in _spec.machines:
        _ARCH_FEATURE_TYPES.setdefault(_machine, set()).add(_spec.property_type)
        _ARCH_KNOWN_MASKS[_machine] = (
            _ARCH_KNOWN_MASKS.get(_machine, 0) | _spec.known_mask
        )


def _evaluate(
    spec: MitigationSpec,
    machine: str,
    words: list[FeatureWord],
    malformed: list[str],
    property_note_count: int,
) -> MitigationResult:
    result = MitigationResult(mitigation=spec.name, verdict=Verdict.ABSENT)

    if machine not in spec.machines:
        # The numeric property type is reused across architectures; never let
        # an AArch64/RISC-V word satisfy an x86 check or vice versa.
        result.applicable = False
        result.verdict = Verdict.ABSENT
        result.reasons.append(
            f"{spec.name} is only defined for {sorted(spec.machines)}, "
            f"this object is {machine}"
        )
        return result

    if malformed:
        result.verdict = Verdict.UNDETERMINED
        result.reasons.extend(malformed)
        return result

    arch_types = _ARCH_FEATURE_TYPES[machine]
    arch_mask = _ARCH_KNOWN_MASKS[machine]

    # A property number this architecture does not assign feature meaning to
    # is foreign metadata.  This is what keeps an AArch64 0xC0000000 word out
    # of the x86 decision and keeps an x86 0xC0000002 word out of AArch64.
    if spec.property_type not in arch_types:
        result.reasons.append(
            f"property type 0x{spec.property_type:08x} has no feature meaning "
            f"on {machine}"
        )
        return result

    relevant = [w for w in words if w.property_type == spec.property_type]
    foreign = [w for w in words if w.property_type not in arch_types]
    if foreign:
        result.reasons.append(
            "ignored feature word(s) with property types "
            f"{sorted({hex(w.property_type) for w in foreign})} that are not "
            f"defined for {machine}"
        )

    if not relevant:
        if property_note_count == 0:
            result.reasons.append(
                "no NT_GNU_PROPERTY_TYPE_0 note present in any NOTE "
                "section or segment"
            )
        else:
            result.reasons.append(
                f"property type 0x{spec.property_type:08x} not declared"
            )
        return result

    # Multiple AND entries must be intersected: every object contributing to
    # the link must support the feature.  Conflicting declarations mean we
    # cannot state a single answer for the resulting artifact.
    values = [w.value for w in relevant]
    intersection = values[0]
    for value in values[1:]:
        intersection &= value

    if len(set(values)) > 1:
        result.verdict = Verdict.UNDETERMINED
        result.reasons.append(
            f"conflicting feature words {[hex(v) for v in values]} from "
            f"{[w.source for w in relevant]}; AND-intersection would be "
            f"{hex(intersection)} but the entries disagree"
        )
        return result

    value = values[0]
    unknown_bits = value & ~arch_mask
    if unknown_bits:
        # The property type is recognized on this architecture, but the word
        # sets a bit this psABI revision does not document (e.g. an AArch64
        # BTI/PAC word carrying a vendor bit, or a RISC-V word using an
        # AArch64-only bit).  Refuse to certify rather than ignoring the bit.
        result.verdict = Verdict.UNDETERMINED
        result.reasons.append(
            f"feature word {hex(value)} contains unknown bit(s) "
            f"{hex(unknown_bits)} outside known mask {hex(arch_mask)} "
            f"for {machine}"
        )
        return result

    if value & spec.bit:
        result.verdict = Verdict.ENABLED
        result.reasons.append(
            f"bit 0x{spec.bit:x} set in property 0x{spec.property_type:08x} "
            f"word {hex(value)} via {relevant[0].source}"
        )
    else:
        result.reasons.append(f"bit 0x{spec.bit:x} clear in property word {hex(value)}")
    return result


def audit_stream(stream: BinaryIO) -> AuditReport:
    """Audit an open binary stream containing one ELF object."""
    # Imported lazily so the module can be imported without an ELFFile cycle.
    from elftools.elf.elffile import ELFFile

    with ELFFile(stream) as elffile:
        machine = elffile["e_machine"]
        words, malformed, note_count = _collect_evidence(elffile)
        results = {
            spec.name: _evaluate(spec, machine, words, malformed, note_count)
            for spec in MITIGATIONS
        }
        return AuditReport(
            machine=machine,
            elfclass=elffile.elfclass,
            little_endian=elffile.little_endian,
            results=results,
            malformed=malformed,
        )


def audit_bytes(data: bytes) -> AuditReport:
    return audit_stream(BytesIO(data))


def audit_path(path: str) -> AuditReport:
    with open(path, "rb") as stream:
        return audit_stream(stream)
