#-------------------------------------------------------------------------------
# elftools: elf/debugsupplement.py
#
# Caller-driven matching of supplementary debug information for ELF files.
#
# A forensic backend must not pick a .debug/.dwo file merely because its
# basename matches the one referenced by an ELF. The classes in this module
# verify the identifier relationship between a primary ELF and the candidate
# streams supplied explicitly by the caller:
#
#   * .gnu_debuglink  -> CRC32 of the whole candidate file
#   * NT_GNU_BUILD_ID -> byte-identical build ID note
#   * split DWARF     -> 64-bit DWO ID (DWARF 5 header or GNU split-dwarf
#                        DW_AT_GNU_dwo_id)
#
# The module never opens a path itself: it only reads the streams it is given.
# It performs no network access and no filesystem traversal. Every decision is
# recorded as evidence, including rejections, so the caller can audit why a
# candidate was or was not used.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import binascii
from dataclasses import dataclass, field
from enum import Enum
from io import BytesIO
from typing import IO, TYPE_CHECKING

from ..common.exceptions import ELFError
from ..common.utils import struct_parse
from ..dwarf.abbrevtable import AbbrevTable
from ..dwarf.structs import DWARFStructs
from .elffile import ELFFile
from .sections import NoteSection
from .segments import NoteSegment

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..construct.lib.container import Container
    from ..dwarf.compileunit import CompileUnit


class RelationKind(str, Enum):
    """ Identifier relationships that may bind a primary file to a supplement.
    """
    DEBUGLINK_CRC = 'debuglink-crc'
    BUILD_ID = 'build-id'
    DWO_ID = 'dwo-id'
    SUPPLEMENTARY = 'supplementary-reference'


class EvidenceOutcome(str, Enum):
    """ What happened when a single candidate was examined.
    """
    MATCHED = 'matched'
    REJECTED_WRONG_IDENTIFIER = 'rejected-wrong-identifier'
    REJECTED_DUPLICATE = 'rejected-duplicate'
    REJECTED_CYCLE = 'rejected-cycle'
    REJECTED_BAD_ELF = 'rejected-bad-elf'
    NAME_MISMATCH = 'name-mismatch'
    NAME_ONLY_HINT = 'name-only-hint'


@dataclass(frozen=True)
class DebugCandidate:
    """ A supplementary debug file offered by the caller.

        label:
            Caller-chosen, unique display name (e.g. a path or an evidence
            item id). Used in reports; never interpreted as a filesystem path.

        stream:
            Binary stream holding the candidate file. The resolver does not
            close it: ownership stays with the caller.

        referenced_name:
            Optional basename the primary file refers to (a .gnu_debuglink
            filename or a DW_AT_dwo_name). It is used only as a hint and is
            never sufficient on its own to accept the candidate.
    """
    label: str
    stream: IO[bytes]
    referenced_name: str | bytes | None = None

    def normalized_name(self) -> str | None:
        """ Basename hint, decoded and stripped of any directory components.
        """
        if self.referenced_name is None:
            return None
        if isinstance(self.referenced_name, bytes):
            name = self.referenced_name.decode('utf-8', 'replace')
        else:
            name = self.referenced_name
        return name.replace('\\', '/').rstrip('/').split('/')[-1] or None


@dataclass(frozen=True)
class MatchEvidence:
    """ Audit record for one (candidate, relation) examination.
    """
    relation: RelationKind
    candidate_label: str
    outcome: EvidenceOutcome
    detail: str
    expected: str | None = None
    observed: str | None = None
    name_hint: str | None = None


@dataclass
class RelationResult:
    """ Outcome of resolving a single identifier relationship.
    """
    relation: RelationKind
    matched_label: str | None = None
    matched_stream: IO[bytes] | None = None
    evidence: list[MatchEvidence] = field(default_factory=list)
    # Every accepted (label, stream) pair; holds more than one entry for
    # relationships such as split DWARF, where each skeleton CU has its own
    # .dwo companion.
    matches: list[tuple[str, IO[bytes]]] = field(default_factory=list)
    # Content digests accepted for this relationship, so the same bytes
    # offered twice only create one match while distinct DWO files each
    # produce their own.
    accepted_digests: set[bytes] = field(default_factory=set)

    @property
    def resolved(self) -> bool:
        """ Whether a supplement was positively identified for this relation.
        """
        return bool(self.matches)


@dataclass
class SupplementReport:
    """ Full audit trail of a resolution run, across every relation checked.
    """
    primary_label: str
    results: dict[RelationKind, RelationResult] = field(default_factory=dict)

    def all_evidence(self) -> list[MatchEvidence]:
        """ Every evidence record, in the order it was produced.
        """
        records: list[MatchEvidence] = []
        for result in self.results.values():
            records.extend(result.evidence)
        return records

    def matched_labels(self) -> list[str]:
        """ Labels of the candidates that were actually accepted.
        """
        return [
            result.matched_label
            for result in self.results.values()
            if result.matched_label is not None
        ]


class DebugInfoResolver:
    """ Matches caller-provided candidates against a primary ELF file.

        The resolver is deliberately I/O-free beyond the streams handed to it:
        no paths are opened, no directories are searched and nothing is
        fetched from the network. Construct one per primary file, then call
        the relation-specific methods or :meth:`resolve_all`.
    """

    def __init__(
        self,
        primary: ELFFile,
        candidates: Sequence[DebugCandidate],
        primary_label: str = 'primary',
    ) -> None:
        self.primary = primary
        self.primary_label = primary_label
        self._candidates = list(candidates)
        self._labels = [candidate.label for candidate in self._candidates]
        if len(set(self._labels)) != len(self._labels):
            raise ValueError('candidate labels must be unique')
        self.report = SupplementReport(primary_label=primary_label)
        # Labels currently being resolved, to break mutual supplementary
        # cycles (A references B which references A ...). Per-relationship
        # content dedup lives on each RelationResult.
        self._resolution_stack: list[str] = [primary_label]

    #-- Public API ---------------------------------------------------------#

    def resolve_all(self) -> SupplementReport:
        """ Check every relationship advertised by the primary file.

            Returns the accumulated :class:`SupplementReport`. Relations the
            primary file gives no identifier for are simply absent from it.
        """
        self.resolve_debuglink()
        self.resolve_build_id()
        self.resolve_dwo()
        return self.report

    def resolve_supplementary_chain(
        self,
        max_depth: int = 16,
    ) -> SupplementReport:
        """ Follow accepted supplements and verify their own references.

            Each time a candidate is accepted it may itself point at another
            supplementary file (via .debug_sup / .gnu_debugaltlink). That
            reference is resolved against the same caller-provided candidate
            pool, using the filename only as a hint. A label already on the
            resolution chain is rejected as a cycle, so mutually referring
            supplements terminate instead of looping forever.

            Only streams from the original candidate pool are ever opened.
        """
        self.resolve_all()
        for result in list(self.report.results.values()):
            if result.matched_label is None:
                continue
            self._follow_supplement(
                result.matched_label, depth=1, max_depth=max_depth)
        return self.report

    def _follow_supplement(
        self,
        label: str,
        depth: int,
        max_depth: int,
    ) -> None:
        """ Resolve the .debug_sup/.gnu_debugaltlink of an accepted file.
        """
        if depth > max_depth or label in self._resolution_stack:
            return
        candidate = self._candidate_by_label(label)
        if candidate is None:
            return
        self._resolution_stack.append(label)
        try:
            candidate.stream.seek(0)
            try:
                supplement_elf = ELFFile(candidate.stream)
            except ELFError:
                return
            referenced = supplement_filename(supplement_elf)
            if referenced is not None:
                self._match_supplement_reference(
                    supplement_elf, referenced, depth, max_depth)
        finally:
            self._resolution_stack.pop()

    def _match_supplement_reference(
        self,
        supplement_elf: ELFFile,
        referenced: bytes,
        depth: int,
        max_depth: int,
    ) -> None:
        """ Verify a single supplementary reference against the candidate pool.

            The filename embedded in .debug_sup / .gnu_debugaltlink is only a
            hint: acceptance requires an identifier (a matching build ID when
            both sides carry one). A name match without identifier support is
            recorded as unresolved evidence.
        """
        referenced_name = referenced.decode('utf-8', 'replace')
        relation = RelationKind.SUPPLEMENTARY
        result = self._new_result(relation)
        expected_id = extract_build_id(supplement_elf)
        for candidate in self._candidates:
            name_hint = candidate.normalized_name()
            if candidate.label in self._resolution_stack:
                result.evidence.append(MatchEvidence(
                    relation=relation,
                    candidate_label=candidate.label,
                    outcome=EvidenceOutcome.REJECTED_CYCLE,
                    detail='supplementary reference points back to a file '
                           'already on the resolution chain',
                    expected=referenced_name,
                    observed=name_hint,
                    name_hint=name_hint))
                continue
            digest = self._stream_digest(candidate.stream)
            if digest in result.accepted_digests:
                result.evidence.append(MatchEvidence(
                    relation=relation,
                    candidate_label=candidate.label,
                    outcome=EvidenceOutcome.REJECTED_DUPLICATE,
                    detail='supplementary target content already accepted',
                    name_hint=name_hint))
                continue
            candidate.stream.seek(0)
            try:
                candidate_elf = ELFFile(candidate.stream)
            except ELFError as exc:
                result.evidence.append(MatchEvidence(
                    relation=relation,
                    candidate_label=candidate.label,
                    outcome=EvidenceOutcome.REJECTED_BAD_ELF,
                    detail=f'candidate is not a readable ELF file: {exc}',
                    name_hint=name_hint))
                continue
            observed_id = extract_build_id(candidate_elf)
            if expected_id is not None and observed_id == expected_id:
                self._accept(result, candidate, digest, name_hint,
                             expected=expected_id.hex(),
                             observed=observed_id.hex(),
                             detail='supplementary build ID is identical')
                self._publish(result)
                self._follow_supplement(
                    candidate.label, depth + 1, max_depth)
                return
            if name_hint == referenced_name.split('/')[-1]:
                result.evidence.append(MatchEvidence(
                    relation=relation,
                    candidate_label=candidate.label,
                    outcome=EvidenceOutcome.NAME_ONLY_HINT,
                    detail='basename matches the supplementary reference, '
                           'but no shared identifier confirms it',
                    name_hint=name_hint))
        self._publish(result)

    def _candidate_by_label(self, label: str) -> DebugCandidate | None:
        for candidate in self._candidates:
            if candidate.label == label:
                return candidate
        return None

    def resolve_debuglink(self) -> RelationResult:
        """ Match a candidate via the .gnu_debuglink CRC32 checksum.

            Every candidate is examined so rejections, duplicates and cycles
            are recorded as evidence; the first positive match wins.
        """
        result = self._new_result(RelationKind.DEBUGLINK_CRC)
        link = self.primary.get_dwarf_link()
        if link is None:
            return result
        expected_crc = int(link.checksum)
        link_name = bytes(link.filename).decode('utf-8', 'replace')
        for candidate in self._candidates:
            if result.resolved:
                self._record_after_match(result, candidate)
                continue
            name_hint = candidate.normalized_name()
            self._record_name_evidence(
                result, candidate, link_name, name_hint)
            digest = self._stream_digest(candidate.stream)
            # A cyclic reference must never be followed, even when its CRC
            # happens to match the link.
            if self._is_duplicate(result, candidate, digest, name_hint):
                continue
            observed_crc = self._stream_crc32(candidate.stream)
            if observed_crc != expected_crc:
                result.evidence.append(MatchEvidence(
                    relation=RelationKind.DEBUGLINK_CRC,
                    candidate_label=candidate.label,
                    outcome=EvidenceOutcome.REJECTED_WRONG_IDENTIFIER,
                    detail='CRC32 of the candidate file differs from the '
                           '.gnu_debuglink checksum',
                    expected=f'0x{expected_crc:08x}',
                    observed=f'0x{observed_crc:08x}',
                    name_hint=name_hint))
                continue
            self._accept(result, candidate, digest, name_hint,
                         expected=f'0x{expected_crc:08x}',
                         observed=f'0x{observed_crc:08x}',
                         detail='CRC32 matches the .gnu_debuglink checksum')
        return self._publish(result)

    def resolve_build_id(self) -> RelationResult:
        """ Match a candidate carrying the same NT_GNU_BUILD_ID note.
        """
        result = self._new_result(RelationKind.BUILD_ID)
        expected_id = extract_build_id(self.primary)
        if expected_id is None:
            return result
        for candidate in self._candidates:
            if result.resolved:
                self._record_after_match(result, candidate)
                continue
            name_hint = candidate.normalized_name()
            digest = self._stream_digest(candidate.stream)
            if self._is_duplicate(result, candidate, digest, name_hint):
                continue
            observed_id = self._candidate_build_id(candidate, result, name_hint)
            if observed_id is None:
                continue
            if observed_id != expected_id:
                result.evidence.append(MatchEvidence(
                    relation=RelationKind.BUILD_ID,
                    candidate_label=candidate.label,
                    outcome=EvidenceOutcome.REJECTED_WRONG_IDENTIFIER,
                    detail='NT_GNU_BUILD_ID differs from the primary file',
                    expected=expected_id.hex(),
                    observed=observed_id.hex(),
                    name_hint=name_hint))
                continue
            self._accept(result, candidate, digest, name_hint,
                         expected=expected_id.hex(),
                         observed=observed_id.hex(),
                         detail='NT_GNU_BUILD_ID is identical')
        return self._publish(result)

    def resolve_dwo(self) -> RelationResult:
        """ Match split-DWARF candidates by their 64-bit DWO ID.

            A primary file may hold several skeleton CUs, each with its own
            DWO ID, so this relation can match more than one candidate.
        """
        result = self._new_result(RelationKind.DWO_ID)
        expected_ids = collect_skeleton_dwo_ids(self.primary)
        if not expected_ids:
            return result
        remaining = dict(expected_ids)
        for candidate in self._candidates:
            name_hint = candidate.normalized_name()
            digest = self._stream_digest(candidate.stream)
            if self._is_duplicate(result, candidate, digest, name_hint):
                continue
            observed = self._candidate_dwo_ids(
                candidate, result, name_hint)
            if observed is None:
                continue
            common = sorted(set(observed) & set(remaining))
            if not common:
                result.evidence.append(MatchEvidence(
                    relation=RelationKind.DWO_ID,
                    candidate_label=candidate.label,
                    outcome=EvidenceOutcome.REJECTED_WRONG_IDENTIFIER,
                    detail='no DWO ID in the candidate matches a skeleton CU',
                    expected=', '.join(
                        f'0x{value:x}' for value in sorted(remaining)),
                    observed=', '.join(
                        f'0x{value:x}' for value in observed),
                    name_hint=name_hint))
                continue
            dwo_id = common[0]
            self._accept(result, candidate, digest, name_hint,
                         expected=f'0x{dwo_id:x}',
                         observed=f'0x{dwo_id:x}',
                         detail='DWO ID matches the skeleton compilation unit')
            del remaining[dwo_id]
        return self._publish(result)

    #-- Internals ----------------------------------------------------------#

    def _new_result(self, relation: RelationKind) -> RelationResult:
        """ Existing published result, or a fresh, not-yet-published one.
        """
        if relation in self.report.results:
            return self.report.results[relation]
        return RelationResult(relation=relation)

    def _publish(self, result: RelationResult) -> RelationResult:
        """ Attach a result to the report once it actually carries evidence.

            Relations the primary file gives no identifier for stay absent
            from the report instead of appearing as empty placeholders.
        """
        if result.evidence:
            self.report.results[result.relation] = result
        return result

    def _record_name_evidence(
        self,
        result: RelationResult,
        candidate: DebugCandidate,
        referenced_name: str,
        name_hint: str | None,
    ) -> None:
        """ Record what the filename hint alone proves (nothing, on its own).
        """
        if name_hint is None:
            return
        if name_hint == referenced_name:
            result.evidence.append(MatchEvidence(
                relation=result.relation,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.NAME_ONLY_HINT,
                detail='basename equals the referenced filename, but the '
                       'identifier still has to be verified',
                name_hint=name_hint))
        else:
            result.evidence.append(MatchEvidence(
                relation=result.relation,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.NAME_MISMATCH,
                detail='basename differs from the referenced filename; '
                       'the identifier alone decides',
                expected=referenced_name,
                observed=name_hint,
                name_hint=name_hint))

    def _is_duplicate(
        self,
        result: RelationResult,
        candidate: DebugCandidate,
        digest: bytes,
        name_hint: str | None,
    ) -> bool:
        """ Reject cyclic references and byte-identical repeats.

            Cycles take precedence: a candidate whose label is already on
            the resolution chain must never be followed, even if its
            identifier would otherwise match.
        """
        if candidate.label in self._resolution_stack:
            result.evidence.append(MatchEvidence(
                relation=result.relation,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.REJECTED_CYCLE,
                detail='candidate is already part of this supplementary '
                       'chain; following it would form a cycle',
                name_hint=name_hint))
            return True
        if digest in result.accepted_digests:
            result.evidence.append(MatchEvidence(
                relation=result.relation,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.REJECTED_DUPLICATE,
                detail='identical candidate content was already accepted; '
                       'duplicates must not create another relationship',
                name_hint=name_hint))
            return True
        return False

    def _record_after_match(
        self,
        result: RelationResult,
        candidate: DebugCandidate,
    ) -> None:
        """ Keep auditing candidates seen after the relation was resolved.

            The match itself is not revisited, but cyclic labels and
            byte-identical duplicates are still recorded explicitly so the
            report shows why they did not create a second relationship.
        """
        name_hint = candidate.normalized_name()
        if candidate.label in self._resolution_stack:
            result.evidence.append(MatchEvidence(
                relation=result.relation,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.REJECTED_CYCLE,
                detail='candidate is already part of this supplementary '
                       'chain; following it would form a cycle',
                name_hint=name_hint))
            return
        digest = self._stream_digest(candidate.stream)
        if digest in result.accepted_digests:
            result.evidence.append(MatchEvidence(
                relation=result.relation,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.REJECTED_DUPLICATE,
                detail='identical candidate content was already accepted; '
                       'duplicates must not create another relationship',
                name_hint=name_hint))

    def _accept(
        self,
        result: RelationResult,
        candidate: DebugCandidate,
        digest: bytes,
        name_hint: str | None,
        expected: str,
        observed: str,
        detail: str,
    ) -> None:
        result.evidence.append(MatchEvidence(
            relation=result.relation,
            candidate_label=candidate.label,
            outcome=EvidenceOutcome.MATCHED,
            detail=detail,
            expected=expected,
            observed=observed,
            name_hint=name_hint))
        result.accepted_digests.add(digest)
        result.matches.append((candidate.label, candidate.stream))
        # The first accepted pair remains directly accessible for the common
        # single-companion case; split DWARF may add further entries.
        if result.matched_stream is None:
            result.matched_label = candidate.label
            result.matched_stream = candidate.stream

    def _candidate_build_id(
        self,
        candidate: DebugCandidate,
        result: RelationResult,
        name_hint: str | None,
    ) -> bytes | None:
        candidate.stream.seek(0)
        try:
            candidate_elf = ELFFile(candidate.stream)
        except ELFError as exc:
            result.evidence.append(MatchEvidence(
                relation=RelationKind.BUILD_ID,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.REJECTED_BAD_ELF,
                detail=f'candidate is not a readable ELF file: {exc}',
                name_hint=name_hint))
            return None
        build_id = extract_build_id(candidate_elf)
        if build_id is None:
            result.evidence.append(MatchEvidence(
                relation=RelationKind.BUILD_ID,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.REJECTED_WRONG_IDENTIFIER,
                detail='candidate carries no NT_GNU_BUILD_ID note',
                name_hint=name_hint))
        return build_id

    def _candidate_dwo_ids(
        self,
        candidate: DebugCandidate,
        result: RelationResult,
        name_hint: str | None,
    ) -> list[int] | None:
        candidate.stream.seek(0)
        try:
            candidate_elf = ELFFile(candidate.stream)
        except ELFError as exc:
            result.evidence.append(MatchEvidence(
                relation=RelationKind.DWO_ID,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.REJECTED_BAD_ELF,
                detail=f'candidate is not a readable ELF file: {exc}',
                name_hint=name_hint))
            return None
        try:
            dwo_ids = collect_dwo_file_ids(candidate_elf)
        except ELFError as exc:
            result.evidence.append(MatchEvidence(
                relation=RelationKind.DWO_ID,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.REJECTED_BAD_ELF,
                detail=f'candidate DWO metadata is unreadable: {exc}',
                name_hint=name_hint))
            return None
        if not dwo_ids:
            result.evidence.append(MatchEvidence(
                relation=RelationKind.DWO_ID,
                candidate_label=candidate.label,
                outcome=EvidenceOutcome.REJECTED_WRONG_IDENTIFIER,
                detail='candidate contains no DWO ID',
                name_hint=name_hint))
        return dwo_ids

    @staticmethod
    def _stream_crc32(stream: IO[bytes]) -> int:
        stream.seek(0)
        checksum = 0
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            checksum = binascii.crc32(chunk, checksum)
        return checksum

    @staticmethod
    def _stream_digest(stream: IO[bytes]) -> bytes:
        # CRC32 is only 32 bits; use it together with the length so that
        # distinct files do not collapse into the same duplicate bucket.
        stream.seek(0)
        checksum = 0
        length = 0
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            length += len(chunk)
            checksum = binascii.crc32(chunk, checksum)
        return length.to_bytes(8, 'little') + checksum.to_bytes(4, 'little')


#-- Identifier extraction helpers ------------------------------------------#

def extract_build_id(elffile: ELFFile) -> bytes | None:
    """ Return the raw NT_GNU_BUILD_ID descriptor bytes, or None.

        Both SHT_NOTE sections and PT_NOTE segments are inspected; the first
        GNU build ID note wins.
    """
    for section in elffile.iter_sections():
        if not isinstance(section, NoteSection):
            continue
        for note in section.iter_notes():
            if note['n_type'] == 'NT_GNU_BUILD_ID' and note['n_name'] == 'GNU':
                return bytes(note['n_descdata'])
    for segment in elffile.iter_segments():
        if not isinstance(segment, NoteSegment):
            continue
        for note in segment.iter_notes():
            if note['n_type'] == 'NT_GNU_BUILD_ID' and note['n_name'] == 'GNU':
                return bytes(note['n_descdata'])
    return None


def supplement_filename(elffile: ELFFile) -> bytes | None:
    """ Return the filename embedded in .debug_sup / .gnu_debugaltlink.

        The value is a caller-supplied hint, not a verified identifier.
    """
    if not elffile.has_dwarf_info(True):
        return None
    dwarf_info = elffile.get_dwarf_info(
        relocate_dwarf_sections=True, follow_links=False)
    return dwarf_info.parse_debugsupinfo()


def collect_skeleton_dwo_ids(elffile: ELFFile) -> dict[int, str | None]:
    """ Map every skeleton CU's DWO ID to its referenced dwo name.

        Covers DWARF 5 skeleton units (dwo_id in the CU header plus
        DW_AT_dwo_name) and the GNU split-DWARF extension used with DWARF 4
        (DW_AT_GNU_dwo_id plus DW_AT_GNU_dwo_name on the root DIE).
    """
    if not elffile.has_dwarf_info(True):
        return {}
    dwarf_info = elffile.get_dwarf_info(
        relocate_dwarf_sections=True, follow_links=False)
    ids: dict[int, str | None] = {}
    for cu in dwarf_info.iter_CUs():
        dwo_id = _skeleton_dwo_id(cu)
        if dwo_id is None:
            continue
        ids[dwo_id] = _skeleton_dwo_name(cu)
    return ids


def collect_dwo_file_ids(elffile: ELFFile) -> list[int]:
    """ Extract the DWO IDs carried by a .dwo candidate file.

        DWARF 5 split compile units store the ID in the CU header. DWARF 4
        GNU split DWARF stores DW_AT_GNU_dwo_id in the root DIE, which is
        parsed directly so the unsupported GNU index forms do not get in the
        way.
    """
    info_section = _dwo_section(elffile, '.debug_info.dwo')
    if info_section is None:
        return []
    version = _peek_dwarf_version(info_section, elffile.little_endian)
    dwarf_format = _peek_dwarf_format(info_section, elffile.little_endian)
    structs = DWARFStructs(
        little_endian=elffile.little_endian,
        dwarf_format=dwarf_format,
        address_size=elffile.elfclass // 8,
        dwarf_version=version)
    stream = info_section
    stream.seek(0)
    end = len(stream.getvalue())
    ids: list[int] = []
    while stream.tell() < end:
        cu_start = stream.tell()
        header = struct_parse(structs.Dwarf_CU_header, stream)
        if version >= 5:
            dwo_id = header.get('dwo_id')
            if dwo_id is not None:
                ids.append(int(dwo_id))
        else:
            ids.extend(_parse_gnu_v4_dwo_ids(
                elffile, structs, stream, header))
        # unit_length counts everything after the initial-length field.
        next_cu = (
            cu_start
            + structs.initial_length_field_size()
            + int(header['unit_length']))
        stream.seek(next_cu)
    return ids


#-- Private DWARF helpers ---------------------------------------------------#

def _skeleton_dwo_id(cu: CompileUnit) -> int | None:
    header: Container = cu.header
    if header.get('unit_type') == 'DW_UT_skeleton':
        dwo_id = header.get('dwo_id')
        return int(dwo_id) if dwo_id is not None else None
    root = cu.get_top_DIE()
    attr = root.attributes.get('DW_AT_GNU_dwo_id')
    if attr is not None:
        return int(attr.value)
    return None


def _skeleton_dwo_name(cu: CompileUnit) -> str | None:
    root = cu.get_top_DIE()
    for attr_name in ('DW_AT_dwo_name', 'DW_AT_GNU_dwo_name'):
        attr = root.attributes.get(attr_name)
        if attr is not None and isinstance(attr.value, bytes):
            return attr.value.decode('utf-8', 'replace')
    return None


def _dwo_section(elffile: ELFFile, name: str) -> BytesIO | None:
    section = elffile.get_section_by_name(name)
    if section is None:
        return None
    return BytesIO(section.data())


def _peek_dwarf_version(stream: BytesIO, little_endian: bool) -> int:
    stream.seek(0)
    prefix = stream.read(4)
    if len(prefix) < 4:
        raise ELFError('truncated .debug_info.dwo section')
    is_64bit = int.from_bytes(
        prefix, 'little' if little_endian else 'big') == 0xFFFFFFFF
    # In the 64-bit format the continuation word is followed by an 8-byte
    # length, so the 2-byte version field starts at offset 12 instead of 4.
    stream.seek(12 if is_64bit else 4)
    raw = stream.read(2)
    stream.seek(0)
    if len(raw) < 2:
        raise ELFError('truncated .debug_info.dwo section')
    return int.from_bytes(raw, 'little' if little_endian else 'big')


def _peek_dwarf_format(stream: BytesIO, little_endian: bool) -> int:
    """ Distinguish the 32-bit and 64-bit DWARF formats (DWARF 7.4).

        The 64-bit format starts with the continuation value 0xFFFFFFFF.
    """
    stream.seek(0)
    prefix = stream.read(4)
    stream.seek(0)
    if len(prefix) < 4:
        raise ELFError('truncated .debug_info.dwo section')
    continuation = int.from_bytes(
        prefix, 'little' if little_endian else 'big')
    return 64 if continuation == 0xFFFFFFFF else 32


def _parse_gnu_v4_dwo_ids(
    elffile: ELFFile,
    structs: DWARFStructs,
    info_stream: IO[bytes],
    header: Container,
) -> list[int]:
    """ Read DW_AT_GNU_dwo_id from a DWARF 4 .dwo root DIE.

        The root DIE's attribute forms are interpreted in declaration order,
        which keeps the GNU-specific index forms out of the generic DIE
        parser while still consuming every attribute before the target one.
        The caller repositions the stream at the next CU afterwards.
    """
    abbrev_section = _dwo_section(elffile, '.debug_abbrev.dwo')
    if abbrev_section is None:
        raise ELFError('DWARF 4 .dwo file lacks .debug_abbrev.dwo')
    abbrev_code = structs.the_Dwarf_uleb128.parse_stream(info_stream)
    table = AbbrevTable(
        structs, abbrev_section, int(header['debug_abbrev_offset']))
    declaration = table.get_abbrev(int(abbrev_code)).decl
    dwo_ids: list[int] = []
    for attr_spec in declaration['attr_spec']:
        form = attr_spec['form']
        # The GNU split-DWARF index forms are uleb128 indices; the generic
        # DIE parser rejects them, but for identifier extraction their exact
        # width is all that matters.
        if form in ('DW_FORM_GNU_str_index', 'DW_FORM_GNU_addr_index'):
            structs.the_Dwarf_uleb128.parse_stream(info_stream)
            continue
        parser = structs.Dwarf_dw_form.get(form)
        if parser is None:
            raise ELFError(
                f'unsupported DWARF form {form} in DWARF 4 .dwo root DIE')
        value = struct_parse(parser, info_stream)
        if attr_spec['name'] == 'DW_AT_GNU_dwo_id':
            dwo_ids.append(int(value))
    return dwo_ids
