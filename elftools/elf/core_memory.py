#-------------------------------------------------------------------------------
# elftools: elf/core_memory.py
#
# Address-to-mapping queries for ELF core files
#
# This code is in the public domain
#-------------------------------------------------------------------------------
""" Combine NT_FILE mappings with the memory bytes an ELF core preserves.

An ELF core describes two related but independent things:

* The ``NT_FILE`` note lists crash-time mappings: virtual ranges, the offset
  within the mapped file (stored in units of ``page_size``), and the recorded
  name.  A mapping can exist even when none of its bytes were written to the
  core.
* ``PT_LOAD`` segments describe what the core actually saved.  ``p_filesz``
  may be much smaller than ``p_memsz`` (for example, only the first page of a
  large mapping, or a completely zero-filled anonymous range).

The query results here keep those sources separate, so a caller can tell "the
address belonged to this mapping" apart from "the core has these bytes".  They
also preserve ambiguity: overlapping mappings and overlapping ``PT_LOAD``
segments are reported as candidates rather than silently resolved.

Names are exactly the byte strings recorded in the core.  This module never
opens a file named by the core; resolving a name against local evidence is the
caller's decision.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from ..common.exceptions import ELFError
from ..common.utils import stream_read
from .segments import NoteSegment

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..construct.lib.container import Container
    from .elffile import ELFFile


ADDRESS_KIND = Literal['file', 'anonymous']
ADDRESS_SOURCE = Literal['nt_file', 'pt_load']
READ_STATUS = Literal['present', 'partial', 'not_present', 'not_unique', 'unavailable']


@dataclass(frozen=True)
class CoreMapping:
    """ One entry from an ``NT_FILE`` note.

        ``page_offset`` is the raw note field, in units of ``page_size``;
        ``file_offset`` is that value converted to bytes.  ``file_offset`` is
        ``None`` when the note declares a non-positive page size, because the
        conversion would be meaningless.

        ``vm_size`` is the mapped virtual length (``vm_end - vm_start``).  It
        is not the size of the underlying file: a core does not record that,
        and the mapping may extend past EOF or cover only part of the file.

        ``name`` is decoded from the core's bytes using UTF-8 with
        ``surrogateescape`` so that the original bytes can be recovered with
        ``raw_name``; it is not a path resolved on this machine.
    """
    index: int
    note_index: int
    vm_start: int
    vm_end: int
    page_offset: int
    page_size: int
    file_offset: int | None
    vm_size: int
    raw_name: bytes
    name: str

    def contains_address(self, address: int) -> bool:
        """ Whether this mapping's virtual range contains ``address``. """
        return self.vm_start <= address < self.vm_end

    def file_offset_for(self, address: int) -> int | None:
        """ The mapped-file offset corresponding to ``address``.

            This is ``file_offset`` plus the distance from ``vm_start``.  It is
            ``None`` when the offset is unknown or the address is outside this
            mapping.  The result is only as precise as the page-granular
            ``page_offset`` field allows.
        """
        if self.file_offset is None or not self.contains_address(address):
            return None
        return self.file_offset + (address - self.vm_start)

    @property
    def deleted(self) -> bool:
        """ Whether Linux marked this name as an already-unlinked file. """
        return self.name.endswith(' (deleted)')

    @property
    def original_name(self) -> str:
        """ The recorded name without the ``" (deleted)"`` marker, if any. """
        suffix = ' (deleted)'
        return self.name[:-len(suffix)] if self.deleted else self.name


@dataclass(frozen=True)
class CoreLoad:
    """ One ``PT_LOAD`` segment of the core.

        ``index`` is the program header index within the ELF file.

        The segment's virtual range is ``[vaddr, vaddr + memsz)``.  The bytes
        the core actually stores for it are ``[content_start, content_end)``,
        where ``content_end == vaddr + filesz``.  A segment with
        ``p_filesz == 0`` still appears here: it proves the address space
        existed while proving no bytes were saved.
    """
    index: int
    vaddr: int
    memsz: int
    filesz: int
    offset: int
    content_start: int
    content_end: int

    def covers_address_space(self, address: int) -> bool:
        """ Whether the segment's virtual range contains ``address``. """
        return self.vaddr <= address < self.vaddr + self.memsz

    def covers_content(self, address: int) -> bool:
        """ Whether the segment's preserved bytes contain ``address``. """
        return self.content_start <= address < self.content_end


@dataclass(frozen=True)
class CoreReadResult:
    """ The bytes the core preserves for the range ``[address, address+size)``.

        ``status`` values:

        * ``present``: exactly one segment supplied all ``size`` bytes; ``data``
          contains them.
        * ``partial``: a unique segment preserves some but not all ``size``
          bytes; ``available`` is the preserved prefix length and ``data`` is
          ``None``.
        * ``not_present``: at least one segment's virtual range covers the
          start address, but none of its preserved bytes do.  ``available`` is
          0 and ``data`` is ``None``.
        * ``not_unique``: a byte in the requested range has several possible
          sources, so no source is chosen.  ``available`` is the uniquely
          readable prefix length (possibly 0) and ``candidates`` lists the
          segment indices involved at the first ambiguous byte.
        * ``unavailable``: no ``PT_LOAD`` segment claims the address at all.
    """
    address: int
    size: int
    status: READ_STATUS
    data: bytes | None
    available: int
    candidates: tuple[int, ...]


@dataclass(frozen=True)
class CoreReadableRange:
    """ The contiguous preserved-byte range available from one address.

        ``start`` is the queried address and ``end`` is the first address after
        the bytes this core actually stores for it, or ``None`` when the status
        does not justify claiming a range.  For ``not_unique`` the range is
        deliberately absent: two segments preserve overlapping bytes and this
        core does not choose between them.
    """
    address: int
    status: READ_STATUS
    start: int | None
    end: int | None
    candidates: tuple[int, ...]


@dataclass(frozen=True)
class CoreAddressResult:
    """ All evidence for one queried address.

        ``mappings`` are ``NT_FILE`` entries covering the address (all of them,
        including overlaps).  ``loads`` are ``PT_LOAD`` segments whose virtual
        range covers it, including segments that preserve only a header page or
        no bytes at all.  ``readable`` describes only the preserved bytes and
        never implies that an NT_FILE mapping was backed by core content.
    """
    address: int
    kind: ADDRESS_KIND
    source: tuple[ADDRESS_SOURCE, ...]
    mappings: tuple[CoreMapping, ...]
    loads: tuple[CoreLoad, ...]
    readable: CoreReadableRange

    @property
    def in_file_mapping(self) -> bool:
        """ Whether at least one ``NT_FILE`` entry covers the address. """
        return bool(self.mappings)

    @property
    def has_memory_content(self) -> bool:
        """ Whether unique preserved bytes exist at the address. """
        return self.readable.status == 'present'

    @property
    def candidate_names(self) -> tuple[str, ...]:
        """ Recorded names of covering mappings, in note order, without repeats.

            More than one name means the file identity cannot be chosen from
            this core's evidence alone.
        """
        names: list[str] = []
        for mapping in self.mappings:
            if mapping.name not in names:
                names.append(mapping.name)
        return tuple(names)

    @property
    def file_name(self) -> str | None:
        """ The unique recorded mapping name, or ``None`` if it is ambiguous. """
        names = self.candidate_names
        return names[0] if len(names) == 1 else None


class CoreFile:
    """ Read-only address queries over an ``ET_CORE`` ELF file.

        Obtain an instance with :meth:`ELFFile.get_core_file`.

        The object snapshots the NT_FILE mappings and PT_LOAD headers when it is
        created.  It never opens a file named in the core.  PT_LOAD headers that
        describe exactly the same range and file bytes are treated as one; only
        genuinely different sources count as overlap.
    """
    def __init__(self, elffile: ELFFile) -> None:
        if elffile['e_type'] != 'ET_CORE':
            raise ELFError('Core queries require an ET_CORE file')

        self.elffile = elffile
        self.mappings: tuple[CoreMapping, ...] = ()
        self.loads: tuple[CoreLoad, ...] = ()
        self.nt_file_note_count = 0
        self.page_size: int | None = None

        self._collect_mappings()
        self._collect_loads()

    def _iter_core_notes(self) -> Iterator[Container]:
        for segment in self.elffile.iter_segments(type='PT_NOTE'):
            assert isinstance(segment, NoteSegment)
            yield from segment.iter_notes()

    @property
    def multiple_nt_file_notes(self) -> bool:
        """ Whether mappings were combined from more than one NT_FILE note. """
        return self.nt_file_note_count > 1

    def _collect_mappings(self) -> None:
        mappings: list[CoreMapping] = []
        page_sizes: set[int] = set()
        note_index = 0
        for note in self._iter_core_notes():
            if note['n_type'] != 'NT_FILE':
                continue
            self.nt_file_note_count += 1
            desc = note['n_desc']
            page_size = desc.get('page_size')
            entries = desc.get('Elf_Nt_File_Entry') or ()
            filenames = desc.get('filename') or ()
            if not isinstance(page_size, int) or page_size <= 0:
                page_size = 0
            else:
                page_sizes.add(page_size)
            for entry, raw_name in zip(entries, filenames):
                vm_start = entry['vm_start']
                vm_end = entry['vm_end']
                page_offset = entry['page_offset']
                mappings.append(CoreMapping(
                    index=len(mappings),
                    note_index=note_index,
                    vm_start=vm_start,
                    vm_end=vm_end,
                    page_offset=page_offset,
                    page_size=page_size,
                    file_offset=page_offset * page_size if page_size else None,
                    vm_size=vm_end - vm_start,
                    raw_name=raw_name,
                    name=raw_name.decode('utf-8', errors='surrogateescape'),
                ))
            note_index += 1
        self.mappings = tuple(mappings)
        self.page_size = page_sizes.pop() if len(page_sizes) == 1 else None

    def _collect_loads(self) -> None:
        loads: list[CoreLoad] = []
        seen: set[tuple[int, int, int, int]] = set()
        for index in range(self.elffile.num_segments()):
            segment = self.elffile.get_segment(index)
            if segment['p_type'] != 'PT_LOAD':
                continue
            vaddr = segment['p_vaddr']
            filesz = segment['p_filesz']
            key = (vaddr, segment['p_memsz'], filesz, segment['p_offset'])
            if key in seen:
                # Two headers describing the same bytes are not an ambiguity:
                # choosing either would produce the same answer.
                continue
            seen.add(key)
            loads.append(CoreLoad(
                index=index,
                vaddr=vaddr,
                memsz=segment['p_memsz'],
                filesz=filesz,
                offset=segment['p_offset'],
                content_start=vaddr,
                content_end=vaddr + filesz,
            ))
        self.loads = tuple(loads)

    def _covering_mappings(self, address: int) -> tuple[CoreMapping, ...]:
        return tuple(m for m in self.mappings
                     if m.vm_start <= address < m.vm_end)

    def _covering_loads(self, address: int) -> tuple[CoreLoad, ...]:
        return tuple(load for load in self.loads if load.covers_address_space(address))

    def resolve(self, address: int) -> CoreAddressResult:
        """ Return mapping and preserved-memory evidence for ``address``.

            NT_FILE coverage and PT_LOAD coverage are independent:
            ``source`` contains ``'nt_file'``, ``'pt_load'``, or both.  An
            address with no NT_FILE entry is ``anonymous`` even if a PT_LOAD
            describes its bytes.
        """
        mappings = self._covering_mappings(address)
        loads = self._covering_loads(address)
        source: tuple[ADDRESS_SOURCE, ...] = ()
        if mappings:
            source += ('nt_file',)
        if loads:
            source += ('pt_load',)
        return CoreAddressResult(
            address=address,
            kind='file' if mappings else 'anonymous',
            source=source,
            mappings=mappings,
            loads=loads,
            readable=self.readable_range(address),
        )

    def _content_segments(self) -> tuple[CoreLoad, ...]:
        return tuple(load for load in self.loads if load.filesz > 0)

    def _content_sources(self, address: int) -> list[CoreLoad]:
        return [load for load in self._content_segments()
                if load.covers_content(address)]

    def _unique_prefix_end(self, address: int, limit: int) -> int:
        """ End of the run of bytes uniquely readable from ``address``.

            Returns ``address`` when the first byte already has zero or several
            sources.  Coverage is constant between segment boundaries, so only
            those boundaries need inspection.
        """
        boundaries = sorted({point
                             for load in self._content_segments()
                             for point in (load.content_start, load.content_end)
                             if address < point <= limit})
        current = address
        while current < limit:
            if len(self._content_sources(current)) != 1:
                return current
            next_boundary = next(
                (point for point in boundaries if point > current), limit)
            current = min(next_boundary, limit)
        return current

    def _walk_content(self, address: int, size: int) -> list[tuple[CoreLoad, int]]:
        """ Return ``(segment, start_address)`` pairs for a uniquely sourced run.
        """
        remaining = size
        current = address
        pieces: list[tuple[CoreLoad, int]] = []
        while remaining > 0:
            sources = self._content_sources(current)
            if len(sources) != 1:
                break
            load = sources[0]
            taken = min(remaining, load.content_end - current)
            pieces.append((load, current))
            current += taken
            remaining -= taken
        return pieces

    def readable_range(self, address: int) -> CoreReadableRange:
        """ Return the contiguous preserved-byte range starting at ``address``.

            The range extends across adjacent non-overlapping ``PT_LOAD``
            segments, because those bytes are all uniquely readable.  It stops
            before the first gap or the first byte preserved by more than one
            segment.  If the queried address itself has multiple sources the
            result is ``not_unique`` and no range is claimed.  A segment's
            known zero-filled tail is not part of the range, because the core
            did not store those bytes.
        """
        covering = self._covering_loads(address)
        sources = self._content_sources(address)
        if len(sources) > 1:
            return CoreReadableRange(address, 'not_unique', None, None,
                                     tuple(load.index for load in sources))
        if not sources:
            status: READ_STATUS = 'not_present' if covering else 'unavailable'
            return CoreReadableRange(address, status, None, None,
                                     tuple(load.index for load in covering))

        max_content_end = max(load.content_end for load in self._content_segments())
        end = self._unique_prefix_end(address, max_content_end)
        return CoreReadableRange(address, 'present', address, end,
                                 (sources[0].index,))

    def read(self, address: int, size: int = 1) -> CoreReadResult:
        """ Return bytes the core preserves starting at ``address``.

            Adjacent non-overlapping ``PT_LOAD`` segments are concatenated when
            their virtual ranges meet.  If a byte in the requested range has
            more than one possible source, the result is ``not_unique`` and no
            byte source is chosen; ``available`` is the uniquely readable
            prefix.  A gap in preserved coverage yields ``partial`` with that
            prefix length.  ``not_present`` means only an address-space segment
            (with no stored bytes) covers the start, and ``unavailable`` means
            no segment covers it at all.
        """
        if size < 0:
            raise ValueError('size must be non-negative')
        if size == 0:
            return CoreReadResult(address, 0, 'present', b'', 0, ())

        sources = self._content_sources(address)
        if len(sources) > 1:
            return CoreReadResult(address, size, 'not_unique', None, 0,
                                  tuple(load.index for load in sources))

        prefix = self._unique_prefix_end(address, address + size) - address
        if len(sources) == 0:
            covering = self._covering_loads(address)
            status: READ_STATUS = 'not_present' if covering else 'unavailable'
            return CoreReadResult(address, size, status, None, 0,
                                  tuple(load.index for load in covering))
        if prefix < size:
            stop = address + prefix
            overlapping = self._content_sources(stop)
            if len(overlapping) > 1:
                return CoreReadResult(
                    address, size, 'not_unique', None, prefix,
                    tuple(load.index for load in overlapping))
            return CoreReadResult(address, size, 'partial', None, prefix,
                                  (sources[0].index,))

        pieces = self._walk_content(address, size)
        data = bytearray()
        for load, start in pieces:
            taken = min(size - len(data), load.content_end - start)
            file_offset = load.offset + (start - load.vaddr)
            data.extend(stream_read(self.elffile.stream, file_offset, taken))
        return CoreReadResult(address, size, 'present', bytes(data), size,
                              tuple(load.index for load, _ in pieces))

    def mapping_loads(self, mapping: CoreMapping) -> tuple[CoreLoad, ...]:
        """ Return PT_LOAD segments whose virtual range intersects ``mapping``.

            This reports adjacency only.  It does not assert that the segment
            holds bytes corresponding to the mapping's file offset; use
            ``read`` for the preserved byte range.
        """
        return tuple(
            load for load in self.loads
            if load.vaddr < mapping.vm_end
            and mapping.vm_start < load.vaddr + load.memsz)

    def find_candidates(self, name: str) -> tuple[CoreMapping, ...]:
        """ Return NT_FILE entries whose recorded name equals ``name``.

            This compares against strings decoded from the core.  It does not
            touch the filesystem and does not assert that a local file with the
            same name was the one mapped.  Use ``Mapping.raw_name`` to compare
            the exact bytes.
        """
        return tuple(m for m in self.mappings if m.name == name)

    def __repr__(self) -> str:
        return (f"<CoreFile page_size={self.page_size!r} "
                f"mappings={len(self.mappings)} loads={len(self.loads)}>")
