"""Deterministic fuzz driver with failure minimization and access reports.

The corpus is structural rather than random: a fixed seed drives a fixed
number of trials, each selecting one relationship-level mutator for one
of the two legal representations. Every unexpected outcome is minimized by
zeroing bytes the failure does not depend on (the layout length is kept
intact), and the parser's actual byte-access envelope is recorded for the
report.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from elftools.common.exceptions import ELFError

from .builder import (
    EHDR_SIZE,
    SECTION_COUNT,
    SYM_SIZE,
    Template,
    WORD_SIZE,
    build_template,
)
from .mutators import MUTATORS, Mutant, all_mutants
from .oracle import (
    AccessTrackingStream,
    resolve_memberships,
    resolve_memberships_on_stream,
)

# Fixed corpus size and seed: the run is fully reproducible.
FUZZ_SEED = 0x5EC10
FUZZ_TRIALS = 64


@dataclass
class FailureRecord:
    mutant: str
    mode: str
    changed_field: str
    detail: str
    observed: str
    access_range: tuple[int, int] | None
    original_size: int
    minimized: bytes
    zeroed_bytes: int
    minimized_range: tuple[int, int] | None


@dataclass
class FuzzReport:
    trials: int
    seed: int
    failures: list[FailureRecord] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures

    def render(self) -> str:
        lines = [
            f'structured fuzz: {self.trials} trials, seed=0x{self.seed:x}, '
            f'{len(self.failures)} unexpected outcome(s)',
        ]
        for record in self.failures:
            lo, hi = record.access_range or (-1, -1)
            mlo, mhi = record.minimized_range or (-1, -1)
            lines.append(
                f'  [{record.mode}] {record.mutant} '
                f'field={record.changed_field}: {record.detail}\n'
                f'    observed={record.observed}\n'
                f'    size={record.original_size}B access=[{lo},{hi}) '
                f'zeroed={record.zeroed_bytes}B '
                f'minimized-access=[{mlo},{mhi})')
        return '\n'.join(lines)


def parse_outcome(data: bytes) -> tuple[str, str, tuple[int, int] | None]:
    """Return (verdict, description, access range) for one input."""
    try:
        result = resolve_memberships(data)
    except ELFError as exc:
        return 'reject', str(exc), None
    return 'ok', str(result['memberships']), result['access_range']


def _fails(data: bytes) -> bool:
    verdict, _, _ = parse_outcome(data)
    return verdict == 'reject'


def _zero_ddmin(data: bytes,
                protected_ranges: list[tuple[int, int]]) -> bytes:
    """Minimize by zeroing removable chunks rather than deleting bytes.

    Deleting bytes would shift every sh_offset and change *why* parsing
    fails, so the layout length is preserved. Instead, chunks disjoint from
    every protected range are replaced with NUL bytes whenever the input
    still fails; the surviving failure is therefore still caused by the
    mutated relationship, not by offset damage.
    """
    current = bytearray(data)
    chunk_count = 2
    while chunk_count <= len(current):
        chunk_size = max(1, len(current) // chunk_count)
        reduced = False
        start = 0
        while start < len(current):
            stop = min(len(current), start + chunk_size)
            if any(not (stop <= lo or start >= hi)
                   for lo, hi in protected_ranges):
                start = stop
                continue
            saved = bytes(current[start:stop])
            if not any(saved):
                start = stop
                continue
            current[start:stop] = b'\x00' * (stop - start)
            if _fails(bytes(current)):
                reduced = True
                break
            current[start:stop] = saved
            start = stop
        if not reduced:
            if chunk_count >= len(current):
                break
            chunk_count = min(len(current), chunk_count * 2)
    return bytes(current)


def minimize_failure(
    data: bytes,
    protected_range: tuple[int, int] | None = None,
) -> tuple[bytes, tuple[int, int] | None]:
    """Smallest-information failing input that keeps the original layout.

    The ELF header, the whole section header table and the mutated field are
    protected; every other byte the failure does not depend on is zeroed via
    delta debugging. The length never changes, so offsets stay valid and the
    rejection remains attributable to the mutation. Returns the minimized
    bytes and the envelope the parser touched while rejecting them.
    """
    if not _fails(data):
        return data, None

    template = build_template('normal')
    protected = [(0, EHDR_SIZE)]
    shoff, sh_size = template.layout['shdr_table']
    protected.append((shoff, shoff + sh_size))
    if protected_range is not None:
        protected.append(protected_range)
    minimized = _zero_ddmin(data, protected)

    stream = AccessTrackingStream(minimized)
    try:
        resolve_memberships_on_stream(stream, len(minimized))
    except ELFError:
        return minimized, stream.access_range
    return minimized, None


def _verdict_matches(mutant: Mutant, verdict: str) -> bool:
    return verdict == mutant.expected


def run_structured_fuzz(trials: int = FUZZ_TRIALS,
                        seed: int = FUZZ_SEED) -> FuzzReport:
    rng = random.Random(seed)
    modes = ('normal', 'extended')
    report = FuzzReport(trials=trials, seed=seed)

    for _ in range(trials):
        mode = modes[rng.randrange(len(modes))]
        mutator = MUTATORS[rng.randrange(len(MUTATORS))]
        mutant = mutator(mode)
        verdict, observed, access_range = parse_outcome(mutant.data)
        if _verdict_matches(mutant, verdict):
            continue
        minimized, minimized_range = minimize_failure(
            mutant.data, mutant.field_range)
        zeroed_bytes = sum(
            1 for original, reduced in zip(mutant.data, minimized)
            if original != 0 and reduced == 0)
        report.failures.append(FailureRecord(
            mutant=mutant.name, mode=mutant.mode,
            changed_field=mutant.changed_field, detail=mutant.detail,
            observed=observed, access_range=access_range,
            original_size=len(mutant.data), minimized=minimized,
            zeroed_bytes=zeroed_bytes,
            minimized_range=minimized_range))
    return report


def run_all_mutants_once() -> list[tuple[Mutant, str, str]]:
    """Exhaustive, non-random sweep used by the deterministic unit tests."""
    results = []
    for mutant in all_mutants():
        verdict, observed, _ = parse_outcome(mutant.data)
        results.append((mutant, verdict, observed))
    return results


def truncate_template(mode: str, cut: int) -> bytes:
    return bytes(build_template(mode).data[:cut])


def build_empty_xindex_template() -> Template:
    """Legal object whose symbol table and SHNDX table contain only the
    mandatory null entries: both tables are empty of real symbols."""
    template = build_template('normal')
    template.set_u32('shdr4.sh_size', SYM_SIZE)       # only null symbol
    template.set_u32('shdr5.sh_size', WORD_SIZE)      # one index word
    return template


def build_empty_symtab_no_shndx_template() -> Template:
    """Legal object with a null-only symbol table and no SHNDX section,
    exercising the empty-table path without any SHN_XINDEX consumer."""
    template = build_template('normal')
    template.set_u32('shdr4.sh_size', SYM_SIZE)
    # Turn the SHNDX section into an inert PROGBITS section so no extended
    # index table is advertised.
    template.set_u32('shdr5.sh_type', 1)
    template.set_u32('shdr5.sh_link', 0)
    template.set_u32('shdr5.sh_size', 4)
    template.set_u32('shdr5.sh_entsize', 0)
    return template


def expected_layout_size() -> int:
    return len(build_template('normal').data)


# Re-export for callers that only import the harness.
__all__ = [
    'FUZZ_SEED', 'FUZZ_TRIALS', 'FuzzReport', 'FailureRecord',
    'run_structured_fuzz', 'run_all_mutants_once', 'minimize_failure',
    'parse_outcome', 'truncate_template', 'build_empty_xindex_template',
    'build_empty_symtab_no_shndx_template', 'expected_layout_size',
    'SECTION_COUNT',
]
