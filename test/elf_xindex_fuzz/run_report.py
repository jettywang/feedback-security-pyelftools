"""Standalone reporter for the structured extended-index fuzz corpus.

Run from the repository root:

    python -m test.elf_xindex_fuzz.run_report

It prints the fixed corpus parameters, every mutator verdict and, for any
unexpected outcome, the minimized failing prefix together with the byte
range the parser actually touched.
"""
from __future__ import annotations

from .builder import build_template
from .harness import (
    FUZZ_SEED,
    FUZZ_TRIALS,
    expected_layout_size,
    minimize_failure,
    run_all_mutants_once,
    run_structured_fuzz,
)
from .oracle import resolve_memberships


def main() -> int:
    size = expected_layout_size()
    print(f'fixed sample size: {size} bytes (both representations)')
    print(f'fuzz seed: 0x{FUZZ_SEED:x}  trials: {FUZZ_TRIALS}')
    print()

    print('exhaustive relationship-level sweep:')
    for mutant, verdict, observed in run_all_mutants_once():
        status = 'ok    ' if verdict == mutant.expected else 'UNEXPECTED'
        print(f'  {status} {mutant.mode:8s} {mutant.name:26s} '
              f'expected={mutant.expected:6s} verdict={verdict:6s} '
              f'field={mutant.changed_field}')
    print()

    report = run_structured_fuzz()
    print(report.render())

    # Demonstrate minimization + access envelope on one known-bad input.
    from .mutators import mutate_shndx_link_oor
    mutant = mutate_shndx_link_oor('extended')
    minimized, access_range = minimize_failure(mutant.data,
                                               mutant.field_range)
    print()
    print(f'minimization example ({mutant.name}):')
    zeroed = sum(1 for original, reduced in zip(mutant.data, minimized)
                 if original != 0 and reduced == 0)
    print(f'  layout size   : {len(mutant.data)} bytes (preserved)')
    print(f'  bytes zeroed  : {zeroed}')
    print(f'  minimized access range: {access_range}')

    healthy = resolve_memberships(bytes(build_template('normal').data))
    print(f'  healthy parse access range: {healthy["access_range"]}')
    return 0 if report.ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
