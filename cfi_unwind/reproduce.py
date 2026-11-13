#!/usr/bin/env python3
"""
Reproduction / demonstration driver.

Walks the hand-crafted .eh_frame, prints the decoded rule-state table, then
evaluates one unwind step for the critical addresses under both input
semantics and under a naive "always subtract 1" policy, showing why the latter
picks the wrong rule exactly at a function boundary.
"""
import os

from elftools.dwarf.callframe import FDE, CIE, ZERO

from unwind import (
    load_cfi, fdes, select_row, unwind_one,
    CURRENT_PC, RETURN_ADDR, UnwindError,
)

ELF = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   'sample_x86_64.ehframe.o')
REG_NAMES = {0: 'rax', 1: 'rdx', 3: 'rbx', 6: 'rbp', 7: 'rsp',
             14: 'r14', 15: 'r15', 16: 'rip'}


def rname(n):
    return REG_NAMES.get(n, f'r{n}')


def print_rule_table(cfi):
    print('================ DECODED CFI RULE-STATE TABLE ================')
    for e in cfi.get_entries():
        if isinstance(e, ZERO):
            print('ZERO terminator')
            continue
        if isinstance(e, CIE):
            print(f'CIE @{e.offset:#x}: code_align={e["code_alignment_factor"]} '
                  f'data_align={e["data_alignment_factor"]} ra_reg={e["return_address_register"]}')
            continue
        start, end = e['initial_location'], e['initial_location'] + e['address_range']
        print(f'FDE @{e.offset:#x}  coverage [{start:#x},{end:#x})')
        for line in e.get_decoded().table:
            cfa = line['cfa']
            cfa_txt = f"{rname(cfa.reg)}+{cfa.offset}"
            saved = []
            for k in sorted(x for x in line if x not in ('pc', 'cfa')):
                rule = line[k]
                if rule.type == 'OFFSET':
                    saved.append(f"{rname(k)}@[cfa{rule.arg:+d}]")
                else:
                    saved.append(f"{rname(k)}={rule.type}")
            print(f"   row pc={line['pc']:#08x}  CFA={cfa_txt:<10} {', '.join(saved)}")
    print()


def show_selection(cfi, addr, semantics):
    cov, row, why = select_row(cfi, addr, semantics)
    cfa = row['cfa']
    print(f"  select [{semantics:11}] addr={addr:#x} -> FDE[{cov.start:#x},{cov.end:#x}) "
          f"row_pc={row['pc']:#x} CFA={rname(cfa.reg)}+{cfa.offset}")
    print(f"      {why}")
    return cov, row


def main():
    cfi = load_cfi(ELF)
    print_rule_table(cfi)

    print('================ FDE COVERAGE (half-open ranges) ================')
    for cov in fdes(cfi):
        print(f"  [{cov.start:#08x},{cov.end:#08x})  fde@{cov.fde.offset:#x}")
    print('  uncovered gaps: [0x1060,0x1080) and everything >= 0x1090')
    print()

    boundary = 0x1040   # exact end of funcA == start of funcB

    print('================ ROW SELECTION AT THE BOUNDARY ================')
    print(f'address {boundary:#x} = end of funcA = start of funcB')
    # 1) treat as a LIVE current PC: belongs to funcB, funcB's row wins
    show_selection(cfi, boundary, CURRENT_PC)
    # 2) treat as a RETURN address: caller is funcA, funcA's final row wins
    show_selection(cfi, boundary, RETURN_ADDR)
    print()

    print('================ WHY A BLANKET "addr - 1" FAILS ================')
    # A return address exactly on the boundary, naively decremented, becomes an
    # address inside funcA -- which happens to give the right FDE here, but for
    # the wrong reason. Show that the same trick on a LIVE pc corrupts result,
    # and on a gap address silently lands on unrelated rules.
    try:
        # live pc at funcB entry: correct semantics picks funcB
        cov_live, row_live, _ = select_row(cfi, boundary, CURRENT_PC)
        # naive tool subtracts 1 from EVERY input before lookup
        cov_naive, row_naive, _ = select_row(cfi, boundary - 1, CURRENT_PC)
        same = row_live['pc'] == row_naive['pc']
        print(f"  live PC {boundary:#x}: correct row_pc={row_live['pc']:#x} "
              f"({rname(row_live['cfa'].reg)}+{row_live['cfa'].offset})")
        print(f"  after blind -1 : row_pc={row_naive['pc']:#x} "
              f"({rname(row_naive['cfa'].reg)}+{row_naive['cfa'].offset})  "
              f"match={same}")
    except UnwindError as ex:
        print('  error:', ex)
    print('  -> subtracting 1 from a *current* PC moves it into the previous')
    print('     function and selects a CFA rule that never applied to that PC.')
    print()

    print('================ ONE-FRAME UNWIND WITH FIXED SNAPSHOT ================')
    # Construct a deterministic callee snapshot at the boundary return address.
    # funcA final row (row pc=0x1030): CFA=rsp+8, rbp@[cfa-32], rbx@[cfa-8],
    # r15@[cfa-16], r14@[cfa-24]. CIE says RIP is the RA register (16).
    rsp = 0x7000
    cfa_a = rsp + 8                       # 0x7008
    memory = {
        cfa_a - 8:  0xA008,               # saved rbx
        cfa_a - 16: 0xA016,               # saved r15
        cfa_a - 24: 0xA024,               # saved r14
        cfa_a - 32: 0xA032,               # saved rbp
        cfa_a:      0x2000,               # return address -> caller PC
    }
    regs = {7: rsp, 6: 0x5000}            # rsp, rbp in the callee

    print('snapshot: rsp=%#x rbp=%#x ; memory slots around CFA=%#x'
          % (rsp, regs[6], cfa_a))
    result = unwind_one(cfi, boundary, RETURN_ADDR, regs, memory)
    print('  RETURN_ADDR semantics (correct):')
    print('    selected FDE range', [hex(x) for x in result['fde_range']],
          'row_pc', hex(result['row_pc']), 'CFA', hex(result['cfa']))
    print('    recovered caller regs:',
          {rname(k): hex(v) for k, v in result['caller_regs'].items() if v is not None})
    print('    caller PC (from RIP slot):', hex(result['caller_regs'][16]))
    print()

    # Same numeric address, but declared as a live current PC -> funcB rules.
    result_b = unwind_one(cfi, boundary, CURRENT_PC, regs, memory)
    print('  CURRENT_PC semantics on the same numeric address:')
    print('    selected FDE range', [hex(x) for x in result_b['fde_range']],
          'row_pc', hex(result_b['row_pc']))
    cfa_b = result_b['cfa']
    print('    CFA = rbp+128 =', hex(cfa_b),
            '(a rule of funcB that never described this call frame)')
    print('    incomplete slots:', result_b.get('incomplete'))
    print('    -> using funcB rules on a funcA frame reads the wrong stack')
    print('       locations; the evaluator flags missing memory instead of')
    print('       inventing values.')
    print()

    print('================ UNCOVERED ADDRESSES MUST STOP ================')
    # A live PC in a coverage gap has no row at all.
    cases = [
        (0x1070, CURRENT_PC, True),    # inside the [0x1060,0x1080) gap
        (0x1099, CURRENT_PC, True),    # past the last FDE end
        (0x0FFF, RETURN_ADDR, True),   # before the first FDE: no caller row
        (0x1070, RETURN_ADDR, True),   # gap interior: not an exact boundary
        (0x1040, RETURN_ADDR, False),  # exact funcA->funcB boundary: valid
        (0x1060, RETURN_ADDR, False),  # exact funcB end: call-site row exists
    ]
    for addr, sem, should_stop in cases:
        try:
            cov, row, _ = select_row(cfi, addr, sem)
            status = 'STOP' if should_stop else 'ok  '
            print(f"  addr={addr:#x} [{sem:11}]: {status} resolved to "
                  f"FDE[{cov.start:#x},{cov.end:#x}) row_pc={row['pc']:#x}")
        except UnwindError as ex:
            status = 'STOP' if should_stop else 'WRONG'
            print(f"  addr={addr:#x} [{sem:11}]: {status} -> {ex}")
    print()

    print('================ MISSING EVIDENCE MUST STOP, NOT FABRICATE ================')
    # Drop the return-address slot and the rbp slot.
    broken_memory = dict(memory)
    del broken_memory[cfa_a]
    del broken_memory[cfa_a - 32]
    res = unwind_one(cfi, boundary, RETURN_ADDR, regs, broken_memory)
    print('  incomplete evidence reported:', res.get('incomplete'))
    print('  caller regs actually recoverable:',
          {rname(k): hex(v) for k, v in res['caller_regs'].items() if v is not None})
    print('  RIP recoverable?', 16 in res['caller_regs'],
          '-> caller cannot be named; do not emit a fabricated stack frame.')


if __name__ == '__main__':
    main()
