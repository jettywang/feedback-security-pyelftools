#!/usr/bin/env python3
"""Assertions pinning the CFI row-selection and one-frame unwind semantics."""
import os
import pytest

from unwind import (
    load_cfi, fdes, select_row, unwind_one, UnwindError,
    CURRENT_PC, RETURN_ADDR,
)

ELF = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   'sample_x86_64.ehframe.o')


@pytest.fixture(scope='module')
def cfi():
    return load_cfi(ELF)


def test_boundary_current_pc_picks_next_function(cfi):
    cov, row, _ = select_row(cfi, 0x1040, CURRENT_PC)
    assert (cov.start, cov.end) == (0x1040, 0x1060)
    assert row['pc'] == 0x1040
    assert row['cfa'].reg == 6 and row['cfa'].offset == 128   # rbp+128


def test_boundary_return_addr_picks_previous_function(cfi):
    cov, row, _ = select_row(cfi, 0x1040, RETURN_ADDR)
    assert (cov.start, cov.end) == (0x1000, 0x1040)
    assert row['pc'] == 0x1030
    assert row['cfa'].reg == 7 and row['cfa'].offset == 8      # rsp+8


def test_same_numeric_address_two_semantics_disagree(cfi):
    _, live, _ = select_row(cfi, 0x1040, CURRENT_PC)
    _, ret, _ = select_row(cfi, 0x1040, RETURN_ADDR)
    assert live['pc'] != ret['pc']
    assert live['cfa'] != ret['cfa']


def test_blind_decrement_of_live_pc_selects_wrong_row(cfi):
    _, correct, _ = select_row(cfi, 0x1040, CURRENT_PC)
    _, decremented, _ = select_row(cfi, 0x103F, CURRENT_PC)
    assert correct['cfa'].reg == 6                  # rbp (funcB)
    assert decremented['cfa'].reg == 7             # rsp (funcA) -- wrong frame


def test_remember_restore_reverts_cfa_register(cfi):
    # Inspect funcA's decoded table directly (no address selection involved).
    fde_a = next(c for c in fdes(cfi) if c.start == 0x1000).fde
    by_pc = {line['pc']: line for line in fde_a.get_decoded().table}
    assert by_pc[0x1018]['cfa'].reg == 6           # rbp after def_cfa_register
    assert by_pc[0x1028]['cfa'].reg == 7           # rsp after restore_state
    assert by_pc[0x1028]['cfa'].offset == 8


def test_uncovered_live_pc_stops(cfi):
    with pytest.raises(UnwindError):
        select_row(cfi, 0x1070, CURRENT_PC)


def test_gap_return_addr_stops_but_exact_boundary_resolves(cfi):
    with pytest.raises(UnwindError):
        select_row(cfi, 0x1070, RETURN_ADDR)       # gap interior
    cov, _, _ = select_row(cfi, 0x1060, RETURN_ADDR)
    assert cov.end == 0x1060


def test_one_frame_unwind_recovers_caller(cfi):
    rsp, cfa = 0x7000, 0x7008
    memory = {cfa - 8: 0xA008, cfa - 16: 0xA016, cfa - 24: 0xA024,
              cfa - 32: 0xA032, cfa: 0x2000}
    regs = {7: rsp, 6: 0x5000}
    res = unwind_one(cfi, 0x1040, RETURN_ADDR, regs, memory)
    assert res['cfa'] == cfa
    assert res['caller_regs'][16] == 0x2000        # return address -> caller PC
    assert res['caller_regs'][6] == 0xA032         # restored rbp


def test_missing_memory_is_flagged_not_fabricated(cfi):
    rsp, cfa = 0x7000, 0x7008
    memory = {cfa - 8: 0xA008, cfa - 16: 0xA016, cfa - 24: 0xA024}
    regs = {7: rsp, 6: 0x5000}
    res = unwind_one(cfi, 0x1040, RETURN_ADDR, regs, memory)
    assert 'incomplete' in res
    assert 16 not in res['caller_regs']            # cannot name caller
