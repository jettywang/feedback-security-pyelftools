#!/usr/bin/env python3
"""
Offline one-frame unwinder built on pyelftools' decoded CFI tables.

Two *different* input semantics are modelled explicitly and must never be
collapsed by a blanket `addr - 1`:

  * CURRENT_PC  : a live, interrupted program counter. The rule row whose
                  interval actually contains this PC is authoritative.

  * RETURN_ADDR : a return address saved by a call. It points one past the
                  call instruction, i.e. at the *first* instruction of the
                  region after the call. The caller's frame is described by
                  the rule row in effect at the call site, which is the last
                  row whose start PC is < the return address (and inside the
                  same FDE). At an exact function boundary that row belongs to
                  the *previous* FDE, not the next one.

The module only performs ONE unwind step. If memory or a register needed by
the selected rules is absent, it stops and reports why instead of inventing
frames.
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Optional

from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import (
    CallFrameInfo, CIE, FDE, ZERO, RegisterRule,
)
from elftools.dwarf.structs import DWARFStructs

CURRENT_PC = "CURRENT_PC"
RETURN_ADDR = "RETURN_ADDR"


class UnwindError(Exception):
    """Raised when an unwind cannot be completed from the evidence given."""


@dataclass
class CoveringFDE:
    fde: FDE
    start: int
    end: int            # exclusive


def load_cfi(path: str) -> CallFrameInfo:
    elf = ELFFile(open(path, 'rb'))
    sec = elf.get_section_by_name('.eh_frame')
    if sec is None:
        raise UnwindError("no .eh_frame section")
    base = DWARFStructs(little_endian=True, dwarf_format=32,
                        address_size=elf.elfclass // 8)
    return CallFrameInfo(io.BytesIO(sec.data()), sec.data_size,
                         sec['sh_addr'], base, for_eh_frame=True)


def fdes(cfi: CallFrameInfo):
    for e in cfi.get_entries():
        if isinstance(e, FDE):
            start = e['initial_location']
            yield CoveringFDE(e, start, start + e['address_range'])


def find_fde(cfi: CallFrameInfo, addr: int) -> Optional[CoveringFDE]:
    """Return the FDE whose half-open range [start, end) contains addr."""
    for cov in fdes(cfi):
        if cov.start <= addr < cov.end:
            return cov
    return None


def _row_at_or_before(fde: FDE, addr: int):
    """Last decoded row whose start PC is <= addr (rows are sorted)."""
    chosen = None
    for line in fde.get_decoded().table:
        if line['pc'] <= addr:
            chosen = line
        else:
            break
    return chosen


def select_row(cfi: CallFrameInfo, addr: int, semantics: str):
    """
    Select the authoritative CFI row and the FDE that owns it.

    Returns (covering_fde, row, explanation). Raises UnwindError when the
    address is not covered by any FDE -- the caller must stop, not guess.
    """
    if semantics == CURRENT_PC:
        cov = find_fde(cfi, addr)
        if cov is None:
            raise UnwindError(
                f"CURRENT_PC {addr:#x} is outside every FDE range; "
                "no rule row exists for this address")
        row = _row_at_or_before(cov.fde, addr)
        why = ("live PC: pick the FDE whose [start,end) contains it, then the "
               "last row with pc <= PC")
        return cov, row, why

    if semantics == RETURN_ADDR:
        # The return address is the instruction after the call. Its own FDE may
        # be a *different* function (exact boundary). The caller's rules live in
        # the FDE/row in effect just before this address.
        cov = find_fde(cfi, addr)
        if cov is not None and cov.start < addr:
            # Common case: return address is strictly inside one function, so
            # the call site is described by the last row with pc < addr.
            row = _row_at_or_before(cov.fde, addr - 1)
            why = ("return addr strictly inside one FDE: use the last row with "
                   "pc < return address (the call-site row)")
            return cov, row, why

        # Not strictly inside an FDE. The only legitimate case is an *exact*
        # boundary: addr equals the end of a preceding FDE (a call into the
        # adjacent function). An address in a coverage gap has no call-site row.
        preceding = [c for c in fdes(cfi) if c.end == addr]
        if not preceding:
            raise UnwindError(
                f"RETURN_ADDR {addr:#x} is not inside an FDE and is not the "
                "exact end of any preceding FDE (coverage gap); no call-site "
                "rule row exists")
        prev = preceding[-1]
        row = prev.fde.get_decoded().table[-1]
        why = ("return addr is an exact FDE boundary: caller row is the final "
               "row of the preceding FDE, NOT the next function's row")
        return prev, row, why

    raise UnwindError(f"unknown semantics {semantics!r}")


# ---- one-frame evaluation against a fixed register/memory snapshot ---------

def _eval_cfa(cfa_rule, regs):
    if cfa_rule.expr is not None:
        raise UnwindError("CFA is a DWARF expression; evaluator supports only "
                          "register+offset")
    base_reg = cfa_rule.reg
    if base_reg not in regs:
        raise UnwindError(f"CFA base register {base_reg} missing from snapshot")
    return regs[base_reg] + cfa_rule.offset


def unwind_one(cfi: CallFrameInfo, addr: int, semantics: str,
               regs: dict, memory: dict, ra_reg: int = 16):
    """
    Perform exactly one unwind step.

    regs:   {dwarf_reg_number: value} for the *callee* frame.
    memory: {address: value} for readable stack slots.
    ra_reg: DWARF register number holding the return address (16 = RIP x86-64).

    Returns a dict describing the recovered caller context, or raises
    UnwindError if required evidence is missing. Nothing is fabricated.
    """
    cov, row, why = select_row(cfi, addr, semantics)
    cfa = _eval_cfa(row['cfa'], regs)

    caller_regs = {}
    missing = []
    for regnum, rule in row.items():
        if regnum in ('pc', 'cfa'):
            continue
        rtype = rule.type
        if rtype == RegisterRule.SAME_VALUE:
            caller_regs[regnum] = regs.get(regnum)
            if regnum not in regs:
                missing.append(f"r{regnum}(same_value)")
        elif rtype == RegisterRule.OFFSET:
            slot = cfa + rule.arg          # arg already in bytes
            if slot not in memory:
                missing.append(f"mem[{slot:#x}] for r{regnum}")
                continue
            caller_regs[regnum] = memory[slot]
        elif rtype == RegisterRule.VAL_OFFSET:
            caller_regs[regnum] = cfa + rule.arg
        elif rtype == RegisterRule.UNDEFINED:
            caller_regs[regnum] = None      # value is not recoverable
        else:
            raise UnwindError(
                f"register r{regnum} uses unsupported rule {rtype}")

    # Recover the return address (caller's PC) per the CIE's RA register rule.
    ra_rule = row.get(ra_reg)
    if ra_rule is None:
        raise UnwindError(
            f"no rule for return-address register {ra_reg} in selected row")
    if ra_rule.type == RegisterRule.OFFSET:
        ra_slot = cfa + ra_rule.arg
        if ra_slot not in memory:
            missing.append(f"mem[{ra_slot:#x}] for return address")
        else:
            caller_regs[ra_reg] = memory[ra_slot]
    else:
        raise UnwindError(
            f"return-address rule {ra_rule.type} not supported by this "
            "one-frame evaluator")

    result = {
        "input": addr,
        "semantics": semantics,
        "fde_range": (cov.start, cov.end),
        "row_pc": row['pc'],
        "cfa": cfa,
        "why": why,
        "caller_regs": caller_regs,
    }
    if missing:
        result["incomplete"] = missing
    return result
