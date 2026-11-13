"""
Reproducible demonstration that a malformed GNU-hash sectionless ELF can make
pyelftools silently inflate the import list by treating adjacent bytes as
symbols.  Run:  python3 audit_sectionless_elf/demo_inflation.py

Two corruption modes are shown for both ELF classes:
  1. chain with no end-of-chain bit (unterminated chain)
  2. sparse bucket whose start index exceeds the real chain
A well-formed control image is built alongside each corrupted one.
"""
from __future__ import annotations

import io
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from elfbuild import Knobs, SectionlessBuilder          # noqa: E402
from elfbuild32 import Builder32                         # noqa: E402
from elftools.elf.elffile import ELFFile                # noqa: E402

REAL = [b"alpha", b"beta", b"gamma"]
TRAILING = b"\x00" * 0x400   # readable adjacent bytes (next mapped object/EOF pad)


def count(blob: bytes):
    elf = ELFFile(io.BytesIO(blob))
    dyn = next(s for s in elf.iter_segments() if s["p_type"] == "PT_DYNAMIC")
    return dyn.num_symbols(), [s.name for s in dyn.iter_symbols()]


def run(builder_cls, label: str) -> None:
    print(f"== {label} ==")
    control = builder_cls(Knobs(mode="gnu"), REAL).build()
    n, names = count(control)
    print(f"  control              : num={n} names={names}")

    for knob, tag in (("gnu_no_terminator", "unterminated chain"),
                      ("gnu_sparse_bucket", "sparse high bucket")):
        blob = bytearray(builder_cls(Knobs(mode="gnu", **{knob: True}), REAL).build())
        # At true EOF the unbounded read finally raises; with adjacent mapped
        # bytes it silently returns fabricated symbols. Show both.
        try:
            n_eof, _ = count(bytes(blob))
            eof = f"num={n_eof}"
        except Exception as ex:  # noqa: BLE001
            eof = f"RAISED {type(ex).__name__}"
        blob += TRAILING
        n_pad, names_pad = count(bytes(blob))
        phantom = n_pad - len(REAL) - 1
        print(f"  {tag:20s}: at-EOF -> {eof}; with-trailing-data -> "
              f"num={n_pad} (+{phantom} phantom) {names_pad}")
    print()


if __name__ == "__main__":
    run(SectionlessBuilder, "ELF64 little-endian, no section headers")
    run(Builder32, "ELF32 little-endian, no section headers")
