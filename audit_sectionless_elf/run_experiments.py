"""
Drive every corruption scenario against pyelftools and record the *observed*
behavior of DynamicSegment.num_symbols()/iter_symbols().

Each result is classified so the audit table can separate:
  - DECLARED  : count comes from an explicit file field (SYSV nchains)
  - DERIVED   : count is computed from in-file boundaries (GNU chain walk,
                nearest pointer, PT_LOAD filesz)
  - INSUFFICIENT: no trustworthy boundary; pyelftools raises or reads bytes
                that are not demonstrably symbols.
"""
from __future__ import annotations

import io
import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(__file__) or ".")
from elfbuild import Knobs, SectionlessBuilder  # noqa: E402
from elftools.elf.elffile import ELFFile  # noqa: E402
from elftools.common.exceptions import ELFError, ELFParseError  # noqa: E402

REAL_SYMBOLS = ["", "alpha", "beta", "gamma"]   # 4 entries incl. null
SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")


def probe(blob: bytes):
    """Return a dict describing pyelftools' reaction to one ELF image."""
    out = {"outcome": None, "num_symbols": None, "names": None,
           "error_type": None, "error_msg": None}
    try:
        elf = ELFFile(io.BytesIO(blob))
        dyn = next(s for s in elf.iter_segments() if s["p_type"] == "PT_DYNAMIC")
        n = dyn.num_symbols()
        names = [sym.name for sym in dyn.iter_symbols()]
        out.update(outcome="OK", num_symbols=n, names=names)
    except (ELFError, ELFParseError) as ex:
        out.update(outcome="RAISED", error_type=type(ex).__name__, error_msg=str(ex))
    except Exception as ex:  # noqa: BLE001 - surface non-ELF crashes too
        out.update(outcome="CRASH", error_type=type(ex).__name__,
                   error_msg=str(ex), traceback=traceback.format_exc())
    return out


# (id, human description, classification, knobs)
SCENARIOS = [
    # ---------- baselines (well-formed, sectionless) ----------
    ("base_gnu", "well-formed GNU hash", "DERIVED", Knobs(mode="gnu")),
    ("base_sysv", "well-formed SYSV hash", "DECLARED", Knobs(mode="sysv")),
    ("base_fallback", "no hash; nearest-pointer boundary", "DERIVED",
     Knobs(mode="fallback")),

    # ---------- DT_GNU_HASH failure modes ----------
    ("gnu_sparse_bucket", "highest bucket index exceeds real chain",
     "INSUFFICIENT", Knobs(mode="gnu", gnu_sparse_bucket=True)),
    ("gnu_no_terminator", "final chain word lacks end-of-chain bit",
     "INSUFFICIENT", Knobs(mode="gnu", gnu_no_terminator=True)),
    ("gnu_chain_bss", "chain walk reaches zero-fill (BSS) region",
     "INSUFFICIENT", Knobs(mode="gnu", gnu_chain_into_bss=True, bss_extra=0x80)),

    # ---------- DT_HASH (SYSV) failure modes ----------
    ("sysv_inflate", "nchains enlarged beyond real symbols",
     "DECLARED", Knobs(mode="sysv", sysv_inflate_nchains=3)),
    ("sysv_deflate", "nchains shrunk below real symbols",
     "DECLARED", Knobs(mode="sysv", sysv_deflate_nchains=2)),
    ("sysv_inflate_eof", "inflated nchains runs past end of file",
     "INSUFFICIENT", Knobs(mode="sysv", sysv_inflate_nchains=40)),

    # ---------- neighbor-pointer fallback failure modes ----------
    ("fallback_dup_strtab", "duplicate lower DT_STRTAB pointer",
     "INSUFFICIENT", Knobs(mode="fallback", dup_tag="DT_STRTAB")),
    ("fallback_dup_symtab", "duplicate lower DT_SYMTAB pointer",
     "INSUFFICIENT", Knobs(mode="fallback", dup_tag="DT_SYMTAB")),
    ("fallback_truncated", "file truncated before derived boundary",
     "INSUFFICIENT", Knobs(mode="fallback", truncate_file=0x30)),

    # ---------- PT_LOAD zero-fill / mapping failures ----------
    ("gnu_symtab_bss", "DT_SYMTAB points into zero-fill range",
     "INSUFFICIENT", Knobs(mode="gnu", symtab_into_bss=True, bss_extra=0x100)),
    ("fallback_strtab_bss", "DT_STRTAB points into zero-fill range",
     "INSUFFICIENT", Knobs(mode="fallback", strtab_into_bss=True, bss_extra=0x100)),
    ("fallback_bss_boundary", "PT_LOAD end boundary sits in zero-fill",
     "DERIVED", Knobs(mode="fallback", bss_extra=0x100)),

    # ---------- dynamic table integrity ----------
    ("gnu_drop_null", "DT_NULL terminator removed",
     "DERIVED", Knobs(mode="gnu", drop_null=True)),

    # ---------- malformed GNU header (defensive coverage) ----------
    ("gnu_zero_buckets", "nbuckets corrupted to zero (max() on empty)",
     "INSUFFICIENT", Knobs(mode="gnu", zero_nbuckets=True)),
]

# Extra post-build byte patches that the knob dataclass cannot express alone.
PATCHES = {
    "gnu_zero_buckets": "zero_nbuckets",
}


def apply_patch(sid: str, blob: bytearray, builder) -> bytearray:
    if PATCHES.get(sid) == "zero_nbuckets":
        h = builder.addr["hash"]
        blob[h:h + 4] = b"\x00\x00\x00\x00"
    return blob


def main() -> int:
    rows = []
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    for sid, desc, classification, knobs in SCENARIOS:
        builder = SectionlessBuilder(
            knobs, [s.encode() for s in REAL_SYMBOLS[1:]])
        blob = bytearray(builder.build())
        blob = apply_patch(sid, blob, builder)
        path = os.path.join(SAMPLE_DIR, sid + ".elf")
        with open(path, "wb") as fh:
            fh.write(blob)
        result = probe(bytes(blob))
        result.update(id=sid, description=desc, classification=classification,
                      file=os.path.relpath(path, os.path.dirname(__file__)),
                      bytes=len(blob))
        # compare against ground truth to label import-list effect
        if result["outcome"] == "OK":
            n = result["num_symbols"]
            if n == len(REAL_SYMBOLS):
                result["bias"] = "exact"
            elif n > len(REAL_SYMBOLS):
                result["bias"] = "INFLATED"
            else:
                result["bias"] = "TRUNCATED"
        else:
            result["bias"] = "UNAVAILABLE"
        rows.append(result)

    out_path = os.path.join(os.path.dirname(__file__), "results", "experiment_results.json")
    with open(out_path, "w") as fh:
        json.dump(rows, fh, indent=2, ensure_ascii=False)

    hdr = f"{'id':22} {'class':12} {'outcome':9} {'bias':11} n   names/error"
    print(hdr)
    print("-" * len(hdr) + "-" * 30)
    for r in rows:
        if r["outcome"] == "OK":
            tail = f"{r['num_symbols']}  {r['names']}"
        else:
            tail = f"{r['error_type']}: {r['error_msg']}"
        print(f"{r['id']:22} {r['classification']:12} {r['outcome']:9} "
              f"{r['bias']:11} {tail}")
    print("\nWrote", os.path.relpath(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
