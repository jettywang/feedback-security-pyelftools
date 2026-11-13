# Offline ELF entry-candidate probe

A static-only pyelftools prototype that inventories places a dynamic loader
*may* transfer control to during load/startup, without mapping or executing the
input:

- `e_entry`
- `DT_INIT` / `DT_FINI`
- `DT_PREINIT_ARRAY` / `DT_INIT_ARRAY` / `DT_FINI_ARRAY` slots
- `R_*_RELATIVE` and `R_*_IRELATIVE` relocation targets
- `STT_GNU_IFUNC` definitions and relocations that reference them

It deliberately separates:

1. the parser-side VA / file offset of a slot;
2. the bytes currently stored there;
3. the relocation that the loader may use to rewrite it;
4. the final expression (`B + addend`, or a resolver result) that cannot be
   reduced to an absolute address statically.

## Usage

```sh
.venv/bin/python tools/offline_elf_entry_probe/probe.py fixture.so
.venv/bin/python tools/offline_elf_entry_probe/probe.py fixture.so --json
.venv/bin/python tools/offline_elf_entry_probe/probe.py fixture.so --markdown
```

## Fixtures

`make_fixtures.py` emits byte-exact ELF files with no linker, loader, or
instruction execution:

- `fixtures/pie-rela.so`: ELF64 x86-64 `ET_DYN`, section headers present,
  RELA addends, IFUNC symbol and `GLOB_DAT` reference, arrays whose slots are
  also RELATIVE/IRELATIVE targets.
- `fixtures/stripped-rel.so`: ELF32 i386 `ET_DYN`, **no section headers**,
  dynamic tags as the only table index, REL in-place addends, `DT_HASH`.
- `fixtures/negative-addend.so`: RELA with a negative addend, to check that
  expressions stay symbolic rather than being clamped or guessed.

Regenerate with:

```sh
.venv/bin/python tools/offline_elf_entry_probe/make_fixtures.py
```

`evidence/` contains generated Markdown evidence graphs and JSON reports for
the two main fixtures.

## Non-goals

- No `dlopen`, `mmap`, `ptrace`, emulator, or process execution.
- No claim that a statically visible slot is actually reached. Ordering,
  constructors' own control flow, `DT_NEEDED` availability, symbol preemption,
  `LD_*` environment controls, and architecture-specific loader policy are
  outside the prototype.
- No attempt to invent an ELF load bias for PIE/ET_DYN. `B` remains symbolic.
- No assertion that an `STT_GNU_IFUNC` resolver result is knowable without
  running it.
