# Static entry-candidate analysis: design and conclusions

## Goal

Given only ELF bytes, list code that the dynamic loader *may* call while
loading or starting a module, and state precisely how much of each target is
knowable offline. The prototype is
`tools/offline_elf_entry_probe/probe.py`; it imports pyelftools and never maps,
relocates, `dlopen`s, or executes the sample.

## Evidence model

A single "address" is not enough. The probe records these distinct fields for
every candidate:

| Field | Meaning |
|---|---|
| `source` | The exact header/tag/relocation/symbol entry that supplied it |
| `slot` | Parser-side VA (or section offset for `ET_REL`) of the word the loader may write and call |
| `file_value` | Bytes or addend as stored in the file, before load-time changes |
| `initializer` | Relocation/table entry that rewrites the slot, if any |
| `final_target` | Expression for what may be called, or an explicit unresolved reason |
| `address_form` | `parser-va`, `base+addend`, `resolver-result`, `raw-word`, `symbol-value`, etc. |
| `requires_load_bias` | True when no absolute address exists without the runtime load bias `B` |
| `loader_condition` | Mapping, table-processing, and invocation conditions |
| `confidence` | `observed`, `derived`, or `unresolved` |

This prevents the common category error of printing
`st_value`, a relocation addend, a raw array word, and a runtime function
address as if they were the same number.

## Structure-by-structure rules

### `STT_GNU_IFUNC`

`st_value` is the address of a resolver, not the final function. The final
address is the resolver's return value. Consequently:

- An IFUNC **symbol** alone is only a potential target, and only if some
  reference resolves to it.
- A `GLOB_DAT`/`JUMP_SLOT` relocation to that symbol is stronger evidence: the
  loader must call the resolver to fill the slot. The slot then holds the
  returned code address.
- The probe does not claim a caller exists because a definition is present.
  Preemption can also redirect the reference to a different provider.

pyelftools 0.33 has no `STT_GNU_IFUNC` name: numeric `st_info.type` 10 is
decoded as `STT_LOOS`. The prototype reads the raw `st_info` byte at
`st_offset + 4` (ELF64) or `st_offset + 12` (ELF32) and treats low nibble 10 as
`STT_GNU_IFUNC`, while the report notes the naming collision.

### `R_*_RELATIVE`

The loader writes `B + A` into `r_offset`. There is normally no symbol; any
nonzero `r_info_sym` is ignored for this relocation type. The expression stays
symbolic because `B` is unknown for `ET_DYN`.

### `R_*_IRELATIVE`

The loader computes an address from `B` and the addend, **calls it as a
resolver**, then writes the resolver's return value into `r_offset`. The
prototype reports two separate expressions:

1. resolver entry: `B + A`;
2. final IFUNC function: `resolver(B + A)`, value unknowable statically.

It never labels the resolver entry itself as the final function.

### `DT_INIT_ARRAY` / `DT_PREINIT_ARRAY`

`DT_INIT_ARRAY` points to an array of function pointers, and `DT_INIT_ARRAYSZ`
gives its byte size. Each array element is a slot, not a symbol value. In a PIE
the slot is frequently initialized by a `RELATIVE` (or `IRELATIVE`) relocation;
the raw file word may be zero or unrelocated. The probe therefore joins array
slots to parsed relocations by `r_offset` and reports the slot word, its
initializer, and the resulting expression separately.

Ordering and applicability are loader policy:

- `DT_PREINIT_ARRAY` is honored only for a main executable, not a `dlopen`ed
  DSO.
- Initializer arrays run in loader-defined dependency order; static presence
  does not establish that a particular element is reached.
- `DT_FINI_ARRAY` is exit-time, not startup; the prototype labels it
  separately.

### `DT_INIT` / `DT_FINI`

These are single pointers, not arrays. For `ET_DYN`, their runtime value is
`B + tag_value`; the tag value is not a symbol value and not an absolute
address.

### `e_entry`

`e_entry` is a process entry point, not an initializer callback. For `ET_DYN`
its runtime value is `B + e_entry`; for `ET_EXEC`, treating it as absolute
still assumes the loader maps the file at its declared VAs. Either way, the
header field alone is not proof that control reaches it.

## REL vs RELA: addend location

This is a structural difference, not a cosmetic one:

- **RELA** carries `r_addend` explicitly. The slot at `r_offset` may be
  completely unspecified in the file image until the loader writes it.
- **REL** has no addend field. The loader reads the current word at
  `r_offset` as the addend. For a writable data slot this is an in-place
  value; for a text slot on some architectures it may be encoded instruction
  bits.

The prototype handles both and reports which form it used. For REL it reads
the word from a `PT_LOAD`-backed file range; if the slot isn't file-backed, it
reports the addend as unresolved instead of assuming zero.

`R_*_RELATIVE` and `R_*_IRELATIVE` type numbers are architecture-specific
(see `RELATIVE_TYPES` in `probe.py`). The prototype currently covers x86,
x86-64, ARM, AArch64, RISC-V, PPC64, S390, and LoongArch.

## PIE / ET_DYN: load bias is unknown

For `ET_DYN`, the runtime address is `B + parser_va`; `B` is chosen by the
loader and may be randomized. The correct static conclusion is an expression,
not a number. The probe:

- labels such targets `requires_load_bias: true`;
- never derives `B` from `e_entry`, `DT_*` values, or segment VAs;
- never maps the file to obtain addresses (which would be loading the sample).

For `ET_EXEC`, file VAs may equal runtime VAs only if the loader honors fixed
mapping. The report says "assumes fixed-VA mapping" and does not treat that as
proven.

## Missing section names / stripped files

ELF section headers are optional at runtime. When they are absent:

- table identities come from `PT_DYNAMIC` `DT_*` tags and `PT_LOAD` mappings;
- `DT_SYMTAB` + `DT_SYMENT` locate symbols, and `DT_HASH`/`DT_GNU_HASH` provide
  the symbol count (pyelftools' `DynamicSegment.num_symbols()` does this);
- `DT_STRTAB` + `DT_STRSZ` resolve symbol names;
- relocation entries come from `DT_REL`/`DT_RELASZ`, `DT_REL`/`DT_RELSZ`, or
  `DT_JMPREL`/`DT_PLTRELSZ`.

What can still be concluded: slot addresses, raw words, relocation types and
addends, symbol types (from raw bytes), and symbolic target expressions.
What cannot: section names, section flags as metadata, and any final absolute
address for `ET_DYN`.

## What remains symbolic

The prototype intentionally leaves these unresolved:

1. `B + addend` for every `ET_DYN` relative/IFUNC entry.
2. `resolver(B + A)` for every IRELATIVE.
3. The initial value of a REL slot that is not backed by a `PT_LOAD` file
   range.
4. Any IFUNC result, even when the resolver address is known.
5. Any target whose only evidence is an unrelocated array word in a PIE.

## Two-fixture evidence summary

### `pie-rela.so` (ELF64 x86-64, section names present)

- `DT_PREINIT_ARRAY=0x1300`, `DT_INIT_ARRAY=0x1308`,
  `DT_FINI_ARRAY=0x1318`; each slot is also a relocation target. Because this
  is a DSO, the preinit array is reported as inapplicable rather than as a
  startup callback.
- `R_X86_64_RELATIVE` at `0x1300`/`0x1308`/`0x1318` with explicit addends
  `0x1030`/`0x1040`/`0x1050`: final expressions `B + addend`.
- `R_X86_64_IRELATIVE` at `0x1310` with `r_addend=0x1020`: resolver entry
  `B + 0x1020`; final result unknown.
- `resolver_ifunc` has raw `st_info.type=10`; pyelftools displays
  `STT_LOOS`. Its `GLOB_DAT` reference at `0x12d8` makes it a loader-called
  resolver candidate, but still not an observed execution.
- A `RELATIVE` at `0x12e0` carries decoy `r_info_sym=2` (`not_ifunc`); the
  symbol is ignored and the addend `0x1040` determines `B + 0x1040`.

### `stripped-rel.so` (ELF32 i386, no section headers)

- `e_shoff=0`, `e_shnum=0`; names are unavailable.
- `PT_DYNAMIC` supplies `DT_REL`, `DT_RELSZ`, `DT_SYMTAB`, `DT_HASH`, and the
  initializer-array tags.
- `R_386_RELATIVE` at `0x1180` and `0x1184`: addends are in-place words
  `0x1030`; expressions `B + 0x1030`.
- `R_386_IRELATIVE` at `0x1188`: in-place addend `0x1020`; resolver entry
  `B + 0x1020`, result unknown.
- `ifunc_resolver` is recovered from `DT_SYMTAB` + `DT_HASH` + `DT_STRTAB`
  despite missing section headers.

Generated graphs: `evidence/pie-rela.md` and `evidence/stripped-rel.md`.

## Explicit non-conclusions

The prototype never turns any of these into "will execute":

- presence of an IFUNC symbol in `.dynsym`/`.symtab`;
- presence of an initializer-array slot;
- presence of `DT_INIT`/`DT_FINI`;
- a `DT_NEEDED` dependency being loadable;
- constructors' internal control flow;
- symbol preemption, `LD_PRELOAD`, `LD_AUDIT`, or architecture-specific loader
  policy;
- `e_entry` being reached after startup.

It also does not claim that missing section names make a file unanalyzable:
dynamic tags plus `PT_LOAD` still support a useful, qualified inventory.
