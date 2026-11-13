# Static CET/BTI/PAC declaration auditing

This document describes the conservative static auditor in
`test/security_note_audit.py` and its test matrix in
`test/test_security_properties.py`.

The auditor inspects the GNU property note (`.note.gnu.property`, exposed as
both an `SHT_NOTE` section and a `PT_NOTE`/`PT_GNU_PROPERTY` segment) and
reports whether a control-flow mitigation is *declared* by an ELF object. It
does not and cannot report whether the mitigation is *enforced at runtime*.

## Why not just search for a constant

Naive scanners grep the file for a feature constant such as the bytes of
`GNU_PROPERTY_X86_FEATURE_1_AND` (`0xc0000002`) or a BTI flag. That approach
false-positives constantly because:

- The same numeric values appear in unrelated contexts (relocations, other
  note owners, string/debug data, padding).
- Note type numbers are only meaningful inside an owner namespace: type `5`
  means `NT_GNU_PROPERTY_TYPE_0` only when the note owner is `GNU`.
- Property type numbers and feature-bit numbers are reused across
  architectures with different meanings. `0xc0000000` is
  `GNU_PROPERTY_AARCH64_FEATURE_1_AND` on AArch64 *and*
  `GNU_PROPERTY_RISCV_FEATURE_1_AND` on RISC-V, where the bits differ.
- Endianness and the 32-bit vs 64-bit property-entry alignment change where
  the value actually sits.
- A truncated or contradictory descriptor can still contain the expected
  bytes while being structurally invalid.

The auditor therefore drives pyelftools' real NOTE decoder
(`elftools.elf.notes.iter_notes`) over every NOTE section and segment, then
re-walks each property descriptor with explicit bounds checks rather than
trusting byte patterns.

## Three-valued verdicts

| Verdict | Meaning |
| --- | --- |
| `ENABLED` | A well-formed GNU property note declares the mitigation bit set for the object's architecture. |
| `ABSENT` | The input is well-formed but carries no declaration of the bit (no property note, no feature entry, or the bit is clear). |
| `UNDETERMINED` | The input is malformed or ambiguous; asserting either enabled or absent would be unsafe. |

## Conservative rules

- **Architecture scoping.** A feature word is only interpreted through the
  `MitigationSpec` whose `machines` match `e_machine`. An AArch64 property
  word never satisfies an x86 CET check and vice versa, even when the raw
  property-type number collides.
- **32/64-bit alignment.** Property entries are 4-byte aligned on ELF32 and
  8-byte aligned on ELF64; the walk uses `e_ident[EI_CLASS]` to pick the
  stride and `EI_DATA` to pick byte order.
- **Feature entry shape.** A processor FEATURE_1_AND entry must carry exactly
  one 4-byte word. Other sizes are not treated as feature evidence.
- **Conflicting entries.** Multiple FEATURE_1_AND entries that disagree yield
  `UNDETERMINED` instead of silently AND-collapsing them. Identical duplicate
  entries remain valid.
- **Unknown bits.** A recognized property type whose word sets bits outside
  the architecture's documented mask yields `UNDETERMINED`, so a
  forward-compatible feature can never be certified by ignoring its bit.
- **Truncation.** Any property header or data that overruns the descriptor,
  or trailing bytes that cannot form a header, yields `UNDETERMINED`. Both the
  auditor's own bounds walk and pyelftools' decoder failures are captured.
- **Owner/type namespacing.** Only a `GNU`-owned `NT_GNU_PROPERTY_TYPE_0`
  note is evidence; another owner's type-5 note or a different note type is
  ignored.

## Test matrix

All fixtures are synthesized in memory as complete ELF objects (real Ehdr,
`PT_NOTE` program header and `SHT_NOTE` section over the same bytes) so each
case is decoded through both NOTE paths. Checked-in binaries from
`test/testfiles_for_readelf` and `test/testfiles_for_unittests` are used as
end-to-end integration cases.

### ENABLED (declared and supported)

| Fixture | Architecture / class | Assertion |
| --- | --- | --- |
| FEATURE_1_AND word `0x3` | x86-64 / ELF64 LE | IBT and SHSTK `ENABLED` |
| FEATURE_1_AND word `0x1` | x86-64 / ELF64 LE | IBT `ENABLED`, SHSTK `ABSENT` |
| AArch64 FEATURE_1 word `0x3` | AArch64 / ELF64 BE | BTI and PAC `ENABLED` |
| FEATURE_1_AND word `0x2` | x86 / ELF32 LE (4-byte alignment) | SHSTK `ENABLED`, IBT `ABSENT` |
| RISC-V FEATURE_1 word `0x1` | RISC-V / ELF64 LE | RISC-V BTI `ENABLED` |
| Duplicate identical FEATURE_1_AND words | x86-64 | both `ENABLED` |
| `aarch64-pac-bti.so.elf` | AArch64 real corpus | BTI/PAC `ENABLED` |
| `note_gnu_property.elf`, `note_gnu_property.o.elf` | x86-64 real corpus | IBT/SHSTK `ENABLED` |

### ABSENT (declared missing / no declaration)

| Fixture | Architecture | Assertion |
| --- | --- | --- |
| Empty NOTE region | x86-64 | IBT/SHSTK `ABSENT` |
| Only `GNU_PROPERTY_STACK_SIZE` | x86-64 | IBT/SHSTK `ABSENT` |
| FEATURE_1_AND word `0x0` | x86-64 | IBT/SHSTK `ABSENT` |
| AArch64 property type on x86-64 | x86-64 | IBT/SHSTK `ABSENT` |
| x86 property type on AArch64 | AArch64 | BTI/PAC `ABSENT` |
| FEATURE_1_AND entry with 8-byte data | x86-64 | not feature evidence, `ABSENT` |
| Non-`GNU` owner, note type 5 | x86-64 | ignored, `ABSENT` |
| GNU owner, unknown note type | x86-64 | ignored, `ABSENT` |
| `exe_simple32.elf` real corpus | x86 ELF32 | IBT/SHSTK `ABSENT` |
| Inapplicable mitigations for the machine | any | marked not applicable, `ABSENT` |

### UNDETERMINED (cannot judge conservatively)

| Fixture | Defect | Assertion |
| --- | --- | --- |
| Feature descriptor truncated by 4 bytes | data overrun | IBT/SHSTK `UNDETERMINED` |
| Valid entry + 4 orphan bytes | incomplete property header | `UNDETERMINED` |
| FEATURE_1_AND words `0x3` and `0x2` | conflicting entries | IBT/SHSTK `UNDETERMINED` |
| x86 word `0x13` (unknown bit `0x10`) | unknown feature bit | IBT/SHSTK `UNDETERMINED` |
| AArch64 word `0x80000001` | unknown high bit | BTI/PAC `UNDETERMINED` |
| AArch64 word `0x3` on RISC-V | bit `0x2` undefined for RISC-V | RISC-V BTI `UNDETERMINED` |

### Mutation tests (a true ENABLED verdict must collapse)

Each mutation starts from a genuinely `ENABLED` object and flips one decoded
field; the original enabled assertion then fails:

| Mutation | Effect on verdict |
| --- | --- |
| Big-endian note bytes labelled little-endian | word reads byte-swapped; no longer `ENABLED` |
| `e_machine` x86-64 → AArch64 | x86 checks no longer apply; AArch64 checks stay not `ENABLED` |
| `pr_type` → unknown number | property no longer recognized; not `ENABLED` |
| Feature word `0x3` → `0x0` | IBT/SHSTK become `ABSENT` |
| `n_descsz` shortened by 4 | descriptor truncation → `UNDETERMINED` |

## Why a static declaration is not runtime proof

`ENABLED` means only that the toolchain wrote a claim into the file. The
claim is an instruction to consumers, not a self-executing protection:

- **The kernel or loader may ignore it.** Enforcement of Intel CET
  (indirect-branch tracking and shadow stack) and Arm BTI/PAC depends on
  kernel support, loader (`ld.so`) support and architecture/CPU support. An
  older kernel or loader sees the note and does nothing.
- **The CPU may lack the feature.** IBT/SHSTK require CET-capable silicon;
  BTI and PAC require the corresponding Armv8.3+/v8.5-A extensions. The note
  can be present on hardware that cannot enforce it.
- **The loader can downgrade or reject.** A single object lacking the
  feature in a link can cause the loader to disable the mitigation for the
  whole process, and policy (`glibc.cet`, sysctls, seccomp, container
  filters) can force it off regardless of the binary's note.
- **The note is trivially forgeable.** It is just bytes in the object; an
  attacker or a misconfigured build can set the bit without the code actually
  being CET/BTI/PAC-safe. Static analysis cannot verify call-target or
  landing-pad correctness.
- **It says nothing about effective configuration.** A declared shadow stack
  does not prove one is active, sized correctly, or not bypassed by JIT,
  signal-handler, or legacy-mapping behavior.

Confirming runtime enforcement therefore requires evidence unavailable to a
file scanner, for example: kernel/loader logs and sysctls,
`GLIBC_TUNABLES`/CET status, CPUID/`getauxval` feature reporting, and live
tests that a control-flow violation is actually trapped. Treat the auditor's
`ENABLED` strictly as "the object declares support", never as "the running
process is protected".
