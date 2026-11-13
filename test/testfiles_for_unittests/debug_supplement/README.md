# Debug-supplement matching fixtures

These ELF objects back `test/test_debug_supplement.py`. Rebuild them with:

```sh
sh build_fixtures.sh
```

The script only needs a Clang able to target `x86_64-linux-gnu`; no GNU
binutils or linker is required. Custom `.gnu_debuglink`,
`.note.gnu.build-id` and `.debug_sup` sections are emitted through inline
assembly, and split-DWARF `.dwo` files through `-gsplit-dwarf`.

## Scenario map

- `debuglink_primary.o` + `program_full.debug` &mdash; verified CRC32 pair;
  `program_wrong.debug` has the right basename but a different CRC.
- `buildid_primary.o` + `buildid_companion.debug` &mdash; identical build ID;
  `random_name.debug` carries a different ID under an unrelated basename.
- `split_program.{o,dwo}` / `split_other.{o,dwo}` &mdash; DWARF 5 split
  DWARF with mismatched DWO IDs across the two programs.
- `split_program_v4.{o,dwo}` &mdash; the DWARF 4 GNU `dwo_id` extension.
- `cycle_primary.o` &rarr; `cycle_a.debug` &rarr; `cycle_b.debug` &rarr;
  `cycle_a.debug` &mdash; mutual `.debug_sup` references forming a cycle.
- `not_elf.bin` &mdash; non-ELF garbage used to check bad-input evidence.
