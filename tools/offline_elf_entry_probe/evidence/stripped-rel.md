## `tools/offline_elf_entry_probe/fixtures/stripped-rel.so`

- Container: ELF32 little-endian, ET_DYN, EM_386, `e_entry=0x1000`
- Section names: absent — no section names; use PT_DYNAMIC and DT_* table addresses
- Dynamic provenance: PT_DYNAMIC segment
- PT_LOAD: #0 vaddr=0x0 off=0x0 filesz=0x1100 flags=5; #1 vaddr=0x1100 off=0x1100 filesz=0x120 flags=6

### Evidence graph

```text
[entry] ELF header e_entry
    | file value: 0x1000 (parser VA)
    +-B-> B + 0x1000 (process entry, not an initializer callback)
       loader: the loader transfers control to this process entry after initialization; it is not itself an initializer-array callback; ET_DYN runtime value is B + e_entry

[relative] PT_DYNAMIC REL table: R_386_RELATIVE @ r_offset=0x1180; [*0x1180]=0x1030 (in-place REL word); no symbol (r_info_sym=0)
    | file value: [*0x1180]=0x1030 (in-place REL word)
    | initializer: R_386_RELATIVE writes the slot at 0x1180
    | slot: 0x1180 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1030 (relative relocation)
       loader: slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias

[relative] PT_DYNAMIC REL table: R_386_RELATIVE @ r_offset=0x1184; [*0x1184]=0x1030 (in-place REL word); no symbol (r_info_sym=0)
    | file value: [*0x1184]=0x1030 (in-place REL word)
    | initializer: R_386_RELATIVE writes the slot at 0x1184
    | slot: 0x1184 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1030 (relative relocation)
       loader: slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias

[irelative] PT_DYNAMIC REL table: R_386_IRELATIVE @ r_offset=0x1188; [*0x1188]=0x1020 (in-place REL word); no symbol (r_info_sym=0)
    | file value: [*0x1188]=0x1020 (in-place REL word)
    | initializer: R_386_IRELATIVE writes the slot at 0x1188
    | slot: 0x1188 (parser VA; add B for ET_DYN runtime address)
    +-B-> call B + 0x1020 as resolver; the resolver return value is the final IFUNC function address
       loader: slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias; resolver must be executable and return a code address

[ifunc-symbol] PT_DYNAMIC DT_SYMTAB (2 symbols) symbol #1 'ifunc_resolver'
    | file value: st_value=0x1020 (STT_GNU_IFUNC (raw 10; pyelftools may print STT_LOOS)), defined
    +-B-> resolver result; the resolver return value is the final function address
       loader: a symbol reference must resolve to this definition; the loader or caller invokes the resolver; no call order is implied by presence

[preinit-array-inapplicable] preinit_array[0]: DT_PREINIT_ARRAY=0x1180 + 0*4 = slot 0x1180
    | file value: 0x1030 (raw file word before relocation)
    | initializer: R_386_RELATIVE at this slot (PT_DYNAMIC REL table)
    | slot: 0x1180 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1030 (relative relocation rewrites this slot)
       loader: slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot

[init-array] init_array[0]: DT_INIT_ARRAY=0x1184 + 0*4 = slot 0x1184
    | file value: 0x1030 (raw file word before relocation)
    | initializer: R_386_RELATIVE at this slot (PT_DYNAMIC REL table)
    | slot: 0x1184 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1030 (relative relocation rewrites this slot)
       loader: slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot

[init-array] init_array[1]: DT_INIT_ARRAY=0x1184 + 1*4 = slot 0x1188
    | file value: 0x1020 (raw file word before relocation)
    | initializer: R_386_IRELATIVE at this slot (PT_DYNAMIC REL table)
    | slot: 0x1188 (parser VA; add B for ET_DYN runtime address)
    +-B-> call B + 0x1020 as resolver, then the returned address is the function candidate
       loader: slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot

```

### Per-entry conditions

| # | kind | source | slot | file value | initializer | final target | load bias needed | loader condition |
|---:|---|---|---|---|---|---|:---:|---|
| 1 | entry | ELF header e_entry | - | 0x1000 (parser VA) | - | B + 0x1000 (process entry, not an initializer callback) | yes | the loader transfers control to this process entry after initialization; it is not itself an initializer-array callback; ET_DYN runtime value is B + e_entry |
| 2 | relative | PT_DYNAMIC REL table: R_386_RELATIVE @ r_offset=0x1180; [*0x1180]=0x1030 (in-place REL word); no symbol (r_info_sym=0) | 0x1180 (parser VA; add B for ET_DYN runtime address) | [*0x1180]=0x1030 (in-place REL word) | R_386_RELATIVE writes the slot at 0x1180 | B + 0x1030 (relative relocation) | yes | slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias |
| 3 | relative | PT_DYNAMIC REL table: R_386_RELATIVE @ r_offset=0x1184; [*0x1184]=0x1030 (in-place REL word); no symbol (r_info_sym=0) | 0x1184 (parser VA; add B for ET_DYN runtime address) | [*0x1184]=0x1030 (in-place REL word) | R_386_RELATIVE writes the slot at 0x1184 | B + 0x1030 (relative relocation) | yes | slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias |
| 4 | irelative | PT_DYNAMIC REL table: R_386_IRELATIVE @ r_offset=0x1188; [*0x1188]=0x1020 (in-place REL word); no symbol (r_info_sym=0) | 0x1188 (parser VA; add B for ET_DYN runtime address) | [*0x1188]=0x1020 (in-place REL word) | R_386_IRELATIVE writes the slot at 0x1188 | call B + 0x1020 as resolver; the resolver return value is the final IFUNC function address | yes | slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias; resolver must be executable and return a code address |
| 5 | ifunc-symbol | PT_DYNAMIC DT_SYMTAB (2 symbols) symbol #1 'ifunc_resolver' | - | st_value=0x1020 (STT_GNU_IFUNC (raw 10; pyelftools may print STT_LOOS)), defined | - | resolver result; the resolver return value is the final function address | yes | a symbol reference must resolve to this definition; the loader or caller invokes the resolver; no call order is implied by presence |
| 6 | preinit-array-inapplicable | preinit_array[0]: DT_PREINIT_ARRAY=0x1180 + 0*4 = slot 0x1180 | 0x1180 (parser VA; add B for ET_DYN runtime address) | 0x1030 (raw file word before relocation) | R_386_RELATIVE at this slot (PT_DYNAMIC REL table) | B + 0x1030 (relative relocation rewrites this slot) | yes | slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot |
| 7 | init-array | init_array[0]: DT_INIT_ARRAY=0x1184 + 0*4 = slot 0x1184 | 0x1184 (parser VA; add B for ET_DYN runtime address) | 0x1030 (raw file word before relocation) | R_386_RELATIVE at this slot (PT_DYNAMIC REL table) | B + 0x1030 (relative relocation rewrites this slot) | yes | slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot |
| 8 | init-array | init_array[1]: DT_INIT_ARRAY=0x1184 + 1*4 = slot 0x1188 | 0x1188 (parser VA; add B for ET_DYN runtime address) | 0x1020 (raw file word before relocation) | R_386_IRELATIVE at this slot (PT_DYNAMIC REL table) | call B + 0x1020 as resolver, then the returned address is the function candidate | yes | slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot |

### Limits

- section names are unavailable; table identities come from PT_DYNAMIC tags and PT_LOAD mappings
- ET_DYN load bias B is chosen at load time (ASLR/loader); no runtime absolute address is computed
- writability is inferred from PT_LOAD PF_W; some loaders may protect arrays or use RELRO, so a truly writable slot at load time is not guaranteed by the file alone
- static entry presence is not proof that the loader will call it
- DT_RELR is reported, but its compressed bitmap is not expanded by this REL/RELA-focused prototype beyond pyelftools RELR entries
