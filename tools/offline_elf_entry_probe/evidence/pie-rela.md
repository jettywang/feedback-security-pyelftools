## `tools/offline_elf_entry_probe/fixtures/pie-rela.so`

- Container: ELF64 little-endian, ET_DYN, EM_X86_64, `e_entry=0x1000`
- Section names: available — usable section names are present; loader semantics still come from dynamic tags
- Dynamic provenance: PT_DYNAMIC segment
- PT_LOAD: #0 vaddr=0x0 off=0x0 filesz=0x1100 flags=5; #1 vaddr=0x1100 off=0x1100 filesz=0x610 flags=6

### Evidence graph

```text
[entry] ELF header e_entry
    | file value: 0x1000 (parser VA)
    +-B-> B + 0x1000 (process entry, not an initializer callback)
       loader: the loader transfers control to this process entry after initialization; it is not itself an initializer-array callback; ET_DYN runtime value is B + e_entry

[relative] section .rela.dyn (SHT_RELA): R_X86_64_RELATIVE @ r_offset=0x1300; r_addend=0x1030 (explicit RELA field); no symbol (r_info_sym=0)
    | file value: r_addend=0x1030 (explicit RELA field)
    | initializer: R_X86_64_RELATIVE writes the slot at 0x1300
    | slot: 0x1300 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1030 (relative relocation)
       loader: slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias

[relative] section .rela.dyn (SHT_RELA): R_X86_64_RELATIVE @ r_offset=0x1308; r_addend=0x1040 (explicit RELA field); no symbol (r_info_sym=0)
    | file value: r_addend=0x1040 (explicit RELA field)
    | initializer: R_X86_64_RELATIVE writes the slot at 0x1308
    | slot: 0x1308 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1040 (relative relocation)
       loader: slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias

[irelative] section .rela.dyn (SHT_RELA): R_X86_64_IRELATIVE @ r_offset=0x1310; r_addend=0x1020 (explicit RELA field); no symbol (r_info_sym=0)
    | file value: r_addend=0x1020 (explicit RELA field)
    | initializer: R_X86_64_IRELATIVE writes the slot at 0x1310
    | slot: 0x1310 (parser VA; add B for ET_DYN runtime address)
    +-B-> call B + 0x1020 as resolver; the resolver return value is the final IFUNC function address
       loader: slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias; resolver must be executable and return a code address

[relative] section .rela.dyn (SHT_RELA): R_X86_64_RELATIVE @ r_offset=0x1318; r_addend=0x1050 (explicit RELA field); no symbol (r_info_sym=0)
    | file value: r_addend=0x1050 (explicit RELA field)
    | initializer: R_X86_64_RELATIVE writes the slot at 0x1318
    | slot: 0x1318 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1050 (relative relocation)
       loader: slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias

[relative] section .rela.dyn (SHT_RELA): R_X86_64_RELATIVE @ r_offset=0x12d0; r_addend=0x1010 (explicit RELA field); no symbol (r_info_sym=0)
    | file value: r_addend=0x1010 (explicit RELA field)
    | initializer: R_X86_64_RELATIVE writes the slot at 0x12d0
    | slot: 0x12d0 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1010 (relative relocation)
       loader: slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias

[ifunc-reference] section .rela.dyn (SHT_RELA): R_X86_64_GLOB_DAT @ r_offset=0x12d8; r_info_sym=1 resolver_ifunc (st_value=0x1020, SHT_DYNSYM[3], type=STT_GNU_IFUNC (raw 10; pyelftools may print STT_LOOS))
    | file value: r_info_sym=1 resolver_ifunc (st_value=0x1020, SHT_DYNSYM[3], type=STT_GNU_IFUNC (raw 10; pyelftools may print STT_LOOS)); relocation type R_X86_64_GLOB_DAT
    | slot: 0x12d8 (parser VA; add B for ET_DYN runtime address)
    +-B-> resolver result (the loader calls the IFUNC resolver and writes the returned code address here)
       loader: slot is in a PT_LOAD with PF_W; the symbol must resolve to this IFUNC definition (preemption can change it); the loader must process this relocation table; the resolver must return a valid code address

[relative] section .rela.dyn (SHT_RELA): R_X86_64_RELATIVE @ r_offset=0x12e0; r_addend=0x1040 (explicit RELA field); r_info_sym=2 not_ifunc (st_value=0x1010, SHT_DYNSYM[3], type=STT_FUNC (raw 2))
    | file value: r_addend=0x1040 (explicit RELA field)
    | initializer: R_X86_64_RELATIVE writes the slot at 0x12e0
    | slot: 0x12e0 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1040 (relative relocation)
       loader: slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias

[ifunc-symbol] SHT_DYNSYM[3] symbol #1 'resolver_ifunc'
    | file value: st_value=0x1020 (STT_GNU_IFUNC (raw 10; pyelftools may print STT_LOOS)), defined
    +-B-> resolver result; the resolver return value is the final function address
       loader: a symbol reference must resolve to this definition; the loader or caller invokes the resolver; no call order is implied by presence

[preinit-array-inapplicable] preinit_array[0]: DT_PREINIT_ARRAY=0x1300 + 0*8 = slot 0x1300
    | file value: 0x0 (raw file word before relocation)
    | initializer: R_X86_64_RELATIVE at this slot (section .rela.dyn (SHT_RELA))
    | slot: 0x1300 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1030 (relative relocation rewrites this slot)
       loader: slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot

[init-array] init_array[0]: DT_INIT_ARRAY=0x1308 + 0*8 = slot 0x1308
    | file value: 0x0 (raw file word before relocation)
    | initializer: R_X86_64_RELATIVE at this slot (section .rela.dyn (SHT_RELA))
    | slot: 0x1308 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1040 (relative relocation rewrites this slot)
       loader: slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot

[init-array] init_array[1]: DT_INIT_ARRAY=0x1308 + 1*8 = slot 0x1310
    | file value: 0x0 (raw file word before relocation)
    | initializer: R_X86_64_IRELATIVE at this slot (section .rela.dyn (SHT_RELA))
    | slot: 0x1310 (parser VA; add B for ET_DYN runtime address)
    +-B-> call B + 0x1020 as resolver, then the returned address is the function candidate
       loader: slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot

[fini-array] fini_array[0]: DT_FINI_ARRAY=0x1318 + 0*8 = slot 0x1318
    | file value: 0x0 (raw file word before relocation)
    | initializer: R_X86_64_RELATIVE at this slot (section .rela.dyn (SHT_RELA))
    | slot: 0x1318 (parser VA; add B for ET_DYN runtime address)
    +-B-> B + 0x1050 (relative relocation rewrites this slot)
       loader: slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot

[dt-init] DT_INIT=0x1030
    | file value: 0x1030 (dynamic tag value; parser VA for ET_DYN)
    +-B-> B + 0x1030 (single function pointer)
       loader: loader must process DT_INIT; runtime address uses B for ET_DYN

```

### Per-entry conditions

| # | kind | source | slot | file value | initializer | final target | load bias needed | loader condition |
|---:|---|---|---|---|---|---|:---:|---|
| 1 | entry | ELF header e_entry | - | 0x1000 (parser VA) | - | B + 0x1000 (process entry, not an initializer callback) | yes | the loader transfers control to this process entry after initialization; it is not itself an initializer-array callback; ET_DYN runtime value is B + e_entry |
| 2 | relative | section .rela.dyn (SHT_RELA): R_X86_64_RELATIVE @ r_offset=0x1300; r_addend=0x1030 (explicit RELA field); no symbol (r_info_sym=0) | 0x1300 (parser VA; add B for ET_DYN runtime address) | r_addend=0x1030 (explicit RELA field) | R_X86_64_RELATIVE writes the slot at 0x1300 | B + 0x1030 (relative relocation) | yes | slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias |
| 3 | relative | section .rela.dyn (SHT_RELA): R_X86_64_RELATIVE @ r_offset=0x1308; r_addend=0x1040 (explicit RELA field); no symbol (r_info_sym=0) | 0x1308 (parser VA; add B for ET_DYN runtime address) | r_addend=0x1040 (explicit RELA field) | R_X86_64_RELATIVE writes the slot at 0x1308 | B + 0x1040 (relative relocation) | yes | slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias |
| 4 | irelative | section .rela.dyn (SHT_RELA): R_X86_64_IRELATIVE @ r_offset=0x1310; r_addend=0x1020 (explicit RELA field); no symbol (r_info_sym=0) | 0x1310 (parser VA; add B for ET_DYN runtime address) | r_addend=0x1020 (explicit RELA field) | R_X86_64_IRELATIVE writes the slot at 0x1310 | call B + 0x1020 as resolver; the resolver return value is the final IFUNC function address | yes | slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias; resolver must be executable and return a code address |
| 5 | relative | section .rela.dyn (SHT_RELA): R_X86_64_RELATIVE @ r_offset=0x1318; r_addend=0x1050 (explicit RELA field); no symbol (r_info_sym=0) | 0x1318 (parser VA; add B for ET_DYN runtime address) | r_addend=0x1050 (explicit RELA field) | R_X86_64_RELATIVE writes the slot at 0x1318 | B + 0x1050 (relative relocation) | yes | slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias |
| 6 | relative | section .rela.dyn (SHT_RELA): R_X86_64_RELATIVE @ r_offset=0x12d0; r_addend=0x1010 (explicit RELA field); no symbol (r_info_sym=0) | 0x12d0 (parser VA; add B for ET_DYN runtime address) | r_addend=0x1010 (explicit RELA field) | R_X86_64_RELATIVE writes the slot at 0x12d0 | B + 0x1010 (relative relocation) | yes | slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias |
| 7 | ifunc-reference | section .rela.dyn (SHT_RELA): R_X86_64_GLOB_DAT @ r_offset=0x12d8; r_info_sym=1 resolver_ifunc (st_value=0x1020, SHT_DYNSYM[3], type=STT_GNU_IFUNC (raw 10; pyelftools may print STT_LOOS)) | 0x12d8 (parser VA; add B for ET_DYN runtime address) | r_info_sym=1 resolver_ifunc (st_value=0x1020, SHT_DYNSYM[3], type=STT_GNU_IFUNC (raw 10; pyelftools may print STT_LOOS)); relocation type R_X86_64_GLOB_DAT | - | resolver result (the loader calls the IFUNC resolver and writes the returned code address here) | yes | slot is in a PT_LOAD with PF_W; the symbol must resolve to this IFUNC definition (preemption can change it); the loader must process this relocation table; the resolver must return a valid code address |
| 8 | relative | section .rela.dyn (SHT_RELA): R_X86_64_RELATIVE @ r_offset=0x12e0; r_addend=0x1040 (explicit RELA field); r_info_sym=2 not_ifunc (st_value=0x1010, SHT_DYNSYM[3], type=STT_FUNC (raw 2)) | 0x12e0 (parser VA; add B for ET_DYN runtime address) | r_addend=0x1040 (explicit RELA field) | R_X86_64_RELATIVE writes the slot at 0x12e0 | B + 0x1040 (relative relocation) | yes | slot is in a PT_LOAD with PF_W; the loader must process the applicable REL/RELA table; B is the actual load bias |
| 9 | ifunc-symbol | SHT_DYNSYM[3] symbol #1 'resolver_ifunc' | - | st_value=0x1020 (STT_GNU_IFUNC (raw 10; pyelftools may print STT_LOOS)), defined | - | resolver result; the resolver return value is the final function address | yes | a symbol reference must resolve to this definition; the loader or caller invokes the resolver; no call order is implied by presence |
| 10 | preinit-array-inapplicable | preinit_array[0]: DT_PREINIT_ARRAY=0x1300 + 0*8 = slot 0x1300 | 0x1300 (parser VA; add B for ET_DYN runtime address) | 0x0 (raw file word before relocation) | R_X86_64_RELATIVE at this slot (section .rela.dyn (SHT_RELA)) | B + 0x1030 (relative relocation rewrites this slot) | yes | slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot |
| 11 | init-array | init_array[0]: DT_INIT_ARRAY=0x1308 + 0*8 = slot 0x1308 | 0x1308 (parser VA; add B for ET_DYN runtime address) | 0x0 (raw file word before relocation) | R_X86_64_RELATIVE at this slot (section .rela.dyn (SHT_RELA)) | B + 0x1040 (relative relocation rewrites this slot) | yes | slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot |
| 12 | init-array | init_array[1]: DT_INIT_ARRAY=0x1308 + 1*8 = slot 0x1310 | 0x1310 (parser VA; add B for ET_DYN runtime address) | 0x0 (raw file word before relocation) | R_X86_64_IRELATIVE at this slot (section .rela.dyn (SHT_RELA)) | call B + 0x1020 as resolver, then the returned address is the function candidate | yes | slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot |
| 13 | fini-array | fini_array[0]: DT_FINI_ARRAY=0x1318 + 0*8 = slot 0x1318 | 0x1318 (parser VA; add B for ET_DYN runtime address) | 0x0 (raw file word before relocation) | R_X86_64_RELATIVE at this slot (section .rela.dyn (SHT_RELA)) | B + 0x1050 (relative relocation rewrites this slot) | yes | slot is in a PT_LOAD with PF_W; the loader must process this dynamic table and map the array; the element is invoked in loader-defined dependency/priority order; the dynamic loader must also process any relocation for the slot |
| 14 | dt-init | DT_INIT=0x1030 | - | 0x1030 (dynamic tag value; parser VA for ET_DYN) | - | B + 0x1030 (single function pointer) | yes | loader must process DT_INIT; runtime address uses B for ET_DYN |

### Limits

- ET_DYN load bias B is chosen at load time (ASLR/loader); no runtime absolute address is computed
- writability is inferred from PT_LOAD PF_W; some loaders may protect arrays or use RELRO, so a truly writable slot at load time is not guaranteed by the file alone
- static entry presence is not proof that the loader will call it
