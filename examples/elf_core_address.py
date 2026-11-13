#-------------------------------------------------------------------------------
# elftools example: elf_core_address.py
#
# Resolve suspicious addresses in an ELF core to NT_FILE mappings and to the
# bytes the core actually preserves.  Run it against a core dump:
#
#     PYTHONPATH=. python examples/elf_core_address.py core.elf 0xADDR...
#
# With --test, it resolves three fixed addresses in the bundled core fixture.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import sys

from elftools.elf.elffile import ELFFile


def describe(elf, address):
    core = elf.get_core_file()
    result = core.resolve(address)
    print(f'Address {address:#x}')
    print(f'  kind: {result.kind}')
    print(f'  evidence: {", ".join(result.source) or "none"}')
    for mapping in result.mappings:
        print(f'  mapping #{mapping.index}: {mapping.name} '
              f'[{mapping.vm_start:#x}, {mapping.vm_end:#x}) '
              f'file offset {mapping.file_offset}')
        if mapping.deleted:
            print(f'    core marked this name as deleted: {mapping.original_name}')
    if result.mappings and not result.file_name:
        print(f'  ambiguous names: {result.candidate_names}')
    for load in result.loads:
        print(f'  PT_LOAD #{load.index}: vaddr {load.vaddr:#x} '
              f'filesz {load.filesz:#x} memsz {load.memsz:#x}')
    readable = result.readable
    if readable.status == 'present':
        print(f'  readable bytes: [{readable.start:#x}, {readable.end:#x})')
    else:
        print(f'  readable bytes: {readable.status}')
    print()


def main(argv):
    if len(argv) < 2 or argv[1] == '--test':
        filename = 'test/testfiles_for_unittests/core_linux64.elf'
        addresses = [0x7fa4593ae010, 0x7fa45956d010, 0x7fa45999e010]
    else:
        filename = argv[1]
        addresses = [int(value, 0) for value in argv[2:]]
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_core_file():
            print(f'{filename} is not an ELF core file')
            return 1
        for address in addresses:
            describe(elf, address)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
