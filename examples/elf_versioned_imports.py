#-------------------------------------------------------------------------------
# elftools example: elf_versioned_imports.py
#
# List the versioned external symbols an ELF file requires. For each imported
# dynamic symbol the example prints the symbol and version indices, the
# required version name, the shared library supplying it, the GNU hidden bit,
# and the file offset of every record the association was derived from.
# Information that cannot be resolved is reported with an explicit reason.
#
# Version definitions are intentionally excluded: they describe what this
# file provides, not what it needs from another library. Nothing is inferred
# from libraries installed on the host.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.versioned_imports import VersionedImports


def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as stream:
        imports = VersionedImports(ELFFile(stream))
        print(f"  parse mode: {imports.mode}")
        for note in imports.notes:
            print(f"  note: {note}")

        records = imports.get_imports()
        print(f"  {len(records)} imported dynamic symbol entries")
        for record in records:
            version = record['version_name'] or '<unresolved>'
            library = record['library'] or '<unknown library>'
            hidden = ' [hidden]' if record['hidden'] else ''
            print(
                f"  #{record['symbol_index']:<4d} "
                f"{record['name'] or '<null symbol>'} "
                f"bind={record['binding']} "
                f"versym={record['version_index']!r}{hidden} "
                f"requires {version} from {library}")
            offsets = ', '.join(
                f"{name}=0x{offset:x}"
                for name, offset in sorted(record['offsets'].items()))
            print(f"      sources: {offsets}")
            for reason in record['reasons']:
                print(f"      unresolved: {reason}")


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        for filename in sys.argv[2:]:
            process_file(filename)
    elif len(sys.argv) > 1:
        for filename in sys.argv[1:]:
            process_file(filename)
    else:
        sys.exit(
            'Usage: {0} <elffile> [...]'.format(sys.argv[0]))
