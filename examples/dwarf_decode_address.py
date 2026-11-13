#-------------------------------------------------------------------------------
# elftools example: dwarf_decode_address.py
#
# Decode an address in an ELF file to find out which function it belongs to
# and from which filename/line it comes in the original source file.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
import sys

from elftools.common.utils import bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile


def process_file(filename, address):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()

        funcname = decode_funcname(dwarfinfo, address)
        file, line = decode_file_line(dwarfinfo, address)

        print('Function:', bytes2str(funcname))
        print('File:', file)
        print('Line:', line)


def decode_funcname(dwarfinfo, address):
    # Go over all DIEs in the DWARF information, looking for a subprogram
    # entry with an address range that includes the given address. Note that
    # this simplifies things by disregarding subprograms that may have
    # split address ranges.
    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            try:
                if DIE.tag == 'DW_TAG_subprogram':
                    lowpc = DIE.attributes['DW_AT_low_pc'].value

                    # DWARF v4 in section 2.17 describes how to interpret the
                    # DW_AT_high_pc attribute based on the class of its form.
                    # For class 'address' it's taken as an absolute address
                    # (similarly to DW_AT_low_pc); for class 'constant', it's
                    # an offset from DW_AT_low_pc.
                    highpc_attr = DIE.attributes['DW_AT_high_pc']
                    highpc_attr_class = describe_form_class(highpc_attr.form)
                    if highpc_attr_class == 'address':
                        highpc = highpc_attr.value
                    elif highpc_attr_class == 'constant':
                        highpc = lowpc + highpc_attr.value
                    else:
                        print('Error: invalid DW_AT_high_pc class:',
                              highpc_attr_class)
                        continue

                    if lowpc <= address < highpc:
                        return DIE.attributes['DW_AT_name'].value
            except KeyError:
                continue
    return None


def decode_file_line(dwarfinfo, address):
    # Find every source location that describes the given address. Optimized
    # code can map one address to several line table rows (duplicate rows with
    # different files, lines, columns or discriminators, or overlapping
    # compilation units), so the lookup returns all candidates instead of
    # silently keeping the first or last one.
    candidates = dwarfinfo.source_locations_for_address(address)
    if not candidates:
        return None, None

    # This example keeps its historical single-result output, so it reports
    # an exact row when the address has one, otherwise the row whose interval
    # covers it. Tools that need every row can iterate the full candidate
    # list and inspect match_reason, discriminator and the address interval.
    chosen = candidates[0]
    return chosen.filename, chosen.line


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        process_file(sys.argv[2], 0x400503)
        sys.exit(0)

    if len(sys.argv) < 3:
        sys.exit(f'Expected usage: {sys.argv[0]} <address> <executable>')
    addr = int(sys.argv[1], 0)
    process_file(sys.argv[2], addr)
