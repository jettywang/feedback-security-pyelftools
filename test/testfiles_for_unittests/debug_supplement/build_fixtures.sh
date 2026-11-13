#!/bin/sh
# Reproducible fixtures for the caller-driven debug-supplement matching tests.
#
# Only a Clang able to target x86_64 ELF is required (no GNU binutils and no
# linker): .gnu_debuglink / .note.gnu.build-id / .debug_sup sections are
# emitted through inline assembly straight into relocatable objects, and
# split DWARF (.dwo) files come from -gsplit-dwarf.
#
# Run from this directory. Identifiers are injected by hand (fixed CRC32,
# build IDs and source content) so the tests can assert exact values.
set -eu

CC="${CC:-clang}"
TARGET=x86_64-linux-gnu
OUT=.

cat > program.c <<'EOF'
int addNumbers(int a, int b) {
    return a + b;
}

int main(void) {
    return addNumbers(1, 2);
}
EOF

cat > other.c <<'EOF'
int unrelatedFunction(int a) {
    return a * 3;
}
EOF

#---------------------------------------------------------------------------
# 1. .gnu_debuglink scenario
#
# program_full.debug keeps the DWARF data and is the legitimate companion.
# program_stripped.o is the stripped primary object; its .gnu_debuglink
# section carries the real basename and the CRC32 of program_full.debug.
#---------------------------------------------------------------------------
"$CC" --target="$TARGET" -gdwarf-5 -fno-ident -c program.c \
    -o "$OUT/program_full.debug"
"$CC" --target="$TARGET" -fno-ident -c program.c \
    -o "$OUT/program_stripped_plain.o"

CRC=$(python3 -c "
import zlib
with open('$OUT/program_full.debug', 'rb') as handle:
    print(zlib.crc32(handle.read()) & 0xffffffff)
")

cat > debuglink_primary.c <<EOF
int addNumbers(int a, int b) { return a + b; }
int main(void) { return addNumbers(1, 2); }

__asm__(
    ".section .gnu_debuglink,\\"\\",@progbits\\n"
    ".asciz \\"program_full.debug\\"\\n"
    ".balign 4\\n"
    ".long $CRC\\n"
);
EOF
"$CC" --target="$TARGET" -fno-ident -c debuglink_primary.c \
    -o "$OUT/debuglink_primary.o"

# Right basename, wrong identifier: DWARF 4 build of the same source.
"$CC" --target="$TARGET" -gdwarf-4 -fno-ident -c program.c \
    -o "$OUT/program_wrong.debug"

#---------------------------------------------------------------------------
# 2. NT_GNU_BUILD_ID scenario
#
# The stripped primary and its debug companion carry the same injected build
# ID; the decoy carries a different one and an unrelated basename.
#---------------------------------------------------------------------------
make_build_id_source() {
    id_hex="$1"
    source="$2"
    cat > "$source" <<EOF
int addNumbers(int a, int b) { return a + b; }
int main(void) { return addNumbers(1, 2); }

__asm__(
    ".section .note.gnu.build-id,\\"\\",@note\\n"
    ".balign 4\\n"
    ".long 2f-1f\\n"
    ".long 4f-3f\\n"
    ".long 3\\n"
    "1: .asciz \\"GNU\\"\\n"
    "2: .balign 4\\n"
    "3: .quad $id_hex\\n"
    "4: .balign 4\\n"
);
EOF
}

make_build_id_source 0x1122334455667788 buildid_primary.c
make_build_id_source 0x1122334455667788 buildid_companion.c
make_build_id_source 0x99aabbccddeeff00 buildid_decoy.c

"$CC" --target="$TARGET" -fno-ident -c buildid_primary.c \
    -o "$OUT/buildid_primary.o"
"$CC" --target="$TARGET" -gdwarf-5 -fno-ident -c buildid_companion.c \
    -o "$OUT/buildid_companion.debug"
"$CC" --target="$TARGET" -gdwarf-5 -fno-ident -c buildid_decoy.c \
    -o "$OUT/random_name.debug"

#---------------------------------------------------------------------------
# 3. Split DWARF (.dwo) scenario, DWARF 5 plus the DWARF 4 GNU extension
#---------------------------------------------------------------------------
"$CC" --target="$TARGET" -gdwarf-5 -gsplit-dwarf -fno-ident \
    -c program.c -o "$OUT/split_program.o"
"$CC" --target="$TARGET" -gdwarf-5 -gsplit-dwarf -fno-ident \
    -c other.c -o "$OUT/split_other.o"
"$CC" --target="$TARGET" -gdwarf-4 -gsplit-dwarf -fno-ident \
    -c program.c -o "$OUT/split_program_v4.o"

#---------------------------------------------------------------------------
# 4. Supplementary cycle: two debug companions that refer to each other
#    through .debug_sup sections. They share one injected build ID so an
#    identifier-based match is possible, while the .debug_sup names form an
#    A -> B -> A cycle that must be detected and broken.
#---------------------------------------------------------------------------
make_sup_source() {
    target_name="$1"
    source="$2"
    cat > "$source" <<EOF
int addNumbers(int a, int b) { return a + b; }

__asm__(
    ".section .note.gnu.build-id,\\"\\",@note\\n"
    ".balign 4\\n"
    ".long 2f-1f\\n"
    ".long 4f-3f\\n"
    ".long 3\\n"
    "1: .asciz \\"GNU\\"\\n"
    "2: .balign 4\\n"
    "3: .quad 0x0102030405060708\\n"
    "4: .balign 4\\n"
);

__asm__(
    ".section .debug_sup,\\"\\",@progbits\\n"
    ".short 5\\n"
    ".byte 0\\n"
    ".asciz \\"$target_name\\"\\n"
);
EOF
}

# Primary whose debuglink points at cycle_a.debug by basename and CRC.
make_sup_source cycle_b.debug cycle_a.c
make_sup_source cycle_a.debug cycle_b.c
"$CC" --target="$TARGET" -gdwarf-5 -fno-ident -c cycle_a.c \
    -o "$OUT/cycle_a.debug"
"$CC" --target="$TARGET" -gdwarf-5 -fno-ident -c cycle_b.c \
    -o "$OUT/cycle_b.debug"

CYCLE_CRC=$(python3 -c "
import zlib
with open('$OUT/cycle_a.debug', 'rb') as handle:
    print(zlib.crc32(handle.read()) & 0xffffffff)
")
cat > cycle_primary.c <<EOF
int addNumbers(int a, int b) { return a + b; }
int main(void) { return addNumbers(1, 2); }

__asm__(
    ".section .gnu_debuglink,\\"\\",@progbits\\n"
    ".asciz \\"cycle_a.debug\\"\\n"
    ".balign 4\\n"
    ".long $CYCLE_CRC\\n"
);
EOF
"$CC" --target="$TARGET" -fno-ident -c cycle_primary.c \
    -o "$OUT/cycle_primary.o"

# Garbage stream used to prove non-ELF candidates are rejected with evidence.
printf 'not an ELF file at all\n' > "$OUT/not_elf.bin"

rm -f debuglink_primary.c buildid_primary.c buildid_companion.c \
    buildid_decoy.c cycle_a.c cycle_b.c cycle_primary.c \
    program_stripped_plain.o
