"""
Minimal, fully-controlled ELF64 little-endian *sectionless* ET_DYN builder.

Sets e_shoff=0 / e_shnum=0 so pyelftools must recover dynamic information from
PT_LOAD + PT_DYNAMIC only (the super-stripped path).  One PT_LOAD spans the
whole file with vaddr == offset (base BASE), which keeps vaddr->offset mapping
auditable while still exercising ELFFile.address_offsets().  Zero-fill (BSS)
range is modeled with p_memsz > p_filesz.

All tables are assembled with struct.pack; corruption knobs mutate one thing at
a time so every experiment isolates a single failure mode.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

ELFMAG = b"\x7fELF"
ELFCLASS64, ELFDATA2LSB, EV_CURRENT = 2, 1, 1
ET_DYN, EM_X86_64 = 3, 62
PT_LOAD, PT_DYNAMIC = 1, 2
PF_R, PF_W, PF_X = 4, 2, 1
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT = \
    0, 1, 4, 5, 6, 10, 11
DT_GNU_HASH = 0x6FFFFEF5

BASE = 0x1000
SYM64, DYNSZ, PHDRSZ, EHDRSZ = 24, 16, 56, 64


def gnu_hash(name: bytes) -> int:
    h = 5381
    for c in bytearray(name):
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


def sysv_hash(name: bytes) -> int:
    h = 0
    for c in bytearray(name):
        h = (h << 4) + c
        x = h & 0xF0000000
        if x:
            h ^= x >> 24
        h &= ~x & 0xFFFFFFFF
    return h & 0xFFFFFFFF


@dataclass
class Knobs:
    mode: str = "gnu"                     # gnu | sysv | fallback
    gnu_sparse_bucket: bool = False       # highest bucket points past real chain
    gnu_no_terminator: bool = False       # clear low bit of last chain word
    gnu_chain_into_bss: bool = False      # terminator only exists in zero-fill
    sysv_inflate_nchains: int = 0         # add phantom nchains entries
    sysv_deflate_nchains: int = 0         # shrink nchains
    dup_tag: str | None = None            # second, lower neighbor pointer
    drop_null: bool = False               # omit DT_NULL
    strtab_into_bss: bool = False
    symtab_into_bss: bool = False
    bss_extra: int = 0                    # p_memsz - p_filesz
    truncate_file: int = 0
    zero_nbuckets: bool = False
    ptr_override: dict = field(default_factory=dict)


class SectionlessBuilder:
    def __init__(self, knobs: Knobs, symbols: list[bytes],
                 needed: bytes = b"libc.so.6"):
        self.k = knobs
        self.sym_names = [b""] + symbols  # index 0 = mandatory null symbol
        self.needed = needed
        self.addr: dict[str, int] = {}
        self.tags: list[tuple[int, int, str]] = []

    # -- tables -------------------------------------------------------------
    def _strtab(self) -> bytes:
        blob = b"\x00"
        self._str_off = {b"": 0}
        for s in [self.needed] + self.sym_names[1:]:
            if s not in self._str_off:
                self._str_off[s] = len(blob)
                blob += s + b"\x00"
        return blob

    def _symtab(self) -> bytes:
        out = b""
        for i, name in enumerate(self.sym_names):
            st_name = self._str_off.get(name, 0)
            st_info = 0 if i == 0 else 0x12  # STB_GLOBAL | STT_FUNC
            out += struct.pack("<IBBHQQ", st_name, st_info, 0, 0, 0, 0)
        return out

    def _sysv_hash(self) -> bytes:
        n = len(self.sym_names)
        nbuckets = 2
        buckets, chains = [0] * nbuckets, [0] * n
        for idx in range(1, n):
            b = sysv_hash(self.sym_names[idx]) % nbuckets
            chains[idx] = buckets[b]
            buckets[b] = idx
        nchains = n + self.k.sysv_inflate_nchains - self.k.sysv_deflate_nchains
        nchains = max(0, nchains)
        out = struct.pack("<II", nbuckets, nchains)
        out += struct.pack("<%dI" % nbuckets, *buckets)
        vals = (chains + [0] * max(0, nchains - n))[:nchains]
        out += struct.pack("<%dI" % len(vals), *vals)
        return out

    def _gnu_hash(self) -> bytes:
        names = self.sym_names[1:]
        symoffset, nbuckets, bloom_size, bloom_shift = 1, 2, 1, 6
        buckets = [0] * nbuckets
        hashes = [gnu_hash(n) for n in names]
        for i, hv in enumerate(hashes):
            b = hv % nbuckets
            symidx = symoffset + i
            if buckets[b] == 0 or symidx < buckets[b]:
                buckets[b] = symidx
        if self.k.gnu_sparse_bucket:
            buckets[1] = symoffset + len(names) + 4
        chain = [hv & ~1 for hv in hashes]
        if chain:
            chain[-1] |= 1
        if self.k.gnu_no_terminator and chain:
            chain[-1] &= ~1
        out = struct.pack("<IIII", nbuckets, symoffset, bloom_size, bloom_shift)
        out += struct.pack("<Q", 0)
        out += struct.pack("<%dI" % nbuckets, *buckets)
        out += struct.pack("<%dI" % len(chain), *chain)
        return out

    # -- assembly -----------------------------------------------------------
    def build(self) -> bytes:
        strtab = self._strtab()
        symtab = self._symtab()
        hashblob = self._sysv_hash() if self.k.mode == "sysv" else self._gnu_hash()

        blocks = [("hash", hashblob), ("symtab", symtab), ("strtab", strtab)]
        cur = BASE
        for name, blob in blocks:
            self.addr[name] = cur
            cur += len(blob)

        sym_ptr = self.addr["symtab"]
        str_ptr = self.addr["strtab"]
        # BSS targets: file-backed region ends at BASE+filesz, computed after
        # dynamic size is known; patch later via _filesz once available.
        tags: list[tuple[int, int, str]] = [(DT_NEEDED, self._str_off[self.needed], "DT_NEEDED")]
        if self.k.mode == "sysv":
            tags.append((DT_HASH, self.addr["hash"], "DT_HASH"))
        elif self.k.mode == "gnu":
            tags.append((DT_GNU_HASH, self.addr["hash"], "DT_GNU_HASH"))
        tags.append((DT_SYMTAB, sym_ptr, "DT_SYMTAB"))
        tags.append((DT_STRTAB, str_ptr, "DT_STRTAB"))
        tags.append((DT_STRSZ, len(strtab), "DT_STRSZ"))
        tags.append((DT_SYMENT, SYM64, "DT_SYMENT"))
        tags = [(t, self.k.ptr_override.get(name, v), name) for t, v, name in tags]
        if self.k.dup_tag:
            base_v = next(v for t, v, name in tags if name == self.k.dup_tag)
            dup_id = DT_STRTAB if self.k.dup_tag == "DT_STRTAB" else DT_SYMTAB
            tags.append((dup_id, base_v - 0x40, "DUP_" + self.k.dup_tag))
        if not self.k.drop_null:
            tags.append((DT_NULL, 0, "DT_NULL"))

        dyn = b"".join(struct.pack("<QQ", t, v) for t, v, _ in tags)
        self.addr["dynamic"] = cur
        dyn_addr, filesz = cur, cur + len(dyn) - BASE
        self.filesz = filesz
        self.tags = tags

        # resolve BSS pointers now that filesz is known
        bss_base = BASE + filesz
        final_tags = []
        for t, v, name in tags:
            if name == "DT_SYMTAB" and self.k.symtab_into_bss:
                v = bss_base + 0x10
            if name == "DT_STRTAB" and self.k.strtab_into_bss:
                v = bss_base + 0x30
            final_tags.append((t, v, name))
        self.tags = final_tags
        dyn = b"".join(struct.pack("<QQ", t, v) for t, v, _ in final_tags)

        memsz = filesz + self.k.bss_extra
        e_ident = ELFMAG + bytes([ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0]) + b"\x00" * 8
        phnum = 2
        ehdr = struct.pack("<16sHHIQQQIHHHHHH",
                           e_ident, ET_DYN, EM_X86_64, EV_CURRENT, 0,
                           EHDRSZ, 0, 0, EHDRSZ, PHDRSZ, phnum, 0, 0, 0)
        phdr_load = struct.pack("<IIQQQQQQ", PT_LOAD, PF_R | PF_W,
                                BASE, BASE, BASE, filesz, memsz, BASE)
        phdr_dyn = struct.pack("<IIQQQQQQ", PT_DYNAMIC, PF_R | PF_W,
                               dyn_addr, dyn_addr, dyn_addr,
                               len(dyn), len(dyn), 8)
        total = BASE + filesz
        out = bytearray(total)
        out[0:EHDRSZ] = ehdr
        out[EHDRSZ:EHDRSZ + PHDRSZ] = phdr_load
        out[EHDRSZ + PHDRSZ:EHDRSZ + 2 * PHDRSZ] = phdr_dyn
        for name, blob in blocks:
            out[self.addr[name]:self.addr[name] + len(blob)] = blob
        out[dyn_addr:dyn_addr + len(dyn)] = dyn

        if self.k.gnu_chain_into_bss:
            self._patch_chain_into_bss(out, hashblob, bss_base)

        result = bytes(out)
        if self.k.truncate_file:
            result = result[:-self.k.truncate_file]
        return result

    def _patch_chain_into_bss(self, out, hashblob, bss_base):
        # GNU header is 16 bytes + 8 bloom + 2*4 buckets => chain starts at
        # hash+32.  Clear the terminator on the only/last chain word and point
        # the highest bucket at a symbol whose terminator lands in zero-fill.
        h = self.addr["hash"]
        chain_pos = h + 16 + 8 + 2 * 4
        nchain = len(self.sym_names) - 1
        # clear low bit of final in-file chain word => walk continues
        last = chain_pos + (nchain - 1) * 4
        out[last:last + 4] = struct.pack("<I", struct.unpack("<I", out[last:last + 4])[0] & ~1)
        # The zero-fill bytes are NOT present in the file; the walk will read
        # past EOF (or into a later mapped object). Record the would-be offset.
        self.chain_terminator_bss_offset = bss_base
