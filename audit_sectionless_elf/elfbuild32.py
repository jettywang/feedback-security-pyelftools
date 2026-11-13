"""ELF32 little-endian sectionless ET_DYN variant (mirrors elfbuild.py layout)."""
from __future__ import annotations
import struct, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from elfbuild import gnu_hash, sysv_hash, Knobs  # noqa: E402

ELFMAG = b"\x7fELF"
ET_DYN, EM_386 = 3, 3
PT_LOAD, PT_DYNAMIC = 1, 2
PF_R, PF_W = 4, 2
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT = 0,1,4,5,6,10,11
DT_GNU_HASH = 0x6FFFFEF5
BASE = 0x1000
SYM32, DYNSZ, PHDRSZ, EHDRSZ = 16, 8, 32, 52


class Builder32:
    def __init__(self, knobs: Knobs, symbols, needed=b"libc.so.6"):
        self.k = knobs
        self.sym_names = [b""] + symbols
        self.needed = needed
        self.addr = {}

    def _strtab(self):
        blob = b"\x00"; self._so = {b"": 0}
        for s in [self.needed] + self.sym_names[1:]:
            if s not in self._so:
                self._so[s] = len(blob); blob += s + b"\x00"
        return blob

    def _symtab(self):
        out = b""
        for i, name in enumerate(self.sym_names):
            st_name = self._so.get(name, 0)
            st_info = 0 if i == 0 else 0x12
            # Elf32_Sym: name, value, size, info, other, shndx
            out += struct.pack("<IIIBBH", st_name, 0, 0, st_info, 0, 0)
        return out

    def _sysv(self):
        n = len(self.sym_names); nb = 2
        buckets, chains = [0]*nb, [0]*n
        for idx in range(1, n):
            b = sysv_hash(self.sym_names[idx]) % nb
            chains[idx] = buckets[b]; buckets[b] = idx
        nc = max(0, n + self.k.sysv_inflate_nchains - self.k.sysv_deflate_nchains)
        vals = (chains + [0]*max(0, nc-n))[:nc]
        return (struct.pack("<II", nb, nc) + struct.pack("<%dI"%nb,*buckets)
                + struct.pack("<%dI"%len(vals),*vals))

    def _gnu(self):
        names = self.sym_names[1:]
        symoff, nb = 1, 2
        buckets = [0]*nb; hashes = [gnu_hash(x) for x in names]
        for i, hv in enumerate(hashes):
            b = hv % nb; si = symoff+i
            if buckets[b] == 0 or si < buckets[b]:
                buckets[b] = si
        if self.k.gnu_sparse_bucket:
            buckets[1] = symoff + len(names) + 4
        chain = [hv & ~1 for hv in hashes]
        if chain: chain[-1] |= 1
        if self.k.gnu_no_terminator and chain: chain[-1] &= ~1
        # 32-bit bloom entries are 4-byte words
        return (struct.pack("<IIII", nb, symoff, 1, 6) + struct.pack("<I", 0)
                + struct.pack("<%dI"%nb,*buckets) + struct.pack("<%dI"%len(chain),*chain))

    def build(self):
        strtab = self._strtab(); symtab = self._symtab()
        hb = self._sysv() if self.k.mode == "sysv" else self._gnu()
        blocks = [("hash", hb), ("symtab", symtab), ("strtab", strtab)]
        cur = BASE
        for n, blob in blocks:
            self.addr[n] = cur; cur += len(blob)
        tags = [(DT_NEEDED, self._so[self.needed], "DT_NEEDED")]
        if self.k.mode == "sysv": tags.append((DT_HASH, self.addr["hash"], "DT_HASH"))
        elif self.k.mode == "gnu": tags.append((DT_GNU_HASH, self.addr["hash"], "DT_GNU_HASH"))
        tags += [(DT_SYMTAB, self.addr["symtab"], "DT_SYMTAB"),
                 (DT_STRTAB, self.addr["strtab"], "DT_STRTAB"),
                 (DT_STRSZ, len(strtab), "DT_STRSZ"),
                 (DT_SYMENT, SYM32, "DT_SYMENT")]
        if not self.k.drop_null: tags.append((DT_NULL, 0, "DT_NULL"))
        dyn = b"".join(struct.pack("<II", t, v) for t, v, _ in tags)
        dyn_addr = cur; filesz = cur + len(dyn) - BASE; memsz = filesz + self.k.bss_extra
        e_ident = ELFMAG + bytes([1, 1, 1, 0]) + b"\x00"*8  # ELFCLASS32
        ehdr = struct.pack("<16sHHIIIIIHHHHHH", e_ident, ET_DYN, EM_386, 1,
                           0, EHDRSZ, 0, 0, EHDRSZ, PHDRSZ, 2, 0, 0, 0)
        # Elf32_Phdr: type, offset, vaddr, paddr, filesz, memsz, flags, align
        pl = struct.pack("<IIIIIIII", PT_LOAD, BASE, BASE, BASE, filesz, memsz, PF_R|PF_W, BASE)
        pd = struct.pack("<IIIIIIII", PT_DYNAMIC, dyn_addr, dyn_addr, dyn_addr,
                         len(dyn), len(dyn), PF_R|PF_W, 8)
        total = BASE + filesz
        out = bytearray(total)
        out[0:EHDRSZ] = ehdr
        out[EHDRSZ:EHDRSZ+PHDRSZ] = pl
        out[EHDRSZ+PHDRSZ:EHDRSZ+2*PHDRSZ] = pd
        for n, blob in blocks:
            out[self.addr[n]:self.addr[n]+len(blob)] = blob
        out[dyn_addr:dyn_addr+len(dyn)] = dyn
        return bytes(out)
