"""PE scan: find 0x90-spaced vtable pairs and string pointer refs in Weixin.dll."""
import struct
import pathlib

dll = pathlib.Path(r"C:\Program Files\Tencent\Weixin\4.1.10.27\Weixin.dll")
data = dll.read_bytes()
e = struct.unpack_from("<I", data, 0x3C)[0]
coff = e + 4
opt = coff + 20
ib = struct.unpack_from("<Q", data, opt + 24)[0]
ns = struct.unpack_from("<H", data, coff + 2)[0]
so = struct.unpack_from("<H", data, coff + 16)[0]
sec_off = opt + so
secs = []
nul = bytes([0])
for i in range(ns):
    o = sec_off + i * 40
    name = data[o : o + 8].split(nul, 1)[0].decode()
    vsz, va, rsz, raw = struct.unpack_from("<IIII", data, o + 8)
    secs.append((name, va, vsz, raw, rsz))
text = next(s for s in secs if s[0] == ".text")
rdata = next(s for s in secs if s[0] == ".rdata")
text_lo, text_hi = text[1], text[1] + text[2]


def rva_to_off(rva: int):
    for name, va, vsz, raw, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None


def looks_vtbl(rva: int, n: int = 4) -> bool:
    off = rva_to_off(rva)
    if off is None:
        return False
    ok = 0
    for i in range(n):
        p = struct.unpack_from("<Q", data, off + i * 8)[0]
        r = p - ib if p >= ib else p
        if text_lo <= r < text_hi:
            ok += 1
    return ok >= 3


print("img pair valid", looks_vtbl(0x84F96B8), looks_vtbl(0x84F9748))

pairs = []
start = max(rdata[1], 0x7400000)
end = min(rdata[1] + rdata[2], 0x8600000)
rva = start & ~7
while rva + 0x90 + 32 < end:
    if looks_vtbl(rva) and looks_vtbl(rva + 0x90):
        pairs.append(rva)
    rva += 8
print("pair count", len(pairs))
near = [p for p in pairs if 0x8200000 <= p <= 0x8600000]
print("near send region", len(near))
for p in near[:50]:
    print(hex(p), hex(p + 0x90))


def find_ptr_refs(str_rva: int, limit: int = 10):
    target = ib + str_rva
    needle = struct.pack("<Q", target)
    hits = []
    for name, va, vsz, raw, rsz in secs:
        if name not in (".rdata", ".data"):
            continue
        chunk = data[raw : raw + rsz]
        i = 0
        while len(hits) < limit:
            j = chunk.find(needle, i)
            if j < 0:
                break
            hits.append(va + j)
            i = j + 1
    return hits


for sname, srva in [
    ("cdnbigimgurl", 0x8678322),
    ("SendAppMsgRequest", 0x8A57198),
    ("SendMsgRequestNew", 0x87A8128),
]:
    print(sname, "ptrrefs", [hex(x) for x in find_ptr_refs(srva)])

for n in [b"message_content", b"Msg_", b"local_type", b"CreateTime"]:
    off = data.find(n)
    print(n, hex(off) if off >= 0 else None)
