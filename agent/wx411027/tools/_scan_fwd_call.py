"""Locate FORWARD_XML_CALL via LEA to hardcoded RVA 0x367849 used in aixed rdx+0x20."""
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


def looks_vtbl(rva: int, n: int = 3) -> bool:
    off = rva_to_off(rva)
    if off is None:
        return False
    ok = 0
    for i in range(n):
        p = struct.unpack_from("<Q", data, off + i * 8)[0]
        r = p - ib if p >= ib else p
        if text_lo <= r < text_hi:
            ok += 1
    return ok >= 2


# check 0x367849 content
off = rva_to_off(0x367849)
print("0x367849 off", hex(off) if off else None)
if off:
    print("bytes", data[off : off + 32].hex())
    print("ascii", data[off : off + 32])

blob = data[text[3] : text[3] + text[4]]
target = ib + 0x367849
hits = []
for pat in (bytes([0x48, 0x8D]), bytes([0x4C, 0x8D])):
    i = 0
    while len(hits) < 30:
        j = blob.find(pat, i)
        if j < 0:
            break
        if j + 7 <= len(blob) and (blob[j + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", blob, j + 3)[0]
            insn_rva = text[1] + j
            if ib + insn_rva + 7 + disp == target:
                hits.append(insn_rva)
        i = j + 1
print("LEA to 0x367849", [hex(h) for h in hits])


def find_func_start(insn_rva: int, back: int = 0x800):
    off = text[3] + (insn_rva - text[1])
    for delta in range(0, back):
        pos = off - delta
        if pos <= text[3]:
            break
        prev = data[pos - 1]
        b = data[pos : pos + 4]
        if prev in (0xCC, 0xC3) or delta == 0:
            if b[0:2] == b"\x40\x55":
                return insn_rva - delta
            if b[0] == 0x55 and b[1] in (0x48, 0x41, 0x56, 0x57, 0x53):
                return insn_rva - delta
            if b[0:3] in (b"\x48\x89\x5c", b"\x48\x83\xec", b"\x4c\x8b\xdc", b"\x48\x89\x54"):
                return insn_rva - delta
    return None


for h in hits:
    print(" insn", hex(h), "func", hex(find_func_start(h) or 0))

# Search imm64 0x100000006 in .text (mov reg, imm64 = 48 B8 / 49 B8 ...)
imm = struct.pack("<Q", 0x100000006)
imm_hits = []
i = 0
while len(imm_hits) < 40:
    j = blob.find(imm, i)
    if j < 0:
        break
    # typically preceded by 48 B8 / 49 B8 / C7 ...
    imm_hits.append(text[1] + j)
    i = j + 1
print("imm 0x100000006 RVAs (data embeds)", [hex(x) for x in imm_hits[:20]])

# Also search for MOV r64, imm with that value: 48 B8 <imm>
pat_mov = bytes([0x48, 0xB8]) + imm
mov_hits = []
i = 0
while len(mov_hits) < 40:
    j = blob.find(pat_mov, i)
    if j < 0:
        break
    mov_hits.append(text[1] + j)
    i = j + 1
print("movabs 0x100000006", [hex(x) for x in mov_hits[:20]])
for h in mov_hits[:10]:
    print("  func?", hex(find_func_start(h) or 0))

# Find dual vtables near img_msg with SECOND table matching img_msg_vtb2 pattern
# (first slots large text funcs, not shared thunks)
ok_img2, = (looks_vtbl(0x84F9748),)
print("img_vtb2 ok", ok_img2)
off2 = rva_to_off(0x84F9748)
ptrs2 = [struct.unpack_from("<Q", data, off2 + i * 8)[0] - ib for i in range(4)]
print("img_vtb2 ptrs", [hex(p) for p in ptrs2])

# candidates: pairs where vtb2 first ptr is in high .text (>0x100000) like img_msg_vtb2
cands = []
rva = 0x8400000
while rva < 0x8580000:
    if looks_vtbl(rva) and looks_vtbl(rva + 0x90):
        o = rva_to_off(rva + 0x90)
        p0 = struct.unpack_from("<Q", data, o)[0] - ib
        if p0 > 0x100000 and p0 < text_hi:
            # first table uses shared thunks like img
            o1 = rva_to_off(rva)
            t0 = struct.unpack_from("<Q", data, o1)[0] - ib
            if t0 < 0x10000:  # shared small thunk
                cands.append(rva)
    rva += 0x8
print("field-like pairs", len(cands))
for c in cands[:40]:
    o2 = rva_to_off(c + 0x90)
    p = [hex(struct.unpack_from("<Q", data, o2 + i * 8)[0] - ib) for i in range(3)]
    print(hex(c), hex(c + 0x90), p)
