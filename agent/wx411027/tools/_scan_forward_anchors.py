"""Locate ForwardXML-like anchors from known-good img_msg_vtbl neighborhood + send_message E8 callers."""
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
    ptrs = []
    for i in range(n):
        p = struct.unpack_from("<Q", data, off + i * 8)[0]
        r = p - ib if p >= ib else p
        ptrs.append(r)
        if text_lo <= r < text_hi:
            ok += 1
    return ok >= 3, ptrs


# dump known send vtables
for label, rva in [
    ("txt_message_vtbl", 0x8279358),
    ("img_msg_vtbl", 0x84F96B8),
    ("img_msg_vtb2", 0x84F9748),
    ("param1_vtable", 0x84EC9C8),
]:
    ok, ptrs = looks_vtbl(rva)
    print(label, hex(rva), "ok", ok, [hex(p) for p in ptrs])

# Find rdata slots that hold pointer TO img_msg_vtbl VA (construction sites / typeinfo)
for label, rva in [("img_msg_vtbl", 0x84F96B8), ("img_msg_vtb2", 0x84F9748), ("txt_message_vtbl", 0x8279358)]:
    needle = struct.pack("<Q", ib + rva)
    hits = []
    for sec_name, va, vsz, raw, rsz in secs:
        chunk = data[raw : raw + rsz]
        i = 0
        while len(hits) < 15:
            j = chunk.find(needle, i)
            if j < 0:
                break
            hits.append((sec_name, va + j))
            i = j + 1
    print("refs to", label, hits[:15])

# E8 callers of send_message 0x1677a30
target = 0x1677A30
blob = data[text[3] : text[3] + text[4]]
callers = []
i = 0
while len(callers) < 40:
    j = blob.find(b"\xE8", i)
    if j < 0:
        break
    if j + 5 <= len(blob):
        rel = struct.unpack_from("<i", blob, j + 1)[0]
        call_rva = text[1] + j
        dest = call_rva + 5 + rel
        if dest == target:
            callers.append(call_rva)
    i = j + 1
print("send_message E8 callers", [hex(c) for c in callers])


def find_func_start(insn_rva: int, back: int = 0x400):
    off = text[3] + (insn_rva - text[1])
    for delta in range(0, back):
        pos = off - delta
        if pos <= text[3]:
            break
        prev = data[pos - 1]
        b = data[pos : pos + 4]
        if prev in (0xCC, 0xC3) or (prev == 0x00 and delta > 8):
            if b[0:2] == b"\x40\x55" or (b[0] == 0x55 and b[1] in (0x48, 0x41, 0x56, 0x57, 0x53)):
                return insn_rva - delta
            if b[0:3] in (b"\x48\x89\x5c", b"\x48\x83\xec", b"\x4c\x8b\xdc"):
                return insn_rva - delta
    return None


for c in callers[:20]:
    print(" caller", hex(c), "func", hex(find_func_start(c) or 0))

# Heuristic: MESSAGE_PARAM style — single vtable near param1 (0x84ec9c8)
# Look for vtables within ±0x200000 of img_msg that have slot0 in small thunk range like 0xa7xx
ok, img_ptrs = looks_vtbl(0x84F96B8)
thunk0 = img_ptrs[0]
print("img thunk0", hex(thunk0))
matches = []
rva = 0x8400000
while rva < 0x8600000:
    ok, ptrs = looks_vtbl(rva)
    if ok and ptrs[0] == thunk0 and looks_vtbl(rva + 0x90)[0]:
        matches.append(rva)
    rva += 8
print("same-thunk0 +0x90 pairs", len(matches))
for m in matches[:30]:
    print(hex(m), hex(m + 0x90), [hex(p) for p in looks_vtbl(m)[1][:4]])
