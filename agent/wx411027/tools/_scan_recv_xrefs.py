"""Find .text LEA/RIP refs to local_type / message_content strings → recv candidate funcs."""
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


def off_to_rva(off: int):
    for name, va, vsz, raw, rsz in secs:
        if raw <= off < raw + rsz:
            return va + (off - raw), name
    return None, None


needles = {
    "local_type": b"local_type",
    "message_content": b"message_content",
    "server_id": b"server_id",
    "CreateTime": b"CreateTime",
}
locs = {}
for name, n in needles.items():
    off = data.find(n)
    rva, sec = off_to_rva(off) if off >= 0 else (None, None)
    locs[name] = rva
    print(name, "file", hex(off) if off >= 0 else None, "rva", hex(rva) if rva else None)

blob = data[text[3] : text[3] + text[4]]
pats = [bytes([0x48, 0x8D]), bytes([0x4C, 0x8D])]


def find_lea(str_rva: int, limit: int = 20):
    str_va = ib + str_rva
    hits = []
    for pat in pats:
        i = 0
        while len(hits) < limit:
            j = blob.find(pat, i)
            if j < 0:
                break
            if j + 7 <= len(blob) and (blob[j + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", blob, j + 3)[0]
                insn_rva = text[1] + j
                if ib + insn_rva + 7 + disp == str_va:
                    hits.append(insn_rva)
            i = j + 1
    return hits


def find_func_start(insn_rva: int, back: int = 0x200):
    """Walk back for a plausible prologue after int3/ret padding."""
    off = text[3] + (insn_rva - text[1])
    for delta in range(0, back):
        pos = off - delta
        if pos < text[3]:
            break
        prev = data[pos - 1] if pos > text[3] else 0xCC
        b = data[pos : pos + 4]
        if prev in (0xCC, 0xC3, 0xC2) or delta == 0:
            if b[0:2] == b"\x40\x55":
                return insn_rva - delta
            if b[0] == 0x55 and b[1] in (0x48, 0x41, 0x56, 0x57, 0x53):
                return insn_rva - delta
            if b[0:3] == b"\x48\x89\x5c":
                return insn_rva - delta
            if b[0:3] == b"\x48\x83\xec":
                return insn_rva - delta
            if b[0:3] == b"\x4c\x8b\xdc":
                return insn_rva - delta
    return None


for name, rva in locs.items():
    if not rva:
        continue
    xs = find_lea(rva)
    print("LEA", name, [hex(x) for x in xs])
    for x in xs[:8]:
        fs = find_func_start(x)
        print("  insn", hex(x), "func?", hex(fs) if fs else None)

# also search absolute VA pointers in .rdata to these strings
for name, rva in locs.items():
    if not rva:
        continue
    needle = struct.pack("<Q", ib + rva)
    hits = []
    for sec_name, va, vsz, raw, rsz in secs:
        if sec_name not in (".rdata", ".data"):
            continue
        chunk = data[raw : raw + rsz]
        i = 0
        while len(hits) < 8:
            j = chunk.find(needle, i)
            if j < 0:
                break
            hits.append(va + j)
            i = j + 1
    print("PTR", name, [hex(h) for h in hits])
