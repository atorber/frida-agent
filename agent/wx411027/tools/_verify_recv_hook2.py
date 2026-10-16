"""干净验证 DoAddMsg：磁盘 PE 特征 + 运行时 hook 命中统计。"""
from __future__ import annotations

import json
import struct
import sys
import time
import urllib.request
from pathlib import Path

import frida

PREFERRED = 0x16D2FAF
PATTERN = bytes([0x48, 0x89, 0x85, 0xF8, 0x01, 0x00, 0x00])
DLL_CANDIDATES = [
    Path(r"C:\Program Files\Tencent\Weixin\4.1.10.27\Weixin.dll"),
    Path(r"C:\Program Files\Tencent\Weixin\Weixin.dll"),
]
PID = 17144
HTTP = "http://127.0.0.1:19088"

SCRIPT = r"""
'use strict';
var base = Process.getModuleByName('Weixin.dll').base;
var counts = {};
var samples = [];

function readStd(addr) {
  try {
    var len = addr.add(0x10).readU64().toNumber();
    var cap = addr.add(0x18).readU64().toNumber();
    if (len > 0x10000 || cap > 0x10000 || len === 0) return null;
    var p = (cap <= 15) ? addr : addr.readPointer();
    return p.readUtf8String(Math.min(len, 200));
  } catch (e) { return null; }
}

function bytesAt(rva, n) {
  var a = [];
  for (var i = 0; i < n; i++) a.push(base.add(rva).add(i).readU8());
  return a;
}

rpc.exports = {
  memBytes: function (rva) { return bytesAt(rva, 7); },
  scan: function () {
    return Memory.scanSync(base.add(0x1600000), 0x150000, '48 89 85 F8 01 00 00').map(function (m) {
      return m.address.sub(base).toInt32() >>> 0;
    });
  },
  install: function (sites) {
    sites.forEach(function (rva) {
      counts[rva] = 0;
      Interceptor.attach(base.add(rva), {
        onEnter: function () {
          counts[rva]++;
          try {
            var p = this.context.rsi.add(0x18).readPointer();
            var from = readStd(p.add(0x18));
            var to = readStd(p.add(0x38));
            var content = readStd(p.add(0x160));
            var type = 0;
            try { type = p.add(0xc).readS32(); } catch (e) {}
            if (from || to || content) {
              var row = { site: rva, from: from, to: to, content: content, type: type };
              samples.push(row);
              send(row);
            }
          } catch (e) {}
        }
      });
    });
    return true;
  },
  snap: function () { return { counts: counts, samples: samples.slice(-40) }; }
};
"""


def rva_to_off(data: bytes, rva: int) -> int | None:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size
    for i in range(num_sections):
        o = sec_off + i * 40
        va = struct.unpack_from("<I", data, o + 12)[0]
        vsz = struct.unpack_from("<I", data, o + 8)[0]
        raw = struct.unpack_from("<I", data, o + 20)[0]
        rsz = struct.unpack_from("<I", data, o + 16)[0]
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None


def check_disk() -> bool:
    dll = next((p for p in DLL_CANDIDATES if p.exists()), None)
    if not dll:
        print("DISK: Weixin.dll not found")
        return False
    data = dll.read_bytes()
    off = rva_to_off(data, PREFERRED)
    assert off is not None
    disk = data[off : off + 7]
    ok = disk == PATTERN
    print(f"DISK {dll}")
    print(f"  preferred 0x{PREFERRED:x} -> fileoff 0x{off:x}")
    print(f"  bytes {disk.hex(' ')}")
    print(f"  pattern_match {ok}")
    return ok


def http_json(method: str, path: str, body: dict | None = None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        HTTP + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    pid = PID
    if "--pid" in sys.argv:
        pid = int(sys.argv[sys.argv.index("--pid") + 1])
    wait_sec = 20
    if "--wait" in sys.argv:
        wait_sec = int(sys.argv[sys.argv.index("--wait") + 1])

    disk_ok = check_disk()

    device = frida.get_local_device()
    print(f"attach pid={pid}", flush=True)
    session = device.attach(pid)
    live = []

    def on_message(message, data):
        if message.get("type") == "send":
            live.append(message["payload"])
            p = message["payload"]
            print(
                f"HIT site=0x{p['site']:x} type={p.get('type')} "
                f"from={p.get('from')!r} to={p.get('to')!r} "
                f"content={(p.get('content') or '')[:80]!r}",
                flush=True,
            )
        else:
            print("MSG", message, flush=True)

    script = session.create_script(SCRIPT)
    script.on("message", on_message)
    script.load()

    mem = script.exports_sync.mem_bytes(PREFERRED)
    print(f"MEM preferred bytes {[hex(b) for b in mem]} is_jmp={mem[0]==0xe9}", flush=True)
    scanned = script.exports_sync.scan()
    print(f"SCAN intact pattern sites: {[hex(x) for x in scanned]}", flush=True)
    if PREFERRED in scanned:
        print("  preferred still has intact pattern in memory")
    elif mem[0] == 0xE9:
        print("  preferred patched by Frida trampoline (already hooked) — expected if agent live")

    sites = list(dict.fromkeys([PREFERRED] + list(scanned)))
    script.exports_sync.install(sites)
    print(f"installed {len(sites)} hooks", flush=True)

    marker = f"recv_verify2_{int(time.time())}"
    try:
        http_json("POST", "/api/message/listen", {"enabled": True})
        print("send", http_json("POST", "/api/message/text", {"contactId": "filehelper", "text": marker}))
    except Exception as e:
        print("HTTP:", e)

    print(f"waiting {wait_sec}s (发一条入站消息到本机微信可增加命中)...", flush=True)
    time.sleep(wait_sec)

    snap = script.exports_sync.snap()
    counts = {int(k): v for k, v in snap["counts"].items()}
    print("\n=== callCounts ===", flush=True)
    for rva, c in sorted(counts.items(), key=lambda kv: -kv[1]):
        mark = " <<<" if rva == PREFERRED else ""
        print(f"  0x{rva:x}: {c}{mark}", flush=True)

    pref_samples = [s for s in snap["samples"] if s["site"] == PREFERRED]
    print(f"\npreferred samples with strings: {len(pref_samples)}", flush=True)
    for s in pref_samples[-5:]:
        print(
            f"  type={s.get('type')} from={s.get('from')!r} to={s.get('to')!r} "
            f"content={(s.get('content') or '')[:60]!r}",
            flush=True,
        )

    try:
        st = http_json("GET", "/api/message/listen")
        print("\nagent listen:", json.dumps(st.get("data"), ensure_ascii=False)[:800], flush=True)
    except Exception as e:
        print("listen status:", e)

    print("\n=== verdict ===", flush=True)
    print(f"DISK pattern at 0x{PREFERRED:x}: {'OK' if disk_ok else 'FAIL'}")
    if counts.get(PREFERRED, 0) > 0 or pref_samples or mem[0] == 0xE9:
        print(f"RUNTIME: 0x{PREFERRED:x} is active recv site (calls={counts.get(PREFERRED, 0)}, "
              f"string_samples={len(pref_samples)}, already_hooked_jmp={mem[0]==0xe9})")
    else:
        print(f"RUNTIME: 0x{PREFERRED:x} idle in this window — need inbound traffic")

    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
