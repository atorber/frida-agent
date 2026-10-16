"""Frida 验证 4.1.10.27 DoAddMsg 收消息 hook 偏移。

1. 校验首选 RVA 0x16d2faf 特征字节
2. 扫描/安装候选 hook（rsi+0x18 → MsgStruct）
3. 经 HTTP 发 marker 到 filehelper，统计命中
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

import frida

HTTP = "http://127.0.0.1:19088"
PREFERRED = 0x16D2FAF
PATTERN = bytes([0x48, 0x89, 0x85, 0xF8, 0x01, 0x00, 0x00])
CANDIDATES = [
    0x16D2FAF,
    0x16D341E,
    0x16AFCF4,
    0x16FC54D,
    0x160EC77,
    0x1641C7D,
]
SCAN_LO, SCAN_HI = 0x1600000, 0x1750000
MARKER = f"recv_verify_{int(time.time())}"

SCRIPT = r"""
'use strict';
var mod = Process.getModuleByName('Weixin.dll');
var base = mod.base;
var hits = [];
var callCounts = {};

function readStd(addr) {
  try {
    var len = addr.add(0x10).readU64().toNumber();
    var cap = addr.add(0x18).readU64().toNumber();
    if (len > 0x10000 || cap > 0x10000 || len === 0) return null;
    var p = (cap <= 15) ? addr : addr.readPointer();
    return p.readUtf8String(Math.min(len, 240));
  } catch (e) { return null; }
}

function dumpMsg(p) {
  if (!p || p.isNull()) return null;
  var from = readStd(p.add(0x18));
  var to = readStd(p.add(0x38));
  var content = readStd(p.add(0x160));
  var type = 0, createTime = 0, msgId = '0';
  try {
    type = p.add(0x0c).readS32();
    createTime = p.add(0x110).readS32();
    msgId = p.add(0x108).readS64().toString();
  } catch (e) {}
  // legacy layout fallback
  var talker = readStd(p);
  var contentOld = readStd(p.add(0x48));
  return {
    from: from, to: to, content: content, type: type,
    createTime: createTime, msgId: msgId,
    talker: talker, contentOld: contentOld
  };
}

function siteBytes(rva) {
  var out = [];
  try {
    for (var i = 0; i < 7; i++) out.push(base.add(rva).add(i).readU8());
  } catch (e) {}
  return out;
}

rpc.exports = {
  info: function () {
    return { base: base.toString(), size: mod.size, name: mod.name };
  },
  checkPreferred: function (rva, expect) {
    var got = siteBytes(rva);
    var match = got.length === expect.length;
    for (var i = 0; i < expect.length && match; i++) {
      if (got[i] !== expect[i]) match = false;
    }
    return { rva: rva, match: match, bytes: got };
  },
  scanPattern: function (lo, hi, patternHex) {
    var matches = Memory.scanSync(base.add(lo), hi - lo, patternHex);
    return matches.map(function (m) {
      return (m.address.sub(base).toInt32() >>> 0);
    });
  },
  install: function (sites) {
    var ok = [];
    sites.forEach(function (rva) {
      try {
        callCounts[rva] = 0;
        Interceptor.attach(base.add(rva), {
          onEnter: function () {
            callCounts[rva] = (callCounts[rva] || 0) + 1;
            var msg = null;
            try {
              var rsi = this.context.rsi;
              if (rsi && !rsi.isNull()) msg = dumpMsg(rsi.add(0x18).readPointer());
            } catch (e) {}
            var payload = {
              site: rva,
              count: callCounts[rva],
              msg: msg,
              rax: this.context.rax.toString(),
              rsi: this.context.rsi.toString()
            };
            // always record structured calls; marker filtered in Python
            hits.push(payload);
            if (msg) {
              var blob = JSON.stringify(msg);
              if (blob.indexOf('recv_verify_') >= 0 || blob.indexOf('filehelper') >= 0) {
                send(payload);
              }
            }
          }
        });
        ok.push(rva);
      } catch (e) {
        send({ error: String(e), rva: rva });
      }
    });
    return ok;
  },
  snapshot: function () {
    return { hits: hits.slice(-80), callCounts: callCounts };
  },
  clear: function () {
    hits = [];
    for (var k in callCounts) callCounts[k] = 0;
    return true;
  }
};
"""


def find_main_pid(device):
    """优先无 --type= 的主进程；避免逐个 attach 卡住。"""
    import subprocess

    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process -Filter \"Name='Weixin.exe'\" | "
                "Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress",
            ],
            text=True,
            timeout=15,
        )
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        for row in data or []:
            cmd = row.get("CommandLine") or ""
            if "--type=" not in cmd:
                return int(row["ProcessId"])
    except Exception as e:
        print("pid enum fallback:", e)

    for p in device.enumerate_processes():
        if p.name.lower() == "weixin.exe":
            return p.pid
    return None


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
    # 无缓冲，避免 attach 时看不到输出
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    wait_sec = 12
    if "--wait" in sys.argv:
        i = sys.argv.index("--wait")
        wait_sec = int(sys.argv[i + 1])

    device = frida.get_local_device()
    pid = None
    if "--pid" in sys.argv:
        pid = int(sys.argv[sys.argv.index("--pid") + 1])
    else:
        pid = find_main_pid(device)
    print("pid", pid, "marker", MARKER, flush=True)
    if not pid:
        raise SystemExit("no Weixin.dll process")

    live = []

    def on_message(message, data):
        if message.get("type") == "send":
            live.append(message["payload"])
            p = message["payload"]
            if "error" in p:
                print("ERR", p)
            else:
                msg = p.get("msg") or {}
                print(
                    f"HIT site=0x{p['site']:x} count={p.get('count')} "
                    f"from={msg.get('from')!r} to={msg.get('to')!r} "
                    f"content={(msg.get('content') or msg.get('contentOld') or '')[:80]!r}"
                )
        else:
            print("MSG", message)

    session = device.attach(pid)
    script = session.create_script(SCRIPT)
    script.on("message", on_message)
    script.load()
    info = script.exports_sync.info()
    print("dll", info)

    pref = script.exports_sync.check_preferred(PREFERRED, list(PATTERN))
    print(
        "preferred",
        hex(PREFERRED),
        "match=",
        pref["match"],
        "bytes=",
        [hex(b) for b in pref["bytes"]],
    )

    scanned = script.exports_sync.scan_pattern(
        SCAN_LO, SCAN_HI, "48 89 85 F8 01 00 00"
    )
    print(f"scan 0x{SCAN_LO:x}-0x{SCAN_HI:x}: {len(scanned)} hits")
    print("  first20:", [hex(x) for x in scanned[:20]])
    if PREFERRED in scanned:
        print("  preferred IN scan results: YES")
    else:
        print("  preferred IN scan results: NO")

    sites = list(dict.fromkeys(CANDIDATES + scanned[:30]))
    installed = script.exports_sync.install(sites)
    print("installed", len(installed), "hooks")
    script.exports_sync.clear()

    # HTTP: enable listen + send marker
    try:
        health = http_json("GET", "/api/health")
        print("health", health.get("data", {}).get("version"), "recvHookRva", health.get("data", {}).get("recvHookRva"))
        listen = http_json("POST", "/api/message/listen", {"enabled": True})
        print("listen", listen.get("data"))
        send = http_json(
            "POST",
            "/api/message/text",
            {"contactId": "filehelper", "text": MARKER},
        )
        print("send", send)
    except Exception as e:
        print("HTTP failed:", e)
        print(f"请在 {wait_sec}s 内手动给本号发消息或发到文件传输助手，marker={MARKER}")

    print(f"waiting {wait_sec}s for DoAddMsg hits...")
    time.sleep(wait_sec)

    snap = script.exports_sync.snapshot()
    counts = {int(k): v for k, v in snap["callCounts"].items()}
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    print("\n=== callCounts (top) ===")
    for rva, c in ranked[:15]:
        mark = " <<<" if rva == PREFERRED else ""
        print(f"  0x{rva:x}: {c}{mark}")

    marker_hits = []
    for h in snap["hits"]:
        msg = h.get("msg") or {}
        blob = json.dumps(msg, ensure_ascii=False)
        if MARKER in blob or "recv_verify_" in blob:
            marker_hits.append(h)

    print(f"\n=== marker hits ({MARKER}): {len(marker_hits)} ===")
    sites_hit = sorted({h["site"] for h in marker_hits})
    for s in sites_hit:
        print(f"  marker site 0x{s:x}")

    # agent recent
    try:
        st = http_json("GET", "/api/message/listen")
        recent = (st.get("data") or {}).get("recent") or []
        print(f"\nagent recent ({len(recent)}):")
        for m in recent[-5:]:
            print(
                f"  type={m.get('type')} talker={m.get('talkerId')!r} "
                f"room={m.get('roomId')!r} text={(m.get('text') or '')[:60]!r}"
            )
    except Exception as e:
        print("listen status fail", e)

    print("\n=== verdict ===")
    if pref["match"]:
        print(f"BYTE: preferred 0x{PREFERRED:x} pattern OK")
    else:
        print(f"BYTE: preferred 0x{PREFERRED:x} pattern MISMATCH")

    if PREFERRED in sites_hit:
        print(f"RUNTIME: preferred 0x{PREFERRED:x} saw marker — OFFSET VALID")
    elif marker_hits:
        print(
            f"RUNTIME: marker seen at {[hex(s) for s in sites_hit]} "
            f"(not preferred) — prefer first hit"
        )
    elif counts.get(PREFERRED, 0) > 0:
        print(
            f"RUNTIME: preferred called {counts[PREFERRED]} times but no marker in MsgStruct; "
            "layout/RSI path may be wrong, or outgoing bypasses this site"
        )
    else:
        print(
            "RUNTIME: no preferred calls / no marker — "
            "try receiving an inbound message while probe runs (--wait 30)"
        )

    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
