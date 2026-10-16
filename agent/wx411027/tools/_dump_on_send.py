"""发送带 marker 的文本时，在所有 DoAddMsg 特征点 dump 指针，定位 content 偏移。"""
from __future__ import annotations

import json
import sys
import time
import urllib.request

import frida

MARKER = f"content_align_{int(time.time())}"
PREFERRED = 0x16D2FAF
SITES = [0x16D2FAF, 0x16D341E, 0x16AFCF4, 0x16FC54D, 0x160EC77, 0x160ED54, 0x1641C7D, 0x17400B9]
HTTP = "http://127.0.0.1:19088"
OUT = __file__.replace("_dump_on_send.py", "_msgstruct_on_send.json")

SCRIPT = r"""
'use strict';
var base = Process.getModuleByName('Weixin.dll').base;
var hits = [];
var marker = '';

function tryStd(addr) {
  try {
    var len = addr.add(0x10).readU64().toNumber();
    var cap = addr.add(0x18).readU64().toNumber();
    if (len <= 0 || len > 0x20000 || cap > 0x20000) return null;
    if (cap < 15 && len > 15) return null;
    var p = (cap <= 15) ? addr : addr.readPointer();
    if (p.isNull()) return null;
    var s = null;
    try { s = p.readUtf8String(Math.min(len, 500)); } catch (e) {}
    if (!s) try { s = p.readUtf16String(Math.min(len, 250)); } catch (e) {}
    return s;
  } catch (e) { return null; }
}

function scan(msg) {
  var out = [];
  for (var off = 0; off + 0x20 <= 0x300; off += 8) {
    var s = tryStd(msg.add(off));
    if (!s) continue;
    out.push({ off: off, text: s.slice(0, 200), hasMarker: s.indexOf(marker) >= 0 });
  }
  return out;
}

function collectPtrs(ctx) {
  var list = [];
  function add(tag, p) {
    if (p && !p.isNull()) list.push({ tag: tag, ptr: p });
  }
  try {
    var rsi = ctx.rsi;
    if (rsi && !rsi.isNull()) {
      add('rsi+0x18', rsi.add(0x18).readPointer());
      add('rsi+0x10', rsi.add(0x10).readPointer());
      add('rsi+0x20', rsi.add(0x20).readPointer());
      add('rsi', rsi);
    }
  } catch (e) {}
  add('rax', ctx.rax); add('rcx', ctx.rcx); add('rdx', ctx.rdx);
  add('r8', ctx.r8); add('r9', ctx.r9);
  return list;
}

rpc.exports = {
  setMarker: function (m) { marker = m; return true; },
  install: function (sites) {
    sites.forEach(function (rva) {
      try {
        Interceptor.attach(base.add(rva), {
          onEnter: function () {
            var ptrs = collectPtrs(this.context);
            for (var i = 0; i < ptrs.length; i++) {
              var strings = scan(ptrs[i].ptr);
              var marked = strings.filter(function (s) { return s.hasMarker; });
              if (marked.length === 0 && strings.length === 0) continue;
              var row = {
                site: rva,
                tag: ptrs[i].tag,
                ptr: ptrs[i].ptr.toString(),
                marked: marked,
                strings: strings.slice(0, 20)
              };
              if (marked.length) {
                hits.push(row);
                send(row);
              } else if (strings.some(function (s) {
                return s.text.indexOf('@chatroom') >= 0 || s.text.indexOf('wxid_') >= 0 || s.text.indexOf('filehelper') >= 0;
              })) {
                hits.push(row);
                send(row);
              }
            }
          }
        });
      } catch (e) { send({ error: String(e), rva: rva }); }
    });
    return true;
  },
  hits: function () { return hits; }
};
"""


def http_json(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        HTTP + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if body else {},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    pid = 17144
    if "--pid" in sys.argv:
        pid = int(sys.argv[sys.argv.index("--pid") + 1])

    device = frida.get_local_device()
    session = device.attach(pid)
    script = session.create_script(SCRIPT)

    def on_msg(message, data):
        if message.get("type") == "send":
            p = message["payload"]
            if "error" in p:
                print("ERR", p, flush=True)
                return
            marked = p.get("marked") or []
            print(
                f"HIT site=0x{p['site']:x} tag={p['tag']} marked={[m['off'] for m in marked]} "
                f"strs={[(hex(s['off']), s['text'][:40]) for s in (p.get('strings') or [])[:6]]}",
                flush=True,
            )
        else:
            print(message, flush=True)

    script.on("message", on_msg)
    script.load()
    script.exports_sync.set_marker(MARKER)
    # 不 detachAll，避免弄坏 agent；叠加 hook
    script.exports_sync.install(SITES)
    print("marker", MARKER, "hooks", [hex(s) for s in SITES], flush=True)

    for to in ["filehelper", "44691574243@chatroom"]:
        try:
            r = http_json("POST", "/api/message/text", {"contactId": to, "text": f"{MARKER} -> {to}"})
            print("send", to, r.get("code"), flush=True)
        except Exception as e:
            print("send fail", to, e, flush=True)
        time.sleep(2)

    print("wait 20s inbound...", flush=True)
    time.sleep(20)
    hits = script.exports_sync.hits()
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(hits, f, ensure_ascii=False, indent=2)
    print(f"hits={len(hits)} saved {OUT}", flush=True)

    # 汇总 marker 出现的 off
    from collections import Counter

    content_offs = Counter()
    site_counts = Counter()
    for h in hits:
        site_counts[h["site"]] += 1
        for m in h.get("marked") or []:
            content_offs[m["off"]] += 1
    print("sites", {hex(k): v for k, v in site_counts.items()})
    print("content_offs_with_marker", {hex(k): v for k, v in content_offs.most_common()})
    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
