"""Frida probe: relocate recv MsgStruct handler on Weixin.dll 4.1.10.27.

Strategy (from docs/wx-4.1.7.30.md):
1. Try nearby RVAs around 0xdb4570 for function prologues
2. Hook candidates lightly; send a marker text via existing HTTP API
3. Prefer hooks that see std::string talker/content layout
"""
from __future__ import annotations

import json
import time
import urllib.request

import frida

PID = 2092
MARKER = f"rea_probe_{int(time.time())}"
HTTP = "http://127.0.0.1:19088"

SCRIPT = r"""
'use strict';
var mod = Process.getModuleByName('Weixin.dll');
var base = mod.base;

function readStdString(addr) {
  try {
    var len = addr.add(0x10).readU64().toNumber();
    var cap = addr.add(0x18).readU64().toNumber();
    if (len > 0x10000 || cap > 0x10000 || len === 0) return null;
    var dataPtr = (cap <= 15) ? addr : addr.readPointer();
    return dataPtr.readUtf8String(Math.min(len, 200));
  } catch (e) { return null; }
}

function looksLikeMsg(p) {
  if (!p || p.isNull()) return null;
  var talker = readStdString(p);
  var content = readStdString(p.add(0x48));
  if (!talker && !content) return null;
  var status = 0, localType = 0, createTime = 0;
  try {
    status = p.add(0x98).readU32();
    localType = p.add(0x9c).readU32();
    createTime = p.add(0x90).readU32();
  } catch (e) {}
  return { talker: talker, content: content, status: status, localType: localType, createTime: createTime };
}

rpc.exports = {
  base: function () { return base.toString(); },
  probeRegion: function (centerRva, radius) {
    var hits = [];
    var start = Math.max(0, centerRva - radius);
    var end = centerRva + radius;
    for (var rva = start; rva < end; rva++) {
      try {
        var b0 = base.add(rva).readU8();
        var b1 = base.add(rva + 1).readU8();
        var b2 = base.add(rva + 2).readU8();
        // common x64 prologues
        var ok = false;
        if (b0 === 0x40 && b1 === 0x55) ok = true; // push rbp with rex
        if (b0 === 0x55 && (b1 === 0x48 || b1 === 0x41 || b1 === 0x56 || b1 === 0x57)) ok = true;
        if (b0 === 0x48 && b1 === 0x89 && b2 === 0x5c) ok = true; // mov [rsp+..], rbx
        if (b0 === 0x48 && b1 === 0x83 && b2 === 0xec) ok = true; // sub rsp, imm8
        if (b0 === 0x4c && b1 === 0x8b && b2 === 0xdc) ok = true; // mov r11, rsp
        if (ok) hits.push(rva);
      } catch (e) {}
      if (hits.length >= 80) break;
    }
    return hits;
  },
  installHooks: function (rvas) {
    var installed = [];
    rvas.forEach(function (rva) {
      try {
        Interceptor.attach(base.add(rva), {
          onEnter: function (args) {
            var cands = [args[0], args[1], args[2], args[3]];
            for (var i = 0; i < cands.length; i++) {
              var m = looksLikeMsg(cands[i]);
              if (!m) continue;
              if (m.content && m.content.indexOf('rea_probe_') >= 0) {
                send({ type: 'hit', rva: rva, arg: i, msg: m });
              }
            }
          }
        });
        installed.push(rva);
      } catch (e) {}
    });
    return installed;
  }
};
"""


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
    device = frida.get_local_device()
    session = device.attach(PID)
    hits = []

    def on_message(message, data):
        if message.get("type") == "send":
            hits.append(message["payload"])
            print("HIT", message["payload"])
        else:
            print("MSG", message)

    script = session.create_script(SCRIPT)
    script.on("message", on_message)
    script.load()
    print("base", script.exports_sync.base())

    # phase 1: prologues around old recv offset
    protos = script.exports_sync.probe_region(0xDB4570, 0x4000)
    print("prologue candidates near 0xdb4570:", len(protos), [hex(x) for x in protos[:20]])

    # also try documented neighbors / WCDB-ish region from docs (± larger)
    more = script.exports_sync.probe_region(0xDB4100, 0x2000)
    seen = set(protos)
    for r in more:
        if r not in seen:
            protos.append(r)
            seen.add(r)

    # prioritize closest to 0xdb4570
    protos = sorted(protos, key=lambda x: abs(x - 0xDB4570))[:40]
    installed = script.exports_sync.install_hooks(protos)
    print("installed", len(installed), [hex(x) for x in installed[:15]])

    # ensure agent HTTP is up? may need run_agent separately; try send anyway
    try:
        health = http_json("GET", "/api/health")
        print("health", health.get("code"), health.get("data", {}).get("version"))
    except Exception as e:
        print("HTTP not up yet:", e)
        print("Hooking only; send a WeChat text containing", MARKER, "manually if needed")
        time.sleep(25)
        print("hits", hits)
        session.detach()
        return

    try:
        r = http_json(
            "POST",
            "/api/message/text",
            {"contactId": "filehelper", "text": MARKER},
        )
        print("send", r)
    except Exception as e:
        print("send failed", e)

    time.sleep(8)
    print("FINAL hits", json.dumps(hits, ensure_ascii=False, indent=2))
    session.detach()


if __name__ == "__main__":
    main()
