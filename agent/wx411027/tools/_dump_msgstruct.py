"""Dump DoAddMsg MsgStruct：扫描 std::string / 整型候选，对齐字段偏移。

会 Interceptor.detachAll() 清掉已有 agent hook，跑完需重新注入 agent。
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import frida

PREFERRED = 0x16D2FAF
PID_DEFAULT = 17144
OUT = Path(__file__).resolve().parent / "_msgstruct_dumps.jsonl"
MARKER = f"struct_dump_{int(time.time())}"

SCRIPT = r"""
'use strict';
var base = Process.getModuleByName('Weixin.dll').base;
var dumps = [];
var maxDumps = 12;

function readStd(addr) {
  try {
    var len = addr.add(0x10).readU64().toNumber();
    var cap = addr.add(0x18).readU64().toNumber();
    if (len <= 0 || len > 0x10000 || cap > 0x10000 || len > cap + 1) return null;
    var p = (cap <= 15) ? addr : addr.readPointer();
    if (p.isNull()) return null;
    var s = p.readUtf8String(Math.min(len, 800));
    if (!s) return null;
    // 过滤明显非文本
    var printable = 0;
    for (var i = 0; i < Math.min(s.length, 40); i++) {
      var c = s.charCodeAt(i);
      if (c >= 0x20 || c === 10 || c === 13 || c === 9) printable++;
    }
    if (printable < Math.min(s.length, 40) * 0.6) return null;
    return { s: s, len: len, cap: cap };
  } catch (e) { return null; }
}

function looksWxid(s) {
  if (!s) return false;
  if (s.indexOf('@chatroom') >= 0) return true;
  if (s.indexOf('wxid_') === 0) return true;
  if (s === 'filehelper' || s === 'fmessage' || s === 'newsapp') return true;
  if (/^[a-zA-Z][\w\-]{4,32}$/.test(s) && s.indexOf(' ') < 0) return true;
  return false;
}

function hexPreview(p, n) {
  var out = [];
  try {
    for (var i = 0; i < n; i++) {
      var b = p.add(i).readU8();
      out.push(('0' + b.toString(16)).slice(-2));
    }
  } catch (e) {}
  return out.join(' ');
}

function scanStrings(msg, size) {
  var found = [];
  for (var off = 0; off + 0x20 <= size; off += 8) {
    var st = readStd(msg.add(off));
    if (!st) continue;
    found.push({
      off: off,
      len: st.len,
      cap: st.cap,
      preview: st.s.slice(0, 160),
      wxidish: looksWxid(st.s),
      hasMarker: st.s.indexOf('struct_dump_') >= 0 || st.s.indexOf('recv_verify') >= 0
    });
  }
  return found;
}

function scanInts(msg, size) {
  var ints = [];
  var now = Math.floor(Date.now() / 1000);
  for (var off = 0; off + 8 <= size; off += 4) {
    try {
      var u32 = msg.add(off).readU32();
      var u64 = null;
      if ((off % 8) === 0) {
        try { u64 = msg.add(off).readU64().toString(); } catch (e) {}
      }
      var flags = [];
      // 常见消息类型
      if ([1, 3, 34, 37, 42, 43, 47, 48, 49, 10000, 10002].indexOf(u32) >= 0) flags.push('typeish');
      // unix 时间附近
      if (u32 > now - 86400 * 7 && u32 < now + 3600) flags.push('timeish');
      // 非零小整数
      if (u32 > 0 && u32 < 100) flags.push('small');
      if (u64 && u64 !== '0' && u64.length >= 10) flags.push('idish');
      if (flags.length) ints.push({ off: off, u32: u32, u64: u64, flags: flags });
    } catch (e) {}
  }
  return ints;
}

function dumpMsg(msg, meta) {
  if (!msg || msg.isNull()) return null;
  var size = 0x280;
  var strings = scanStrings(msg, size);
  var ints = scanInts(msg, size);
  return {
    meta: meta,
    msg: msg.toString(),
    hex80: hexPreview(msg, 0x80),
    strings: strings,
    ints: ints.filter(function (x) {
      return x.flags.indexOf('typeish') >= 0 || x.flags.indexOf('timeish') >= 0 || x.flags.indexOf('idish') >= 0;
    }).slice(0, 40)
  };
}

// 简易主线程发文本（触发入站/出站入库）
var queue = [];
var sending = false;
var mainTid = 0;
var pumped = false;

function setStr(dst, s) {
  for (var i = 0; i < 0x20; i++) dst.add(i).writeU8(0);
  var bytes = [];
  for (var j = 0; j < s.length; j++) {
    var c = s.charCodeAt(j);
    bytes.push(c < 0x80 ? c : 0x3f);
  }
  var len = bytes.length;
  if (len < 16) {
    for (var k = 0; k < len; k++) dst.add(k).writeU8(bytes[k]);
    dst.add(0x10).writeU64(len);
    dst.add(0x18).writeU64(0xf);
  } else {
    var buf = Memory.alloc(len + 1);
    for (var k2 = 0; k2 < len; k2++) buf.add(k2).writeU8(bytes[k2]);
    buf.add(len).writeU8(0);
    dst.writePointer(buf);
    dst.add(0x10).writeU64(len);
    var need = len + 1;
    var cap = (need + 0xf) & ~0xf;
    dst.add(0x18).writeU64(cap - 1);
  }
}

function doSendText(wxid, text) {
  var o = {
    create_param2: 0xdf40, send_message: 0x1677a30, param1_vtable: 0x84ec9c8,
    param2: 0xa0ce0b0, param2_1: 0x8595f58, param2_2: 0x8595e98, param2_3: 0x8595dd8,
    txt_message_ctr: 0x6b2c30, txt_message_vtbl: 0x8279358
  };
  function heap(n) { return Memory.alloc(n); }
  var createParam2 = new NativeFunction(base.add(o.create_param2), 'pointer', ['pointer','pointer','pointer','pointer','pointer','uint64']);
  var sendMessage = new NativeFunction(base.add(o.send_message), 'void', ['pointer','pointer']);
  var txtCtr = new NativeFunction(base.add(o.txt_message_ctr), 'void', ['pointer']);
  var msgBuf = heap(0x768 * 8);
  msgBuf.writePointer(base.add(o.txt_message_vtbl));
  msgBuf.add(8).writeU64(uint64('0x200000005'));
  var msg = msgBuf.add(0x10);
  txtCtr(msg);
  setStr(msg.add(0xb0), wxid);
  setStr(msg.add(0x708), text);
  msg.add(0xd8).writeU64(1);
  msg.add(0x188).writeU64(text.length);
  function allocUnknown(vt) {
    var p = heap(64); p.writePointer(base.add(vt)); p.add(0x38).writePointer(p); return p;
  }
  var arg2 = heap(0xe8);
  createParam2(arg2, allocUnknown(o.param2_1), allocUnknown(o.param2_2), allocUnknown(o.param2_3), heap(128), base.add(o.param2).readU64());
  var data = heap(0x20);
  data.writePointer(msgBuf.add(0x10));
  data.add(8).writePointer(msgBuf);
  var arg1 = heap(0x28);
  arg1.writePointer(base.add(o.param1_vtable));
  arg1.add(8).writePointer(data);
  arg1.add(0x10).writePointer(data.add(0x10));
  arg1.add(0x18).writePointer(data.add(0x10));
  arg1.add(0x20).writeU64(1);
  sendMessage(arg1, arg2);
}

function ensurePump() {
  if (pumped) return;
  var user32 = Process.getModuleByName('user32.dll');
  var EnumWindows = new NativeFunction(user32.getExportByName('EnumWindows'), 'int', ['pointer','pointer']);
  var GetWindowThreadProcessId = new NativeFunction(user32.getExportByName('GetWindowThreadProcessId'), 'uint32', ['pointer','pointer']);
  var IsWindowVisible = new NativeFunction(user32.getExportByName('IsWindowVisible'), 'int', ['pointer']);
  var found = Memory.alloc(4); found.writeU32(0);
  var myPid = Process.id;
  var cb = new NativeCallback(function (hwnd) {
    try {
      if (!IsWindowVisible(hwnd)) return 1;
      var pidBuf = Memory.alloc(4);
      var tid = GetWindowThreadProcessId(hwnd, pidBuf);
      if (pidBuf.readU32() === myPid && tid && found.readU32() === 0) found.writeU32(tid);
    } catch (e) {}
    return 1;
  }, 'int', ['pointer','pointer']);
  EnumWindows(cb, ptr(0));
  mainTid = found.readU32() || Process.getCurrentThreadId();
  var peek = Module.getGlobalExportByName
    ? Module.getGlobalExportByName('PeekMessageW')
    : Module.getExportByName(null, 'PeekMessageW');
  Interceptor.attach(peek, {
    onLeave: function () {
      if (sending || queue.length === 0) return;
      if (Process.getCurrentThreadId() !== mainTid) return;
      var job = queue.shift();
      sending = true;
      try { doSendText(job.wxid, job.text); job.ok = true; }
      catch (e) { job.err = String(e); }
      finally { sending = false; job.done = true; }
    }
  });
  pumped = true;
}

rpc.exports = {
  prepare: function () {
    try { Interceptor.detachAll(); } catch (e) {}
    return true;
  },
  install: function (rva) {
    Interceptor.attach(base.add(rva), {
      onEnter: function () {
        if (dumps.length >= maxDumps) return;
        var c = this.context;
        var candidates = [];
        try {
          var rsi = c.rsi;
          if (rsi && !rsi.isNull()) {
            candidates.push({ tag: 'rsi+0x18', ptr: rsi.add(0x18).readPointer() });
            candidates.push({ tag: 'rsi', ptr: rsi });
          }
        } catch (e) {}
        try { candidates.push({ tag: 'rax', ptr: c.rax }); } catch (e) {}
        try { candidates.push({ tag: 'rcx', ptr: c.rcx }); } catch (e) {}
        try { candidates.push({ tag: 'rdx', ptr: c.rdx }); } catch (e) {}
        try { candidates.push({ tag: 'r8', ptr: c.r8 }); } catch (e) {}
        try { candidates.push({ tag: 'r9', ptr: c.r9 }); } catch (e) {}

        var best = null;
        var all = [];
        for (var i = 0; i < candidates.length; i++) {
          var d = dumpMsg(candidates[i].ptr, { tag: candidates[i].tag, site: rva });
          if (!d) continue;
          all.push({ tag: candidates[i].tag, stringCount: d.strings.length, wxids: d.strings.filter(function(s){return s.wxidish;}).length, marker: d.strings.some(function(s){return s.hasMarker;}) });
          // 选含 wxid/marker 最多的
          var score = d.strings.filter(function (s) { return s.wxidish || s.hasMarker; }).length;
          if (!best || score > best._score) {
            best = d;
            best._score = score;
          }
        }
        if (!best || best._score <= 0) {
          // 仍记录 rsi+0x18 原始 dump（哪怕没识别到）
          try {
            best = dumpMsg(c.rsi.add(0x18).readPointer(), { tag: 'rsi+0x18', site: rva, weak: true });
            best._score = 0;
          } catch (e) { return; }
        }
        best.candidateSummary = all;
        dumps.push(best);
        send({ type: 'dump', n: dumps.length, score: best._score, tag: best.meta.tag, strings: best.strings.slice(0, 8) });
      }
    });
    return true;
  },
  enqueueSend: function (wxid, text) {
    ensurePump();
    var job = { wxid: wxid, text: text, done: false, ok: false, err: null };
    queue.push(job);
    var t0 = Date.now();
    while (!job.done && Date.now() - t0 < 12000) Thread.sleep(0.05);
    return { done: job.done, ok: job.ok, err: job.err };
  },
  dumps: function () { return dumps; },
  clear: function () { dumps = []; return true; }
};
"""


def analyze(dumps: list) -> dict:
    """统计各 off 出现 wxid/content 的频率，推断布局。"""
    from collections import Counter, defaultdict

    wxid_offs = Counter()
    content_offs = Counter()
    type_offs = Counter()
    time_offs = Counter()
    id_offs = Counter()
    examples = defaultdict(list)

    for d in dumps:
        strings = d.get("strings") or []
        wxids = [s for s in strings if s.get("wxidish")]
        contents = [
            s
            for s in strings
            if not s.get("wxidish")
            and s.get("len", 0) >= 1
            and (
                s.get("hasMarker")
                or ":" in (s.get("preview") or "")
                or len(s.get("preview") or "") >= 2
            )
        ]
        for s in wxids:
            wxid_offs[s["off"]] += 1
            if len(examples[f"wxid@{s['off']:x}"]) < 3:
                examples[f"wxid@{s['off']:x}"].append(s["preview"][:80])
        for s in contents:
            # content 通常不是纯 wxid
            content_offs[s["off"]] += 1
            if len(examples[f"content@{s['off']:x}"]) < 3:
                examples[f"content@{s['off']:x}"].append(s["preview"][:80])
        for it in d.get("ints") or []:
            flags = it.get("flags") or []
            if "typeish" in flags:
                type_offs[it["off"]] += 1
            if "timeish" in flags:
                time_offs[it["off"]] += 1
            if "idish" in flags:
                id_offs[it["off"]] += 1

    def top(counter, n=8):
        return [(hex(k), v) for k, v in counter.most_common(n)]

    return {
        "wxid_offs": top(wxid_offs),
        "content_offs": top(content_offs),
        "type_offs": top(type_offs),
        "time_offs": top(time_offs),
        "id_offs": top(id_offs),
        "examples": dict(examples),
    }


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    pid = PID_DEFAULT
    if "--pid" in sys.argv:
        pid = int(sys.argv[sys.argv.index("--pid") + 1])
    wait_sec = 30
    if "--wait" in sys.argv:
        wait_sec = int(sys.argv[sys.argv.index("--wait") + 1])

    print(f"pid={pid} marker={MARKER} out={OUT}", flush=True)
    device = frida.get_local_device()
    session = device.attach(pid)
    script = session.create_script(SCRIPT)

    def on_message(message, data):
        if message.get("type") == "send":
            p = message["payload"]
            if p.get("type") == "dump":
                strs = p.get("strings") or []
                brief = [
                    f"0x{s['off']:x}:{s['preview'][:40]!r}" for s in strs[:5]
                ]
                print(f"DUMP#{p['n']} tag={p.get('tag')} score={p.get('score')} {brief}", flush=True)
        else:
            print("MSG", message, flush=True)

    script.on("message", on_message)
    script.load()
    print("detachAll...", flush=True)
    script.exports_sync.prepare()
    script.exports_sync.install(PREFERRED)
    print(f"hooked 0x{PREFERRED:x}", flush=True)

    print("enqueue send filehelper...", flush=True)
    print(script.exports_sync.enqueue_send("filehelper", MARKER), flush=True)

    print(f"waiting {wait_sec}s for inbound (请给本机微信发几条消息)...", flush=True)
    time.sleep(wait_sec)

    dumps = script.exports_sync.dumps()
    print(f"\ncollected {len(dumps)} dumps", flush=True)
    OUT.write_text("", encoding="utf-8")
    with OUT.open("a", encoding="utf-8") as f:
        for d in dumps:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")

    summary = analyze(dumps)
    print("\n=== offset frequency ===", flush=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)

    # 启发式推荐
    wx = summary["wxid_offs"]
    ct = summary["content_offs"]
    print("\n=== suggested layout ===", flush=True)
    if len(wx) >= 1:
        print(f"  from/talker? {wx[0][0]} (hits={wx[0][1]})")
    if len(wx) >= 2:
        print(f"  to?         {wx[1][0]} (hits={wx[1][1]})")
    if ct:
        print(f"  content?    {ct[0][0]} (hits={ct[0][1]})")
    if summary["type_offs"]:
        print(f"  type?       {summary['type_offs'][0][0]}")
    if summary["time_offs"]:
        print(f"  time?       {summary['time_offs'][0][0]}")
    if summary["id_offs"]:
        print(f"  msg_id?     {summary['id_offs'][0][0]}")

    try:
        session.detach()
    except Exception:
        pass
    print("done; re-inject agent after updating offsets", flush=True)


if __name__ == "__main__":
    main()
