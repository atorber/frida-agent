"""Frida: probe DoAddMsg candidates; send via PeekMessageW main-thread pump."""
from __future__ import annotations

import time

import frida

PID = 2092
MARKER = f"doadd_probe_{int(time.time())}"
CANDIDATES = [
    0x160EC77,
    0x160ED54,
    0x1641C7D,
    0x16AFCF4,
    0x16D2FAF,
    0x16D341E,
    0x16FC54D,
    0x17400B9,
    # also try function starts near delta prediction
    0x16D2F00,
    0x16D3000,
]

SCRIPT = r"""
'use strict';
var base = Process.getModuleByName('Weixin.dll').base;
var hits = [];
var queue = [];
var sending = false;
var mainTid = 0;
var pumped = false;

function readStd(addr) {
  try {
    var len = addr.add(0x10).readU64().toNumber();
    var cap = addr.add(0x18).readU64().toNumber();
    if (len > 0x10000 || cap > 0x10000 || len === 0) return null;
    var p = (cap <= 15) ? addr : addr.readPointer();
    return p.readUtf8String(Math.min(len, 160));
  } catch (e) { return null; }
}

function tryMsg(p, tag, site) {
  if (!p || p.isNull()) return;
  var from = readStd(p.add(0x18));
  var to = readStd(p.add(0x38));
  var content = readStd(p.add(0x160));
  var talker = readStd(p);
  var content2 = readStd(p.add(0x48));
  var payload = { site: site, tag: tag, from: from, to: to, content: content, talker: talker, content2: content2 };
  var blob = JSON.stringify(payload);
  if (blob.indexOf('doadd_probe_') >= 0) {
    hits.push(payload);
    send(payload);
  }
}

function setStr(dst, s) {
  for (var i = 0; i < 0x20; i++) dst.add(i).writeU8(0);
  var bytes = [];
  for (var j = 0; j < s.length; j++) {
    var c = s.charCodeAt(j);
    if (c < 0x80) bytes.push(c);
    else bytes.push(0x3f);
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
  var offsets = {
    create_param2: 0xdf40,
    send_message: 0x1677a30,
    param1_vtable: 0x84ec9c8,
    param2: 0xa0ce0b0,
    param2_1: 0x8595f58,
    param2_2: 0x8595e98,
    param2_3: 0x8595dd8,
    txt_message_ctr: 0x6b2c30,
    txt_message_vtbl: 0x8279358
  };
  function heap(n) { return Memory.alloc(n); }
  var createParam2 = new NativeFunction(base.add(offsets.create_param2), 'pointer', ['pointer','pointer','pointer','pointer','pointer','uint64']);
  var sendMessage = new NativeFunction(base.add(offsets.send_message), 'void', ['pointer','pointer']);
  var txtCtr = new NativeFunction(base.add(offsets.txt_message_ctr), 'void', ['pointer']);
  var msgBuf = heap(0x768 * 8);
  msgBuf.writePointer(base.add(offsets.txt_message_vtbl));
  msgBuf.add(8).writeU64(uint64('0x200000005'));
  var msg = msgBuf.add(0x10);
  txtCtr(msg);
  setStr(msg.add(0xb0), wxid);
  setStr(msg.add(0x708), text);
  msg.add(0xd8).writeU64(1);
  msg.add(0x188).writeU64(text.length);
  function allocUnknown(vt) {
    var p = heap(64);
    p.writePointer(base.add(vt));
    p.add(0x38).writePointer(p);
    return p;
  }
  var arg2 = heap(0xe8);
  var buf = heap(128);
  createParam2(arg2, allocUnknown(offsets.param2_1), allocUnknown(offsets.param2_2), allocUnknown(offsets.param2_3), buf, base.add(offsets.param2).readU64());
  var data = heap(0x20);
  data.writePointer(msgBuf.add(0x10));
  data.add(8).writePointer(msgBuf);
  var arg1 = heap(0x28);
  arg1.writePointer(base.add(offsets.param1_vtable));
  arg1.add(8).writePointer(data);
  arg1.add(0x10).writePointer(data.add(0x10));
  arg1.add(0x18).writePointer(data.add(0x10));
  arg1.add(0x20).writeU64(1);
  sendMessage(arg1, arg2);
}

function resolveMainTid() {
  if (mainTid) return mainTid;
  try {
    var user32 = Process.getModuleByName('user32.dll');
    var EnumWindows = new NativeFunction(user32.getExportByName('EnumWindows'), 'int', ['pointer', 'pointer']);
    var GetWindowThreadProcessId = new NativeFunction(user32.getExportByName('GetWindowThreadProcessId'), 'uint32', ['pointer', 'pointer']);
    var IsWindowVisible = new NativeFunction(user32.getExportByName('IsWindowVisible'), 'int', ['pointer']);
    var myPid = Process.id;
    var found = Memory.alloc(4);
    found.writeU32(0);
    var cb = new NativeCallback(function (hwnd) {
      try {
        if (!IsWindowVisible(hwnd)) return 1;
        var pidBuf = Memory.alloc(4);
        var tid = GetWindowThreadProcessId(hwnd, pidBuf);
        if (pidBuf.readU32() === myPid && tid && found.readU32() === 0) found.writeU32(tid);
      } catch (e) {}
      return 1;
    }, 'int', ['pointer', 'pointer']);
    EnumWindows(cb, ptr(0));
    mainTid = found.readU32();
  } catch (e) {}
  if (!mainTid) mainTid = Process.getCurrentThreadId();
  return mainTid;
}

function ensurePump() {
  if (pumped) return;
  var peek = Module.getGlobalExportByName
    ? Module.getGlobalExportByName('PeekMessageW')
    : Module.getExportByName(null, 'PeekMessageW');
  resolveMainTid();
  Interceptor.attach(peek, {
    onLeave: function () {
      if (sending || queue.length === 0) return;
      if (Process.getCurrentThreadId() !== resolveMainTid()) return;
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
  install: function (sites) {
    var ok = [];
    sites.forEach(function (rva) {
      try {
        Interceptor.attach(base.add(rva), {
          onEnter: function () {
            try {
              tryMsg(this.context.rsi.add(0x18).readPointer(), 'rsi+0x18', rva);
            } catch (e) {}
            tryMsg(this.context.rax, 'rax', rva);
          }
        });
        ok.push(rva);
      } catch (e) {}
    });
    return ok;
  },
  hits: function () { return hits; },
  enqueueSend: function (wxid, text) {
    ensurePump();
    var job = { wxid: wxid, text: text, done: false, ok: false, err: null };
    queue.push(job);
    var t0 = Date.now();
    while (!job.done && Date.now() - t0 < 12000) Thread.sleep(0.05);
    return { done: job.done, ok: job.ok, err: job.err, mainTid: mainTid };
  }
};
"""


def main():
    device = frida.get_local_device()
    session = device.attach(PID)
    hits = []

    def on_message(message, data):
        if message.get("type") == "send":
            hits.append(message["payload"])
            print("HIT", message["payload"])
        else:
            print(message)

    script = session.create_script(SCRIPT)
    script.on("message", on_message)
    script.load()
    print("installed", [hex(x) for x in script.exports_sync.install(CANDIDATES)])
    print("enqueue", script.exports_sync.enqueue_send("filehelper", MARKER))
    time.sleep(2)
    print("total hits", len(hits))
    sites = sorted({h.get("site") for h in hits})
    print("sites", [hex(s) if isinstance(s, int) else s for s in sites])
    session.detach()


if __name__ == "__main__":
    main()
