"""拉取 /api/message/structDump 并汇总字段偏移。"""
from __future__ import annotations

import json
import urllib.request
from collections import Counter

URL = "http://127.0.0.1:19088/api/message/structDump"
OUT = __file__.replace("_analyze_dumps.py", "_msgstruct_dumps.json")


def main():
    raw = urllib.request.urlopen(URL, timeout=15).read()
    data = json.loads(raw)
    dumps = (data.get("data") or {}).get("dumps") or []
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dumps, f, ensure_ascii=False, indent=2)
    print("n=", len(dumps), "saved", OUT)

    wx = Counter()
    other = Counter()
    for d in dumps:
        print("---", d.get("tag"), "score", d.get("score"), "ptr", d.get("ptr"))
        print(" parsed", d.get("parsed"))
        for s in d.get("strings") or []:
            off = s["off"]
            text = s.get("text") or ""
            if s.get("wxidish"):
                wx[off] += 1
                kind = "wxid"
            else:
                other[off] += 1
                kind = "str"
            print(f"  {kind} 0x{off:x} len={s.get('len')} {text[:100]!r}")
        for i in d.get("ints") or []:
            fl = i.get("flags") or []
            if not any(x in fl for x in ("typeish", "timeish", "idish")):
                continue
            if i["off"] > 0x220:
                continue
            print(f"  int 0x{i['off']:x} u32={i.get('u32')} u64={i.get('u64')} {fl}")

    print("\nWXID_OFF", [(hex(k), v) for k, v in wx.most_common()])
    print("OTHER_OFF", [(hex(k), v) for k, v in other.most_common()])


if __name__ == "__main__":
    main()
