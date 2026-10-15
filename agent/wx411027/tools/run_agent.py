"""用 Python frida 注入 wx411027 agent，并可选发一条测试消息。"""
import json
import sys
import time
import urllib.error
import urllib.request

import frida

SCRIPT = (
    __file__.replace("\\", "/")
    .rsplit("/tools/", 1)[0]
    .replace("agent/wx411027", "dist/agent/wx411027")
    + "/index.js"
)
# 上面路径在 Windows 上不稳，改用 pathlib
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[3] / "dist" / "agent" / "wx411027" / "index.js"


def find_main_pid(device):
    for p in device.enumerate_processes():
        if p.name.lower() != "weixin.exe":
            continue
        try:
            s = device.attach(p.pid)
            sc = s.create_script(
                "var m=Process.findModuleByName('Weixin.dll'); send(m?1:0);"
            )
            box = []
            sc.on("message", lambda m, d: box.append(m))
            sc.load()
            time.sleep(0.25)
            try:
                sc.unload()
            except Exception:
                pass
            try:
                s.detach()
            except Exception:
                pass
            if box and box[0].get("payload") == 1:
                return p.pid
        except Exception:
            continue
    return None


def http_send(text: str):
    payload = json.dumps({"contactId": "filehelper", "text": text}).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:19088/api/message/text",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8")


def main():
    do_send = "--send" in sys.argv
    device = frida.get_local_device()
    pid = find_main_pid(device)
    print("main_pid", pid, "script", SCRIPT)
    if not pid:
        raise SystemExit("no Weixin.dll process")
    if not SCRIPT.exists():
        raise SystemExit(f"missing {SCRIPT}, run npm run build:wx411027")

    session = device.attach(pid)
    script = session.create_script(SCRIPT.read_text(encoding="utf-8"))
    script.on("message", lambda m, d: print("[msg]", m))
    script.load()
    print("injected, waiting HTTP...")
    time.sleep(1.0)

    if do_send:
        text = f"wx411027-{int(time.time())}"
        print("sending", text)
        try:
            print(http_send(text))
        except urllib.error.URLError as e:
            print("http err", e)
        print("watching 12s for crash...")
        time.sleep(12)
        try:
            print("ping", script.exports_sync.ping())
        except Exception as e:
            print("ping failed (可能已崩):", e)
    else:
        print("HTTP :19088 ready. Ctrl+C to detach. Use --send to test.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    try:
        script.exports_sync.stop_http_server()
    except Exception:
        pass
    try:
        script.unload()
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
