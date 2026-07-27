#!/usr/bin/env python3
"""wx391027 Frida Agent HTTP 客户端（wx-helper skill）。

用法示例:
  python wx_api.py health
  python wx_api.py check-login
  python wx_api.py self
  python wx_api.py send-text --to filehelper --text "hello"
  python wx_api.py send-text --to 123@chatroom --text "hi" --at wxid_a,wxid_b
  python wx_api.py get /api/rooms
  python wx_api.py post /api/message/forward --json '{"msgId":"123","receiver":"filehelper"}'
  python wx_api.py forward --msg-id 8233065081616396038 --to filehelper

环境变量:
  WX_AGENT_BASE  默认 http://127.0.0.1:19088
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

DEFAULT_BASE = os.environ.get("WX_AGENT_BASE", "http://127.0.0.1:19088").rstrip("/")

# Windows 控制台常见 GBK，避免昵称含 emoji 时炸输出
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:
    pass


def _req(
    method: str,
    path: str,
    body: Optional[dict] = None,
    query: Optional[dict] = None,
    base: str = DEFAULT_BASE,
    timeout: float = 60,
) -> Any:
    url = base + (path if path.startswith("/") else "/" + path)
    if query:
        q = {k: v for k, v in query.items() if v is not None and v != ""}
        if q:
            url += "?" + urllib.parse.urlencode(q)
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else {"code": 0, "msg": str(e)}
        except json.JSONDecodeError:
            payload = {"code": 0, "msg": raw or str(e), "httpStatus": e.code}
        _print(payload)
        sys.exit(1)
    except urllib.error.URLError as e:
        _print({"code": 0, "msg": f"无法连接 Agent ({base}): {e.reason}"})
        sys.exit(2)
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        payload = {"code": 0, "msg": "非 JSON 响应", "raw": raw}
    _print(payload)
    if isinstance(payload, dict) and payload.get("code") == 0:
        sys.exit(1)
    return payload


def _print(obj: Any) -> None:
    text = json.dumps(obj, ensure_ascii=False, indent=2) + "\n"
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        sys.stdout.buffer.write(text.encode(enc, errors="replace"))


def _parse_json_arg(s: str) -> dict:
    try:
        v = json.loads(s)
    except json.JSONDecodeError as e:
        raise SystemExit(f"--json 解析失败: {e}") from e
    if not isinstance(v, dict):
        raise SystemExit("--json 必须是 JSON object")
    return v


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="wx391027 Agent HTTP helper")
    p.add_argument("--base", default=DEFAULT_BASE, help="Agent Base URL")
    p.add_argument("--timeout", type=float, default=60)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_simple(name: str, help_: str):
        return sub.add_parser(name, help=help_)

    add_simple("health", "GET /api/health")
    add_simple("check-login", "GET /api/checkLogin")
    add_simple("self", "GET /api/contacts/self")
    add_simple("contacts", "GET /api/contacts")
    add_simple("rooms", "GET /api/rooms")
    add_simple("db-names", "GET /api/db/names")
    add_simple("msg-types", "GET /api/message/types")
    add_simple("server-status", "GET /api/server/status")

    c = sub.add_parser("contact", help="GET /api/contact")
    c.add_argument("--id", required=True, dest="contact_id")

    r = sub.add_parser("room", help="GET /api/room")
    r.add_argument("--room-id", required=True)

    rm = sub.add_parser("room-members", help="GET /api/room/members")
    rm.add_argument("--room-id", required=True)

    r1 = sub.add_parser("room-member", help="GET /api/room/member")
    r1.add_argument("--room-id", required=True)
    r1.add_argument("--contact-id", required=True)

    st = sub.add_parser("send-text", help="POST /api/message/text")
    st.add_argument("--to", required=True, help="contactId / roomId")
    st.add_argument("--text", required=True)
    st.add_argument("--at", default="", help="逗号分隔 atWxids；notify@all=@所有人")

    si = sub.add_parser("send-image", help="POST /api/message/image")
    si.add_argument("--to", required=True)
    si.add_argument("--path", required=True)

    sf = sub.add_parser("send-file", help="POST /api/message/file")
    sf.add_argument("--to", required=True)
    sf.add_argument("--path", required=True)

    se = sub.add_parser("send-emotion", help="POST /api/message/emotion")
    se.add_argument("--to", required=True)
    se.add_argument("--path", required=True)

    sr = sub.add_parser("send-rich", help="POST /api/message/richText")
    sr.add_argument("--to", required=True, dest="receiver")
    sr.add_argument("--title", default="")
    sr.add_argument("--url", default="")
    sr.add_argument("--digest", default="")
    sr.add_argument("--thumburl", default="")
    sr.add_argument("--account", default="")
    sr.add_argument("--name", default="")

    pat = sub.add_parser("pat", help="POST /api/message/pat")
    pat.add_argument("--room-id", required=True)
    pat.add_argument("--contact-id", required=True)

    fw = sub.add_parser("forward", help="POST /api/message/forward")
    fw.add_argument("--msg-id", required=True, help="字符串 MsgSvrID")
    fw.add_argument("--to", required=True, dest="receiver")

    au = sub.add_parser("audio", help="POST /api/message/audio")
    au.add_argument("--msg-id", required=True)
    au.add_argument("--dir", required=True)

    ch = sub.add_parser("chat-history", help="GET/POST /api/message/history")
    ch.add_argument("--talker", required=True, help="好友 wxid 或群 ID")
    ch.add_argument("--limit", type=int, default=50)
    ch.add_argument("--offset", type=int, default=0)
    ch.add_argument("--order", choices=["asc", "desc"], default="desc")
    ch.add_argument("--type", type=int, default=None, dest="msg_type")
    ch.add_argument("--from-time", type=int, default=None)
    ch.add_argument("--to-time", type=int, default=None)

    ss = sub.add_parser("sessions", help="GET /api/sessions 会话列表")
    ss.add_argument("--limit", type=int, default=50)
    ss.add_argument("--offset", type=int, default=0)
    ss.add_argument("--include-stranger", action="store_true")

    da = sub.add_parser("download-attach", help="POST /api/message/downloadAttach")
    da.add_argument("--msg-id", required=True)
    da.add_argument("--thumb", default="")
    da.add_argument("--extra", default="")

    di = sub.add_parser("decrypt-image", help="POST /api/message/decryptImage")
    di.add_argument("--src", required=True)
    di.add_argument("--dir", default="")

    ml = sub.add_parser("message-listen", help="消息 Hook 开关/查询")
    ml.add_argument("--enabled", choices=["true", "false", "status"], default="status")

    sl = sub.add_parser("sns-listen", help="朋友圈监听开关/查询")
    sl.add_argument("--enabled", choices=["true", "false", "status"], default="status")

    sn = sub.add_parser("sns-refresh", help="POST /api/sns/refresh")
    sn.add_argument("--id", type=int, default=0)

    ra = sub.add_parser("room-add", help="POST /api/room/add")
    ra.add_argument("--room-id", required=True)
    ra.add_argument("--wxids", required=True)

    ri = sub.add_parser("room-invite", help="POST /api/room/invite")
    ri.add_argument("--room-id", required=True)
    ri.add_argument("--wxids", required=True)

    rd = sub.add_parser("room-del", help="POST /api/room/del")
    rd.add_argument("--room-id", required=True)
    rd.add_argument("--wxids", required=True)

    rt = sub.add_parser("room-topic", help="POST /api/room/topic")
    rt.add_argument("--room-id", required=True)
    rt.add_argument("--topic", required=True)

    dq = sub.add_parser("db-query", help="POST /api/db/query")
    dq.add_argument("--db", required=True, dest="db_name")
    dq.add_argument("--sql", required=True)

    dt = sub.add_parser("db-tables", help="GET /api/db/tables")
    dt.add_argument("--db", required=True, dest="db_name")

    pc = sub.add_parser("push-config", help="推送配置")
    pc.add_argument("--enabled", choices=["true", "false", "status"], default="status")
    pc.add_argument("--callback-url", default="")

    add_simple("server-stop", "POST /api/server/stop")
    add_simple("server-start", "POST /api/server/start")

    g = sub.add_parser("get", help="通用 GET，例: get /api/rooms")
    g.add_argument("path")
    g.add_argument("--query-json", default="", help='查询参数 JSON，如 {"roomId":"x"}')

    po = sub.add_parser("post", help="通用 POST")
    po.add_argument("path")
    po.add_argument("--json", default="{}", help="请求体 JSON object")

    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    base = args.base.rstrip("/")
    timeout = args.timeout
    cmd = args.cmd

    def get(path: str, query: Optional[dict] = None):
        return _req("GET", path, query=query, base=base, timeout=timeout)

    def post(path: str, body: Optional[dict] = None):
        return _req("POST", path, body=body or {}, base=base, timeout=timeout)

    if cmd == "health":
        get("/api/health")
    elif cmd == "check-login":
        get("/api/checkLogin")
    elif cmd == "self":
        get("/api/contacts/self")
    elif cmd == "contacts":
        get("/api/contacts")
    elif cmd == "rooms":
        get("/api/rooms")
    elif cmd == "db-names":
        get("/api/db/names")
    elif cmd == "msg-types":
        get("/api/message/types")
    elif cmd == "server-status":
        get("/api/server/status")
    elif cmd == "contact":
        get("/api/contact", {"contactId": args.contact_id})
    elif cmd == "room":
        get("/api/room", {"roomId": args.room_id})
    elif cmd == "room-members":
        get("/api/room/members", {"roomId": args.room_id})
    elif cmd == "room-member":
        get("/api/room/member", {"roomId": args.room_id, "contactId": args.contact_id})
    elif cmd == "send-text":
        body: dict[str, Any] = {"contactId": args.to, "text": args.text}
        if args.at.strip():
            body["atWxids"] = [x.strip() for x in args.at.split(",") if x.strip()]
        post("/api/message/text", body)
    elif cmd == "send-image":
        post("/api/message/image", {"contactId": args.to, "path": args.path})
    elif cmd == "send-file":
        post("/api/message/file", {"contactId": args.to, "path": args.path})
    elif cmd == "send-emotion":
        post("/api/message/emotion", {"contactId": args.to, "path": args.path})
    elif cmd == "send-rich":
        post(
            "/api/message/richText",
            {
                "receiver": args.receiver,
                "title": args.title,
                "url": args.url,
                "digest": args.digest,
                "thumburl": args.thumburl,
                "account": args.account,
                "name": args.name,
            },
        )
    elif cmd == "pat":
        post("/api/message/pat", {"roomId": args.room_id, "contactId": args.contact_id})
    elif cmd == "forward":
        post("/api/message/forward", {"msgId": str(args.msg_id), "receiver": args.receiver})
    elif cmd == "audio":
        post("/api/message/audio", {"msgId": str(args.msg_id), "dir": args.dir})
    elif cmd == "chat-history":
        body = {
            "talker": args.talker,
            "limit": args.limit,
            "offset": args.offset,
            "order": args.order,
        }
        if args.msg_type is not None:
            body["type"] = args.msg_type
        if args.from_time is not None:
            body["fromTime"] = args.from_time
        if args.to_time is not None:
            body["toTime"] = args.to_time
        post("/api/message/history", body)
    elif cmd == "sessions":
        get(
            "/api/sessions",
            {
                "limit": args.limit,
                "offset": args.offset,
                "includeStranger": "1" if args.include_stranger else None,
            },
        )
    elif cmd == "download-attach":
        post(
            "/api/message/downloadAttach",
            {"msgId": str(args.msg_id), "thumb": args.thumb, "extra": args.extra},
        )
    elif cmd == "decrypt-image":
        post("/api/message/decryptImage", {"src": args.src, "dir": args.dir})
    elif cmd == "message-listen":
        if args.enabled == "status":
            get("/api/message/listen")
        else:
            post("/api/message/listen", {"enabled": args.enabled == "true"})
    elif cmd == "sns-listen":
        if args.enabled == "status":
            get("/api/sns/listen")
        else:
            post("/api/sns/listen", {"enabled": args.enabled == "true"})
    elif cmd == "sns-refresh":
        post("/api/sns/refresh", {"id": args.id})
    elif cmd == "room-add":
        post("/api/room/add", {"roomId": args.room_id, "wxids": args.wxids})
    elif cmd == "room-invite":
        post("/api/room/invite", {"roomId": args.room_id, "wxids": args.wxids})
    elif cmd == "room-del":
        post("/api/room/del", {"roomId": args.room_id, "wxids": args.wxids})
    elif cmd == "room-topic":
        post("/api/room/topic", {"roomId": args.room_id, "topic": args.topic})
    elif cmd == "db-query":
        post("/api/db/query", {"dbName": args.db_name, "sql": args.sql})
    elif cmd == "db-tables":
        get("/api/db/tables", {"dbName": args.db_name})
    elif cmd == "push-config":
        if args.enabled == "status":
            get("/api/push/config")
        else:
            body = {"enabled": args.enabled == "true"}
            if args.callback_url:
                body["callbackUrl"] = args.callback_url
            post("/api/push/config", body)
    elif cmd == "server-stop":
        post("/api/server/stop", {})
    elif cmd == "server-start":
        post("/api/server/start", {})
    elif cmd == "get":
        q = _parse_json_arg(args.query_json) if args.query_json else None
        get(args.path, q)
    elif cmd == "post":
        post(args.path, _parse_json_arg(args.json))
    else:
        raise SystemExit(f"未知命令: {cmd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
