---
name: wx-helper
description: >-
  通过本仓库 wx391027 Frida Agent（HTTP :19088）操作微信：发消息、查联系人/群成员、
  转发、媒体下载、朋友圈、数据库查询、推送配置与服务启停。
  在用户提到用 agent 发微信、操作微信、群成员、朋友圈、19088、wx391027、Frida 微信助手时使用。
---

# wx-helper

通过 **已注入的** wx391027 Agent HTTP API 操作微信。优先跑 `scripts/wx_api.py`，不要在 PowerShell 里用 bash 风格 `curl`/`BASE=`。

## 前置条件

1. 微信 3.9.10.27 已登录；Agent 已启动：`cd agent && npm run start`
2. 先探活：

```bash
python skills/wx-helper/scripts/wx_api.py health
```

- 成功：`code=1`
- 连不上：提示用户先启动 Agent；**不要**擅自杀微信进程
- Base URL 可用环境变量：`WX_AGENT_BASE`（默认 `http://127.0.0.1:19088`）

详细接口见 [references/api.md](references/api.md)；HTTP 全文见 `agent/wx391027/README.md`。

## 强制约定

| 规则 | 说明 |
|--|--|
| `msgId` | **永远用字符串**，禁止 JS/JSON number（大整数丢精度） |
| 本地路径 | 绝对路径；Windows 传给 API 时用 `C:\\a\\b.jpg` 这种转义 |
| 响应 | `code=1` 成功，`code=0` 失败；把 `msg`/`data` 摘要给用户 |
| 工具 | 优先 `wx_api.py`；通用缺口用 `get` / `post` 子命令 |
| 退出监听 | 优雅停 HTTP 用 `server-stop`，不要 kill 微信 |

## 工作流

```
任务进度:
- [ ] 1. health / check-login
- [ ] 2. 解析目标（wxid / 群 ID / 路径 / msgId）
- [ ] 3. 执行对应子命令
- [ ] 4. 根据 code 汇报结果
```

查人/群不确定时：`contacts` / `rooms` / `room-members` 先搜，再操作。

## 常用命令

在仓库根目录执行（或把路径换成绝对路径）：

```bash
# 账号
python skills/wx-helper/scripts/wx_api.py check-login
python skills/wx-helper/scripts/wx_api.py self

# 联系人 / 群
python skills/wx-helper/scripts/wx_api.py contacts
python skills/wx-helper/scripts/wx_api.py contact --id filehelper
python skills/wx-helper/scripts/wx_api.py rooms
python skills/wx-helper/scripts/wx_api.py room --room-id 21341182572@chatroom
python skills/wx-helper/scripts/wx_api.py room-members --room-id 21341182572@chatroom

# 发消息
python skills/wx-helper/scripts/wx_api.py send-text --to filehelper --text "hello"
python skills/wx-helper/scripts/wx_api.py send-text --to 21341182572@chatroom --text "请看" --at wxid_xxx
python skills/wx-helper/scripts/wx_api.py send-text --to 21341182572@chatroom --text "全体" --at notify@all
python skills/wx-helper/scripts/wx_api.py send-image --to filehelper --path "C:\GitHub\frida-agent\agent\1.jpg"
python skills/wx-helper/scripts/wx_api.py send-file --to filehelper --path "C:\path\a.pdf"
python skills/wx-helper/scripts/wx_api.py send-emotion --to filehelper --path "C:\path\a.gif"
python skills/wx-helper/scripts/wx_api.py forward --msg-id 8233065081616396038 --to filehelper
python skills/wx-helper/scripts/wx_api.py pat --room-id 21341182572@chatroom --contact-id wxid_xxx

# 媒体
python skills/wx-helper/scripts/wx_api.py audio --msg-id 1234567890123456 --dir "C:\temp\voice"
python skills/wx-helper/scripts/wx_api.py chat-history --talker wxxxx --limit 20
python skills/wx-helper/scripts/wx_api.py download-attach --msg-id 123 --extra "C:\temp\out.jpg"
python skills/wx-helper/scripts/wx_api.py decrypt-image --src "C:\path\a.dat" --dir "C:\temp"

# 监听 / 朋友圈 / 推送
python skills/wx-helper/scripts/wx_api.py message-listen --enabled true
python skills/wx-helper/scripts/wx_api.py sns-listen --enabled true
python skills/wx-helper/scripts/wx_api.py sns-refresh --id 0
python skills/wx-helper/scripts/wx_api.py push-config --enabled true --callback-url http://127.0.0.1:3000/wx-callback

# 群管理 / DB
python skills/wx-helper/scripts/wx_api.py room-add --room-id RID --wxids wxid_a,wxid_b
python skills/wx-helper/scripts/wx_api.py db-query --db MicroMsg.db --sql "SELECT UserName,NickName FROM Contact LIMIT 5;"

# 服务
python skills/wx-helper/scripts/wx_api.py server-stop
python skills/wx-helper/scripts/wx_api.py server-start

# 通用
python skills/wx-helper/scripts/wx_api.py get /api/db/names
python skills/wx-helper/scripts/wx_api.py post /api/message/richText --json "{\"receiver\":\"filehelper\",\"title\":\"t\",\"url\":\"https://example.com\"}"
```

Windows PowerShell 注意：若要用 curl，必须 `curl.exe`，且变量用 `$BASE = "..."`。

## 场景映射

| 用户意图 | 命令 |
|--|--|
| 微信登了没 / 我是谁 | `check-login` / `self` |
| 发文字/图片/文件/表情 | `send-text` / `send-image` / `send-file` / `send-emotion` |
| @群成员 / @所有人 | `send-text --at ...` / `--at notify@all` |
| 转发某条消息 | `forward --msg-id <字符串>` |
| 查群成员 | `room-members` |
| 查聊天记录 | `chat-history --talker <wxid>` |
| 导出语音 | `audio` |
| 开消息回调 | `message-listen` + `push-config` |
| 关 HTTP 不杀微信 | `server-stop` |

## 启动 Agent（仅用户明确要求时）

```bash
cd agent
npm run start
# Ctrl+C：start.js 会先停 HTTP 再卸载
```

需要 REPL：`npm run start:wx391027:repl`（退出前应 `server-stop`）。
