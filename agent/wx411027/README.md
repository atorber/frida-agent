# wx411027 — 微信 4.1.10.27

本目录为 **微信 4.1.10.27**（`Weixin.exe` / `Weixin.dll`）的 Frida Agent。

- HTTP 路由形态对齐 [wx391027](../wx391027/README.md)
- **偏移与原生发送/解码** 来自 [aixed/WeChat-Hook](https://github.com/aixed/WeChat-Hook) 4.1.10.27
- 联系人 / 群 / 会话 / 历史走 4.x 库：`contact.db`、`session.db`、`message_N.db`（无旧版 `MicroMsg.db`）
- 总览与其它版本：[仓库根 README](../../README.md)

默认 HTTP：`http://127.0.0.1:19088`  
统一响应：`{ "code": 1, "data": ..., "msg": "success" }`（`code=0` 失败 / 未实现）

## 使用方式

```bash
cd agent
npm install
npm run build:wx411027
```

注入（推荐 Python Frida，避免 Node 绑定 ABI 不匹配）：

```bash
python wx411027/tools/run_agent.py
# 可选：注入后发一条到文件传输助手
python wx411027/tools/run_agent.py --send
```

或：`npm run start:wx411027`（依赖本机 Node `frida` 可用）。

探活与发送示例（仓库根目录，Agent 已在跑）：

```bash
python skills/wx-helper/scripts/wx_api.py health
python skills/wx-helper/scripts/wx_api.py send-text --to filehelper --text "hello"
python skills/wx-helper/scripts/wx_api.py send-image --to filehelper --path "C:\path\to\a.jpg"
```

优雅停止：`POST /api/server/stop`，或脚本退出时会尝试关闭监听。

## 能力概览

| 功能 | 来源 | 接口 |
|--|--|--|
| 发文本 | aixed `SendText` | `POST /api/message/text` |
| 发图片 | aixed `SendImage` | `POST /api/message/image` |
| 解码图片 | aixed `DecodePic` | `POST /api/message/decryptImage` |
| 转发 XML | aixed `ForwardXMLMsg` 逻辑已移植 | `POST /api/message/forward`、`/ForwardXMLMsg`（**偏移待校准**，见下） |
| 登录状态 / 自己 | `contact.db` 路径 + contact 行 | `GET /api/checkLogin`、`/api/contacts/self` |
| 联系人 / 群 / 成员 | `contact.db`（contact / chat_room / name2id） | `/api/contacts`、`/api/rooms`、`/api/room/members` |
| 数据库 | aixed SQLITE3_API_ROUTINES + VFS 扫描 | `/api/db/*` |
| 聊天记录 / 会话 | `message_N.db`（`Msg_{md5}`）/ `session.db` | `/api/message/history`、`/api/sessions` |
| 发文件 / 拍一拍 / 按 msgId 转发 / 收消息 Hook / SNS / 群管理 | aixed 未提供 | 见下方「未实现」 |

与 `wx391027` 相比：本版本**没有**收消息推送、文件发送、拍一拍、按 msgId 转发、朋友圈、群管理等。

**XML 转发说明**：代码已按 aixed `wx_send_xml.cpp` 接好（`/ForwardXMLMsg`），但 aixed `global.h` 里 `Offsets` 明确标注为 **4.1.5.30**。在当前 **4.1.10.27** `Weixin.dll` 上这些虚表地址非法，调用会被安全拦截并返回错误（避免崩溃）。校准偏移后即可直接启用。

## HTTP 接口

### 可用

| 方法 | 路径 | 说明 |
|--|--|--|
| GET | `/api/health` 或 `/` | 健康检查 / 能力列表 |
| GET | `/api/server/status` | HTTP 服务状态 |
| POST | `/api/server/start` | 重新开启监听 |
| POST | `/api/server/stop` | 关闭监听（不杀微信） |
| GET | `/api/checkLogin` | 登录状态（`1` / `-1`） |
| GET | `/api/contacts/self` | 自己资料 |
| GET | `/api/contacts` | 联系人列表（`local_type=1` 好友） |
| GET | `/api/contact?id=` | 单个联系人 |
| GET | `/api/rooms` | 群列表 |
| GET | `/api/room?roomId=` | 单个群 |
| GET | `/api/room/members?roomId=` | 群成员 wxid 列表 |
| GET | `/api/room/member?roomId=&contactId=` | 单个群成员 |
| GET | `/api/message/types` | 消息类型常量 |
| POST | `/api/message/text` | 发文本：`{ contactId, text, atWxids? }` |
| POST | `/api/message/image` | 发图片：`{ contactId, path }` |
| POST | `/api/message/decryptImage` | 解码图片：`{ src, dst }` |
| POST | `/api/message/forward` | 转发 XML：`{ to_wxid\|contactId, content\|xml }`（img/videomsg/emoji） |
| GET/POST | `/api/message/history` | 聊天记录：`talker` + `limit?` |
| GET/POST | `/api/sessions` | 会话列表：`limit?` |
| GET | `/api/db/names` | 已打开 DB 名 |
| GET | `/api/db/info` | DB 名 + 句柄 |
| GET | `/api/db/tables?dbName=` | 表结构 |
| POST | `/api/db/query` | 执行 SQL：`{ dbName, sql }` |

### aixed 路径别名

| 方法 | 路径 | 说明 |
|--|--|--|
| POST | `/SendTextMsg` | 发文本（`wxidorgid`/`contactId` + `msg`/`text`） |
| POST | `/SendImgMsg` | 发图片 |
| POST | `/Decode_Pic` | 解码图片（`src_path` / `dst_path`） |
| POST | `/ForwardXMLMsg` | 转发 XML（`to_wxid` + `content`） |
| POST | `/GetSelfProfile` | 自己资料 |
| GET | `/QueryDB/status` | 登录状态 + DLL base |
| POST | `/QueryDB/GetAllDBName` | 同 `/api/db/info` |
| POST | `/QueryDB/execute` | 同 `/api/db/query`（`optDbName` + `SQL`） |

### 未实现（占位，返回 `code=0`）

| 方法 | 路径 |
|--|--|
| POST | `/api/message/file` |
| POST | `/api/message/pat` |
| POST | `/api/message/richText` |
| POST | `/api/message/emotion` |
| POST | `/api/message/downloadAttach` |
| POST | `/api/message/audio` |
| GET | `/api/message/listen` |
| POST | `/api/sns/refresh` |
| GET | `/api/sns/listen` |
| GET/POST | `/api/push/config` |
| POST | `/api/room/add` |
| POST | `/api/room/invite` |
| POST | `/api/room/del` |
| POST | `/api/room/topic` |
