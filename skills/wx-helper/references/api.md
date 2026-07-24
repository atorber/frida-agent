# wx391027 Agent API 速查

Base: `http://127.0.0.1:19088`（或 `WX_AGENT_BASE`）  
响应: `{ "code": 1|0, "data": ..., "msg": "..." }`

完整说明与 curl 示例见 `agent/wx391027/README.md`。Postman：`agent/wx391027/wx391027.postman_collection.json`。

## 端点一览

### 服务

| Method | Path | 说明 |
|--|--|--|
| GET | `/api/health` | 健康检查 / API 列表 |
| GET | `/api/server/status` | 监听是否关闭 |
| POST | `/api/server/stop` | 释放端口，不杀微信 |
| POST | `/api/server/start` | 重新监听 |

### 账号 / 联系人 / 群

| Method | Path | 参数 |
|--|--|--|
| GET | `/api/checkLogin` | — |
| GET | `/api/contacts/self` | — |
| GET | `/api/contacts` | — |
| GET | `/api/contact` | `contactId` |
| GET | `/api/rooms` | — |
| GET | `/api/room` | `roomId` |
| GET | `/api/room/members` | `roomId` |
| GET | `/api/room/member` | `roomId`, `contactId` |
| POST | `/api/room/add` | `roomId`, `wxids` |
| POST | `/api/room/invite` | `roomId`, `wxids` |
| POST | `/api/room/del` | `roomId`, `wxids` |
| POST | `/api/room/topic` | `roomId`, `topic` |

### 消息

| Method | Path | Body 要点 |
|--|--|--|
| POST | `/api/message/text` | `contactId`, `text`, 可选 `atWxids[]` |
| POST | `/api/message/image` | `contactId`, `path` |
| POST | `/api/message/file` | `contactId`, `path` |
| POST | `/api/message/emotion` | `contactId`, `path`（>500KB 改文件发送） |
| POST | `/api/message/richText` | `receiver`, `title`, `url`, … |
| POST | `/api/message/pat` | `roomId`, `contactId` |
| POST | `/api/message/forward` | `msgId`(**string**), `receiver` |
| GET | `/api/message/types` | — |
| GET/POST | `/api/message/listen` | POST: `enabled` |

### 媒体

| Method | Path | Body 要点 |
|--|--|--|
| POST | `/api/message/downloadAttach` | `msgId`, `thumb?`, `extra?` |
| POST | `/api/message/decryptImage` | `src`, `dir?` |
| POST | `/api/message/audio` | `msgId`, `dir` → 优先 mp3 |
| GET/POST | `/api/message/history` | `talker`/`contactId`, `limit?`, `offset?`, `order?`, `type?` |
| POST | `/api/message/downloadFinderVideo` | `url`, `msgId?`, `savePath?` |

收消息后 Agent 可自动：图片下载+解密、视频/文件下载、语音导出转 mp3。

### 朋友圈 / DB / 推送

| Method | Path | 参数 |
|--|--|--|
| GET/POST | `/api/sns/listen` | POST: `enabled` |
| POST | `/api/sns/refresh` | `id`（0=首页） |
| GET | `/api/db/names` | — |
| GET | `/api/db/tables` | `dbName` |
| POST | `/api/db/query` | `dbName`, `sql` |
| GET/POST | `/api/push/config` | POST: `enabled`, `callbackUrl?` |

## wx_api.py 子命令 ↔ 端点

见 `python skills/wx-helper/scripts/wx_api.py -h`。未封装的用：

```bash
python skills/wx-helper/scripts/wx_api.py get /api/...
python skills/wx-helper/scripts/wx_api.py post /api/... --json "{...}"
```
