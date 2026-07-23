## 功能清单

|功能|是否支持|说明|
|--|--|--|
|查询登录状态|Y|`GET /api/checkLogin`|
|获取登录账号信息|Y|`GET /api/contacts/self`|
|获取消息类型|Y|`GET /api/message/types`|
|获取联系人|Y|`GET /api/contacts`、`GET /api/contact`|
|获取群列表|Y|`GET /api/rooms`|
|获取群详情|Y|`GET /api/room?roomId=xxx`|
|获取可查询数据库|Y|`GET /api/db/names`|
|获取数据库所有表|Y|`GET /api/db/tables?dbName=xxx`|
|获取语音消息|Y|`POST /api/message/audio`（导出 silk；无内置 silk→mp3）|
|发送文本消息|Y|`POST /api/message/text`|
|发送@文本消息|Y|`POST /api/message/text`，`atWxids`|
|发送图片消息|Y|`POST /api/message/image`|
|发送文件消息|Y|`POST /api/message/file`|
|发送卡片消息|Y|`POST /api/message/richText`|
|发送表情/GIF|Y|`POST /api/message/emotion`|
|拍一拍群友|Y|`POST /api/message/pat`|
|转发消息|Y|`POST /api/message/forward`|
|开启/关闭接收消息|Y|`GET\|POST /api/message/listen`|
|查询数据库|Y|`POST /api/db/query`|
|朋友圈接收|Y|`GET\|POST /api/sns/listen`|
|刷新朋友圈|Y|`POST /api/sns/refresh`（需先开启 listen）|
|下载图片、视频、文件|Y|`POST /api/message/downloadAttach`|
|解密图片|Y|`POST /api/message/decryptImage`|
|添加群成员|Y|`POST /api/room/add`|
|删除群成员|Y|`POST /api/room/del`|
|邀请群成员|Y|`POST /api/room/invite`|
|修改群名|Y|`POST /api/room/topic`|
|消息推送|Y|`GET\|POST /api/push/config`|
|视频号视频下载|Y|`POST /api/message/downloadFinderVideo`|

### 与 WCF 对齐说明

- 已对齐 WCF 3.9.10.27 **实际可用**能力。
- WCF 自身未实现/已禁用项（发 XML、通过好友、收款、OCR、撤回、扫码 URL）未迁移。
- 语音：Frida 环境无 `Codec.lib`，`getAudio` 导出 `.silk`；若目录已有同名 `.mp3` 则直接返回。

---

## HTTP 接口文档

### 基础信息

| 项 | 值 |
|--|--|
| Base URL | `http://127.0.0.1:19088` |
| Content-Type | `application/json`（POST 请求体） |
| 统一响应 | `{ "code": 1, "data": ..., "msg": "success" }`，`code=0` 表示失败 |

下方示例统一使用：

```bash
BASE=http://127.0.0.1:19088
```

Windows 路径在 JSON 中需转义反斜杠，例如 `"C:\\\\Users\\\\me\\\\a.jpg"`。

也可访问 `GET $BASE/api/health` 查看当前已注册路径列表。

---

### 1. 健康检查

**`GET /api/health`**（或 `GET /`）

无参数。

```bash
curl "$BASE/api/health"
```

---

### 2. 登录 / 账号

#### 2.1 查询登录状态

**`GET /api/checkLogin`**

无参数。`data` 一般为 `1`（已登录）或 `-1`（未登录）。

```bash
curl "$BASE/api/checkLogin"
```

#### 2.2 获取自己的账号信息

**`GET /api/contacts/self`**

无参数。

```bash
curl "$BASE/api/contacts/self"
```

---

### 3. 联系人

#### 3.1 联系人列表

**`GET /api/contacts`**

无参数。

```bash
curl "$BASE/api/contacts"
```

#### 3.2 联系人详情

**`GET /api/contact`**

| 参数 | 位置 | 必填 | 说明 |
|--|--|--|--|
| `contactId` | Query | 是 | 微信 ID，如 `wxid_xxx` / `filehelper` |

```bash
curl "$BASE/api/contact?contactId=filehelper"
```

---

### 4. 群聊

#### 4.1 群列表

**`GET /api/rooms`**

无参数。

```bash
curl "$BASE/api/rooms"
```

#### 4.2 群详情

**`GET /api/room`**

| 参数 | 位置 | 必填 | 说明 |
|--|--|--|--|
| `roomId` | Query | 是 | 群 ID，如 `123456@chatroom` |

```bash
curl "$BASE/api/room?roomId=12345678901@chatroom"
```

#### 4.3 添加群成员（40 人以下群）

**`POST /api/room/add`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `roomId` | string | 是 | 群 ID |
| `wxids` | string | 是 | 成员 wxid，多个用英文逗号分隔 |

```bash
curl -X POST "$BASE/api/room/add" \
  -H "Content-Type: application/json" \
  -d "{\"roomId\":\"12345678901@chatroom\",\"wxids\":\"wxid_aaa,wxid_bbb\"}"
```

#### 4.4 邀请群成员（40 人以上群）

**`POST /api/room/invite`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `roomId` | string | 是 | 群 ID |
| `wxids` | string | 是 | 成员 wxid，逗号分隔 |

```bash
curl -X POST "$BASE/api/room/invite" \
  -H "Content-Type: application/json" \
  -d "{\"roomId\":\"12345678901@chatroom\",\"wxids\":\"wxid_aaa\"}"
```

#### 4.5 删除群成员

**`POST /api/room/del`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `roomId` | string | 是 | 群 ID |
| `wxids` | string | 是 | 成员 wxid，逗号分隔 |

```bash
curl -X POST "$BASE/api/room/del" \
  -H "Content-Type: application/json" \
  -d "{\"roomId\":\"12345678901@chatroom\",\"wxids\":\"wxid_aaa\"}"
```

#### 4.6 修改群名

**`POST /api/room/topic`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `roomId` | string | 是 | 群 ID |
| `topic` | string | 是 | 新群名 |

```bash
curl -X POST "$BASE/api/room/topic" \
  -H "Content-Type: application/json" \
  -d "{\"roomId\":\"12345678901@chatroom\",\"topic\":\"新群名称\"}"
```

---

### 5. 消息发送

#### 5.1 发送文本 / @

**`POST /api/message/text`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `contactId` | string | 是 | 接收人 wxid 或群 ID |
| `text` | string | 是 | 文本内容 |
| `atWxids` | string[] | 否 | 群聊 @ 列表；`notify@all` 表示 @所有人 |

```bash
# 私聊 / 文件传输助手
curl -X POST "$BASE/api/message/text" \
  -H "Content-Type: application/json" \
  -d "{\"contactId\":\"filehelper\",\"text\":\"hello from agent\"}"

# 群聊 @指定人
curl -X POST "$BASE/api/message/text" \
  -H "Content-Type: application/json" \
  -d "{\"contactId\":\"12345678901@chatroom\",\"text\":\"请看一下\",\"atWxids\":[\"wxid_aaa\"]}"

# 群聊 @所有人
curl -X POST "$BASE/api/message/text" \
  -H "Content-Type: application/json" \
  -d "{\"contactId\":\"12345678901@chatroom\",\"text\":\"全体注意\",\"atWxids\":[\"notify@all\"]}"
```

#### 5.2 发送图片

**`POST /api/message/image`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `contactId` | string | 是 | 接收人 / 群 |
| `path` | string | 是 | 本地图片绝对路径 |

```bash
curl -X POST "$BASE/api/message/image" \
  -H "Content-Type: application/json" \
  -d "{\"contactId\":\"filehelper\",\"path\":\"C:\\\\GitHub\\\\frida-agent\\\\agent\\\\1.jpg\"}"
```

#### 5.3 发送文件

**`POST /api/message/file`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `contactId` | string | 是 | 接收人 / 群 |
| `path` | string | 是 | 本地文件绝对路径 |

```bash
curl -X POST "$BASE/api/message/file" \
  -H "Content-Type: application/json" \
  -d "{\"contactId\":\"filehelper\",\"path\":\"C:\\\\temp\\\\demo.pdf\"}"
```

#### 5.4 发送表情 / GIF

**`POST /api/message/emotion`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `contactId` | string | 是 | 接收人 / 群 |
| `path` | string | 是 | 本地 gif/表情文件路径 |

```bash
curl -X POST "$BASE/api/message/emotion" \
  -H "Content-Type: application/json" \
  -d "{\"contactId\":\"filehelper\",\"path\":\"C:\\\\temp\\\\funny.gif\"}"
```

#### 5.5 发送链接卡片

**`POST /api/message/richText`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `receiver` | string | 是 | 接收人 / 群 |
| `title` | string | 否 | 标题 |
| `url` | string | 否 | 跳转链接 |
| `digest` | string | 否 | 摘要 |
| `thumburl` | string | 否 | 缩略图 URL |
| `account` | string | 否 | 公众号 id |
| `name` | string | 否 | 显示名称 |

```bash
curl -X POST "$BASE/api/message/richText" \
  -H "Content-Type: application/json" \
  -d "{\"receiver\":\"filehelper\",\"title\":\"示例标题\",\"url\":\"https://example.com\",\"digest\":\"这是摘要\",\"thumburl\":\"https://example.com/thumb.png\",\"account\":\"\",\"name\":\"示例号\"}"
```

#### 5.6 拍一拍

**`POST /api/message/pat`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `roomId` | string | 是 | 群 ID |
| `contactId` | string | 是 | 被拍成员 wxid |

```bash
curl -X POST "$BASE/api/message/pat" \
  -H "Content-Type: application/json" \
  -d "{\"roomId\":\"12345678901@chatroom\",\"contactId\":\"wxid_aaa\"}"
```

#### 5.7 转发消息

**`POST /api/message/forward`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `msgId` | number/string | 是 | 消息 MsgSvrID |
| `receiver` | string | 是 | 转发目标（wxid 或群 ID） |

```bash
curl -X POST "$BASE/api/message/forward" \
  -H "Content-Type: application/json" \
  -d "{\"msgId\":1234567890123456,\"receiver\":\"filehelper\"}"
```

---

### 6. 媒体 / 附件

#### 6.1 下载附件（图片 / 视频 / 文件）

**`POST /api/message/downloadAttach`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `msgId` | number/string | 是 | 消息 ID |
| `thumb` | string | 否 | 缩略图路径（视频常用） |
| `extra` | string | 否 | 图片/文件保存路径 |

```bash
curl -X POST "$BASE/api/message/downloadAttach" \
  -H "Content-Type: application/json" \
  -d "{\"msgId\":1234567890123456,\"thumb\":\"\",\"extra\":\"C:\\\\temp\\\\out.jpg\"}"
```

#### 6.2 解密图片（`.dat` XOR）

**`POST /api/message/decryptImage`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `src` | string | 是 | 加密图片源路径 |
| `dir` | string | 否 | 输出目录；空则同目录换扩展名 |

```bash
curl -X POST "$BASE/api/message/decryptImage" \
  -H "Content-Type: application/json" \
  -d "{\"src\":\"C:\\\\Users\\\\me\\\\Documents\\\\WeChat Files\\\\xxx\\\\FileStorage\\\\MsgAttach\\\\a.dat\",\"dir\":\"C:\\\\temp\"}"
```

#### 6.3 导出语音

**`POST /api/message/audio`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `msgId` | number/string | 是 | 语音消息 ID |
| `dir` | string | 是 | 保存目录 |

成功时 `data` 为文件路径（优先已有 `.mp3`，否则 `.silk`）。

```bash
curl -X POST "$BASE/api/message/audio" \
  -H "Content-Type: application/json" \
  -d "{\"msgId\":1234567890123456,\"dir\":\"C:\\\\temp\\\\voice\"}"
```

#### 6.4 下载视频号视频

**`POST /api/message/downloadFinderVideo`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `url` | string | 是 | 视频直链 |
| `msgId` | string | 否 | 用于默认文件名 |
| `savePath` | string | 否 | 自定义保存路径 |

异步下载，立即返回 `{ savePath, status: "downloading" }`。

```bash
curl -X POST "$BASE/api/message/downloadFinderVideo" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://finder.video.qq.com/xxx.mp4\",\"msgId\":\"123\",\"savePath\":\"C:\\\\temp\\\\finder.mp4\"}"
```

---

### 7. 消息接收控制

#### 7.1 消息类型表

**`GET /api/message/types`**

无参数。

```bash
curl "$BASE/api/message/types"
```

#### 7.2 开启 / 关闭聊天消息 Hook

**`GET /api/message/listen`**：查询当前状态  
**`POST /api/message/listen`**：开关

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `enabled` | boolean | POST 时建议传 | `true` 开启，`false` 关闭；缺省按开启处理 |

```bash
# 查询
curl "$BASE/api/message/listen"

# 开启
curl -X POST "$BASE/api/message/listen" \
  -H "Content-Type: application/json" \
  -d "{\"enabled\":true}"

# 关闭
curl -X POST "$BASE/api/message/listen" \
  -H "Content-Type: application/json" \
  -d "{\"enabled\":false}"
```

---

### 8. 朋友圈

#### 8.1 开启 / 关闭朋友圈接收

**`GET /api/sns/listen`** / **`POST /api/sns/listen`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `enabled` | boolean | POST 时建议传 | `true` 开启，`false` 关闭 |

```bash
curl "$BASE/api/sns/listen"

curl -X POST "$BASE/api/sns/listen" \
  -H "Content-Type: application/json" \
  -d "{\"enabled\":true}"

curl -X POST "$BASE/api/sns/listen" \
  -H "Content-Type: application/json" \
  -d "{\"enabled\":false}"
```

#### 8.2 刷新朋友圈

**`POST /api/sns/refresh`**

需先开启 `/api/sns/listen`。

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `id` | number | 否 | `0` 或省略=第一页；非 0=下一页锚点 |

```bash
curl -X POST "$BASE/api/sns/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"id\":0}"
```

---

### 9. 数据库

#### 9.1 数据库名列表

**`GET /api/db/names`**

```bash
curl "$BASE/api/db/names"
```

#### 9.2 表列表

**`GET /api/db/tables`**

| 参数 | 位置 | 必填 | 说明 |
|--|--|--|--|
| `dbName` | Query | 是 | 如 `MicroMsg.db` |

```bash
curl "$BASE/api/db/tables?dbName=MicroMsg.db"
```

#### 9.3 执行查询

**`POST /api/db/query`**

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `dbName` | string | 是 | 数据库名 |
| `sql` | string | 是 | SQL（建议只读查询） |

```bash
curl -X POST "$BASE/api/db/query" \
  -H "Content-Type: application/json" \
  -d "{\"dbName\":\"MicroMsg.db\",\"sql\":\"SELECT UserName,NickName FROM Contact WHERE NickName!=\\\"\\\" LIMIT 5;\"}"
```

---

### 10. 消息推送回调

**`GET /api/push/config`**：查询配置  
**`POST /api/push/config`**：设置配置

| 参数 | 类型 | 必填 | 说明 |
|--|--|--|--|
| `enabled` | boolean | POST 必填 | 是否开启推送 |
| `callbackUrl` | string | 开启时必填 | 完整 URL，如 `http://127.0.0.1:3000/hook` |

开启后，收到消息会向 `callbackUrl` POST JSON（Message 对象）。

```bash
# 查询
curl "$BASE/api/push/config"

# 开启推送
curl -X POST "$BASE/api/push/config" \
  -H "Content-Type: application/json" \
  -d "{\"enabled\":true,\"callbackUrl\":\"http://127.0.0.1:3000/wx-callback\"}"

# 关闭推送
curl -X POST "$BASE/api/push/config" \
  -H "Content-Type: application/json" \
  -d "{\"enabled\":false}"
```

---

### 响应示例

成功：

```json
{
  "code": 1,
  "data": 1,
  "msg": "success"
}
```

失败：

```json
{
  "code": 0,
  "data": null,
  "msg": "参数错误: 需要 contactId 和 text"
}
```
