# WCF vs agent/wx391027 功能差距分析报告

> 对比基准：`wcf/WeChatFerry-3.9.10.27`（与 agent 目标版本一致）  
> 对照目标：`agent/wx391027`  
> 参考日期：2026-07-23  
> 说明：3.9.12.17 的 proto API 集合与 3.9.10.27 基本一致，本报告以 3.9.10.27 源码为准。

---

## 1. 结论摘要

`agent/wx391027` 已覆盖 WCF 的**核心链路**（登录、联系人、群列表、文本/图片/文件/@、拍一拍、转发、SQLite、消息 Hook），并在部分能力上**超出** WCF（HTTP API、消息推送、AppMsg/视频号解析与下载）。

当前主要差距不在「完全缺失」，而在三类问题：

1. **WCF 已有且可用，agent 未实现或实现不完整**（如发送卡片/表情、图片解密落地、语音导出）。
2. **agent 底层已有实现，但未接到 HTTP/RPC 出口**（如群成员增删邀、附件下载、朋友圈刷新）。
3. **双方都未真正可用**（OCR、撤回、收款、扫码登录 URL、发送 XML 等），优先级应靠后。

建议优先做「可落地集成」：补齐发送能力 + 暴露已有 API + 完善媒体处理。

---

## 2. 对比方法与资料来源

| 来源 | 用途 |
|------|------|
| `wcf/.../rpc/proto/wcf.proto` | WCF 对外能力清单（Functions 枚举） |
| `wcf/.../spy/*.cpp|*.h` | 实际实现状态（含 `#if 0` 禁用项） |
| `agent/wx391027/*.ts` | agent 函数实现与 stub |
| `agent/wx391027/index.ts` | HTTP API / rpc.exports 暴露面 |
| `agent/wx391027/README.md` / `docs/api-reference.md` | 既有文档声明 |

状态标记：

- **Y**：已实现且可用
- **P**：部分实现 / 代码存在但不完整或未出口
- **N**：未实现或空 stub
- **X**：协议/接口存在，但源码明确禁用或空实现（双方均不宜优先）

---

## 3. WCF 功能清单与实现真相

### 3.1 Proto 声明的全部 Functions

| Func | 名称 | WCF 实现状态 | 说明 |
|------|------|--------------|------|
| 0x01 | IS_LOGIN | Y | `IsLogin()` |
| 0x10 | GET_SELF_WXID | Y | |
| 0x11 | GET_MSG_TYPES | Y | 静态类型表 |
| 0x12 | GET_CONTACTS | Y | |
| 0x13 | GET_DB_NAMES | Y | |
| 0x14 | GET_DB_TABLES | Y | |
| 0x15 | GET_USER_INFO | Y | wxid/name/mobile/home |
| 0x16 | GET_AUDIO_MSG | Y | DB 取 silk + `Silk2Mp3` |
| 0x20 | SEND_TXT | Y | 支持 at |
| 0x21 | SEND_IMG | Y | |
| 0x22 | SEND_FILE | Y | |
| 0x23 | SEND_XML | X | `#if 0` 禁用 |
| 0x24 | SEND_EMOTION | Y | GIF/表情 |
| 0x25 | SEND_RICH_TXT | Y | 链接卡片 |
| 0x26 | SEND_PAT_MSG | Y | |
| 0x27 | FORWARD_MSG | Y | |
| 0x30 | ENABLE_RECV_TXT | Y | Hook + 可选 ListenPyq |
| 0x40 | DISABLE_RECV_TXT | Y | UnListen |
| 0x50 | EXEC_DB_QUERY | Y | |
| 0x51 | ACCEPT_FRIEND | X | `#if 0`（旧 32 位 asm） |
| 0x52 | RECV_TRANSFER | X | 明确不实现 |
| 0x53 | REFRESH_PYQ | Y | 依赖先 ListenPyq |
| 0x54 | DOWNLOAD_ATTACH | Y | 图片/视频/文件 |
| 0x55 | GET_CONTACT_INFO | X | `#if 0` |
| 0x56 | REVOKE_MSG | X | stub |
| 0x57 | REFRESH_QRCODE | X | `GetLoginUrl` 假实现 |
| 0x60 | DECRYPT_IMAGE | Y | XOR 解 `.dat` |
| 0x61 | EXEC_OCR | X | `#if 0`，参数未调通 |
| 0x70 | ADD_ROOM_MEMBERS | Y | |
| 0x71 | DEL_ROOM_MEMBERS | Y | |
| 0x72 | INV_ROOM_MEMBERS | Y | |

### 3.2 WCF 模块结构（便于对照移植）

```
spy/
├── user_info.*          # 登录态 / 账号 / HomePath
├── contact_mgmt.*       # 联系人列表、通过好友(禁用)
├── chatroom_mgmt.*      # 加/删/邀群成员
├── send_msg.*           # 文本/图/文件/卡片/表情/拍一拍/转发
├── receive_msg.*        # 消息 Hook、朋友圈 Hook、消息类型表
├── exec_sql.*           # DB 句柄、查询、localId
├── funcs.*              # 解密图、附件下载、语音、朋友圈刷新、OCR/撤回 stub
└── rpc_server.*         # nanopb RPC 出口
```

---

## 4. agent/wx391027 已实现能力

### 4.1 已实现并已暴露（HTTP / rpc.exports）

| 能力 | 入口 | 对应 WCF |
|------|------|----------|
| 登录状态 | `GET /api/checkLogin` | IS_LOGIN |
| 自己信息 | `GET /api/contacts/self` | GET_USER_INFO |
| 联系人列表/详情 | `/api/contacts`, `/api/contact` | GET_CONTACTS |
| 群列表/详情 | `/api/rooms`, `/api/room` | （WCF 无独立群 API，靠联系人过滤） |
| 发文本/@ | `POST /api/message/text` | SEND_TXT |
| 发图片 | `POST /api/message/image` | SEND_IMG |
| 发文件 | `POST /api/message/file` | SEND_FILE |
| 拍一拍 | `POST /api/message/pat` | SEND_PAT_MSG |
| 转发 | `POST /api/message/forward` | FORWARD_MSG |
| DB 名/表/查询 | `/api/db/*` | GET_DB_* / EXEC_DB_QUERY |
| 消息接收 | Hook `kDoAddMsg` 自动开启 | ENABLE_RECV_TXT |
| 消息推送回调 | `/api/push/config` | （WCF 无 HTTP 推送） |
| 视频号下载 | `/api/message/downloadFinderVideo` | （WCF 无） |

### 4.2 已有底层实现，但未充分出口 / 不完整

| 函数 | 文件 | 状态 | 说明 |
|------|------|------|------|
| `roomAdd` / `roomInvite` / `roomDel` | `room.ts` | P | 逻辑有，HTTP/RPC 未暴露；Invite 参数结构简化过，多人逗号分隔需对照 WCF 修正 |
| `downloadAttach` | `message.ts` | P | 已实现，index 内图片消息会调用，无独立 HTTP |
| `refreshPyq` / `getFirstPage` / `getNextPage` | `message.ts` | P | 偏移齐全，未 Hook 朋友圈消息，也未暴露 API |
| `decryptImage` | `message.ts` | P | XOR 算法对齐 WCF，但文件读写为空实现 |
| `getAudio` | `message.ts` | P | 路径逻辑有；`getAudioData` 已能查 MediaMSG；缺 silk→mp3 |
| `revokeMsg` | `message.ts` | X | 与 WCF 同为 stub |
| `roomTopic` | `room.ts` | P | 偏移有，实际调用被注释 |
| `modifyContactLabel` | `tag.ts` | P | 有调用骨架，未导出、未验证 |
| `parseAppMsg` | `appMsgParser.ts` | Y | agent 独有增强 |
| `downloadFinderFeedVideo` | `httpDownload.ts` | Y | agent 独有增强 |

### 4.3 仅占位（空函数 / mock）

`friendship.ts`、`roomInvitation.ts`、`tagContact*`、`messageSendContact/Url/MiniProgram/Location`、`roomCreate`、`roomQuit`、`roomQRCode`、`roomAnnounce`、`roomAvatar`、`roomMemberList`（返回空）等。

### 4.4 agent 相对 WCF 的优势

1. **HTTP 控制面**（`:19088`），便于脚本/后端直接调用。  
2. **消息推送**（callbackUrl）。  
3. **AppMsg 结构化解析**（type=49，含视频号 feed）。  
4. **视频号直链下载**（不依赖微信附件管线）。  
5. **群列表/群详情** 独立 API，体验优于仅返回 contacts。  
6. Frida 注入，迭代偏移与调试成本通常更低。

---

## 5. 逐项差距矩阵（可集成视角）

### 5.1 建议优先集成（WCF 可用 → agent 缺失或未出口）

| 优先级 | 能力 | WCF | agent | 集成建议 |
|--------|------|-----|-------|----------|
| P0 | 发送链接卡片 `SendRichText` | Y | N（仅空 stub） | `offset.ts` 已有 `OS_RTM_NEW/FREE/SEND_RICH_TEXT`，可按 `send_msg.cpp::SendRichTextMessage` 移植；补 HTTP `POST /api/message/richText` |
| P0 | 发送表情/GIF `SendEmotion` | Y | N | 已有 `OS_GET_EMOTION_MGR` / `OS_SEND_EMOTION`；移植 `SendEmotionMessage`；HTTP `POST /api/message/emotion` |
| P0 | 暴露群成员管理 API | Y | P | 直接把现有 `roomAdd/Del/Invite` 接到 HTTP + rpc.exports；修正 Invite 的 vector/WxString 结构对齐 WCF |
| P0 | 暴露附件下载 API | Y | P | `POST /api/message/downloadAttach`；参数 `msgId/thumb/extra` |
| P1 | 完善 `decryptImage` | Y | P | 用 Frida `File`/`fopen`/`fwrite` 或 Node fs 能力补齐读写；HTTP `POST /api/message/decryptImage` |
| P1 | 语音导出 `getAudio` | Y | P | `getAudioData` 已就绪；silk→mp3 可选：① 调用外部 ffmpeg/silk 工具 ② 移植 `smc/Codec` ③ 先导出 silk 原文件 |
| P1 | 朋友圈：Hook + 刷新出口 | Y | P | 移植 `ListenPyq/UnListenPyq`（偏移 `OS_PYQ_MSG_CALL=0x2EFAA10`）；暴露 `POST /api/sns/refresh`；接收侧把 pyq 消息推入 push |
| P1 | 关闭接收消息 | Y | N | 保存 Interceptor detach 句柄，提供 `POST /api/message/unlisten` |
| P2 | 消息类型表 `GetMsgTypes` | Y | N | 静态 map 即可，HTTP `GET /api/message/types` |
| P2 | 修复/开放 `roomTopic` | — | P | 取消注释 `ModChatRoomTopic` 并实测；WCF 本身无此 RPC，属于 agent 增强补全 |
| P2 | 标签修改 `modifyContactLabel` | — | P | 验证后导出；WCF 无对应 RPC |

### 5.2 暂不建议投入（WCF 自身也不可用）

| 能力 | 原因 |
|------|------|
| SEND_XML | WCF `#if 0`，且依赖旧 asm call |
| ACCEPT_FRIEND | WCF `#if 0`，32 位 asm，需重新逆向 64 位调用约定 |
| GET_CONTACT_INFO（非好友） | WCF 注释「非好友获取不到」且禁用 |
| RECV_TRANSFER | WCF 明确不实现 |
| REVOKE_MSG | 双方 stub；自己发的消息 msgid 获取困难 |
| REFRESH_QRCODE / GetLoginUrl | 假实现 |
| EXEC_OCR | 参数未调通会抛异常 |

若业务强依赖「通过好友」，应单独开逆向任务，而不是直接抄 WCF 当前源码。

### 5.3 agent 已有、WCF 没有（保持并文档化）

- HTTP Server + Health  
- Push callback  
- AppMsg / FinderFeed 解析  
- Finder 视频 HTTP 下载  
- 独立房间 API（list/detail）  

这些应视为 agent 产品差异化，不必回退到 WCF RPC 模型。

---

## 6. 可落地集成方案（按工作包）

### 工作包 A：消息发送补齐（预估工作量：中）

参考：`wcf/.../spy/send_msg.cpp`

1. 新增 `messageSendRichText(rt)`  
   - 结构字段：`name/account/title/digest/url/thumburl/receiver`  
   - 缓冲布局：`0x8 title / 0x48 url / 0xB0 thumb / 0xF0 digest / 0x2C0 account / 0x2E0 name`  
2. 新增 `messageSendEmotion(contactId, path)`  
3. HTTP + `rpc.exports` + README 同步  
4. 自测：发往 `filehelper`、群聊各一次  

### 工作包 B：API 出口补齐（预估：低）

将已有函数接到 `index.ts::handleRequest`：

| Method | Path | 调用 |
|--------|------|------|
| POST | `/api/room/add` | `roomAdd` |
| POST | `/api/room/del` | `roomDel` |
| POST | `/api/room/invite` | `roomInvite` |
| POST | `/api/message/downloadAttach` | `downloadAttach` |
| POST | `/api/sns/refresh` | `refreshPyq` |
| POST | `/api/message/decryptImage` | `decryptImage`（完善后） |
| GET | `/api/message/types` | 静态表 |

同步更新 `/api/health` 的 apis 列表与 `README.md` 功能表。

### 工作包 C：媒体闭环（预估：中高）

1. **图片**：收到 type=3 → `downloadAttach` → `decryptImage` → 得到 jpg/png/gif  
2. **语音**：type=34 → `getAudioData` → 导出 silk 或转 mp3  
3. **视频/文件**：type=43/49(file) → `downloadAttach`  

关键点：Frida 环境文件 I/O、异步完成通知（微信下载是异步任务，WCF 同样只是 push task）。

### 工作包 D：朋友圈（预估：中）

参考：`receive_msg.cpp` 的 `ListenPyq` / `DispatchPyq`

1. Hook `0x2EFAA10`  
2. 解析 pyq 结构偏移（`OS_PYQ_MSG_*`）  
3. 与现有 push 通道合并  
4. `refreshPyq(0)` 拉首页，`refreshPyq(id)` 下一页  

注意：WCF 要求先 ListenPyq 再 Refresh，否则返回 -1。

### 工作包 E：群能力加固（预估：中）

对照 `chatroom_mgmt.cpp`：

1. `Add/Invite` 支持逗号分隔多人，使用正确 `std::vector<WxString>` 内存布局  
2. 完善 `roomMemberList`：从 `roomRawPayload` / DB `ChatRoom` 解析成员  
3. 视需求补 `roomTopic`（ModChatRoomTopic）

---

## 7. 偏移与移植注意点

`agent/wx391027/offset.ts` 已收录大量与 WCF `funcs.cpp` / `send_msg.cpp` 一致的偏移，例如：

| 用途 | 偏移 |
|------|------|
| DoAddMsg | `0x2205510` |
| SendRichText | `0x21A09C0` |
| EmotionMgr / SendEmotion | `0x1C988D0` / `0x227B9E0` |
| SNS First/Next | `0x2ED9080` / `0x2EFEC00` |
| DownloadAttach 相关 | `0x1C51CF0` / `0x1CD87E0` / `0x1DA69C0` / `0x2206280` |

移植时建议：

1. **优先抄调用序列与结构布局**，不要只抄函数名。  
2. WxString / Vector 的 Frida 封装以现有 `writeWStringPtr` 为准，对照 WCF `NewWxStringFromStr`。  
3. 对 `#if 0` 代码不要直接启用；那是历史 32 位实现。  
4. 任何新 Hook 都要可卸载，避免重复 attach。

---

## 8. README 现状修正建议

`agent/wx391027/README.md` 中若干条目与代码不完全一致，建议后续同步：

| README 声明 | 实际代码 |
|-------------|----------|
| 发送卡片 N | 正确，待做 |
| 获取朋友圈 N | 底层 `refreshPyq` 已有，缺 Hook 与 API |
| 解密图片 N | 有半成品，需补文件 I/O |
| 下载附件「有函数未提供 API」 | 正确 |
| 群成员增删邀「有函数未提供 API」 | 正确 |
| 关闭接收消息 N | 正确 |

---

## 9. 推荐落地顺序

```text
第 1 周：工作包 B（API 出口） + 工作包 A（RichText/Emotion）
第 2 周：工作包 C（decryptImage + 附件/语音闭环）
第 3 周：工作包 D（朋友圈 Hook） + 工作包 E（群成员多人/成员列表）
之后按需：好友通过（独立逆向）、标签、群公告/建群等
```

验收标准建议：

1. 对 `filehelper` 成功发送：文本、图片、文件、表情、卡片、转发、拍一拍（群）。  
2. 收到图片后可下载并解密出可打开图片。  
3. 群：加/邀/删成员 HTTP 返回成功且客户端可见。  
4. 开启 pyq listen 后，刷新朋友圈能收到推送。  

---

## 10. 附录：能力总表（一页版）

| 能力 | WCF | agent 底层 | agent HTTP | 集成动作 |
|------|-----|------------|------------|----------|
| 登录/账号信息 | Y | Y | Y | 保持 |
| 联系人 | Y | Y | Y | 保持 |
| 群列表详情 | 间接 | Y | Y | 保持 |
| 消息接收 | Y | Y | Push | 补 Unlisten |
| 发文本/图/文件 | Y | Y | Y | 保持 |
| 发卡片 | Y | N | N | **实现** |
| 发表情 | Y | N | N | **实现** |
| 发 XML | X | N | N | 暂缓 |
| 拍一拍/转发 | Y | Y | Y | 保持 |
| DB 查询 | Y | Y | Y | 保持 |
| 附件下载 | Y | Y | N | **暴露 API** |
| 解密图片 | Y | P | N | **完善+暴露** |
| 语音转存 | Y | P | N | **完善+暴露** |
| 朋友圈刷新/接收 | Y | P | N | **Hook+暴露** |
| 群成员增删邀 | Y | Y | N | **暴露+加固** |
| 通过好友 | X | N | N | 暂缓/独立逆向 |
| 收款/OCR/撤回/扫码 | X | X/N | N | 暂缓 |
| 视频号解析下载 | N | Y | Y | 保持（优势） |
| HTTP/Push | N | Y | Y | 保持（优势） |

---

*本报告仅基于仓库内 WCF 与 agent 源码静态对比，未做运行时验证。实施前应对关键偏移在目标微信进程中再确认一次。*

---

## 11. 实施状态（2026-07-23）

报告中 **WCF 实际可用、agent 缺失** 的能力已迁入 `agent/wx391027`：

| 能力 | 状态 |
|------|------|
| SendRichText / SendEmotion | 已实现 + HTTP |
| downloadAttach / decryptImage / getAudio | 已完善 + HTTP（语音导出 silk） |
| GetMsgTypes / enable&disable recv | 已实现 + HTTP |
| ListenPyq / RefreshPyq | 已实现 + HTTP |
| 群成员 add/del/invite | 已加固多人向量 + HTTP |
| roomTopic | 已接通调用 + HTTP |

仍按报告暂缓：SEND_XML、ACCEPT_FRIEND、RECV_TRANSFER、REVOKE_MSG、OCR、REFRESH_QRCODE（WCF 自身不可用）。
