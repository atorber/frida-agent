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

### 新增 API 示例

```bash
# 发送链接卡片
curl -X POST http://127.0.0.1:19088/api/message/richText -H "Content-Type: application/json" -d "{\"receiver\":\"filehelper\",\"title\":\"标题\",\"url\":\"https://example.com\",\"digest\":\"摘要\",\"thumburl\":\"\",\"account\":\"\",\"name\":\"\"}"

# 发送表情
curl -X POST http://127.0.0.1:19088/api/message/emotion -H "Content-Type: application/json" -d "{\"contactId\":\"filehelper\",\"path\":\"C:\\\\path\\\\to.gif\"}"

# 群成员
curl -X POST http://127.0.0.1:19088/api/room/add -H "Content-Type: application/json" -d "{\"roomId\":\"xxx@chatroom\",\"wxids\":\"wxid_a,wxid_b\"}"

# 朋友圈
curl -X POST http://127.0.0.1:19088/api/sns/listen -H "Content-Type: application/json" -d "{\"enabled\":true}"
curl -X POST http://127.0.0.1:19088/api/sns/refresh -H "Content-Type: application/json" -d "{\"id\":0}"
```
