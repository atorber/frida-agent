## 功能清单

|功能|是否支持|说明|
|--|--|--|
|查询登录状态|Y|通过 `/api/checkLogin` API|
|获取登录账号信息|Y|通过 `/api/contacts/self` API|
|获取消息类型|Y|通过接收消息回调，消息对象包含 `type` 字段|
|获取联系人|Y|通过 `/api/contacts` 和 `/api/contact` API|
|获取群列表|Y|通过 `/api/rooms` API|
|获取群详情|Y|通过 `/api/room?roomId=xxx` API|
|获取可查询数据库|Y|通过 `/api/db/names` API|
|获取数据库所有表|Y|通过 `/api/db/tables?dbName=xxx` API|
|获取语音消息|Y|通过接收消息回调，消息类型包含语音类型|
|发送文本消息|Y|通过 `/api/message/text` API|
|发送@文本消息|Y|通过 `/api/message/text` API，使用 `atWxids` 参数|
|发送图片消息|Y|通过 `/api/message/image` API|
|发送文件消息|Y|通过 `/api/message/file` API|
|发送卡片消息|N|暂未实现|
|发送 GIF 消息|Y|通过 `/api/message/image` API，自动识别 GIF 格式|
|拍一拍群友|Y|通过 `/api/message/pat` API|
|转发消息|Y|通过 `/api/message/forward` API|
|开启接收消息|Y|脚本加载时自动开启，通过 Hook 机制|
|关闭接收消息|N|暂未实现关闭功能|
|查询数据库|Y|通过 `/api/db/query` API|
|获取朋友圈消息|N|暂未实现|
|下载图片、视频、文件|Y|有 `downloadAttach` 函数，但未提供 API 接口|
|解密图片|N|暂未实现|
|添加群成员|Y|有 `roomAdd` 函数，但未提供 API 接口|
|删除群成员|Y|有 `roomDel` 函数，但未提供 API 接口|
|邀请群成员|Y|有 `roomInvite` 函数，但未提供 API 接口|
