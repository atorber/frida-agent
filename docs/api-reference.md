# API 快速参考

## 登录模块 (`login.ts`)

```typescript
// 检查登录状态
checkLogin(): number
// 返回: 1=已登录, -1=未登录

// 获取当前用户微信ID
getSelfWxid(): string
// 返回: "wxid_xxx"

// 获取用户完整信息
getUserInfo(): UserInfo
// 返回: { wxid, name, mobile, home }

// 获取数据目录路径
getHomePath(): string
// 返回: "C:\\Users\\xxx\\Documents\\WeChat Files\\"
```

## 联系人模块 (`contact.ts`)

```typescript
// 获取自己的信息
contactSelfInfo(): Contact

// 获取所有联系人
contactList(): Contact[]

// 获取指定联系人详情
contactRawPayload(wxid: string): ContactInfo
```

## 消息模块 (`message.ts`)

```typescript
// 发送文本消息 (支持@)
messageSendText(contactId: string, text: string, atWxids?: string[]): number

// 发送图片
messageSendImage(contactId: string, path: string): number

// 发送文件
messageSendFile(contactId: string, path: string): number

// 发送链接卡片
messageSendRichText(rt: RichTextMsg): number

// 发送表情/GIF
messageSendEmotion(contactId: string, path: string): number

// 发送拍一拍
messageSendPat(roomId: string, contactId: string): number

// 转发消息
messageForward(msgId: number, receiver: string): number

// 下载附件
downloadAttach(id: number, thumb: string, extra: string): number

// 解密图片 (.dat XOR)
decryptImage(src: string, dir: string): string

// 导出语音 (silk；已有 mp3 则返回 mp3)
getAudio(id: number, dir: string): string

// 消息类型表
getMsgTypes(): { [key: number]: string }

// 刷新朋友圈（需先 listenPyq）
refreshPyq(id: number): number
```

## 接收控制 (`recv.ts`)

```typescript
enableRecvMsg(handler?): boolean
disableRecvMsg(): boolean
listenPyq(handler?): boolean
unListenPyq(): boolean
```

## 群聊模块 (`room.ts`)

```typescript
// 获取所有群聊
roomList(): Room[]

// 获取群聊详情
roomRawPayload(roomId: string): RoomInfo

// 添加成员 (40人以下群，wxids 逗号分隔)
roomAdd(roomId: string, wxids: string): boolean

// 邀请成员 (40人以上群)
roomInvite(roomId: string, wxids: string): boolean

// 移除成员
roomDel(roomId: string, wxids: string): boolean

// 修改群名
roomTopic(roomId: string, topic: string): number
```

## 数据库模块 (`sqlite.ts`)

```typescript
// 获取数据库句柄
getDbHandles(): DbHandleMap

// 获取数据库名列表
getDbNames(): string[]

// 获取表名列表
getDbTables(dbName: string): string[]

// 执行SQL查询
execDbQuery(dbName: string, sql: string): any[]

// 获取消息本地ID
getLocalIdAndDbIdx(msgId: number): { localId: number, dbIdx: number } | null
```

## 类型定义

```typescript
interface Contact {
  id: string;
  name: string;
  avatar: string;
  gender: number;
  city: string;
  province: string;
  weixin: string;
  phone: string[];
  alias: string;
  type: number;
}

interface Message {
  id: number;
  type: number;
  text: string;
  timestamp: number;
  talkerId: string;
  roomId: string;
  listenerId: string;
  isSelf: boolean;
  filename: string;
  mentionIds: string[];
}

interface UserInfo {
  wxid: string;
  name: string;
  mobile: string;
  home: string;
}
```

## 消息类型常量

| 值 | 类型 |
|----|------|
| 1 | 文本 |
| 3 | 图片 |
| 34 | 语音 |
| 43 | 视频 |
| 47 | 表情 |
| 49 | 应用消息 |
| 10000 | 系统消息 |
| 10002 | 撤回消息 |

## 偏移地址 (3.9.10.27)

```typescript
const offsets = {
  kSendMessageMgr: 0x1C1E690,
  kSendTextMsg: 0x238DDD0,
  kFreeChatMsg: 0x1C1FF10,
  kNewChatMsg: 0x1C28800,
  kSendImageMsg: 0x2383560,
  kSendFileMsg: 0x21969E0,
  kSendPatMsg: 0x2D669B0,
  kForwardMsg: 0x238D350,
  kGetContactMgr: 0x1C0BDE0,
  kGetContactList: 0x2265540,
  kDoAddMsg: 0x2205510,
}
```

