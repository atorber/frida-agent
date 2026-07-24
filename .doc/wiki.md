# Frida-Agent 项目 Wiki

## 目录

- [项目概述](#项目概述)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [核心模块](#核心模块)
  - [登录模块](#登录模块)
  - [联系人模块](#联系人模块)
  - [群聊模块](#群聊模块)
  - [消息模块](#消息模块)
  - [SQLite模块](#sqlite模块)
  - [消息Hook](#消息hook)
- [API参考](#api参考)
- [偏移地址说明](#偏移地址说明)
- [常见问题](#常见问题)
- [开发指南](#开发指南)

---

## 项目概述

Frida-Agent 是一个基于 [Frida](https://frida.re/) 动态插桩框架的微信 Windows 客户端自动化工具。它通过注入到微信进程中，调用微信内部函数实现各种自动化操作。

### 主要特性

- 🔐 **登录管理** - 检查登录状态、获取用户信息
- 👥 **联系人管理** - 获取联系人列表、查询联系人详情
- 💬 **群聊管理** - 获取群列表、添加/删除群成员、群邀请
- 📨 **消息功能** - 发送文本/图片/文件/拍一拍消息、转发消息、@功能
- 📰 **朋友圈** - 刷新朋友圈、获取动态
- 🗄️ **数据库操作** - 直接查询微信SQLite数据库
- 🎣 **消息Hook** - 实时接收消息回调

### 支持的微信版本

| 微信版本 | 支持状态 | 备注 |
|---------|---------|------|
| 3.9.10.27 | ✅ 完全支持 | 主要开发版本 |
| 3.9.12.17 | 🔄 开发中 | 部分功能 |

---

## 系统要求

### 环境要求

- **操作系统**: Windows 10/11 (64位)
- **Node.js**: v18.x 或更高版本
- **Python**: 3.8+ (用于 Frida)
- **微信**: Windows 客户端 3.9.10.27

### 依赖安装

```bash
# 安装 Node.js 依赖
npm install

# 安装 Frida CLI (如果尚未安装)
pip install frida-tools
```

---

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/your-repo/frida-agent.git
cd frida-agent
```

### 2. 安装依赖

```bash
npm install
```

### 3. 编译 TypeScript

```bash
# 开发模式 (自动监听文件变化)
npm run watch:wx391027

# 或者一次性编译
npm run build
```

### 4. 启动微信并注入

```bash
# 确保微信已启动并登录
npm run start:wx391027
```

### 5. 验证注入成功

注入成功后，控制台会输出类似以下信息：

```
homePath: C:\Users\xxx\Documents\WeChat Files\
selfInfo: {"wxid":"wxid_xxx","name":"用户名",...}
wxid: wxid_xxx
```

---

## 项目结构

```
frida-agent/
├── agent/                      # 核心代理代码
│   ├── wx391027/              # 微信 3.9.10.27 版本模块
│   │   ├── index.ts           # 主入口文件
│   │   ├── login.ts           # 登录相关功能
│   │   ├── contact.ts         # 联系人管理
│   │   ├── room.ts            # 群聊管理
│   │   ├── message.ts         # 消息功能
│   │   ├── sqlite.ts          # 数据库操作
│   │   ├── utils.ts           # 工具函数
│   │   ├── types.ts           # 类型定义
│   │   └── offset.ts          # 偏移地址
│   ├── index.ts               # 全局入口
│   └── xp-3.9.10.27.ts        # 精简版入口
├── dist/                       # 编译输出目录
├── examples/                   # 示例代码
├── nodejs/                     # Node.js 客户端
├── python/                     # Python 客户端
├── sidecar/                    # Sidecar 集成
├── wcf/                        # WeChatFerry 参考代码
├── package.json
└── tsconfig.json
```

---

## 核心模块

### 登录模块

文件: `agent/wx391027/login.ts`

#### checkLogin()

检查微信登录状态。

```typescript
import { checkLogin } from './login.js'

const status = checkLogin()
// 返回值: 1 = 已登录, -1 = 未登录
```

#### getSelfWxid()

获取当前登录账号的微信ID。

```typescript
import { getSelfWxid } from './login.js'

const wxid = getSelfWxid()
// 返回值: "wxid_xxx" 或 "empty_wxid"
```

#### getUserInfo()

获取当前登录用户的完整信息。

```typescript
import { getUserInfo } from './login.js'

const userInfo = getUserInfo()
// 返回值:
// {
//   wxid: string,    // 微信ID
//   name: string,    // 昵称
//   mobile: string,  // 手机号
//   home: string     // 数据目录路径
// }
```

#### getHomePath()

获取微信数据存储目录。

```typescript
import { getHomePath } from './login.js'

const path = getHomePath()
// 返回值: "C:\\Users\\xxx\\Documents\\WeChat Files\\"
```

---

### 联系人模块

文件: `agent/wx391027/contact.ts`

#### contactSelfInfo()

获取当前登录账号的详细信息。

```typescript
import { contactSelfInfo } from './contact.js'

const selfInfo = contactSelfInfo()
// 返回值: Contact 对象
// {
//   id: string,        // 微信ID
//   name: string,      // 昵称
//   avatar: string,    // 头像URL
//   gender: number,    // 性别 (1=男, 2=女)
//   city: string,      // 城市
//   province: string,  // 省份
//   weixin: string,    // 微信号
//   phone: string[],   // 手机号列表
//   ...
// }
```

#### contactList()

获取所有联系人列表。

```typescript
import { contactList } from './contact.js'

const contacts = contactList()
// 返回值: Contact[] 数组
console.log(`共有 ${contacts.length} 个联系人`)
```

#### contactRawPayload(wxid)

获取指定联系人的详细信息。

```typescript
import { contactRawPayload } from './contact.js'

const contact = contactRawPayload('wxid_xxx')
// 返回值: 联系人详细信息对象
```

---

### 群聊模块

文件: `agent/wx391027/room.ts`

#### roomList()

获取所有群聊列表。

```typescript
import { roomList } from './room.js'

const rooms = roomList()
// 返回值: Room[] 数组
```

#### roomRawPayload(roomId)

获取指定群聊的详细信息。

```typescript
import { roomRawPayload } from './room.js'

const room = roomRawPayload('xxx@chatroom')
// 返回值: 群聊详细信息对象
```

#### roomAdd(roomId, contactId)

添加成员到群聊（40人以下群）。

```typescript
import { roomAdd } from './room.js'

const result = roomAdd('xxx@chatroom', 'wxid_xxx')
// 返回值: 1 = 成功, -1 = 失败
```

#### roomInvite(roomId, contactId)

邀请成员加入群聊（40人以上群）。

```typescript
import { roomInvite } from './room.js'

const result = roomInvite('xxx@chatroom', 'wxid_xxx')
// 返回值: 1 = 成功, -1 = 失败
```

#### roomDel(roomId, contactId)

从群聊中移除成员。

```typescript
import { roomDel } from './room.js'

const result = roomDel('xxx@chatroom', 'wxid_xxx')
// 返回值: 1 = 成功, -1 = 失败
```

---

### 消息模块

文件: `agent/wx391027/message.ts`

#### messageSendText(contactId, text, atWxids?)

发送文本消息，支持@功能。

```typescript
import { messageSendText } from './message.js'

// 发送普通文本
messageSendText('wxid_xxx', 'Hello World')

// 在群聊中@指定用户
messageSendText('xxx@chatroom', 'Hello', ['wxid_user1', 'wxid_user2'])

// @所有人
messageSendText('xxx@chatroom', 'Hello everyone', ['notify@all'])
```

**参数说明:**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| contactId | string | 是 | 接收者ID (个人wxid或群ID) |
| text | string | 是 | 消息内容 |
| atWxids | string[] | 否 | @的用户列表，使用 `notify@all` 表示@所有人 |

#### messageSendImage(contactId, path)

发送图片消息。

```typescript
import { messageSendImage } from './message.js'

const result = messageSendImage('wxid_xxx', 'C:\\path\\to\\image.jpg')
// 返回值: 1 = 成功, -1 = 失败
```

#### messageSendFile(contactId, path)

发送文件消息。

```typescript
import { messageSendFile } from './message.js'

const result = messageSendFile('wxid_xxx', 'C:\\path\\to\\file.pdf')
// 返回值: 1 = 成功, -1 = 失败
```

#### messageSendPat(roomId, contactId)

发送拍一拍消息。

```typescript
import { messageSendPat } from './message.js'

const result = messageSendPat('xxx@chatroom', 'wxid_xxx')
// 返回值: 1 = 成功, -1 = 失败
```

#### messageForward(msgId, receiver)

转发消息。

```typescript
import { messageForward } from './message.js'

const result = messageForward(12345678, 'wxid_xxx')
// 返回值: 转发状态
```

#### downloadAttach(id, thumb, extra)

下载附件（图片、视频、文件）。

```typescript
import { downloadAttach } from './message.js'

const result = downloadAttach(12345678, '', 'C:\\download\\image.jpg')
// 返回值: 1 = 成功, -1 = 失败
```

---

### SQLite模块

文件: `agent/wx391027/sqlite.ts`

#### getDbHandles()

获取所有数据库句柄。

```typescript
import { getDbHandles } from './sqlite.js'

const handles = getDbHandles()
// 返回值: 数据库句柄映射
```

#### getDbNames()

获取所有可查询的数据库名称。

```typescript
import { getDbNames } from './sqlite.js'

const dbNames = getDbNames()
// 返回值: ["MicroMsg.db", "ChatMsg.db", ...]
```

#### getDbTables(dbName)

获取指定数据库的所有表名。

```typescript
import { getDbTables } from './sqlite.js'

const tables = getDbTables('MicroMsg.db')
// 返回值: ["Contact", "ChatRoom", ...]
```

#### execDbQuery(dbName, sql)

执行SQL查询。

```typescript
import { execDbQuery } from './sqlite.js'

const sql = 'SELECT UserName, NickName FROM Contact LIMIT 10'
const results = execDbQuery('MicroMsg.db', sql)
// 返回值: 查询结果数组
```

#### getLocalIdAndDbIdx(msgId)

根据消息ID获取本地ID和数据库索引。

```typescript
import { getLocalIdAndDbIdx } from './sqlite.js'

const result = getLocalIdAndDbIdx(12345678)
// 返回值: { localId: number, dbIdx: number } 或 null
```

---

### 消息Hook

文件: `agent/wx391027/index.ts`

消息Hook通过拦截微信的 `DoAddMsg` 函数实现实时消息接收。

#### 消息结构

```typescript
interface Message {
  id: number;           // 消息ID
  type: number;         // 消息类型
  text: string;         // 消息内容
  timestamp: number;    // 时间戳
  talkerId: string;     // 发送者ID
  roomId: string;       // 群聊ID (如果是群消息)
  listenerId: string;   // 接收者ID (如果是私聊)
  isSelf: boolean;      // 是否自己发送
  filename: string;     // 文件名 (如果是文件消息)
  mentionIds: string[]; // @的用户列表
}
```

#### 消息类型

| 类型值 | 说明 |
|--------|------|
| 1 | 文本消息 |
| 3 | 图片消息 |
| 34 | 语音消息 |
| 43 | 视频消息 |
| 47 | 表情消息 |
| 49 | 应用消息 (文件、链接、小程序等) |
| 10000 | 系统消息 |
| 10002 | 撤回消息 |

#### 示例: 自动回复

```typescript
// 在 index.ts 中的消息处理逻辑
const handleMsg = (msg: Message) => {
  // 自动回复 "ding" -> "dong"
  if (msg.roomId && msg.text === 'ding') {
    messageSendText(msg.roomId, 'dong', [msg.talkerId])
  }
}
```

---

## API参考

### 导出函数一览

```typescript
// 登录相关
export { checkLogin, getSelfWxid, getUserInfo, getHomePath }

// 联系人相关
export { contactSelfInfo, contactList, contactRawPayload }

// 群聊相关
export { roomList, roomRawPayload, roomAdd, roomInvite, roomDel }

// 消息相关
export { 
  messageSendText, 
  messageSendImage, 
  messageSendFile, 
  messageSendPat,
  messageForward,
  downloadAttach,
  decryptImage
}

// 数据库相关
export { 
  getDbHandles, 
  getDbNames, 
  getDbTables, 
  execDbQuery,
  getLocalIdAndDbIdx
}
```

---

## 偏移地址说明

偏移地址是微信DLL中函数的内存地址偏移量，不同微信版本的偏移地址不同。

### 微信 3.9.10.27 偏移地址

```typescript
const offsets = {
  // 消息相关
  kSendMessageMgr: 0x1C1E690,    // 发送消息管理器
  kSendTextMsg: 0x238DDD0,       // 发送文本消息
  kFreeChatMsg: 0x1C1FF10,       // 释放消息对象
  kNewChatMsg: 0x1C28800,        // 创建消息对象
  kSendImageMsg: 0x2383560,      // 发送图片消息
  kSendFileMsg: 0x21969E0,       // 发送文件消息
  kSendPatMsg: 0x2D669B0,        // 发送拍一拍
  kForwardMsg: 0x238D350,        // 转发消息
  
  // 联系人相关
  kGetContactMgr: 0x1C0BDE0,     // 获取联系人管理器
  kGetContactList: 0x2265540,    // 获取联系人列表
  kGetContact: 0x225F950,        // 获取联系人详情
  
  // 账号相关
  kGetAccountServiceMgr: 0x1C1FE90,  // 获取账号服务
  kGetAppDataSavePath: 0x26A7780,    // 获取数据路径
  
  // Hook相关
  kDoAddMsg: 0x2205510,          // 接收消息Hook点
  
  // 数据库相关
  kSQLiteExec: 0x2A5C2A0,        // SQLite执行
  kSQLiteStep: 0x2A6C630,        // SQLite步进
}
```

### 如何获取偏移地址

1. 使用IDA Pro或Ghidra反编译WeChatWin.dll
2. 搜索特征字符串定位函数
3. 计算函数地址相对于模块基址的偏移

---

## 常见问题

### Q1: 注入失败，提示"无法找到进程"

**解决方案:**
1. 确保微信已经启动
2. 以管理员权限运行命令行
3. 检查微信进程名是否为 `WeChat.exe`

### Q2: 函数调用失败，返回-1

**可能原因:**
1. 微信版本不匹配，偏移地址错误
2. 微信未登录
3. 参数格式错误

**解决方案:**
1. 确认微信版本与偏移地址匹配
2. 检查 `checkLogin()` 返回值
3. 检查参数类型和格式

### Q3: @功能不生效

**可能原因:**
1. WxString结构不匹配
2. RawVector构造错误
3. 消息文本中缺少@符号

**解决方案:**
1. 检查日志输出，确认WxString结构正确
2. 确保在群聊中使用@功能
3. 消息文本中需要包含对应的@用户昵称

### Q4: 数据库查询返回空

**可能原因:**
1. 数据库句柄未初始化
2. SQL语法错误
3. 表名或字段名错误

**解决方案:**
1. 先调用 `getDbHandles()` 初始化
2. 使用 `getDbTables()` 确认表名
3. 检查SQL语句语法

---

## 开发指南

### 添加新功能

1. 在对应模块文件中添加函数
2. 在 `offset.ts` 中添加必要的偏移地址
3. 在 `index.ts` 中导出函数
4. 编写测试代码验证

### 调试技巧

1. 使用 `console.log()` 输出调试信息
2. 检查内存地址和指针值
3. 使用Frida的交互模式测试

```bash
# 交互模式
frida -l agent/wx391027/index.js WeChat.exe -q
```

### 代码规范

1. 使用TypeScript编写
2. 添加必要的类型注解
3. 函数添加JSDoc注释
4. 错误处理使用try-catch

### 参考资源

- [Frida 官方文档](https://frida.re/docs/)
- [WeChatFerry 项目](https://github.com/lich0821/WeChatFerry)
- [微信逆向分析资料](https://github.com/nicehero/wechat-hook)

---

## 许可证

本项目仅供学习研究使用，请勿用于非法用途。

---

## 贡献指南

欢迎提交Issue和Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

