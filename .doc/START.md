# 启动指南

## 方式一：使用 Frida 命令行直接启动（推荐）

### 1. 编译 TypeScript 脚本

在项目根目录执行：

```bash
# 编译到 weebot 目录（用于 Python 打包）
frida-compile agent/wx391027/index.ts -o weebot/xp-3.9.10.27.js

# 或者编译到 agent 目录（用于直接运行）
frida-compile agent/wx391027/index.ts -o agent/wx391027/index.js
```

### 2. 启动微信

确保微信（WeChat.exe）已经启动并登录。

### 3. 使用 Frida 加载脚本

```bash
# 方式 1：使用 npm 脚本
npm run start:wx391027

# 方式 2：直接使用 frida 命令
frida -l agent/wx391027/index.js WeChat.exe
```

### 4. 验证 HTTP 服务器

脚本加载成功后，你会看到：
```
[HTTP] 服务器已启动，监听端口 19088
[HTTP] 访问 http://localhost:19088/api/health 查看 API 列表
```

然后可以在浏览器或使用 curl 测试：

```bash
# 检查服务器状态
curl http://localhost:19088/api/health

# 检查登录状态
curl http://localhost:19088/api/checkLogin

# 获取联系人列表
curl http://localhost:19088/api/contacts
```

## 方式二：使用 Python WeeBot（可选）

如果你需要使用 Python GUI 界面：

### 1. 编译脚本到 weebot 目录

```bash
frida-compile agent/wx391027/index.ts -o weebot/xp-3.9.10.27.js
```

### 2. 启动 Python 程序

```bash
cd weebot
python WeeBot.py
```

> **注意**：现在 HTTP 服务器直接在 Frida 脚本中运行，Python 程序主要用于 GUI 界面。HTTP API 可以直接访问，无需通过 Python。

## 开发模式（自动重新编译）

如果你在开发过程中需要自动重新编译：

```bash
# 在项目根目录执行
npm run watch:wx391027
```

然后在另一个终端执行：

```bash
npm run start:wx391027
```

这样当你修改 `agent/wx391027/index.ts` 时，会自动重新编译。

## API 接口文档

### 统一响应格式

所有 API 接口都遵循统一的响应格式：

```json
{
  "code": 1,        // 1 表示成功，0 表示失败
  "data": {},       // 响应数据，成功时包含具体数据，失败时可能为 null 或错误详情
  "msg": "success"  // 响应消息，成功时为 "success"，失败时为错误描述
}
```

### 基础信息接口

#### 1. 健康检查和 API 列表

**接口地址：** `GET /api/health` 或 `GET /`

**请求参数：** 无

**响应示例：**
```json
{
  "code": 1,
  "data": {
    "status": "ok",
    "timestamp": "2024-01-14T19:00:00.000Z",
    "apis": [
      "GET /api/checkLogin",
      "GET /api/contacts/self",
      "GET /api/contacts",
      "GET /api/contact?contactId=xxx",
      "GET /api/rooms",
      "GET /api/room?roomId=xxx",
      "POST /api/message/text",
      "GET /api/db/names",
      "GET /api/db/tables?dbName=xxx",
      "POST /api/db/query"
    ]
  },
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl http://localhost:19088/api/health

# PowerShell
Invoke-WebRequest -Uri http://localhost:19088/api/health
```

#### 2. 检查登录状态

**接口地址：** `GET /api/checkLogin` 或 `GET /api/checklogin`

**请求参数：** 无

**响应示例：**
```json
{
  "code": 1,
  "data": true,  // true 表示已登录，false 表示未登录
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl http://localhost:19088/api/checkLogin

# PowerShell
Invoke-WebRequest -Uri http://localhost:19088/api/checkLogin
```

### 联系人接口

#### 3. 获取自己的信息

**接口地址：** `GET /api/contacts/self`

**请求参数：** 无

**响应示例：**
```json
{
  "code": 1,
  "data": {
    "id": "wxid_xxx",
    "name": "用户名",
    "mobile": "手机号",
    "avatar": "头像URL"
  },
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl http://localhost:19088/api/contacts/self

# PowerShell
Invoke-WebRequest -Uri http://localhost:19088/api/contacts/self
```

#### 4. 获取联系人列表

**接口地址：** `GET /api/contacts`

**请求参数：** 无

**响应示例：**
```json
{
  "code": 1,
  "data": [
    {
      "id": "wxid_xxx",
      "name": "联系人名称",
      "alias": "备注名",
      "avatar": "头像URL",
      "gender": 1,
      "type": 1,
      "friend": true,
      "phone": ["13800138000"]
    }
  ],
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl http://localhost:19088/api/contacts

# PowerShell
Invoke-WebRequest -Uri http://localhost:19088/api/contacts
```

#### 5. 获取联系人详情

**接口地址：** `GET /api/contact`

**请求参数：**
- `contactId` (必需) - 联系人 ID（微信 ID）

**响应示例（成功）：**
```json
{
  "code": 1,
  "data": {
    "UserName": "wxid_xxx",
    "Alias": "备注名",
    "NickName": "昵称",
    "Remark": "备注",
    "BigHeadImgUrl": "大头像URL",
    "SmallHeadImgUrl": "小头像URL",
    "Sex": 1,
    "Type": 1,
    "Province": "省份",
    "City": "城市",
    "Signature": "个性签名"
  },
  "msg": "success"
}
```

**响应示例（失败）：**
```json
{
  "code": 0,
  "data": {
    "error": true,
    "message": "获取联系人失败: wxid=xxx, 无法读取联系人信息",
    "wxid": "xxx"
  },
  "msg": "获取联系人失败: wxid=xxx, 无法读取联系人信息"
}
```

**命令示例：**
```bash
# curl
curl "http://localhost:19088/api/contact?contactId=wxid_xxx"

# PowerShell
Invoke-WebRequest -Uri "http://localhost:19088/api/contact?contactId=wxid_xxx"
```

### 群聊接口

#### 6. 获取群聊列表

**接口地址：** `GET /api/rooms`

**请求参数：** 无

**响应示例：**
```json
{
  "code": 1,
  "data": [
    {
      "id": "xxx@chatroom",
      "name": "群聊名称",
      "avatar": "群头像URL",
      "type": 2
    }
  ],
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl http://localhost:19088/api/rooms

# PowerShell
Invoke-WebRequest -Uri http://localhost:19088/api/rooms
```

#### 7. 获取群聊详情

**接口地址：** `GET /api/room`

**请求参数：**
- `roomId` (必需) - 群聊 ID（格式：`xxx@chatroom`）

**响应示例（成功）：**
```json
{
  "code": 1,
  "data": {
    "id": "xxx@chatroom",
    "notice": "群公告",
    "admin": "群管理员wxid",
    "xml": "群信息XML"
  },
  "msg": "success"
}
```

**响应示例（失败）：**
```json
{
  "code": 0,
  "data": {
    "error": true,
    "message": "获取群详情失败: roomId=xxx@chatroom, 无法读取群信息",
    "roomId": "xxx@chatroom",
    "success": 0
  },
  "msg": "获取群详情失败: roomId=xxx@chatroom, 无法读取群信息"
}
```

**命令示例：**
```bash
# curl
curl "http://localhost:19088/api/room?roomId=xxx@chatroom"

# PowerShell
Invoke-WebRequest -Uri "http://localhost:19088/api/room?roomId=xxx@chatroom"
```

### 消息发送接口

#### 8. 发送文本消息

**接口地址：** `POST /api/message/text`

**请求头：**
- `Content-Type: application/json`

**请求体：**
```json
{
  "contactId": "wxid_xxx",           // 必需：接收者 ID（私聊）或群聊 ID（群聊，格式：xxx@chatroom）
  "text": "消息内容",                  // 必需：消息文本内容
  "atWxids": ["wxid1", "wxid2"]      // 可选：群聊中要@的用户 ID 列表
}
```

**响应示例：**
```json
{
  "code": 1,
  "data": true,  // true 表示发送成功
  "msg": "success"
}
```

**命令示例：**

**Linux/Mac/Git Bash 中使用 curl：**
```bash
# 发送普通文本消息
curl -X POST http://localhost:19088/api/message/text \
  -H "Content-Type: application/json" \
  -d '{"contactId":"wxid_xxx","text":"hello world"}'

# 发送群聊消息并@用户
curl -X POST http://localhost:19088/api/message/text \
  -H "Content-Type: application/json" \
  -d '{"contactId":"xxx@chatroom","text":"消息内容","atWxids":["wxid1","wxid2"]}'
```

**PowerShell 中使用 Invoke-WebRequest：**
```powershell
# 方式 1：单行命令
Invoke-WebRequest -Uri http://localhost:19088/api/message/text -Method POST -ContentType "application/json" -Body '{"contactId":"wxid_xxx","text":"hello world"}'

# 方式 2：使用反引号换行（推荐）
Invoke-WebRequest -Uri http://localhost:19088/api/message/text `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"contactId":"wxid_xxx","text":"hello world"}'

# 方式 3：使用变量（最易读，适合复杂 JSON）
$body = @{
  contactId = "wxid_xxx"
  text = "hello world"
} | ConvertTo-Json
Invoke-WebRequest -Uri http://localhost:19088/api/message/text -Method POST -ContentType "application/json" -Body $body

# 方式 4：群聊消息并@用户
$body = @{
  contactId = "xxx@chatroom"
  text = "消息内容"
  atWxids = @("wxid1", "wxid2")
} | ConvertTo-Json
Invoke-WebRequest -Uri http://localhost:19088/api/message/text -Method POST -ContentType "application/json" -Body $body
```

#### 9. 发送图片消息

**接口地址：** `POST /api/message/image`

**请求头：**
- `Content-Type: application/json`

**请求体：**
```json
{
  "contactId": "wxid_xxx",           // 必需：接收者 ID 或群聊 ID
  "path": "C:\\path\\to\\image.jpg"  // 必需：图片文件的完整路径
}
```

**响应示例：**
```json
{
  "code": 1,
  "data": true,
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl -X POST http://localhost:19088/api/message/image \
  -H "Content-Type: application/json" \
  -d '{"contactId":"wxid_xxx","path":"C:\\path\\to\\image.jpg"}'

# PowerShell
$body = @{
  contactId = "wxid_xxx"
  path = "C:\path\to\image.jpg"
} | ConvertTo-Json
Invoke-WebRequest -Uri http://localhost:19088/api/message/image -Method POST -ContentType "application/json" -Body $body
```

#### 10. 发送文件消息

**接口地址：** `POST /api/message/file`

**请求头：**
- `Content-Type: application/json`

**请求体：**
```json
{
  "contactId": "wxid_xxx",           // 必需：接收者 ID 或群聊 ID
  "path": "C:\\path\\to\\file.pdf"  // 必需：文件的完整路径
}
```

**响应示例：**
```json
{
  "code": 1,
  "data": true,
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl -X POST http://localhost:19088/api/message/file \
  -H "Content-Type: application/json" \
  -d '{"contactId":"wxid_xxx","path":"C:\\path\\to\\file.pdf"}'

# PowerShell
$body = @{
  contactId = "wxid_xxx"
  path = "C:\path\to\file.pdf"
} | ConvertTo-Json
Invoke-WebRequest -Uri http://localhost:19088/api/message/file -Method POST -ContentType "application/json" -Body $body
```

#### 11. 发送拍一拍消息（仅群聊）

**接口地址：** `POST /api/message/pat`

**请求头：**
- `Content-Type: application/json`

**请求体：**
```json
{
  "roomId": "xxx@chatroom",  // 必需：群聊 ID
  "contactId": "wxid_xxx"     // 必需：要拍的用户 ID
}
```

**响应示例：**
```json
{
  "code": 1,
  "data": true,
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl -X POST http://localhost:19088/api/message/pat \
  -H "Content-Type: application/json" \
  -d '{"roomId":"xxx@chatroom","contactId":"wxid_xxx"}'

# PowerShell
$body = @{
  roomId = "xxx@chatroom"
  contactId = "wxid_xxx"
} | ConvertTo-Json
Invoke-WebRequest -Uri http://localhost:19088/api/message/pat -Method POST -ContentType "application/json" -Body $body
```

#### 12. 转发消息

**接口地址：** `POST /api/message/forward`

**请求头：**
- `Content-Type: application/json`

**请求体：**
```json
{
  "msgId": 123456,        // 必需：要转发的消息 ID（数字）
  "receiver": "wxid_xxx"  // 必需：接收者 ID 或群聊 ID
}
```

**响应示例：**
```json
{
  "code": 1,
  "data": true,
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl -X POST http://localhost:19088/api/message/forward \
  -H "Content-Type: application/json" \
  -d '{"msgId":123456,"receiver":"wxid_xxx"}'

# PowerShell
$body = @{
  msgId = 123456
  receiver = "wxid_xxx"
} | ConvertTo-Json
Invoke-WebRequest -Uri http://localhost:19088/api/message/forward -Method POST -ContentType "application/json" -Body $body
```

### 数据库接口

#### 13. 获取数据库列表

**接口地址：** `GET /api/db/names`

**请求参数：** 无

**响应示例：**
```json
{
  "code": 1,
  "data": [
    "MicroMsg.db",
    "FTS5IndexMicroMsg.db",
    "Media.db"
  ],
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl http://localhost:19088/api/db/names

# PowerShell
Invoke-WebRequest -Uri http://localhost:19088/api/db/names
```

#### 14. 获取表列表

**接口地址：** `GET /api/db/tables`

**请求参数：**
- `dbName` (必需) - 数据库名称

**响应示例：**
```json
{
  "code": 1,
  "data": [
    "Contact",
    "ChatRoom",
    "Message",
    "Session"
  ],
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl "http://localhost:19088/api/db/tables?dbName=MicroMsg.db"

# PowerShell
Invoke-WebRequest -Uri "http://localhost:19088/api/db/tables?dbName=MicroMsg.db"
```

#### 15. 执行 SQL 查询

**接口地址：** `POST /api/db/query`

**请求头：**
- `Content-Type: application/json`

**请求体：**
```json
{
  "dbName": "MicroMsg.db",                    // 必需：数据库名称
  "sql": "SELECT * FROM Contact LIMIT 10"     // 必需：SQL 查询语句
}
```

**响应示例：**
```json
{
  "code": 1,
  "data": [
    {
      "UserName": "wxid_xxx",
      "NickName": "昵称",
      "Alias": "备注"
    }
  ],
  "msg": "success"
}
```

**命令示例：**
```bash
# curl
curl -X POST http://localhost:19088/api/db/query \
  -H "Content-Type: application/json" \
  -d '{"dbName":"MicroMsg.db","sql":"SELECT * FROM Contact LIMIT 10"}'

# PowerShell
$body = @{
  dbName = "MicroMsg.db"
  sql = "SELECT * FROM Contact LIMIT 10"
} | ConvertTo-Json
Invoke-WebRequest -Uri http://localhost:19088/api/db/query -Method POST -ContentType "application/json" -Body $body
```

### 错误处理

所有接口在发生错误时都会返回统一的错误格式：

```json
{
  "code": 0,                    // 0 表示失败
  "data": null,                 // 或包含错误详情对象
  "msg": "错误描述信息"         // 详细的错误信息
}
```

**常见错误：**
- `参数错误: 需要 xxx` - 缺少必需参数
- `方法错误: 需要使用 POST` - HTTP 方法不正确
- `获取联系人失败: ...` - 获取联系人信息失败
- `获取群详情失败: ...` - 获取群聊信息失败
- `未知的 API 端点: xxx` - 请求的 API 端点不存在

## Python 测试脚本

项目根目录提供了 `test_api.py` 测试脚本，可以测试所有 API 端点：

```bash
# 安装依赖
pip install requests

# 运行测试脚本
python test_api.py
```

脚本会自动测试所有可用的 API，包括：
- 健康检查和登录状态
- 联系人和群聊信息
- 数据库查询
- 消息发送功能（默认禁用，需要手动取消注释）

你也可以在脚本中自定义测试参数，例如：

```python
# 发送文本消息
test_send_text_message("wxid_xxx", "测试消息")

# 发送图片消息
test_send_image_message("wxid_xxx", "C:\\path\\to\\image.jpg")

# 发送文件消息
test_send_file_message("wxid_xxx", "C:\\path\\to\\file.pdf")

# 发送拍一拍消息
test_send_pat_message("xxx@chatroom", "wxid_xxx")

# 转发消息
test_forward_message(123456, "wxid_xxx")

# 执行 SQL 查询
test_db_query("MicroMsg.db", "SELECT * FROM Contact LIMIT 10")
```

## 常见问题

### 1. 找不到 WeChat.exe 进程

确保微信已经启动并登录。

### 2. 端口 19088 被占用

可以修改 `agent/wx391027/index.ts` 中的 `HTTP_PORT` 常量。

### 3. 编译错误

确保已安装所有依赖：
```bash
npm install
```

### 4. HTTP 请求失败

检查 Frida 脚本是否成功加载，查看控制台输出是否有错误信息。
