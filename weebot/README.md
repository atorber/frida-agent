# WeeBot Python

WeeBot 是一个基于 Frida 的微信机器人，支持通过 WebSocket 接口与微信进行交互。

## 快速开始

### 环境要求

1. **微信版本**: 3.9.10.27
2. **Python版本**: 3.7+
3. **操作系统**: Windows

### 安装依赖

```shell
pip install frida
pip install frida-tools
pip install websockets
```

> **注意**: `tkinter` 是 Python 标准库，通常已包含在 Python 安装中。如果缺失，请根据系统安装相应的 tkinter 包。

### 启动

1. 确保微信已启动（WeChat.exe 正在运行）
2. 运行主程序：

```shell
python WeeBot.py
```

3. 在 GUI 界面中点击"启动"按钮，开始附加到微信进程

## 编译打包

### 前置步骤：编译 Frida 脚本

在项目根目录下，需要先将 TypeScript 源文件编译为 JavaScript：

**方法一：编译到 weebot 目录（推荐）**

```bash
# 在项目根目录执行，直接编译到 weebot 目录
# 注意：不要使用 -c 参数，否则会生成打包格式，Python 无法直接加载
frida-compile agent/xp-3.9.10.27.ts -o weebot/xp-3.9.10.27.js
```

或者编译 `agent/wx391027/index.ts`（推荐使用这个，功能更完整）：

```bash
frida-compile agent/wx391027/index.ts -o weebot/xp-3.9.10.27.js
```

> **重要**: 
> - 如果使用 `-c` 参数会生成打包格式（以 `📦` 开头），Python 的 `create_script()` 无法直接加载。代码已添加自动提取功能，但建议使用不带 `-c` 的编译方式。
> - 如果遇到类型定义错误，确保 `types/@frida/index.d.ts` 文件存在。

**方法二：使用 npm 脚本后复制文件**

```bash
# 在项目根目录执行
npm run build:lite

# 然后将编译好的文件复制到 weebot 目录
copy dist\xp-3.9.10.27.js weebot\xp-3.9.10.27.js
# 或 Linux/Mac:
# cp dist/xp-3.9.10.27.js weebot/xp-3.9.10.27.js
```

> **注意**: 确保 `weebot/xp-3.9.10.27.js` 文件存在后再进行 PyInstaller 打包

### 使用 PyInstaller 打包

#### 方法一：使用 spec 文件（推荐）

```bash
cd weebot
pyinstaller WeeBot.spec
```

打包后的可执行文件位于 `dist/WeeBot.exe`

#### 方法二：使用命令行参数

**打包为单文件（带控制台窗口）**：
```bash
pyinstaller --onefile --add-data "xp-3.9.10.27.js;." WeeBot.py
```

**打包为单文件（无控制台窗口，GUI应用）**：
```bash
pyinstaller --onefile --windowed --add-data "xp-3.9.10.27.js;." WeeBot.py
```

**打包为单文件（无控制台窗口，无调试信息）**：
```bash
pyinstaller --onefile --windowed --noconsole --add-data "xp-3.9.10.27.js;." WeeBot.py
```

> **注意**: 
> - `--add-data "xp-3.9.10.27.js;."` 中的分号 `;` 是 Windows 路径分隔符
> - 确保 `xp-3.9.10.27.js` 文件已存在于 `weebot` 目录中
> - 打包前需要先安装 PyInstaller: `pip install pyinstaller`

### 编译流程总结

完整的编译流程：

```bash
# 1. 安装 Node.js 依赖（如果尚未安装）
npm install

# 2. 编译 Frida 脚本到 weebot 目录（不使用 -c 参数）
frida-compile agent/xp-3.9.10.27.ts -o weebot/xp-3.9.10.27.js

# 3. 进入 weebot 目录
cd weebot

# 4. 安装 Python 依赖（如果尚未安装）
pip install frida websockets pyinstaller

# 5. 使用 PyInstaller 打包
pyinstaller WeeBot.spec

# 6. 打包完成，可执行文件在 dist/WeeBot.exe（约 45MB）
```

### 验证编译结果

编译完成后，可执行文件位于 `weebot/dist/WeeBot.exe`，文件大小约 45MB。

**运行可执行文件：**

1. 确保微信已启动（WeChat.exe 正在运行）
2. 双击运行 `dist/WeeBot.exe`
3. 在 GUI 界面中点击"启动"按钮

> **注意**: 
> - 首次运行可能需要管理员权限（Frida 附加进程需要）
> - 如果遇到 DLL 缺失警告，这是正常的，这些是 Windows 系统 DLL，会在运行时自动加载
> - 确保防火墙允许 HTTP API 服务（端口 19088）和 WebSocket 服务（端口 19099）

## 功能说明

### HTTP API 接口

WeeBot 启动后会在 `localhost:19088` 端口提供 HTTP API 服务，可以通过 HTTP 请求控制微信。

**API 端点：**

1. **获取登录用户信息**
   ```
   GET /api/contacts/self
   ```

2. **获取联系人列表**
   ```
   GET /api/contacts
   ```

3. **获取群列表**
   ```
   GET /api/rooms
   ```

4. **获取联系人详情**
   ```
   GET /api/contact?contactId=wxid_xxx
   ```

5. **获取群详情**
   ```
   GET /api/room?roomId=xxx@chatroom
   ```

6. **发送文本消息**
   ```
   POST /api/message/text
   Content-Type: application/json
   
   {
     "contactId": "wxid_xxx",
     "text": "Hello World"
   }
   ```

7. **检查登录状态**
   ```
   GET /api/checkLogin
   ```

8. **获取数据库名称列表**
   ```
   GET /api/db/names
   ```

9. **获取数据库表列表**
   ```
   GET /api/db/tables?dbName=MicroMsg.db
   ```

10. **执行数据库查询**
    ```
    POST /api/db/query
    Content-Type: application/json
    
    {
      "dbName": "MicroMsg.db",
      "sql": "SELECT * FROM Contact LIMIT 10"
    }
    ```

**响应格式：**
```json
{
  "code": 1,
  "data": {},
  "msg": "success"
}
```

**示例：**
```bash
# 获取联系人列表
curl http://localhost:19088/api/contacts

# 发送消息
curl -X POST http://localhost:19088/api/message/text \
  -H "Content-Type: application/json" \
  -d '{"contactId": "wxid_xxx", "text": "Hello"}'
```

### WebSocket 接口

WeeBot 启动后会在 `localhost:19099` 端口提供 WebSocket 服务，客户端可以通过 WebSocket 连接接收微信消息。

### 消息类型

- **文本消息**: `type` 字段为文本类型
- **图片消息**: `type` 为 3，包含加密的图片文件路径，程序会自动解密并保存
- **文件消息**: `type` 为 49，包含文件路径

### 消息格式

通过 WebSocket 接收的消息为 JSON 格式，包含以下字段：

```json
{
  "id": "消息ID",
  "type": "消息类型",
  "text": "消息内容",
  "talkerId": "发送者ID",
  "filename": "文件路径（如果是文件/图片消息）"
}
```

## 接口说明

WeeBot 提供两种接口方式：**HTTP API** 和 **WebSocket**。

### HTTP API 接口

Frida 脚本在 `localhost:19088` 端口提供 HTTP API 服务。

#### 1. 获取登录用户信息

**接口**: `GET /api/contacts/self`

**请求示例**:
```bash
curl http://localhost:19088/api/contacts/self
```

**响应格式**:
```json
{
  "code": 1,
  "msg": "success",
  "data": {
    "id": "wxid_xxx",
    "name": "用户名",
    "weixin": "微信号",
    "mobile": "手机号",
    "city": "城市",
    "province": "省份",
    "avatar": "头像URL",
    "signature": "个性签名"
  }
}
```

**兼容接口**: `GET /api/userInfo` (兼容 wxhelper API)

#### 2. 获取联系人列表

**接口**: `GET /api/contacts`

**请求示例**:
```bash
curl http://localhost:19088/api/contacts
```

**响应格式**:
```json
{
  "code": 1,
  "msg": "success",
  "data": [
    {
      "id": "wxid_xxx",
      "name": "联系人昵称",
      "weixin": "微信号",
      "type": 1,
      "avatar": "头像URL"
    }
  ]
}
```

**兼容接口**: 
- `GET /api/getContactList` (兼容 wxhelper API)
- `GET /api/getcontactlist` (兼容 wechat-bot API)

#### 3. 获取群列表

**接口**: `GET /api/rooms`

**请求示例**:
```bash
curl http://localhost:19088/api/rooms
```

**响应格式**:
```json
{
  "code": 1,
  "msg": "success",
  "data": [
    {
      "id": "xxx@chatroom",
      "name": "群名称"
    }
  ]
}
```

#### 4. 发送文本消息

**接口**: `POST /api/message/text`

**请求示例**:
```bash
curl -X POST http://localhost:19088/api/message/text \
  -H "Content-Type: application/json" \
  -d '{"contactId": "wxid_xxx", "text": "消息内容"}'
```

**请求参数**:
```json
{
  "contactId": "接收者微信ID（可以是联系人ID或群ID）",
  "text": "要发送的文本消息"
}
```

**响应格式**:
```json
{
  "code": 1,
  "msg": "success",
  "data": 1
}
```
- `data: 1` 表示发送成功
- `data: 0` 表示发送失败

**兼容接口**:
- `POST /api/sendTextMsg` (兼容 wxhelper API，参数: `{"wxid": "xxx", "msg": "xxx"}`)
- `POST /api/sendtxtmsg` (兼容 wechat-bot API，参数: `{"wxid": "xxx", "content": "xxx"}`)

### WebSocket 接口

WeeBot 在 `localhost:19099` 端口提供 WebSocket 服务，用于实时接收微信消息。

#### 连接 WebSocket

```javascript
const ws = new WebSocket('ws://localhost:19099');

ws.on('open', () => {
  console.log('已连接到 WeeBot WebSocket 服务');
});

ws.on('message', (data) => {
  const message = JSON.parse(data);
  console.log('收到消息:', message);
});
```

#### 接收消息格式

通过 WebSocket 接收的消息为 JSON 格式：

```json
{
  "id": "消息ID",
  "type": 1,
  "text": "消息内容",
  "talkerId": "发送者ID",
  "roomId": "群ID（如果是群消息）",
  "timestamp": 1234567890,
  "isSelf": false,
  "filename": "文件路径（如果是文件/图片消息）"
}
```

**消息类型说明**:
- `type: 1` - 文本消息
- `type: 3` - 图片消息（`filename` 字段包含解密后的图片路径）
- `type: 49` - 文件消息（`filename` 字段包含文件路径）

**字段说明**:
- `talkerId`: 发送者微信ID（一对一聊天时）或群内发送者ID（群聊时）
- `roomId`: 群ID（群消息时存在，一对一消息为空）
- `listenerId`: 接收者ID（一对一聊天时，自己发送的消息）
- `isSelf`: 是否为自己发送的消息

### 发送消息（通过 Frida 脚本）

目前 WeeBot 通过 Frida 脚本的 `script.post()` 方法发送消息，需要在 Python 代码中实现：

```python
# 在 WeeBot.py 中发送消息
script.post({
    'type': 'send',
    'payload': {
        'text': '消息内容',
        'contactId': '接收者ID',
    }
})
```

> **注意**: 当前版本中，建议使用 HTTP API (`/api/message/text`) 发送消息，这是更稳定的方式。

## 项目结构

```
weebot/
├── WeeBot.py              # 主程序文件
├── WeeBot.spec            # PyInstaller 配置文件
├── xp-3.9.10.27.js        # Frida 脚本（需要从 TypeScript 编译）
├── setup.py               # Python 包配置
├── dist/                  # 打包输出目录
│   └── WeeBot.exe         # 打包后的可执行文件
└── build/                 # PyInstaller 临时文件
```

## 注意事项

1. 运行前确保微信（WeChat.exe）已启动
2. 首次运行可能需要管理员权限（Frida 附加进程需要）
3. 确保防火墙允许 WebSocket 服务（端口 19099）
4. 图片解密功能需要访问微信文件目录：`%USERPROFILE%\Documents\WeChat Files\`
