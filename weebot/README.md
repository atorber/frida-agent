# WeeBot Python

WeeBot 是一个基于 Frida 的微信机器人 GUI 客户端，通过 HTTP API 与微信进行交互，支持消息推送功能。

## 快速开始

### 环境要求

1. **微信版本**: 3.9.10.27
2. **Python版本**: 3.7+
3. **操作系统**: Windows

### 安装依赖

```shell
pip install frida-tools
pip install pyinstaller
```

> **注意**: 
> - `frida-tools` 包含了 `frida` CLI 工具，这是 WeeBot 运行所必需的
> - `tkinter` 是 Python 标准库，通常已包含在 Python 安装中。如果缺失，请根据系统安装相应的 tkinter 包
> - WeeBot 使用 `subprocess` 调用 `frida` CLI，不需要直接使用 `frida` Python 包

### 启动

1. 确保微信已启动（WeChat.exe 正在运行）
2. 运行主程序：

```shell
python WeeBot.py
```

3. 在 GUI 界面中点击"启动"按钮，开始附加到微信进程
4. Agent 启动后，在"消息推送配置"区域配置推送回调地址

## 实现原理

WeeBot 采用 **直接调用 frida CLI** 的方式加载脚本，而不是使用 Python 的 `frida` 包直接加载脚本内容。这种方式的优势：

1. **完全避免脚本格式问题** - frida CLI 自己处理所有脚本格式（包括打包格式、ES6 模块等）
2. **代码简洁** - 不需要复杂的脚本解析逻辑
3. **易于调试** - 日志直接显示 frida CLI 的所有输出
4. **行为一致** - 与命令行 `frida -l xxx.js WeChat.exe` 完全一致
5. **灵活性** - 支持任何 frida-compile 生成的格式

## 功能特性

### 1. Frida Agent 管理
- 一键启动/停止 Frida Agent（通过 frida CLI）
- 自动查找并加载 Frida 脚本
- 实时日志输出（显示 frida CLI 的所有输出）
- 自动检测 WeChat 进程和 frida CLI 是否可用
- API 健康状态监控

### 2. 消息推送配置
- 启用/禁用消息推送
- 配置回调地址（HTTP/HTTPS）
- 实时查看推送配置状态
- 支持通过 HTTP POST 接收消息推送

### 3. HTTP API 访问
- Agent 在 `http://127.0.0.1:19088` 提供 HTTP API 服务
- 支持所有 Agent 提供的 API 接口
- 可通过 GUI 或直接调用 API

## 编译打包

### 快速构建（推荐）

使用提供的构建脚本，一键完成所有步骤：

**Windows:**
```bash
cd weebot
build.bat
```

**Linux/Mac:**
```bash
cd weebot
chmod +x build.sh
./build.sh
```

构建脚本会自动：
1. 编译 Frida 脚本（`npm run build`）
2. 检查脚本文件是否存在
3. 使用 PyInstaller 打包为可执行文件

### 手动构建步骤

#### 步骤 1: 编译 Frida 脚本

在项目根目录执行：

```bash
# 编译到标准输出目录（推荐）
npm run build

# 这会生成 dist/agent/wx391027/index.js
```

或者手动编译：

```bash
# 使用 frida-compile（可以使用 -c 参数，WeeBot 通过 frida CLI 加载）
frida-compile agent/wx391027/index.ts -o dist/agent/wx391027/index.js -c
```

> **重要**: 
> - WeeBot 使用 `frida CLI` 来加载脚本，而不是直接使用 Python API
> - 这种方式完全避免了脚本格式解析问题，支持任何 frida-compile 生成的格式
> - WeeBot 会自动查找 `dist/agent/wx391027/index.js`
> - 确保 `frida` 命令在系统 PATH 中（通过 `pip install frida-tools` 安装）

#### 步骤 2: 安装 Python 依赖

```bash
pip install frida-tools pyinstaller
```

> **注意**: 只需要 `frida-tools`，它包含了 `frida` CLI 工具。WeeBot 使用 `subprocess` 调用 `frida` CLI，不需要直接使用 `frida` Python 包。

#### 步骤 3: 使用 PyInstaller 打包

**方法一：使用 spec 文件（推荐）**

```bash
cd weebot
pyinstaller WeeBot.spec
```

打包后的可执行文件位于 `weebot/dist/WeeBot.exe`

**方法二：使用命令行参数**

```bash
cd weebot
pyinstaller --onefile --windowed --add-data "../dist/agent/wx391027/index.js;dist/agent/wx391027/" WeeBot.py
```

> **注意**: 
> - `--add-data` 中的分号 `;` 是 Windows 路径分隔符（Linux/Mac 使用 `:`）
> - `WeeBot.spec` 已配置自动查找脚本文件，优先使用新路径

### 编译流程总结

完整的编译流程：

```bash
# 1. 安装 Node.js 依赖（如果尚未安装）
npm install

# 2. 编译 Frida 脚本（在项目根目录）
npm run build
# 这会生成 dist/agent/wx391027/index.js

# 3. 进入 weebot 目录
cd weebot

# 4. 安装 Python 依赖（如果尚未安装）
pip install frida pyinstaller

# 5. 使用 PyInstaller 打包
pyinstaller WeeBot.spec

# 6. 打包完成，可执行文件在 dist/WeeBot.exe（约 45MB）
```

### 脚本文件路径

WeeBot 会查找以下路径的脚本文件：

1. `dist/agent/wx391027/index.js`（打包后的路径）
2. `../dist/agent/wx391027/index.js`（开发环境路径）

如果找不到脚本文件，程序会提示错误并要求先运行 `npm run build`。

### 验证编译结果

编译完成后，可执行文件位于 `weebot/dist/WeeBot.exe`，文件大小约 45MB。

**运行可执行文件：**

1. 确保微信已启动（WeChat.exe 正在运行）
2. 双击运行 `dist/WeeBot.exe`
3. 在 GUI 界面中点击"启动"按钮

> **注意**: 
> - 首次运行可能需要管理员权限（Frida 附加进程需要）
> - 如果遇到 DLL 缺失警告，这是正常的，这些是 Windows 系统 DLL，会在运行时自动加载
> - 确保防火墙允许 HTTP API 服务（端口 19088）

## 使用说明

### 启动 Agent

1. 确保微信（WeChat.exe）已启动
2. 点击"启动"按钮
3. 等待日志显示"API 服务连接成功"
4. 此时 Agent 已在 `http://127.0.0.1:19088` 提供 HTTP API 服务

### 配置消息推送

1. 在"消息推送配置"区域：
   - 勾选"启用消息推送"复选框
   - 输入回调地址（例如：`http://127.0.0.1:8888`）
   - 点击"设置推送配置"按钮

2. 回调地址要求：
   - 必须是完整的 HTTP/HTTPS URL
   - 例如：`http://127.0.0.1:8888` 或 `https://your-server.com/webhook`

3. 查看当前配置：
   - 点击"刷新配置"按钮可查看当前推送配置状态

4. 消息推送格式：
   - Agent 会通过 HTTP POST 将消息推送到配置的回调地址
   - 请求体为 JSON 格式，包含完整的消息信息

### 消息推送格式

当收到新消息时，Agent 会向配置的回调地址发送 HTTP POST 请求：

**请求格式：**
```
POST {callbackUrl} HTTP/1.1
Content-Type: application/json

{
  "id": "消息ID",
  "type": 1,
  "text": "消息内容",
  "talkerId": "发送者ID",
  "roomId": "群ID（如果是群消息）",
  "listenerId": "接收者ID",
  "timestamp": 1234567890,
  "isSelf": false
}
```

**消息类型：**
- `type: 1` - 文本消息
- `type: 3` - 图片消息
- `type: 49` - 文件消息

**字段说明：**
- `id`: 消息唯一标识
- `type`: 消息类型
- `text`: 消息文本内容
- `talkerId`: 发送者微信ID（一对一聊天时）或群内发送者ID（群聊时）
- `roomId`: 群ID（群消息时存在，一对一消息为空）
- `listenerId`: 接收者ID（一对一聊天时，自己发送的消息）
- `isSelf`: 是否为自己发送的消息
- `timestamp`: 消息时间戳

## HTTP API 接口

Agent 在 `http://127.0.0.1:19088` 端口提供 HTTP API 服务，可以通过 HTTP 请求控制微信。

### API 端点列表

1. **健康检查**
   ```
   GET /api/health
   ```

2. **检查登录状态**
   ```
   GET /api/checkLogin
   ```

3. **获取登录用户信息**
   ```
   GET /api/contacts/self
   ```

4. **获取联系人列表**
   ```
   GET /api/contacts
   ```

5. **获取联系人详情**
   ```
   GET /api/contact?contactId=wxid_xxx
   ```

6. **获取群列表**
   ```
   GET /api/rooms
   ```

7. **获取群详情**
   ```
   GET /api/room?roomId=xxx@chatroom
   ```

8. **发送文本消息**
   ```
   POST /api/message/text
   Content-Type: application/json
   
   {
     "contactId": "wxid_xxx",
     "text": "Hello World",
     "atWxids": ["wxid_xxx"]  // 可选，群聊时@用户
   }
   ```

9. **发送图片消息**
   ```
   POST /api/message/image
   Content-Type: application/json
   
   {
     "contactId": "wxid_xxx",
     "path": "C:\\path\\to\\image.jpg"
   }
   ```

10. **发送文件消息**
    ```
    POST /api/message/file
    Content-Type: application/json
    
    {
      "contactId": "wxid_xxx",
      "path": "C:\\path\\to\\file.txt"
    }
    ```

11. **发送拍一拍**
    ```
    POST /api/message/pat
    Content-Type: application/json
    
    {
      "roomId": "xxx@chatroom",
      "contactId": "wxid_xxx"
    }
    ```

12. **转发消息**
    ```
    POST /api/message/forward
    Content-Type: application/json
    
    {
      "msgId": "消息ID",
      "contactId": "接收者ID"
    }
    ```

13. **获取推送配置**
    ```
    GET /api/push/config
    ```

14. **设置推送配置**
    ```
    POST /api/push/config
    Content-Type: application/json
    
    {
      "enabled": true,
      "callbackUrl": "http://127.0.0.1:8888"
    }
    ```

15. **获取数据库名称列表**
    ```
    GET /api/db/names
    ```

16. **获取数据库表列表**
    ```
    GET /api/db/tables?dbName=MicroMsg.db
    ```

17. **执行数据库查询**
    ```
    POST /api/db/query
    Content-Type: application/json
    
    {
      "dbName": "MicroMsg.db",
      "sql": "SELECT * FROM Contact LIMIT 10"
    }
    ```

### 响应格式

所有 API 响应统一格式：

```json
{
  "code": 1,
  "data": {},
  "msg": "success"
}
```

- `code: 1` 表示成功，`code: 0` 表示失败
- `data` 包含返回的数据
- `msg` 包含状态消息或错误信息

### API 调用示例

```bash
# 获取联系人列表
curl http://127.0.0.1:19088/api/contacts

# 发送文本消息
curl -X POST http://127.0.0.1:19088/api/message/text \
  -H "Content-Type: application/json" \
  -d '{"contactId": "wxid_xxx", "text": "Hello"}'

# 设置推送配置
curl -X POST http://127.0.0.1:19088/api/push/config \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "callbackUrl": "http://127.0.0.1:8888"}'

# 获取推送配置
curl http://127.0.0.1:19088/api/push/config
```

## 项目结构

```
weebot/
├── WeeBot.py              # 主程序文件
├── WeeBot.spec            # PyInstaller 配置文件
├── build.bat / build.sh   # 构建脚本
├── setup.py               # Python 包配置
├── dist/                  # 打包输出目录
│   └── WeeBot.exe         # 打包后的可执行文件
└── build/                 # PyInstaller 临时文件

注意: Frida 脚本位于 ../dist/agent/wx391027/index.js（需要先运行 npm run build）
```

## 注意事项

1. **运行前确保微信（WeChat.exe）已启动**
2. **首次运行可能需要管理员权限**（Frida 附加进程需要）
3. **确保防火墙允许 HTTP API 服务**（端口 19088）
4. **消息推送回调地址必须是可访问的 HTTP/HTTPS URL**
5. **建议在本地或内网环境使用，避免暴露到公网**

## 常见问题

### Q: Agent 启动失败？
A: 检查以下几点：
- 微信是否已启动
- 是否有管理员权限
- Frida 脚本文件是否存在（运行 `npm run build`）

### Q: 无法连接到 API？
A: 检查：
- Agent 是否成功启动（查看日志）
- 端口 19088 是否被占用
- 防火墙是否允许该端口

### Q: 消息推送不工作？
A: 检查：
- 推送是否已启用
- 回调地址格式是否正确（必须是 http:// 或 https:// 开头）
- 回调服务器是否可访问
- 查看 Agent 日志中的推送错误信息

### Q: 如何测试消息推送？
A: 可以使用简单的 HTTP 服务器接收推送：
```python
# test_callback_server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        message = json.loads(body.decode('utf-8'))
        print(f"收到消息: {json.dumps(message, indent=2, ensure_ascii=False)}")
        self.send_response(200)
        self.end_headers()

httpd = HTTPServer(('127.0.0.1', 8888), Handler)
httpd.serve_forever()
```

运行后，在 WeeBot 中设置回调地址为 `http://127.0.0.1:8888` 即可。
