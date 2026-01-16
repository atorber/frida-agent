# 消息推送回调测试服务器

本目录包含用于测试 Frida Agent 消息推送功能的测试服务器脚本。

## 文件说明

- `test_callback_server.py` - Python 版本（推荐，使用标准库）
- `test_callback_server.js` - Node.js 版本
- `test_callback_server.ps1` - PowerShell 版本（Windows）

## 使用方法

### Python 版本（推荐）

```bash
# 使用默认端口 8888
python test_callback_server.py

# 指定端口
python test_callback_server.py --port 8888

# 指定主机和端口（允许外部访问）
python test_callback_server.py --host 0.0.0.0 --port 8888
```

### Node.js 版本

```bash
# 使用默认端口 8888
node test_callback_server.js

# 指定端口
node test_callback_server.js --port 8888

# 指定主机和端口
node test_callback_server.js --host 0.0.0.0 --port 8888
```

### PowerShell 版本（Windows）

```powershell
# 使用默认端口 8888
.\test_callback_server.ps1

# 指定端口
.\test_callback_server.ps1 -Port 8888

# 指定主机和端口
.\test_callback_server.ps1 -Host 0.0.0.0 -Port 8888
```

## 测试步骤

1. **启动测试服务器**

   选择一个脚本启动测试服务器，例如：
   ```bash
   python test_callback_server.py
   ```

2. **在 Frida Agent 中设置推送回调地址**

   **使用 curl (Linux/Mac):**
   ```bash
   curl -X POST http://localhost:19088/api/push/config \
     -H "Content-Type: application/json" \
     -d '{"enabled": true, "callbackUrl": "http://127.0.0.1:8888"}'
   ```

   **使用 PowerShell (Windows):**
   ```powershell
   Invoke-WebRequest -Uri http://localhost:19088/api/push/config -Method POST `
     -ContentType "application/json" `
     -Body '{"enabled": true, "callbackUrl": "http://127.0.0.1:8888"}'
   ```

   **使用 Python requests:**
   ```python
   import requests
   requests.post('http://localhost:19088/api/push/config', json={
       'enabled': True,
       'callbackUrl': 'http://127.0.0.1:8888'
   })
   ```

3. **验证配置**

   ```bash
   curl http://localhost:19088/api/push/config
   ```

   应该返回：
   ```json
   {
     "code": 1,
     "data": {
       "enabled": true,
       "callbackUrl": "http://127.0.0.1:8888"
     },
     "msg": "success"
   }
   ```

4. **发送测试消息**

   在微信中发送任意消息（文本、图片、文件等），测试服务器会自动接收并显示推送的消息。

5. **关闭推送（可选）**

   ```bash
   curl -X POST http://localhost:19088/api/push/config \
     -H "Content-Type: application/json" \
     -d '{"enabled": false}'
   ```

## 输出示例

当收到消息推送时，测试服务器会显示类似以下内容：

```
================================================================================
[2026-01-16 15:30:45] 📨 收到消息推送
================================================================================
消息ID: 1234567890123456789
消息类型: 1
是否自己发送: false
时间戳: 1705392645
发送者ID: wxid_xxxxx
接收者ID: 
群ID: 
消息内容: 这是一条测试消息

完整消息数据:
{
  "id": "1234567890123456789",
  "type": 1,
  "isSelf": false,
  "timestamp": 1705392645,
  "talkerId": "wxid_xxxxx",
  "listenerId": "",
  "roomId": "",
  "text": "这是一条测试消息",
  "mentionIds": [],
  "filename": ""
}
================================================================================
```

## 注意事项

1. **防火墙设置**: 如果使用 `0.0.0.0` 作为主机，确保防火墙允许相应端口的访问。

2. **HTTPS 支持**: 当前测试服务器仅支持 HTTP。如果需要 HTTPS，需要配置 SSL 证书。

3. **网络连接**: 确保 Frida Agent 能够访问测试服务器的地址和端口。

4. **回调地址格式**: 回调地址必须是完整的 URL，例如：
   - ✅ `http://127.0.0.1:8888`
   - ✅ `http://localhost:8888`
   - ✅ `http://192.168.1.100:8888`
   - ❌ `127.0.0.1:8888` (缺少协议)
   - ❌ `localhost:8888` (缺少协议)

## 故障排查

1. **服务器无法启动**
   - 检查端口是否被占用
   - 检查是否有权限监听该端口

2. **收不到推送消息**
   - 确认推送已开启：`curl http://localhost:19088/api/push/config`
   - 检查回调地址是否正确
   - 检查网络连接
   - 查看 Frida Agent 的日志输出

3. **JSON 解析错误**
   - 检查消息格式是否正确
   - 查看 Frida Agent 发送的原始数据
