# WeChat Frida Agent Client 示例

这是一个使用 TypeScript SDK 调用 WeChat Frida Agent API 的完整示例。

## 前置要求

1. **Frida Agent 已启动**
   - 确保 Frida Agent 正在运行
   - HTTP 服务器监听在 `http://localhost:19088`

2. **回调测试服务器（可选）**
   - 用于接收消息推送
   - 运行: `python tests/test_callback_server.py`

3. **Node.js 环境**
   - Node.js 16+ 
   - 已安装依赖: `npm install`

## 安装依赖

```bash
cd client
npm install
```

或者在项目根目录：

```bash
npm install
```

## 运行示例

```bash
# 使用 ts-node 运行
npx ts-node client/start.ts

# 或者使用 npm 脚本
npm run start --prefix client

# 或者使用 watch 模式（自动重新运行）
npm run dev --prefix client
```

## 示例内容

示例脚本会依次执行以下操作：

1. ✅ 检查服务器状态
2. ✅ 检查登录状态
3. ✅ 设置消息推送（开启推送并设置回调地址）
4. ✅ 获取自己的信息
5. ✅ 获取联系人列表
6. ✅ 获取联系人详情
7. ✅ 获取群列表
8. ✅ 获取群详情
9. 📝 发送文本消息示例（代码示例，未实际发送）
10. 📝 发送图片消息示例
11. 📝 发送文件消息示例
12. 📝 发送拍一拍示例
13. 📝 转发消息示例
14. ✅ 数据库查询示例
15. 📝 SQL 查询示例（代码示例）
16. ✅ 获取推送配置

## 自定义配置

编辑 `start.ts` 文件，修改以下配置：

```typescript
const API_BASE_URL = 'http://localhost:19088';  // Frida Agent API 地址
const CALLBACK_URL = 'http://localhost:8888';  // 回调服务器地址
```

## 实际发送消息

默认情况下，发送消息的代码被注释掉了，避免误发消息。

要实际发送消息，请取消注释相关代码：

```typescript
// 取消注释以实际发送消息
try {
    await sdk.sendTextMessage('filehelper', `测试消息 ${new Date().toLocaleString()}`);
    console.log('✅ 消息发送成功\n');
} catch (error: any) {
    console.error('❌ 发送失败:', error.message, '\n');
}
```

## 输出示例

```
================================================================================
WeChat Frida Agent SDK 使用示例
================================================================================
API 地址: http://localhost:19088
回调地址: http://localhost:8888

📡 步骤 1: 检查服务器状态...
✅ 服务器运行正常
   状态: ok
   可用 API 数量: 12

🔐 步骤 2: 检查登录状态...
✅ 微信已登录

📨 步骤 3: 设置消息推送...
✅ 消息推送已开启
   回调地址: http://localhost:8888
   状态: 已启用

...
```

## 故障排查

### 连接失败

如果出现 "服务器连接失败" 错误：

1. 确保 Frida Agent 已启动
2. 检查 API 地址是否正确
3. 检查防火墙设置

### 登录状态检查失败

如果显示 "微信未登录"：

1. 确保微信已启动并登录
2. 检查 Frida Agent 是否正确附加到微信进程

### 推送设置失败

如果推送设置失败：

1. 检查回调地址格式是否正确（必须是 http:// 或 https:// 开头）
2. 确保回调测试服务器已启动（可选）

## 相关文档

- [SDK 文档](../sdk/README.md)
- [API 参考文档](../docs/api-reference.md)
- [回调测试说明](../tests/README_CALLBACK_TEST.md)
