# Frida Agent for WeChat

基于 Frida 的微信自动化工具，支持微信 3.9.10.27 版本。

## 功能特性

- ✅ 查询登录状态
- ✅ 获取联系人列表和详情
- ✅ 获取群列表和详情
- ✅ 发送文本、图片、文件消息
- ✅ 支持 @ 消息和拍一拍
- ✅ 消息转发
- ✅ 接收消息推送（支持回调）
- ✅ 数据库查询
- ✅ HTTP API 接口

详细功能清单请查看 [agent/wx391027/README.md](./agent/wx391027/README.md)

## 快速开始

### 1. 安装依赖

```bash
npm install
```

### 2. 编译脚本

```bash
npm run build
```

或者：

```bash
frida-compile agent/wx391027/index.ts -o dist/agent/wx391027/index.js -c
```

### 3. 启动微信并加载脚本

```bash
npm run start:wx391027
```

或者：

```bash
frida -l dist/agent/wx391027/index.js WeChat.exe
```

### 4. 测试 API

脚本加载成功后，HTTP 服务器会在 `http://localhost:19088` 启动。

```bash
# 检查服务器状态
curl http://localhost:19088/api/health

# 检查登录状态
curl http://localhost:19088/api/checkLogin

# 获取联系人列表
curl http://localhost:19088/api/contacts
```

## 项目结构

详细的项目结构请查看 [PROJECT_STRUCTURE.md](./PROJECT_STRUCTURE.md)

```
frida-agent/
├── agent/              # Frida Agent 源代码
│   └── wx391027/      # 微信 3.9.10.27 版本实现
├── dist/              # 编译输出
├── tests/             # 测试脚本
├── docs/              # 文档
└── examples/          # 示例代码
```

## 文档

- [启动指南](./docs/START.md)
- [API 参考文档](./docs/api-reference.md)
- [Wiki](./docs/wiki.md)
- [项目结构说明](./PROJECT_STRUCTURE.md)
- [回调测试说明](./tests/README_CALLBACK_TEST.md)

## 开发

### 开发模式（自动重新编译）

```bash
npm run watch:wx391027
```

### 运行测试

```bash
# 启动回调测试服务器
python tests/test_callback_server.py

# 运行 API 测试
python tests/test_api.py
```

## 许可证

[LICENSE](./LICENSE)

## 贡献

欢迎提交 Issue 和 Pull Request！
