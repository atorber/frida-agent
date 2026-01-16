# 项目目录结构

```
frida-agent/
├── agent/                    # Frida Agent 源代码
│   ├── wx391027/            # 微信 3.9.10.27 版本实现
│   │   ├── index.ts         # 主入口文件
│   │   ├── login.ts         # 登录相关功能
│   │   ├── contact.ts       # 联系人相关功能
│   │   ├── room.ts          # 群聊相关功能
│   │   ├── message.ts       # 消息相关功能
│   │   ├── sqlite.ts        # 数据库相关功能
│   │   ├── offset.ts        # 内存偏移地址
│   │   ├── utils.ts         # 工具函数
│   │   ├── types.ts         # 类型定义
│   │   ├── test.ts          # 测试代码
│   │   └── README.md        # 功能清单
│   ├── wx391217/            # 微信 3.9.12.17 版本实现
│   └── legacy/              # 旧版本代码（已废弃）
│
├── dist/                     # 编译输出目录
│   └── agent/
│       └── wx391027/
│           └── index.js     # 编译后的 JavaScript 文件
│
├── tests/                    # 测试脚本目录
│   ├── test_callback_server.py    # 回调测试服务器（Python）
│   ├── test_callback_server.js    # 回调测试服务器（Node.js）
│   ├── test_callback_server.ps1   # 回调测试服务器（PowerShell）
│   ├── test_api.py          # API 测试脚本
│   └── README_CALLBACK_TEST.md    # 回调测试说明
│
├── docs/                     # 文档目录
│   ├── api-reference.md     # API 参考文档
│   ├── wiki.md              # Wiki 文档
│   └── START.md             # 启动指南
│
├── examples/                 # 示例代码
│   ├── http-client.js       # HTTP 客户端示例
│   ├── ws-server.js         # WebSocket 服务器示例
│   └── ...
│
├── scripts/                  # 工具脚本目录（可选）
│
├── types/                    # TypeScript 类型定义
│   └── @frida/              # Frida 类型定义
│
├── nodejs/                   # Node.js 客户端
├── python/                   # Python 客户端
├── weebot/                   # WeeBot GUI 应用
├── sidecar/                  # Sidecar 相关代码
├── wcf/                      # WeChatFerry C++ 代码
│
├── package.json              # Node.js 项目配置
├── tsconfig.json             # TypeScript 配置
├── README.md                 # 项目主文档
└── PROJECT_STRUCTURE.md     # 本文件
```

## 目录说明

### agent/
Frida Agent 的源代码目录，按微信版本组织。

- `wx391027/` - 微信 3.9.10.27 版本的完整实现
- `wx391217/` - 微信 3.9.12.17 版本的实现
- `legacy/` - 旧版本代码，已废弃但保留用于参考

### dist/
编译输出目录，包含编译后的 JavaScript 文件。

### tests/
测试脚本目录，包含各种测试工具。

### docs/
项目文档目录，包含 API 文档、使用指南等。

### examples/
示例代码目录，包含各种使用示例。

### types/
TypeScript 类型定义目录。

## 编译和构建

```bash
# 编译 wx391027 版本
npm run build

# 或者使用 frida-compile 直接编译
frida-compile agent/wx391027/index.ts -o dist/agent/wx391027/index.js -c
```

## 开发规范

1. **源代码**：放在 `agent/` 目录下，按版本组织
2. **编译产物**：统一放在 `dist/` 目录
3. **测试脚本**：放在 `tests/` 目录
4. **文档**：放在 `docs/` 目录
5. **示例代码**：放在 `examples/` 目录

## 清理编译文件

编译后的 `.js` 文件会自动生成在 `dist/` 目录，不要将编译产物提交到版本控制。

如果需要清理编译文件：

```bash
# 删除所有编译文件
rm -rf dist/
# 或 Windows
Remove-Item -Recurse -Force dist\
```
