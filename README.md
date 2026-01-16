# Frida-Agent for WeChat

[![Node.js](https://img.shields.io/badge/Node.js-18.x-green.svg)](https://nodejs.org/)
[![Frida](https://img.shields.io/badge/Frida-16.x-orange.svg)](https://frida.re/)
[![WeChat](https://img.shields.io/badge/WeChat-3.9.10.27-blue.svg)](https://pc.weixin.qq.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

基于 Frida 动态插桩框架的微信 Windows 客户端自动化工具。

## ✨ 功能特性

| 功能 | 描述 | 状态 |
|------|------|------|
| 🔐 登录管理 | 检查登录状态、获取用户信息 | ✅ |
| 👥 联系人管理 | 获取联系人列表、查询联系人详情 | ✅ |
| 💬 群聊管理 | 获取群列表、添加/删除群成员 | ✅ |
| 📨 发送消息 | 文本、图片、文件、拍一拍 | ✅ |
| 🎯 @功能 | 在群聊中@指定用户或@所有人 | 🔄 |
| 📰 朋友圈 | 刷新朋友圈、获取动态 | ✅ |
| 🗄️ 数据库 | 直接查询微信SQLite数据库 | ✅ |
| 🎣 消息Hook | 实时接收消息回调 | ✅ |

## 🚀 快速开始

### 环境要求

- Windows 10/11 (64位)
- Node.js 18.x+
- Python 3.8+ (用于 Frida)
- 微信 Windows 3.9.10.27

### 安装

```bash
# 克隆项目
git clone https://github.com/your-repo/frida-agent.git
cd frida-agent

# 安装依赖
npm install

# 安装 Frida CLI
pip install frida-tools
```

### 运行

```bash
# 1. 启动微信并登录

# 2. 编译 TypeScript (开发模式)
npm run watch:wx391027

# 3. 在另一个终端注入到微信
npm run start:wx391027
```

## 📖 使用示例

### 发送文本消息

```typescript
import { messageSendText } from './message.js'

// 发送普通消息
messageSendText('wxid_xxx', 'Hello World')

// 在群聊中@用户
messageSendText('xxx@chatroom', 'Hello', ['wxid_user1'])

// @所有人
messageSendText('xxx@chatroom', 'Hello everyone', ['notify@all'])
```

### 获取联系人列表

```typescript
import { contactList } from './contact.js'

const contacts = contactList()
console.log(`共有 ${contacts.length} 个联系人`)
```

### 查询数据库

```typescript
import { execDbQuery } from './sqlite.js'

const sql = 'SELECT UserName, NickName FROM Contact LIMIT 10'
const results = execDbQuery('MicroMsg.db', sql)
console.log(results)
```

## 📁 项目结构

```
frida-agent/
├── agent/                      # 核心代理代码
│   └── wx391027/              # 微信 3.9.10.27 版本模块
│       ├── index.ts           # 主入口
│       ├── login.ts           # 登录功能
│       ├── contact.ts         # 联系人管理
│       ├── room.ts            # 群聊管理
│       ├── message.ts         # 消息功能
│       ├── sqlite.ts          # 数据库操作
│       └── utils.ts           # 工具函数
├── docs/                       # 文档
│   └── wiki.md                # 详细Wiki文档
├── examples/                   # 示例代码
├── nodejs/                     # Node.js 客户端
├── python/                     # Python 客户端
└── wcf/                        # WeChatFerry 参考代码
```

## 📚 文档

详细文档请查看 [Wiki](docs/wiki.md)

- [API 参考](docs/wiki.md#api参考)
- [偏移地址说明](docs/wiki.md#偏移地址说明)
- [常见问题](docs/wiki.md#常见问题)
- [开发指南](docs/wiki.md#开发指南)

## 🔧 NPM Scripts

| 命令 | 描述 |
|------|------|
| `npm run build` | 编译生产版本 |
| `npm run watch:wx391027` | 开发模式编译 (监听文件变化) |
| `npm run start:wx391027` | 注入到微信进程 |
| `npm run watch:dev` | 开发测试模式 |

## ⚠️ 免责声明

本项目仅供学习研究使用，请勿用于非法用途。使用本工具所产生的一切后果由使用者自行承担。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

[MIT License](LICENSE)

## 🙏 致谢

- [Frida](https://frida.re/) - 动态插桩框架
- [WeChatFerry](https://github.com/lich0821/WeChatFerry) - 参考实现
