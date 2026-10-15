# Frida Agent for WeChat

基于 [Frida](https://frida.re/) 的微信桌面端自动化 Agent：注入进程后提供本地 **HTTP API**（默认 `http://127.0.0.1:19088`），用于发消息、查联系人/群、查库等。

按**微信客户端小版本**拆分实现目录；各版本能力与启动方式见对应 README，本文只做总览与导航。

## 微信版本支持

| 目录 | 微信版本 | 进程 / DLL | 状态 | 说明 |
|--|--|--|--|--|
| [agent/wx391027](./agent/wx391027/README.md) | **3.9.10.27** | `WeChat.exe` | **推荐 / 能力最全** | 对齐 WCF 可用能力：收发消息、媒体、朋友圈、群管理、推送等 |
| [agent/wx411027](./agent/wx411027/README.md) | **4.1.10.27** | `Weixin.exe` / `Weixin.dll` | **可用 / 能力子集** | HTTP 形态对齐 391027；原生发送/解码来自 aixed，联系人/群/历史走 4.x SQLite |
| `agent/wx41730` 等 | 4.1.x 试验 | — | 实验 / 未完成 | 偏移探索与半成品，勿当生产使用 |
| [agent/legacy](./agent/legacy/README.md) | 旧实现 | — | 废弃 | 仅作参考 |

**选型建议**

- 仍使用 **3.9.10.27** → 用 `wx391027`
- 已升级到 **4.1.10.27（新版微信）** → 用 `wx411027`（文件/表情/收消息 Hook 等尚未实现）

## 文档导航

| 文档 | 内容 |
|--|--|
| [agent/wx391027/README.md](./agent/wx391027/README.md) | 3.9.10.27：能力清单、启动方式、完整 HTTP 接口 |
| [agent/wx411027/README.md](./agent/wx411027/README.md) | 4.1.10.27：能力清单、启动方式、已实现 / 未实现接口 |
| [PROJECT_STRUCTURE.md](./PROJECT_STRUCTURE.md) | 仓库目录结构 |
| [docs/](./docs/) | 逆向笔记等（如 `wx-4.1.7.30.md`） |
| [skills/wx-helper](./skills/wx-helper/SKILL.md) | Cursor Skill：通过 HTTP 操作已注入的 Agent |

## 快速开始

依赖安装在 `agent/` 下：

```bash
cd agent
npm install
```

### 3.9.10.27（wx391027）

```bash
cd agent
npm run build:wx391027
npm run start:wx391027
```

### 4.1.10.27（wx411027）

```bash
cd agent
npm run build:wx411027
# Node frida ABI 不匹配时用 Python 注入：
python wx411027/tools/run_agent.py
```

注入成功后探活：

```bash
# 仓库根目录
python skills/wx-helper/scripts/wx_api.py health
```

或：

```bash
curl http://127.0.0.1:19088/api/health
```

统一响应形如：`{ "code": 1, "data": ..., "msg": "success" }`（`code=0` 表示失败或该版本未实现）。

## 项目结构（摘要）

```
frida-agent-example/
├── agent/
│   ├── wx391027/          # 微信 3.9.10.27 Agent（推荐）
│   ├── wx411027/          # 微信 4.1.10.27 Agent
│   ├── legacy/            # 废弃代码
│   └── package.json       # frida-compile / 启动脚本
├── dist/agent/            # 编译产物 *.js
├── skills/wx-helper/      # HTTP 调用封装
├── docs/                  # 版本逆向笔记等
├── web/ server/ client/   # 周边控制台 / 服务（可选）
└── README.md              # 本文件（总览）
```

## 开发约定

- **一版本一目录**：偏移、DLL 名、DB schema 不可混用
- **HTTP 路径尽量对齐**：新版本优先复用 `wx391027` 的路由命名，能力不足时返回明确未实现信息
- **不要**在未确认版本时用错 Agent；`GET /api/health` 的 `version` 字段可核对

## 许可证

见 [LICENSE](./LICENSE)（若仓库内提供）。
