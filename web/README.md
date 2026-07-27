# Relay · IM 控制台

面向运营与调试的即时通讯工作台，连接 wx391027 Agent，侧栏应用走独立 Apps Server。

## 启动

需要同时启动 **Agent（19088）**、**Apps Server（19089）**、**Web**：

```bash
# 1) 应用后端（助手/速记/工具 + SQLite）
cd server
npm install
npm run dev

# 2) Web 控制台
cd web
npm install
npm run dev
```

Agent 注入另按 `agent/wx391027` 文档启动。

打开终端中的 Local / Network 地址。开发态代理：

| 前缀 | 目标 |
|--|--|
| `/api` | Agent `http://127.0.0.1:19088` |
| `/apps` | Apps Server `http://127.0.0.1:19089` |

**局域网访问请勿把 Agent 填成 `127.0.0.1`**（侧栏头像 → 连接设置，推荐同源代理）。

## 信息架构

| 导航 | 作用 |
|--|--|
| 会话 | 近期对话、消息流、右侧应用坞（助手/速记/工具）、选文件发送 |
| 人脉 | 联系人资料与发起私信 |
| 群组 | 群资料、成员宫格、添加/移出 |
| 设置 | 服务、接收、推送、数据库、媒体工具 |

## 说明

- 发图片/文件：本机选择 → `POST /api/upload` → 再调用发送接口
- 侧栏三应用（助手 / 速记 / 工具）：数据在 `server/data/apps.db`，LLM 见 `server/.env`（`OPENAI_*` / `LLM_*`）
  - **助手**：情境/建议走 LLM 分析缓存；对话支持流式 SSE；可存速记；可调 temperature / maxTokens
  - **速记**：编辑、置顶、标签（待办/报价/风险/其他）与过滤
  - **工具**：回复草案 / 摘要 / 润色 / 翻译；结果可填入输入框或存速记；**不自动发微信**
  - **实时消息**：Agent 推送回调指向 `http://…:19089/apps/hook` 后，Apps Server 抛出 `onMessage`（见 `server/README.md`）
- 消息靠历史轮询；推送需在「设置」开启并指向上述 Hook
- 需 Agent 已注入并监听 `19088`
