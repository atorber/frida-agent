# wx391027 Apps Server

会话侧栏三应用（助手 / 速记 / 工具）的独立 Node.js 后端，SQLite 持久化；助手与工具走真实大模型（OpenAI 兼容接口）。**不代发微信消息**，前端仅填入输入框。

## 启动

```bash
cd server
npm install
cp .env.example .env   # Windows: copy .env.example .env
# 编辑 .env，填写 OPENAI_API_KEY / LLM_API_KEY（及可选 BASE_URL / MODEL）
npm run dev
```

当前使用 **sql.js**（纯 JS SQLite，无需本机 C++ 编译）。数据库文件：`server/data/apps.db`。

## 环境变量

| 变量 | 默认 | 说明 |
|--|--|--|
| `APPS_PORT` | `19089` | 监听端口 |
| `APPS_DB_PATH` | `server/data/apps.db` | SQLite 路径 |
| `LLM_API_KEY` / `OPENAI_API_KEY` | （必填） | 大模型 API Key |
| `LLM_BASE_URL` / `OPENAI_API_URL` | `https://api.openai.com/v1` | 兼容 `/chat/completions` 的基址 |
| `LLM_MODEL` / `OPENAI_MODEL` | `gpt-4o-mini` | 模型名 |
| `LLM_TIMEOUT_MS` | `60000` | 请求超时 |

示例：

```env
OPENAI_API_KEY=sk-xxx
OPENAI_API_URL=https://llm-xxx.cn-beijing.maas.aliyuncs.com/compatible-mode/v1
OPENAI_MODEL=deepseek-v4-flash
```

## 前端代理

Vite 开发态将 `/apps` 代理到本服务；Agent 仍走 `/api` → `19088`。

## API（均返回 `{ code, data, msg }`，`code=1` 成功）

### 健康

| 方法 | 路径 | 说明 |
|--|--|--|
| GET | `/apps/health` | 健康检查（含 `llm.configured`） |

### 助手

| 方法 | 路径 | 说明 |
|--|--|--|
| GET | `/apps/assistant/context?talker=&name=` | 情境/建议/历史（缓存优先） |
| POST | `/apps/assistant/analyze` | `{ talker, name?, context?, force?, mode? }` 生成情境/建议（按会话指纹缓存；mode: 'both'|'insight'|'suggest'） |
| POST | `/apps/assistant/chat` | `{ talker, prompt, name?, context?, temperature?, maxTokens? }` |
| POST | `/apps/assistant/chat/stream` | 同上，SSE：`user` / `delta` / `done` / `error` |
| DELETE | `/apps/assistant/messages?talker=` | 清空助手历史 |

### 速记

| 方法 | 路径 | 说明 |
|--|--|--|
| GET | `/apps/notes?talker=&tag=` | 列表（置顶优先；可选标签过滤） |
| GET | `/apps/notes/tags` | 允许标签：`待办/报价/风险/其他` |
| POST | `/apps/notes` | `{ talker, text, tags?, pinned? }` |
| PATCH | `/apps/notes/:id` | `{ text?, tags?, pinned? }` 编辑/置顶/改标签 |
| DELETE | `/apps/notes/:id` | 删除 |

### 工具（四件套）

| 方法 | 路径 | 说明 |
|--|--|--|
| GET | `/apps/toolkit/tools` | `reply_draft` / `summarize` / `polish` / `translate` |
| POST | `/apps/toolkit/run` | `{ talker, toolId, name?, draft?, context?, direction?, temperature?, maxTokens? }` |
| GET | `/apps/toolkit/history?talker=&limit=` | 运行历史 |

`context` 可选：传入微信近期消息摘录，帮助模型结合真实会话。
`direction`：翻译工具 `zh2en`（默认）或 `en2zh`。

### Agent 消息 Hook

Agent 开启推送后，将微信消息 POST 到本服务，内部抛出 **`onMessage`** 事件，供其他模块订阅。

| 方法 | 路径 | 说明 |
|--|--|--|
| POST | `/apps/hook` | 接收 Agent `Message` JSON，emit `onMessage` |
| GET | `/apps/hook` | Hook 状态（监听数、最近一条预览） |

Agent 配置示例：

```bash
curl -X POST "http://127.0.0.1:19088/api/push/config" \
  -H "Content-Type: application/json" \
  -d "{\"enabled\":true,\"callbackUrl\":\"http://127.0.0.1:19089/apps/hook\"}"
```

在 Apps Server 内订阅：

```js
import { onMessage } from './messageBus.js'
// 或：import { onMessage } from './index.js'

onMessage((msg) => {
  // msg: { id, text, type, talkerId, roomId, isSelf, ... }
  console.log('realtime', msg.talkerId, msg.text)
})
```
