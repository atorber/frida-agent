import cors from 'cors'
import express from 'express'
import { loadEnvFile } from './env.js'
import assistantRouter from './routes/assistant.js'
import notesRouter from './routes/notes.js'
import toolkitRouter from './routes/toolkit.js'
import hookRouter from './routes/hook.js'
import { initDb, ok } from './db.js'
import { llmConfig } from './llm.js'
import { messageBus, onMessage } from './messageBus.js'

loadEnvFile()

const PORT = Number(process.env.APPS_PORT || 19089)
const app = express()

app.use(cors())
app.use(express.json({ limit: '2mb' }))

app.get('/apps/health', (_req, res) => {
  const llm = llmConfig()
  res.json(
    ok({
      status: 'ok',
      service: 'wx391027-apps-server',
      timestamp: new Date().toISOString(),
      llm: { configured: llm.configured, model: llm.model, baseUrl: llm.baseUrl },
      hook: {
        path: '/apps/hook',
        listeners: messageBus.listenerCount('onMessage'),
        receivedCount: messageBus.receivedCount,
      },
    }),
  )
})

app.use('/apps/assistant', assistantRouter)
app.use('/apps/notes', notesRouter)
app.use('/apps/toolkit', toolkitRouter)
app.use('/apps/hook', hookRouter)

app.use((err, _req, res, _next) => {
  console.error('[apps-server]', err)
  res.status(500).json({ code: 0, data: null, msg: err?.message || 'server error' })
})

await initDb()

// 默认日志监听（可在其他模块再订阅 onMessage）
onMessage((msg) => {
  const who = msg.roomId || msg.talkerId || '?'
  const preview = String(msg.text || '').replace(/\s+/g, ' ').slice(0, 80)
  console.log(
    `[onMessage] type=${msg.type} talker=${who} self=${!!msg.isSelf} text=${preview}`,
  )
})

app.listen(PORT, '0.0.0.0', () => {
  const llm = llmConfig()
  console.log(`[apps-server] http://0.0.0.0:${PORT}  (proxy path /apps)`)
  console.log(
    `[apps-server] LLM ${llm.configured ? 'ready' : 'NOT configured'} model=${llm.model} base=${llm.baseUrl}`,
  )
  console.log(`[apps-server] hook POST http://0.0.0.0:${PORT}/apps/hook  → emit onMessage`)
})

export { messageBus, onMessage }
