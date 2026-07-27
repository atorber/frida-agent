import { Router } from 'express'
import { db, fail, fingerprint, newId, ok } from '../db.js'
import {
  buildAssistantSystemPrompt,
  chatCompletion,
  chatCompletionStream,
  extractJson,
  llmConfig,
} from '../llm.js'

const router = Router()

const NOTE_TAGS = ['待办', '报价', '风险', '其他']

function listMessages(talker) {
  return db
    .prepare(
      `SELECT id, role, content, created_at AS at
       FROM assistant_messages WHERE talker = ? ORDER BY created_at ASC`,
    )
    .all(talker)
}

function listNotesText(talker) {
  const rows = db
    .prepare(
      `SELECT text, tags FROM notes WHERE talker = ? ORDER BY pinned DESC, updated_at DESC, created_at DESC LIMIT 12`,
    )
    .all(talker)
  if (!rows.length) return ''
  return rows
    .map((r) => {
      let tags = []
      try {
        tags = JSON.parse(r.tags || '[]')
      } catch {
        tags = []
      }
      const tagStr = tags.length ? `[${tags.join(',')}] ` : ''
      return `- ${tagStr}${r.text}`
    })
    .join('\n')
}

function ensureSeed(talker, name) {
  const row = db.prepare(`SELECT COUNT(1) AS c FROM assistant_messages WHERE talker = ?`).get(talker)
  const count = Number(row?.c || 0)
  if (count > 0) return
  const now = Date.now()
  const insert = db.prepare(
    `INSERT INTO assistant_messages (id, talker, role, content, created_at) VALUES (?, ?, ?, ?, ?)`,
  )
  const tx = db.transaction(() => {
    insert.run(
      newId('am'),
      talker,
      'system',
      `已切换到与「${name || talker}」的会话上下文。`,
      now - 2000,
    )
    insert.run(
      newId('am'),
      talker,
      'assistant',
      '我可以帮你分析情境、生成建议回复，或多轮润色/总结。结果只会填入输入框，不会自动发送。',
      now - 1000,
    )
  })
  tx()
}

function getCachedAnalysis(talker) {
  const row = db
    .prepare(
      `SELECT fingerprint, insights_json, suggestions_json, updated_at
       FROM assistant_analysis WHERE talker = ?`,
    )
    .get(talker)
  if (!row) return null
  try {
    return {
      fingerprint: row.fingerprint,
      insights: JSON.parse(row.insights_json),
      suggestions: JSON.parse(row.suggestions_json),
      updatedAt: row.updated_at,
    }
  } catch {
    return null
  }
}

function saveAnalysis(talker, fp, insights, suggestions) {
  // 省 token：按 mode 生成时，模型可能只返回部分字段；这里做合并，避免把另一部分覆盖成空数组。
  const now = Date.now()
  const existing = db
    .prepare(`SELECT fingerprint, insights_json, suggestions_json FROM assistant_analysis WHERE talker = ?`)
    .get(talker)

  let mergedInsights = insights
  let mergedSuggestions = suggestions

  if (existing && existing.fingerprint === fp) {
    try {
      const existingInsights = JSON.parse(existing.insights_json || '[]')
      const existingSuggestions = JSON.parse(existing.suggestions_json || '[]')
      if ((!mergedInsights || mergedInsights.length === 0) && Array.isArray(existingInsights) && existingInsights.length > 0) {
        mergedInsights = existingInsights
      }
      if (
        (!mergedSuggestions || mergedSuggestions.length === 0) &&
        Array.isArray(existingSuggestions) &&
        existingSuggestions.length > 0
      ) {
        mergedSuggestions = existingSuggestions
      }
    } catch {
      /* ignore merge parse errors */
    }
  }

  db.prepare(`DELETE FROM assistant_analysis WHERE talker = ?`).run(talker)
  db.prepare(
    `INSERT INTO assistant_analysis (talker, fingerprint, insights_json, suggestions_json, updated_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(talker, fp, JSON.stringify(mergedInsights), JSON.stringify(mergedSuggestions), now)
}

function buildLlmMessages(talker, name, prompt, extraContext) {
  const history = listMessages(talker)
    .filter((m) => m.role === 'user' || m.role === 'assistant')
    .slice(-10)

  const messages = [
    {
      role: 'system',
      content: buildAssistantSystemPrompt({ talkerName: name, talkerId: talker }),
    },
  ]

  const notes = listNotesText(talker)
  if (notes) {
    messages.push({
      role: 'system',
      content: `用户对该会话的速记（事实补充，勿编造）：\n${notes}`,
    })
  }

  if (extraContext && String(extraContext).trim()) {
    messages.push({
      role: 'system',
      content: `以下是该微信会话的近期消息摘录，供参考：\n${String(extraContext).trim().slice(0, 2000)}`,
    })
  }

  for (const m of history) {
    messages.push({ role: m.role, content: m.content })
  }
  messages.push({ role: 'user', content: prompt })
  return messages
}

function normalizeAnalysis(raw) {
  const insights = Array.isArray(raw?.insights) ? raw.insights : []
  const suggestions = Array.isArray(raw?.suggestions) ? raw.suggestions : []
  return {
    insights: insights.slice(0, 5).map((it, i) => ({
      id: String(it.id || `i${i + 1}`),
      title: String(it.title || '要点').slice(0, 40),
      detail: String(it.detail || '').slice(0, 300),
    })),
    suggestions: suggestions.slice(0, 4).map((s, i) => ({
      id: String(s.id || `s${i + 1}`),
      label: String(s.label || '建议').slice(0, 20),
      tone: ['friendly', 'formal', 'brief'].includes(s.tone) ? s.tone : 'friendly',
      text: String(s.text || '').slice(0, 500),
    })),
  }
}

async function runAnalyze({ talker, name, context, force, mode }) {
  if (!llmConfig().configured) {
    throw new Error('未配置大模型 API Key')
  }
  const analysisMode = mode === 'insight' || mode === 'suggest' ? mode : 'both'
  const fp = fingerprint(context || '')
  if (!force) {
    const cached = getCachedAnalysis(talker)
    if (cached && cached.fingerprint === fp) {
      const hasInsights = Array.isArray(cached.insights) && cached.insights.length > 0
      const hasSuggestions = Array.isArray(cached.suggestions) && cached.suggestions.length > 0
      if (
        (analysisMode === 'both' && (hasInsights || hasSuggestions)) ||
        (analysisMode === 'insight' && hasInsights) ||
        (analysisMode === 'suggest' && hasSuggestions)
      ) {
        return { ...cached, cached: true, fingerprint: fp }
      }
    }
  }

  const notes = listNotesText(talker)
  const ctxSnippet = String(context || '（暂无消息）').slice(0, analysisMode === 'both' ? 3000 : 2000)
  const promptPieces = [
    '请根据微信会话摘录与速记，输出 JSON（不要 markdown 围栏）。',
    analysisMode === 'both'
      ? [
          '格式：',
          '{',
          '  "insights": [{"id":"i1","title":"语气|待办|风险|其他","detail":"..."}],',
          '  "suggestions": [{"id":"s1","label":"短标签","tone":"friendly|formal|brief","text":"可直接发送的回复"}]',
          '}',
        ].join('\n')
      : analysisMode === 'insight'
        ? [
            '格式：{ "insights": [{"id":"i1","title":"语气|待办|风险|其他","detail":"..."}] }',
          ].join('\n')
        : '格式：{ "suggestions": [{"id":"s1","label":"短标签","tone":"friendly|formal|brief","text":"可直接发送的回复"}] }',
    analysisMode === 'both'
      ? '要求：insights 3～5 条；suggestions 3～4 条且 text 可直接发送；勿编造未出现的事实。'
      : analysisMode === 'insight'
        ? '要求：insights 3～5 条；detail 简洁准确；勿编造未出现的事实。'
        : '要求：suggestions 3～4 条且 text 可直接发送；勿编造未出现的事实。',
    notes ? `\n速记：\n${notes}` : '',
    `\n会话摘录：\n${ctxSnippet}`,
  ]
  const prompt = promptPieces.filter(Boolean).join('\n')

  const rawText = await chatCompletion(
    [
      {
        role: 'system',
        content: buildAssistantSystemPrompt({ talkerName: name, talkerId: talker }),
      },
      { role: 'user', content: prompt },
    ],
    {
      temperature: analysisMode === 'suggest' ? 0.35 : 0.4,
      maxTokens: analysisMode === 'both' ? 900 : analysisMode === 'suggest' ? 700 : 600,
    },
  )

  const normalized = normalizeAnalysis(extractJson(rawText))
  if (analysisMode === 'both') {
    if (!normalized.insights.length && !normalized.suggestions.length) {
      throw new Error('模型未返回有效情境/建议')
    }
  } else if (analysisMode === 'insight') {
    if (!normalized.insights.length) throw new Error('模型未返回有效情境')
  } else if (!normalized.suggestions.length) {
    throw new Error('模型未返回有效建议')
  }
  saveAnalysis(talker, fp, normalized.insights, normalized.suggestions)
  return {
    insights: normalized.insights,
    suggestions: normalized.suggestions,
    fingerprint: fp,
    updatedAt: Date.now(),
    cached: false,
  }
}

function llmOptsFromBody(body) {
  const temperature = Number(body?.temperature)
  const maxTokens = Number(body?.maxTokens)
  return {
    temperature: Number.isFinite(temperature) ? Math.min(2, Math.max(0, temperature)) : 0.7,
    maxTokens: Number.isFinite(maxTokens) ? Math.min(4096, Math.max(64, maxTokens)) : 1024,
  }
}

/** GET /apps/assistant/context */
router.get('/context', (req, res) => {
  const talker = String(req.query.talker || '').trim()
  if (!talker) return res.json(fail('缺少 talker'))
  const name = String(req.query.name || '').trim()
  ensureSeed(talker, name)
  const cfg = llmConfig()
  const cached = getCachedAnalysis(talker)
  res.json(
    ok({
      talker,
      name: name || talker,
      suggestions: cached?.suggestions || [],
      insights: cached?.insights || [],
      analysisUpdatedAt: cached?.updatedAt || null,
      analysisFingerprint: cached?.fingerprint || null,
      messages: listMessages(talker),
      noteTags: NOTE_TAGS,
      llm: { configured: cfg.configured, model: cfg.model, baseUrl: cfg.baseUrl },
    }),
  )
})

/** POST /apps/assistant/analyze { talker, name?, context?, force? } */
router.post('/analyze', async (req, res) => {
  const talker = String(req.body?.talker || '').trim()
  const name = String(req.body?.name || '').trim()
  const context = String(req.body?.context || '').trim()
  const force = !!req.body?.force
  const mode = String(req.body?.mode || 'both').trim()
  if (!talker) return res.json(fail('缺少 talker'))
  ensureSeed(talker, name)
  try {
    const data = await runAnalyze({ talker, name: name || talker, context, force, mode })
    res.json(ok(data))
  } catch (e) {
    console.error('[assistant/analyze]', e)
    res.json(fail(e?.message || '分析失败'))
  }
})

/** GET /apps/assistant/messages */
router.get('/messages', (req, res) => {
  const talker = String(req.query.talker || '').trim()
  if (!talker) return res.json(fail('缺少 talker'))
  res.json(ok(listMessages(talker)))
})

/** POST /apps/assistant/chat */
router.post('/chat', async (req, res) => {
  const talker = String(req.body?.talker || '').trim()
  const prompt = String(req.body?.prompt || '').trim()
  const name = String(req.body?.name || '').trim()
  const extraContext = String(req.body?.context || '').trim()
  if (!talker) return res.json(fail('缺少 talker'))
  if (!prompt) return res.json(fail('缺少 prompt'))
  if (!llmConfig().configured) {
    return res.json(fail('未配置大模型 API Key'))
  }

  ensureSeed(talker, name)
  try {
    const opts = llmOptsFromBody(req.body)
    const llmMessages = buildLlmMessages(talker, name || talker, prompt, extraContext)
    const replyText = await chatCompletion(llmMessages, opts)

    const now = Date.now()
    const insert = db.prepare(
      `INSERT INTO assistant_messages (id, talker, role, content, created_at) VALUES (?, ?, ?, ?, ?)`,
    )
    const userMsg = { id: newId('am'), role: 'user', content: prompt, at: now }
    const asstMsg = { id: newId('am'), role: 'assistant', content: replyText, at: now + 1 }
    const tx = db.transaction(() => {
      insert.run(userMsg.id, talker, userMsg.role, userMsg.content, userMsg.at)
      insert.run(asstMsg.id, talker, asstMsg.role, asstMsg.content, asstMsg.at)
    })
    tx()

    res.json(ok({ user: userMsg, assistant: asstMsg, messages: listMessages(talker) }))
  } catch (e) {
    console.error('[assistant/chat]', e)
    res.json(fail(e?.message || '大模型调用失败'))
  }
})

/** POST /apps/assistant/chat/stream  SSE */
router.post('/chat/stream', async (req, res) => {
  const talker = String(req.body?.talker || '').trim()
  const prompt = String(req.body?.prompt || '').trim()
  const name = String(req.body?.name || '').trim()
  const extraContext = String(req.body?.context || '').trim()
  if (!talker) {
    res.status(400).json(fail('缺少 talker'))
    return
  }
  if (!prompt) {
    res.status(400).json(fail('缺少 prompt'))
    return
  }
  if (!llmConfig().configured) {
    res.status(400).json(fail('未配置大模型 API Key'))
    return
  }

  ensureSeed(talker, name)
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.flushHeaders?.()

  const send = (event, data) => {
    res.write(`event: ${event}\n`)
    res.write(`data: ${JSON.stringify(data)}\n\n`)
  }

  const now = Date.now()
  const userMsg = { id: newId('am'), role: 'user', content: prompt, at: now }
  send('user', userMsg)

  try {
    const opts = llmOptsFromBody(req.body)
    const llmMessages = buildLlmMessages(talker, name || talker, prompt, extraContext)
    const replyText = await chatCompletionStream(llmMessages, opts, (delta) => {
      send('delta', { content: delta })
    })
    const asstMsg = { id: newId('am'), role: 'assistant', content: replyText, at: Date.now() }
    const insert = db.prepare(
      `INSERT INTO assistant_messages (id, talker, role, content, created_at) VALUES (?, ?, ?, ?, ?)`,
    )
    const tx = db.transaction(() => {
      insert.run(userMsg.id, talker, userMsg.role, userMsg.content, userMsg.at)
      insert.run(asstMsg.id, talker, asstMsg.role, asstMsg.content, asstMsg.at)
    })
    tx()
    send('done', { assistant: asstMsg, messages: listMessages(talker) })
  } catch (e) {
    console.error('[assistant/chat/stream]', e)
    send('error', { msg: e?.message || '流式调用失败' })
  } finally {
    res.end()
  }
})

/** DELETE /apps/assistant/messages */
router.delete('/messages', (req, res) => {
  const talker = String(req.query.talker || '').trim()
  if (!talker) return res.json(fail('缺少 talker'))
  db.prepare(`DELETE FROM assistant_messages WHERE talker = ?`).run(talker)
  res.json(ok({ cleared: true }))
})

export default router
