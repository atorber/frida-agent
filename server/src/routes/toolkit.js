import { Router } from 'express'
import { db, fail, newId, ok } from '../db.js'
import { buildAssistantSystemPrompt, chatCompletion, llmConfig } from '../llm.js'

const router = Router()

const TOOLS = [
  {
    id: 'reply_draft',
    title: '回复草案',
    desc: '根据近期会话生成一条可发送回复',
  },
  {
    id: 'summarize',
    title: '会话摘要',
    desc: '提炼要点列表，便于存入速记',
  },
  {
    id: 'polish',
    title: '润色草稿',
    desc: '润色输入框或传入的草稿',
  },
  {
    id: 'translate',
    title: '翻译',
    desc: '中英互译（默认中→英）',
  },
]

function toolPrompt(toolId, { name, draft, context, direction }) {
  // 省 token：工具侧摘录也做长度裁剪
  const snippet = (context || '（暂无消息）').slice(0, 2500)
  switch (toolId) {
    case 'reply_draft':
      return [
        `会话对象：${name || '对方'}`,
        '请根据会话摘录，输出【一条】可直接发送的中文回复，不要解释、不要前缀。',
        `会话摘录：\n${snippet}`,
      ].join('\n')
    case 'summarize':
      return [
        '请根据会话摘录输出要点摘要，使用编号列表，简洁准确，勿编造。',
        `会话摘录：\n${snippet}`,
      ].join('\n')
    case 'polish':
      return [
        '请润色以下草稿，使其更自然得体，适合微信发送。只输出润色后正文。',
        `草稿：\n${(draft || '').trim() || '（空）'}`,
        draft ? '' : `若草稿为空，可参考会话摘录起草一条：\n${snippet}`,
      ]
        .filter(Boolean)
        .join('\n')
    case 'translate': {
      const dir = direction === 'en2zh' ? '英译中' : '中译英'
      return [
        `请将下列文本做${dir}，只输出译文。`,
        `文本：\n${(draft || '').trim() || snippet.slice(0, 800) || '（空）'}`,
      ].join('\n')
    }
    default:
      return null
  }
}

/** GET /apps/toolkit/tools */
router.get('/tools', (_req, res) => {
  res.json(ok(TOOLS))
})

/** POST /apps/toolkit/run */
router.post('/run', async (req, res) => {
  const talker = String(req.body?.talker || '').trim()
  const toolId = String(req.body?.toolId || '').trim()
  const name = String(req.body?.name || '').trim()
  const draft = String(req.body?.draft || '').trim()
  const context = String(req.body?.context || '').trim()
  const direction = String(req.body?.direction || 'zh2en').trim()
  if (!talker) return res.json(fail('缺少 talker'))
  if (!toolId) return res.json(fail('缺少 toolId'))
  if (!llmConfig().configured) return res.json(fail('未配置大模型 API Key'))

  const userPrompt = toolPrompt(toolId, { name, draft, context, direction })
  if (!userPrompt) return res.json(fail('未知工具'))
  if (toolId === 'polish' && !draft && !context) {
    return res.json(fail('润色需要草稿或会话上下文'))
  }

  try {
    const temperature = Number(req.body?.temperature)
    const maxTokens = Number(req.body?.maxTokens)
    const result = await chatCompletion(
      [
        {
          role: 'system',
          content: buildAssistantSystemPrompt({ talkerName: name, talkerId: talker }),
        },
        { role: 'user', content: userPrompt },
      ],
      {
        temperature: Number.isFinite(temperature) ? temperature : toolId === 'translate' ? 0.3 : 0.6,
        maxTokens:
          Number.isFinite(maxTokens)
            ? maxTokens
            : toolId === 'translate'
              ? 350
              : toolId === 'polish'
                ? 450
                : 650,
      },
    )

    const id = newId('tool')
    const at = Date.now()
    db.prepare(
      `INSERT INTO toolkit_runs (id, talker, tool_id, result, created_at) VALUES (?, ?, ?, ?, ?)`,
    ).run(id, talker, toolId, result, at)

    res.json(ok({ id, toolId, result, at }))
  } catch (e) {
    console.error('[toolkit/run]', e)
    res.json(fail(e?.message || '工具执行失败'))
  }
})

/** GET /apps/toolkit/history */
router.get('/history', (req, res) => {
  const talker = String(req.query.talker || '').trim()
  if (!talker) return res.json(fail('缺少 talker'))
  let limit = Number(req.query.limit)
  if (!Number.isFinite(limit) || limit <= 0) limit = 20
  if (limit > 100) limit = 100
  const rows = db
    .prepare(
      `SELECT id, tool_id AS toolId, result, created_at AS at
       FROM toolkit_runs WHERE talker = ? ORDER BY created_at DESC LIMIT ?`,
    )
    .all(talker, limit)
  res.json(ok(rows))
})

export default router
