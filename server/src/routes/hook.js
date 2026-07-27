import { Router } from 'express'
import { fail, ok } from '../db.js'
import { emitOnMessage, messageBus } from '../messageBus.js'

const router = Router()

/**
 * Agent 消息推送回调入口。
 * 配置：POST Agent `/api/push/config` → callbackUrl = http://host:19089/apps/hook
 * Body：Message JSON（与 agent/wx391027 Message 一致）
 */
router.post('/', (req, res) => {
  const msg = req.body
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
    return res.status(400).json(fail('期望 Message JSON 对象'))
  }
  if (msg.id == null && msg.talkerId == null && msg.text == null) {
    return res.status(400).json(fail('无效消息：缺少 id / talkerId / text'))
  }

  try {
    emitOnMessage(msg)
    res.json(
      ok({
        accepted: true,
        listeners: messageBus.listenerCount('onMessage'),
        receivedCount: messageBus.receivedCount,
      }),
    )
  } catch (e) {
    console.error('[hook]', e)
    res.status(500).json(fail(e?.message || 'hook 处理失败'))
  }
})

/** GET /apps/hook — 状态（便于确认回调是否可达） */
router.get('/', (_req, res) => {
  res.json(
    ok({
      path: '/apps/hook',
      method: 'POST',
      event: 'onMessage',
      listeners: messageBus.listenerCount('onMessage'),
      receivedCount: messageBus.receivedCount,
      lastAt: messageBus.lastAt,
      lastMessage: messageBus.lastMessage
        ? {
            id: messageBus.lastMessage.id,
            type: messageBus.lastMessage.type,
            talkerId: messageBus.lastMessage.talkerId,
            roomId: messageBus.lastMessage.roomId,
            isSelf: messageBus.lastMessage.isSelf,
            textPreview: String(messageBus.lastMessage.text || '').slice(0, 120),
          }
        : null,
    }),
  )
})

export default router
