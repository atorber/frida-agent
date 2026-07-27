import { Router } from 'express'
import { db, fail, newId, ok } from '../db.js'

const router = Router()

const ALLOWED_TAGS = new Set(['待办', '报价', '风险', '其他'])

function parseTags(input) {
  let arr = input
  if (typeof input === 'string') {
    try {
      arr = JSON.parse(input)
    } catch {
      arr = input.split(/[,，]/).map((s) => s.trim()).filter(Boolean)
    }
  }
  if (!Array.isArray(arr)) return []
  return [...new Set(arr.map((t) => String(t).trim()).filter((t) => ALLOWED_TAGS.has(t)))]
}

function mapNote(row) {
  if (!row) return null
  let tags = []
  try {
    tags = JSON.parse(row.tags || '[]')
  } catch {
    tags = []
  }
  return {
    id: row.id,
    text: row.text,
    at: row.created_at,
    updatedAt: row.updated_at || row.created_at,
    pinned: !!row.pinned,
    tags,
  }
}

/** GET /apps/notes?talker=&tag= */
router.get('/', (req, res) => {
  const talker = String(req.query.talker || '').trim()
  if (!talker) return res.json(fail('缺少 talker'))
  const tag = String(req.query.tag || '').trim()
  const rows = db
    .prepare(
      `SELECT id, text, created_at, updated_at, pinned, tags
       FROM notes WHERE talker = ?
       ORDER BY pinned DESC, COALESCE(updated_at, created_at) DESC
       LIMIT 200`,
    )
    .all(talker)
  let list = rows.map(mapNote)
  if (tag && ALLOWED_TAGS.has(tag)) {
    list = list.filter((n) => n.tags.includes(tag))
  }
  res.json(ok(list))
})

/** GET /apps/notes/tags */
router.get('/tags', (_req, res) => {
  res.json(ok([...ALLOWED_TAGS]))
})

/** POST /apps/notes { talker, text, tags?, pinned? } */
router.post('/', (req, res) => {
  const talker = String(req.body?.talker || '').trim()
  const text = String(req.body?.text || '').trim()
  if (!talker) return res.json(fail('缺少 talker'))
  if (!text) return res.json(fail('缺少 text'))
  const tags = parseTags(req.body?.tags)
  const pinned = req.body?.pinned ? 1 : 0
  const id = newId('note')
  const at = Date.now()
  db.prepare(
    `INSERT INTO notes (id, talker, text, created_at, updated_at, pinned, tags)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, talker, text, at, at, pinned, JSON.stringify(tags))
  res.json(ok(mapNote({ id, text, created_at: at, updated_at: at, pinned, tags: JSON.stringify(tags) })))
})

/** PATCH /apps/notes/:id { text?, tags?, pinned? } */
router.patch('/:id', (req, res) => {
  const id = String(req.params.id || '').trim()
  if (!id) return res.json(fail('缺少 id'))
  const row = db
    .prepare(`SELECT id, text, created_at, updated_at, pinned, tags FROM notes WHERE id = ?`)
    .get(id)
  if (!row) return res.json(fail('速记不存在'))

  let text = row.text
  let pinned = row.pinned
  let tags = row.tags
  if (req.body?.text !== undefined) {
    text = String(req.body.text || '').trim()
    if (!text) return res.json(fail('text 不能为空'))
  }
  if (req.body?.pinned !== undefined) {
    pinned = req.body.pinned ? 1 : 0
  }
  if (req.body?.tags !== undefined) {
    tags = JSON.stringify(parseTags(req.body.tags))
  }
  const updatedAt = Date.now()
  db.prepare(
    `UPDATE notes SET text = ?, pinned = ?, tags = ?, updated_at = ? WHERE id = ?`,
  ).run(text, pinned, tags, updatedAt, id)

  res.json(
    ok(
      mapNote({
        id,
        text,
        created_at: row.created_at,
        updated_at: updatedAt,
        pinned,
        tags,
      }),
    ),
  )
})

/** DELETE /apps/notes/:id */
router.delete('/:id', (req, res) => {
  const id = String(req.params.id || '').trim()
  if (!id) return res.json(fail('缺少 id'))
  const info = db.prepare(`DELETE FROM notes WHERE id = ?`).run(id)
  if (!info.changes) return res.json(fail('速记不存在'))
  res.json(ok({ deleted: true, id }))
})

export default router
