import { useEffect, useMemo, useState } from 'react'
import { appsApi, type NoteItem } from '../api/apps'
import { useAgent } from '../context/AgentContext'

const TAGS = ['待办', '报价', '风险', '其他']

/** 速记：编辑 / 置顶 / 标签过滤 / 增删 */
export function NotesApp() {
  const { activeTalker } = useAgent()
  const [draft, setDraft] = useState('')
  const [draftTags, setDraftTags] = useState<string[]>(['其他'])
  const [notes, setNotes] = useState<NoteItem[]>([])
  const [filterTag, setFilterTag] = useState('')
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editText, setEditText] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const reload = async (talker: string, tag?: string) => {
    setBusy(true)
    setErr(null)
    try {
      const list = await appsApi.listNotes(talker, tag || undefined)
      setNotes(list || [])
    } catch (e) {
      setErr((e as Error).message)
      setNotes([])
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    if (!activeTalker) {
      setNotes([])
      setDraft('')
      setErr(null)
      setEditingId(null)
      return
    }
    setDraft('')
    setEditingId(null)
    void reload(activeTalker, filterTag)
  }, [activeTalker, filterTag])

  const sorted = useMemo(() => notes, [notes])

  const toggleDraftTag = (tag: string) => {
    setDraftTags((prev) => (prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]))
  }

  const add = async () => {
    const text = draft.trim()
    if (!text || !activeTalker || busy) return
    setBusy(true)
    setErr(null)
    try {
      const item = await appsApi.addNote(activeTalker, text, {
        tags: draftTags.length ? draftTags : ['其他'],
      })
      setNotes((prev) => [item, ...prev])
      setDraft('')
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const remove = async (id: string) => {
    if (!activeTalker || busy) return
    setBusy(true)
    setErr(null)
    try {
      await appsApi.deleteNote(id)
      setNotes((prev) => prev.filter((x) => x.id !== id))
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const togglePin = async (n: NoteItem) => {
    setBusy(true)
    try {
      const updated = await appsApi.updateNote(n.id, { pinned: !n.pinned })
      setNotes((prev) => {
        const next = prev.map((x) => (x.id === n.id ? updated : x))
        return next.sort((a, b) => Number(!!b.pinned) - Number(!!a.pinned))
      })
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const saveEdit = async () => {
    if (!editingId || !editText.trim()) return
    setBusy(true)
    try {
      const updated = await appsApi.updateNote(editingId, { text: editText.trim() })
      setNotes((prev) => prev.map((x) => (x.id === editingId ? updated : x)))
      setEditingId(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const setNoteTags = async (n: NoteItem, tag: string) => {
    const cur = n.tags || []
    const next = cur.includes(tag) ? cur.filter((t) => t !== tag) : [...cur, tag]
    setBusy(true)
    try {
      const updated = await appsApi.updateNote(n.id, { tags: next.length ? next : ['其他'] })
      setNotes((prev) => prev.map((x) => (x.id === n.id ? updated : x)))
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (!activeTalker) {
    return <div className="assistant-empty">选中会话后，可记录与该对话相关的要点。</div>
  }

  return (
    <div className="notes-app">
      {err && <div className="banner error">{err}</div>}
      <div className="notes-filters">
        <button
          type="button"
          className={`chip ${!filterTag ? 'on' : ''}`}
          onClick={() => setFilterTag('')}
        >
          全部
        </button>
        {TAGS.map((t) => (
          <button
            key={t}
            type="button"
            className={`chip ${filterTag === t ? 'on' : ''}`}
            onClick={() => setFilterTag(t)}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="notes-compose">
        <textarea
          value={draft}
          placeholder="记一条要点…"
          rows={3}
          disabled={busy}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
              e.preventDefault()
              void add()
            }
          }}
        />
        <div className="notes-tag-pick">
          {TAGS.map((t) => (
            <button
              key={t}
              type="button"
              className={`chip ${draftTags.includes(t) ? 'on' : ''}`}
              onClick={() => toggleDraftTag(t)}
            >
              {t}
            </button>
          ))}
        </div>
        <button type="button" className="btn primary" disabled={busy || !draft.trim()} onClick={() => void add()}>
          添加
        </button>
      </div>
      <ul className="notes-list">
        {sorted.length === 0 ? (
          <li className="notes-empty">{busy ? '加载中…' : '还没有速记。'}</li>
        ) : (
          sorted.map((n) => (
            <li key={n.id} className={n.pinned ? 'pinned' : ''}>
              {editingId === n.id ? (
                <>
                  <textarea value={editText} rows={3} onChange={(e) => setEditText(e.target.value)} />
                  <div className="notes-meta">
                    <button type="button" className="btn soft" onClick={() => void saveEdit()}>
                      保存
                    </button>
                    <button type="button" className="btn ghost" onClick={() => setEditingId(null)}>
                      取消
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <p>
                    {n.pinned ? '📌 ' : ''}
                    {n.text}
                  </p>
                  <div className="notes-tags">
                    {(n.tags || []).map((t) => (
                      <em key={t}>{t}</em>
                    ))}
                  </div>
                  <div className="notes-tag-pick">
                    {TAGS.map((t) => (
                      <button
                        key={t}
                        type="button"
                        className={`chip ${n.tags?.includes(t) ? 'on' : ''}`}
                        onClick={() => void setNoteTags(n, t)}
                      >
                        {t}
                      </button>
                    ))}
                  </div>
                  <div className="notes-meta">
                    <span>
                      {new Date(n.updatedAt || n.at).toLocaleString('zh-CN', { hour12: false })}
                    </span>
                    <span className="notes-actions">
                      <button type="button" className="link" onClick={() => void togglePin(n)}>
                        {n.pinned ? '取消置顶' : '置顶'}
                      </button>
                      <button
                        type="button"
                        className="link"
                        onClick={() => {
                          setEditingId(n.id)
                          setEditText(n.text)
                        }}
                      >
                        编辑
                      </button>
                      <button type="button" className="link muted" onClick={() => void remove(n.id)}>
                        删除
                      </button>
                    </span>
                  </div>
                </>
              )}
            </li>
          ))
        )}
      </ul>
    </div>
  )
}
