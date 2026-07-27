import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/endpoints'
import type { Contact } from '../api/types'
import { useAgent } from '../context/AgentContext'
import { Avatar } from './Avatar'

type Props = {
  open: boolean
  title?: string
  excludeIds?: string[]
  confirmLabel?: string
  onClose: () => void
  onConfirm: (contacts: Contact[]) => void
}

export function ContactPicker({
  open,
  title = '选择联系人',
  excludeIds = [],
  confirmLabel = '完成',
  onClose,
  onConfirm,
}: Props) {
  const { baseUrl, connected } = useAgent()
  const [list, setList] = useState<Contact[]>([])
  const [q, setQ] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(false)
  const exclude = useMemo(() => new Set(excludeIds), [excludeIds])

  useEffect(() => {
    if (!open) return
    setQ('')
    setSelected(new Set())
    if (!connected) return
    setLoading(true)
    void api
      .getContacts(baseUrl)
      .then((data) => setList(Array.isArray(data) ? data : []))
      .catch(() => setList([]))
      .finally(() => setLoading(false))
  }, [open, baseUrl, connected])

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase()
    return list.filter((c) => {
      if (!c.id || c.id.endsWith('@chatroom')) return false
      if (!s) return true
      return (
        (c.name || '').toLowerCase().includes(s) ||
        (c.id || '').toLowerCase().includes(s) ||
        (c.alias || '').toLowerCase().includes(s)
      )
    })
  }, [list, q])

  if (!open) return null

  const picked = list.filter((c) => selected.has(c.id))

  return (
    <div className="overlay" onClick={onClose} role="presentation">
      <div className="sheet" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal>
        <div className="sheet-head">
          <button type="button" className="link muted" onClick={onClose}>
            取消
          </button>
          <strong>{title}</strong>
          <button
            type="button"
            className="link"
            disabled={!picked.length}
            onClick={() => onConfirm(picked)}
          >
            {confirmLabel}
            {picked.length ? ` · ${picked.length}` : ''}
          </button>
        </div>
        <div className="search-wrap">
          <input
            placeholder="搜索"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            autoFocus
          />
        </div>
        <div className="sheet-body">
          {loading && <div className="row-empty">加载中…</div>}
          {!loading &&
            filtered.map((c) => {
              const disabled = exclude.has(c.id)
              const on = selected.has(c.id)
              return (
                <button
                  key={c.id}
                  type="button"
                  className="picker-row"
                  disabled={disabled}
                  onClick={() => {
                    if (disabled) return
                    setSelected((prev) => {
                      const next = new Set(prev)
                      if (next.has(c.id)) next.delete(c.id)
                      else next.add(c.id)
                      return next
                    })
                  }}
                >
                  <span className={`check ${on ? 'on' : ''}`}>{on ? '✓' : ''}</span>
                  <Avatar src={c.avatar} name={c.name || c.id} size="sm" />
                  <div className="meta">
                    <div className="title">{c.name || c.id}</div>
                    <div className="sub">{disabled ? '已在群内' : c.alias || '联系人'}</div>
                  </div>
                </button>
              )
            })}
        </div>
      </div>
    </div>
  )
}
