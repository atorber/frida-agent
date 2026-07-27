import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/endpoints'
import type { Contact } from '../api/types'
import { useAgent } from '../context/AgentContext'
import { Avatar } from './Avatar'

type Props = {
  selectedId: string | null
  onSelect: (c: Contact) => void
}

export function ContactList({ selectedId, onSelect }: Props) {
  const { baseUrl, connected } = useAgent()
  const [list, setList] = useState<Contact[]>([])
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(false)

  const load = async () => {
    if (!connected) return
    setLoading(true)
    try {
      const data = await api.getContacts(baseUrl)
      setList(Array.isArray(data) ? data : [])
    } catch {
      setList([])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [baseUrl, connected])

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase()
    if (!s) return list
    return list.filter(
      (c) =>
        (c.name || '').toLowerCase().includes(s) ||
        (c.id || '').toLowerCase().includes(s) ||
        (c.alias || '').toLowerCase().includes(s),
    )
  }, [list, q])

  return (
    <aside className="column">
      <div className="column-head">
        <h1>人脉</h1>
        <button type="button" className="link muted" onClick={() => void load()}>
          {loading ? '…' : '同步'}
        </button>
      </div>
      <div className="search-wrap">
        <input placeholder="搜索联系人" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="list">
        {filtered.map((c) => (
          <button
            key={c.id}
            type="button"
            className={`row ${selectedId === c.id ? 'active' : ''}`}
            onClick={() => onSelect(c)}
          >
            <Avatar src={c.avatar} name={c.name || c.id} />
            <div className="meta">
              <div className="title">{c.name || c.id}</div>
              <div className="sub">{c.alias || '联系人'}</div>
            </div>
          </button>
        ))}
      </div>
    </aside>
  )
}
