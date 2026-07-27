import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/endpoints'
import type { Room } from '../api/types'
import { useAgent } from '../context/AgentContext'
import { Avatar } from './Avatar'

type Props = {
  selectedId: string | null
  onSelect: (r: Room) => void
}

export function RoomList({ selectedId, onSelect }: Props) {
  const { baseUrl, connected } = useAgent()
  const [list, setList] = useState<Room[]>([])
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(false)

  const load = async () => {
    if (!connected) return
    setLoading(true)
    try {
      const data = await api.getRooms(baseUrl)
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
      (r) => (r.name || '').toLowerCase().includes(s) || (r.id || '').toLowerCase().includes(s),
    )
  }, [list, q])

  return (
    <aside className="column">
      <div className="column-head">
        <h1>群组</h1>
        <button type="button" className="link muted" onClick={() => void load()}>
          {loading ? '…' : '同步'}
        </button>
      </div>
      <div className="search-wrap">
        <input placeholder="搜索群组" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="list">
        {filtered.map((r) => (
          <button
            key={r.id}
            type="button"
            className={`row ${selectedId === r.id ? 'active' : ''}`}
            onClick={() => onSelect(r)}
          >
            <Avatar src={r.avatar} name={r.name || r.id} />
            <div className="meta">
              <div className="title">{r.name || r.id}</div>
              <div className="sub">群组</div>
            </div>
          </button>
        ))}
      </div>
    </aside>
  )
}
