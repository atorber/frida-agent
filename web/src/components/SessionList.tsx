import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/endpoints'
import type { SessionItem } from '../api/types'
import { useAgent } from '../context/AgentContext'
import { Avatar } from './Avatar'

export function SessionList() {
  const { baseUrl, connected, sessions, activeTalker, setActiveTalker, openSession } = useAgent()
  const [q, setQ] = useState('')
  const [remote, setRemote] = useState<SessionItem[]>([])
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const load = async () => {
    if (!connected) return
    setLoading(true)
    setErr(null)
    try {
      const data = await api.sessions(baseUrl, { limit: 100 })
      const items = (data.items || []).map((it) => ({
        id: it.id,
        name: it.name || it.id,
        avatar: it.avatar || '',
        kind: it.kind,
        lastPreview: it.lastContent,
        lastTime: it.lastTime ? it.lastTime * 1000 : undefined,
      }))
      setRemote(items)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [baseUrl, connected])

  // 远端会话优先；本地 recent 补上远端没有的
  const merged = useMemo(() => {
    const map = new Map<string, SessionItem>()
    for (const s of remote) map.set(s.id, s)
    for (const s of sessions) {
      if (!map.has(s.id)) map.set(s.id, s)
    }
    return Array.from(map.values())
  }, [remote, sessions])

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase()
    if (!s) return merged
    return merged.filter(
      (x) => x.name.toLowerCase().includes(s) || x.id.toLowerCase().includes(s),
    )
  }, [merged, q])

  // 进入会话页且未选中（或选中已失效）时，默认打开第一个会话
  useEffect(() => {
    if (loading || merged.length === 0) return
    if (activeTalker && merged.some((s) => s.id === activeTalker)) return
    openSession(merged[0])
  }, [merged, activeTalker, loading, openSession])

  return (
    <aside className="column">
      <div className="column-head">
        <h1>会话</h1>
        <button type="button" className="link muted" onClick={() => void load()}>
          {loading ? '…' : '同步'}
        </button>
      </div>
      <div className="search-wrap">
        <input placeholder="搜索名称或 ID" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {err && (
        <div className="banner error" style={{ margin: '0 12px 8px' }}>
          {err}
        </div>
      )}
      <div className="list">
        {filtered.length === 0 ? (
          <div className="row-empty">
            {loading ? '加载中…' : '还没有会话。'}
            {!loading && (
              <>
                <br />
                从「人脉」或「群组」发起对话，或点同步。
              </>
            )}
          </div>
        ) : (
          filtered.map((s: SessionItem) => (
            <button
              key={s.id}
              type="button"
              className={`row ${activeTalker === s.id ? 'active' : ''}`}
              onClick={() => {
                openSession(s)
                setActiveTalker(s.id)
              }}
            >
              <Avatar src={s.avatar} name={s.name} />
              <div className="meta">
                <div className="title">{s.name || s.id}</div>
                <div className="sub">
                  {s.lastPreview || (s.kind === 'room' ? '群组对话' : '私信')}
                </div>
              </div>
            </button>
          ))
        )}
      </div>
    </aside>
  )
}
