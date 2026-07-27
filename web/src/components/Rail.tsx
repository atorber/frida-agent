import { useEffect, useState } from 'react'
import type { NavView } from '../api/types'
import {
  pageIsLoopback,
  resolveApiBase,
  suggestDirectBaseUrl,
} from '../api/client'
import { useAgent } from '../context/AgentContext'
import { Avatar } from './Avatar'

const items: { id: NavView; label: string; path: string }[] = [
  {
    id: 'chat',
    label: '会话',
    path: 'M4 5.5A1.5 1.5 0 0 1 5.5 4h13A1.5 1.5 0 0 1 20 5.5v9A1.5 1.5 0 0 1 18.5 16H9l-4 3.5V5.5z',
  },
  {
    id: 'contacts',
    label: '人脉',
    path: 'M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4zm0 2c-3.9 0-8 1.8-8 4.5V20h16v-1.5C20 15.8 15.9 14 12 14z',
  },
  {
    id: 'rooms',
    label: '群组',
    path: 'M8.5 11a3 3 0 1 0-3-3 3 3 0 0 0 3 3zm7 0a3 3 0 1 0-3-3 3 3 0 0 0 3 3zM8.5 13c-3 0-5.5 1.4-5.5 3.2V18h11v-1.8c0-1.8-2.5-3.2-5.5-3.2zm7 .2c-.4 0-.8 0-1.2.1 1.3.7 2.2 1.8 2.2 3.1V18H21v-1.7c0-1.8-2.4-3.1-5.5-3.1z',
  },
  {
    id: 'tools',
    label: '设置',
    path: 'M19.4 13a7.5 7.5 0 0 0 0-2l1.8-1.4-1.7-3-2.2.9a7.4 7.4 0 0 0-1.7-1L15.2 3h-3.4l-.4 2.5a7.4 7.4 0 0 0-1.7 1l-2.2-.9-1.7 3L7.6 11a7.5 7.5 0 0 0 0 2l-1.8 1.4 1.7 3 2.2-.9a7.4 7.4 0 0 0 1.7 1l.4 2.5h3.4l.4-2.5a7.4 7.4 0 0 0 1.7-1l2.2.9 1.7-3zm-7.4 2.2A3.2 3.2 0 1 1 15.2 12 3.2 3.2 0 0 1 12 15.2z',
  },
]

export function Rail() {
  const { view, setView, connected, self, baseUrl, setBaseUrl, refresh, refreshing, loggedIn } =
    useAgent()
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState(baseUrl)
  const effective = resolveApiBase(baseUrl)
  const lanHint = !pageIsLoopback()

  useEffect(() => {
    setDraft(baseUrl)
  }, [baseUrl])

  // 局域网打开却存了 127.0.0.1：清掉，改走同源代理
  useEffect(() => {
    if (!lanHint) return
    if (/127\.0\.0\.1|localhost/i.test(baseUrl)) {
      setBaseUrl('')
    }
  }, [lanHint, baseUrl, setBaseUrl])

  return (
    <>
      <aside className="rail">
        <div className="rail-mark" title="Relay">
          R
        </div>
        <nav className="rail-nav">
          {items.map((it) => (
            <button
              key={it.id}
              type="button"
              className={`rail-btn ${view === it.id ? 'active' : ''}`}
              onClick={() => setView(it.id)}
            >
              <svg viewBox="0 0 24 24">
                <path d={it.path} />
              </svg>
              <span>{it.label}</span>
            </button>
          ))}
        </nav>
        <div className="rail-foot">
          <span
            className={`rail-status ${connected ? 'on' : ''}`}
            title={connected ? (loggedIn ? '已连接 · 已登录' : '已连接') : '未连接'}
          />
          <button
            type="button"
            className="rail-avatar"
            title="连接设置"
            onClick={() => setOpen((v) => !v)}
          >
            <Avatar src={self?.avatar} name={self?.name || 'Agent'} size="sm" />
          </button>
        </div>
      </aside>

      {open && (
        <div className="connect-pop">
          <label>
            Agent 地址
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="留空 = 同源 /api 代理"
            />
          </label>
          <p className="hint">
            当前生效：{effective || '同源 /api（Vite 代理）'}
            {lanHint
              ? '。局域网请勿填 127.0.0.1，否则会打到访客本机。'
              : '。本地可留空走代理，或填 http://127.0.0.1:19088。'}
          </p>
          <div className="actions" style={{ margin: 0 }}>
            <button
              type="button"
              className="btn ghost"
              onClick={() => {
                setDraft('')
                setBaseUrl('')
                setOpen(false)
              }}
            >
              同源代理
            </button>
            <button
              type="button"
              className="btn ghost"
              onClick={() => {
                const u = suggestDirectBaseUrl()
                setDraft(u)
                setBaseUrl(u)
                setOpen(false)
              }}
            >
              同主机:19088
            </button>
            <button
              type="button"
              className="btn ghost"
              disabled={refreshing}
              onClick={() => void refresh()}
            >
              检测
            </button>
            <button
              type="button"
              className="btn primary"
              onClick={() => {
                let next = draft.trim()
                // 局域网页面禁止保存 loopback
                if (lanHint && /127\.0\.0\.1|localhost/i.test(next)) {
                  next = ''
                }
                setBaseUrl(next)
                setOpen(false)
              }}
            >
              应用
            </button>
          </div>
        </div>
      )}
    </>
  )
}
