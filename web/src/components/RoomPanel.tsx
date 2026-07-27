import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api/endpoints'
import type { Room, RoomInfo, RoomMember } from '../api/types'
import { useAgent } from '../context/AgentContext'
import { Avatar } from './Avatar'
import { ContactPicker } from './ContactPicker'
import { ConfirmDialog } from './ConfirmDialog'

type Props = { room: Room | null }
type Menu = { wxid: string; x: number; y: number } | null

export function RoomPanel({ room }: Props) {
  const { baseUrl, openSession } = useAgent()
  const [info, setInfo] = useState<RoomInfo | null>(null)
  const [members, setMembers] = useState<RoomMember[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const [q, setQ] = useState('')
  const [pickerOpen, setPickerOpen] = useState(false)
  const [menu, setMenu] = useState<Menu>(null)
  const [removeTarget, setRemoveTarget] = useState<RoomMember | null>(null)
  const [selectMode, setSelectMode] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [batchOpen, setBatchOpen] = useState(false)

  const showToast = (m: string) => {
    setToast(m)
    window.setTimeout(() => setToast(null), 2400)
  }

  const reload = async () => {
    if (!room) return
    setErr(null)
    try {
      const [r, ms] = await Promise.all([
        api.getRoom(baseUrl, room.id),
        api.getRoomMembers(baseUrl, room.id),
      ])
      setInfo(r)
      setMembers(ms)
      setDraft(r.topic || r.name || room.name || '')
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  useEffect(() => {
    setInfo(null)
    setMembers([])
    setEditing(false)
    setSelectMode(false)
    setSelected(new Set())
    setMenu(null)
    setQ('')
    if (room) void reload()
  }, [room?.id, baseUrl])

  useEffect(() => {
    if (editing) inputRef.current?.focus()
  }, [editing])

  useEffect(() => {
    if (!menu) return
    const close = () => setMenu(null)
    window.addEventListener('click', close)
    return () => window.removeEventListener('click', close)
  }, [menu])

  const title = info?.topic || info?.name || room?.name || room?.id || ''
  const memberIds = useMemo(() => members.map((m) => m.wxid), [members])
  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase()
    if (!s) return members
    return members.filter((m) =>
      `${m.displayName || ''} ${m.remark || ''} ${m.name || ''} ${m.wxid}`.toLowerCase().includes(s),
    )
  }, [members, q])

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    setErr(null)
    try {
      await fn()
      showToast(ok)
      await reload()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const saveTitle = async () => {
    if (!room || !draft.trim() || draft.trim() === title) {
      setEditing(false)
      setDraft(title)
      return
    }
    await run(() => api.roomTopic(baseUrl, room.id, draft.trim()), '名称已更新')
    setEditing(false)
  }

  const label = (m: RoomMember) => m.displayName || m.remark || m.name || m.wxid

  if (!room) {
    return (
      <div className="stage-empty">
        <div>
          <h2>选择群组</h2>
          <p>管理成员、修改名称，或进入对话。</p>
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="profile">
        {err && <div className="banner error">{err}</div>}

        <section className="profile-hero">
          <Avatar src={room.avatar} name={title} size="lg" />
          <div className="identity">
            {editing ? (
              <input
                ref={inputRef}
                className="inline-input"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') void saveTitle()
                  if (e.key === 'Escape') {
                    setEditing(false)
                    setDraft(title)
                  }
                }}
                onBlur={() => void saveTitle()}
                disabled={busy}
              />
            ) : (
              <button
                type="button"
                className="title-btn"
                onClick={() => {
                  setDraft(title)
                  setEditing(true)
                }}
              >
                <h2>{title}</h2>
                <span className="hint">编辑</span>
              </button>
            )}
            <div className="sub">{members.length} 位成员</div>
          </div>
          <button
            type="button"
            className="btn primary"
            onClick={() =>
              openSession({
                id: room.id,
                name: String(title),
                avatar: String(room.avatar || ''),
                kind: 'room',
              })
            }
          >
            进入对话
          </button>
        </section>

        {info?.notice ? (
          <section className="profile-section">
            <div className="section-head">
              <h3>公告</h3>
            </div>
            <div className="notice">{info.notice}</div>
          </section>
        ) : null}

        <section className="profile-section">
          <div className="section-head">
            <h3>成员</h3>
            <div className="section-actions">
              {!selectMode ? (
                <>
                  <button type="button" className="link" onClick={() => setPickerOpen(true)}>
                    添加
                  </button>
                  <button
                    type="button"
                    className="link muted"
                    onClick={() => {
                      setSelectMode(true)
                      setSelected(new Set())
                    }}
                  >
                    管理
                  </button>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    className="link danger"
                    disabled={!selected.size || busy}
                    onClick={() => setBatchOpen(true)}
                  >
                    移出{selected.size ? ` ${selected.size}` : ''}
                  </button>
                  <button
                    type="button"
                    className="link muted"
                    onClick={() => {
                      setSelectMode(false)
                      setSelected(new Set())
                    }}
                  >
                    完成
                  </button>
                </>
              )}
            </div>
          </div>

          <input
            className="member-search"
            placeholder="筛选成员"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />

          <div className="member-grid">
            {!selectMode && (
              <button type="button" className="member-cell add" onClick={() => setPickerOpen(true)}>
                <span className="plus">+</span>
                <span className="name">添加</span>
              </button>
            )}
            {filtered.map((m) => {
              const on = selected.has(m.wxid)
              return (
                <button
                  key={m.wxid}
                  type="button"
                  className={`member-cell ${on ? 'picked' : ''}`}
                  title={m.wxid}
                  onClick={(e) => {
                    if (selectMode) {
                      setSelected((prev) => {
                        const next = new Set(prev)
                        if (next.has(m.wxid)) next.delete(m.wxid)
                        else next.add(m.wxid)
                        return next
                      })
                      return
                    }
                    e.stopPropagation()
                    setMenu({ wxid: m.wxid, x: e.clientX, y: e.clientY })
                  }}
                >
                  <Avatar src={m.avatar} name={label(m)} />
                  <span className="name">{label(m)}</span>
                  {selectMode && <span className={`pick-dot ${on ? 'on' : ''}`}>{on ? '✓' : ''}</span>}
                </button>
              )
            })}
          </div>
        </section>

        <details className="fold">
          <summary>更多信息</summary>
          <p>
            <code>{room.id}</code>
          </p>
        </details>
      </div>

      {menu && (
        <div
          className="menu"
          style={{
            left: Math.min(menu.x, window.innerWidth - 170),
            top: Math.min(menu.y, window.innerHeight - 160),
          }}
          onClick={(e) => e.stopPropagation()}
        >
          {(() => {
            const m = members.find((x) => x.wxid === menu.wxid)
            if (!m) return null
            return (
              <>
                <div className="cap">{label(m)}</div>
                <button
                  type="button"
                  onClick={() => {
                    setMenu(null)
                    void run(() => api.pat(baseUrl, room.id, m.wxid), `已拍 ${label(m)}`)
                  }}
                >
                  轻拍一下
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMenu(null)
                    openSession({
                      id: m.wxid,
                      name: label(m),
                      avatar: String(m.avatar || ''),
                      kind: 'contact',
                    })
                  }}
                >
                  发私信
                </button>
                <button
                  type="button"
                  className="danger"
                  onClick={() => {
                    setMenu(null)
                    setRemoveTarget(m)
                  }}
                >
                  移出群组
                </button>
              </>
            )
          })()}
        </div>
      )}

      <ContactPicker
        open={pickerOpen}
        title="添加成员"
        excludeIds={memberIds}
        confirmLabel="添加"
        onClose={() => setPickerOpen(false)}
        onConfirm={(cs) => {
          setPickerOpen(false)
          if (!cs.length) return
          void run(
            () => api.roomAdd(baseUrl, room.id, cs.map((c) => c.id).join(',')),
            `已添加 ${cs.length} 人`,
          )
        }}
      />

      <ConfirmDialog
        open={!!removeTarget}
        title="移出成员"
        message={`确定将「${removeTarget ? label(removeTarget) : ''}」移出群组？`}
        confirmLabel="移出"
        danger
        onCancel={() => setRemoveTarget(null)}
        onConfirm={() => {
          const m = removeTarget
          setRemoveTarget(null)
          if (!m) return
          void run(() => api.roomDel(baseUrl, room.id, m.wxid), `已移出 ${label(m)}`)
        }}
      />

      <ConfirmDialog
        open={batchOpen}
        title="批量移出"
        message={`确定移出选中的 ${selected.size} 人？`}
        confirmLabel="移出"
        danger
        onCancel={() => setBatchOpen(false)}
        onConfirm={() => {
          setBatchOpen(false)
          void run(() => api.roomDel(baseUrl, room.id, [...selected].join(',')), `已移出 ${selected.size} 人`)
          setSelectMode(false)
          setSelected(new Set())
        }}
      />

      {toast && <div className="toast">{toast}</div>}
    </>
  )
}
