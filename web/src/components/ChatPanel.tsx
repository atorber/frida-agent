import { useEffect, useRef, useState, type ChangeEvent } from 'react'
import { api } from '../api/endpoints'
import type { ChatHistoryItem, RoomMember, SessionItem } from '../api/types'
import { useAgent } from '../context/AgentContext'
import { Avatar } from './Avatar'

type ExtraMode = null | 'card' | 'forward' | 'at' | 'more'

type Props = {
  injectText?: string | null
  onInjectConsumed?: () => void
  onDraftChange?: (text: string) => void
}

function typeLabel(t: number) {
  const map: Record<number, string> = {
    1: '文本',
    3: '图片',
    34: '语音',
    42: '名片',
    43: '视频',
    47: '表情',
    49: '应用',
    10000: '系统',
  }
  return map[t] || `类型 ${t}`
}

export function ChatPanel({ injectText, onInjectConsumed, onDraftChange }: Props) {
  const { baseUrl, activeTalker, sessions, touchSession } = useAgent()
  const session: SessionItem | undefined = sessions.find((s) => s.id === activeTalker)
  const [messages, setMessages] = useState<ChatHistoryItem[]>([])
  const [text, setText] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const [sending, setSending] = useState(false)
  const [status, setStatus] = useState<string | null>(null)
  const [extra, setExtra] = useState<ExtraMode>(null)
  const [card, setCard] = useState({ title: '', url: '', digest: '', thumburl: '', name: '' })
  const [fwdMsgId, setFwdMsgId] = useState('')
  const [fwdTo, setFwdTo] = useState('')
  const [members, setMembers] = useState<RoomMember[]>([])
  const [atWxids, setAtWxids] = useState<string[]>([])
  const bottomRef = useRef<HTMLDivElement>(null)
  const imageInputRef = useRef<HTMLInputElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const emotionInputRef = useRef<HTMLInputElement>(null)
  const isRoom = !!activeTalker?.endsWith('@chatroom') || session?.kind === 'room'

  useEffect(() => {
    if (injectText == null || injectText === '') return
    setText(injectText)
    onInjectConsumed?.()
  }, [injectText, onInjectConsumed])

  useEffect(() => {
    onDraftChange?.(text)
  }, [text, onDraftChange])

  const showToast = (msg: string) => {
    setToast(msg)
    window.setTimeout(() => setToast(null), 2600)
  }

  const loadHistory = async (silent = false) => {
    if (!activeTalker) return
    try {
      const data = await api.history(baseUrl, { talker: activeTalker, limit: 80, order: 'asc' })
      const items = data.items || []
      setMessages((prev) => {
        if (
          silent &&
          prev.length === items.length &&
          prev[prev.length - 1]?.msgId === items[items.length - 1]?.msgId
        ) {
          return prev
        }
        return items
      })
      if (!silent) setErr(null)
      const last = items[items.length - 1]
      if (last) {
        touchSession(activeTalker, last.displayContent || last.content || typeLabel(last.type))
      }
    } catch (e) {
      if (!silent) setErr((e as Error).message)
    }
  }

  useEffect(() => {
    setMessages([])
    setText('')
    setExtra(null)
    setAtWxids([])
    setStatus(null)
    if (!activeTalker) return
    void loadHistory()
    const t = window.setInterval(() => void loadHistory(true), 4000)
    return () => window.clearInterval(t)
  }, [activeTalker, baseUrl])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages.length])

  useEffect(() => {
    if (!isRoom || !activeTalker) {
      setMembers([])
      return
    }
    void api
      .getRoomMembers(baseUrl, activeTalker)
      .then(setMembers)
      .catch(() => setMembers([]))
  }, [isRoom, activeTalker, baseUrl])

  const sendText = async () => {
    if (!activeTalker || !text.trim()) return
    setSending(true)
    setErr(null)
    try {
      await api.sendText(
        baseUrl,
        activeTalker,
        text.trim(),
        isRoom && atWxids.length ? atWxids : undefined,
      )
      setText('')
      setAtWxids([])
      showToast('已发送')
      await loadHistory(true)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setSending(false)
    }
  }

  const uploadAndSend = async (kind: 'image' | 'file' | 'emotion', file: File) => {
    if (!activeTalker) return
    setSending(true)
    setErr(null)
    setStatus(`上传 ${file.name}`)
    try {
      const up = await api.upload(baseUrl, file, file.name, kind)
      setStatus('发送中')
      if (kind === 'image') await api.sendImage(baseUrl, activeTalker, up.path)
      else if (kind === 'file') await api.sendFile(baseUrl, activeTalker, up.path)
      else await api.sendEmotion(baseUrl, activeTalker, up.path)
      showToast('已发送')
      await loadHistory(true)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setSending(false)
      setStatus(null)
    }
  }

  const onPick =
    (kind: 'image' | 'file' | 'emotion') =>
    (e: ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      e.target.value = ''
      if (file) void uploadAndSend(kind, file)
    }

  if (!activeTalker) {
    return (
      <div className="stage-empty">
        <div>
          <h2>选择一个对话</h2>
          <p>左侧打开会话，或从人脉 / 群组发起新的沟通。</p>
        </div>
      </div>
    )
  }

  return (
    <>
      <header className="stage-top">
        <div className="who">
          <Avatar src={session?.avatar} name={session?.name || activeTalker} size="sm" />
          <div>
            <h2>{session?.name || activeTalker}</h2>
            <div className="who-sub">{isRoom ? '群组' : '私信'}</div>
          </div>
        </div>
        <div className="stage-actions">
          <button type="button" className="btn ghost" onClick={() => void loadHistory()}>
            刷新
          </button>
        </div>
      </header>

      <div className="chat-stream">
        {err && <div className="banner error">{err}</div>}
        {messages.map((m) => (
          <div
            key={`${m.dbName}-${m.localId}-${m.msgId}`}
            className={`msg ${m.isSender ? 'mine' : ''}`}
          >
            <Avatar name={m.isSender ? '我' : session?.name} size="sm" />
            <div className="bubble">
              {m.displayContent || m.content || `[${typeLabel(m.type)}]`}
              <div className="bubble-meta">
                <span>{m.createTimeText}</span>
                <span>{typeLabel(m.type)}</span>
              </div>
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      <footer className="composer">
        <input ref={imageInputRef} type="file" accept="image/*" hidden onChange={onPick('image')} />
        <input ref={fileInputRef} type="file" hidden onChange={onPick('file')} />
        <input
          ref={emotionInputRef}
          type="file"
          accept="image/gif,.gif,.png"
          hidden
          onChange={onPick('emotion')}
        />

        <div className="composer-bar">
          <button type="button" className="chip" disabled={sending} onClick={() => imageInputRef.current?.click()}>
            图片
          </button>
          <button type="button" className="chip" disabled={sending} onClick={() => fileInputRef.current?.click()}>
            文件
          </button>
          <button type="button" className="chip" disabled={sending} onClick={() => emotionInputRef.current?.click()}>
            动图
          </button>
          {isRoom && (
            <button
              type="button"
              className={`chip ${extra === 'at' ? 'on' : ''}`}
              onClick={() => setExtra(extra === 'at' ? null : 'at')}
            >
              提及
            </button>
          )}
          <button
            type="button"
            className={`chip ${extra === 'more' || extra === 'card' || extra === 'forward' ? 'on' : ''}`}
            onClick={() =>
              setExtra(extra === 'more' || extra === 'card' || extra === 'forward' ? null : 'more')
            }
          >
            更多
          </button>
        </div>

        {status && <div className="upload-line">{status}</div>}

        {(extra === 'more' || extra === 'card' || extra === 'forward') && (
          <div className="panel-sheet">
            <div className="actions" style={{ margin: 0 }}>
              <button type="button" className={`chip ${extra === 'card' ? 'on' : ''}`} onClick={() => setExtra('card')}>
                链接卡片
              </button>
              <button
                type="button"
                className={`chip ${extra === 'forward' ? 'on' : ''}`}
                onClick={() => setExtra('forward')}
              >
                转发
              </button>
            </div>
            {extra === 'card' && (
              <>
                <label>
                  标题
                  <input value={card.title} onChange={(e) => setCard({ ...card, title: e.target.value })} />
                </label>
                <label>
                  链接
                  <input value={card.url} onChange={(e) => setCard({ ...card, url: e.target.value })} />
                </label>
                <label>
                  摘要
                  <input value={card.digest} onChange={(e) => setCard({ ...card, digest: e.target.value })} />
                </label>
                <button
                  type="button"
                  className="btn primary"
                  disabled={sending}
                  onClick={() =>
                    void (async () => {
                      setSending(true)
                      try {
                        await api.sendRichText(baseUrl, { receiver: activeTalker, ...card })
                        setExtra(null)
                        showToast('卡片已发送')
                        await loadHistory(true)
                      } catch (e) {
                        setErr((e as Error).message)
                      } finally {
                        setSending(false)
                      }
                    })()
                  }
                >
                  发送卡片
                </button>
              </>
            )}
            {extra === 'forward' && (
              <>
                <label>
                  消息 ID
                  <input value={fwdMsgId} onChange={(e) => setFwdMsgId(e.target.value)} />
                </label>
                <label>
                  转发到
                  <input value={fwdTo} onChange={(e) => setFwdTo(e.target.value)} placeholder="对方或群组" />
                </label>
                <button
                  type="button"
                  className="btn primary"
                  disabled={sending}
                  onClick={() =>
                    void (async () => {
                      setSending(true)
                      try {
                        await api.forward(baseUrl, fwdMsgId.trim(), fwdTo.trim())
                        showToast('已转发')
                        setExtra(null)
                      } catch (e) {
                        setErr((e as Error).message)
                      } finally {
                        setSending(false)
                      }
                    })()
                  }
                >
                  转发
                </button>
              </>
            )}
          </div>
        )}

        {extra === 'at' && isRoom && (
          <div className="panel-sheet">
            <div className="at-cloud">
              <label>
                <input
                  type="checkbox"
                  checked={atWxids.includes('notify@all')}
                  onChange={(e) => {
                    setAtWxids((prev) =>
                      e.target.checked
                        ? [...prev.filter((x) => x !== 'notify@all'), 'notify@all']
                        : prev.filter((x) => x !== 'notify@all'),
                    )
                  }}
                />
                所有人
              </label>
              {members.map((m) => (
                <label key={m.wxid}>
                  <input
                    type="checkbox"
                    checked={atWxids.includes(m.wxid)}
                    onChange={(e) => {
                      setAtWxids((prev) =>
                        e.target.checked ? [...prev, m.wxid] : prev.filter((x) => x !== m.wxid),
                      )
                    }}
                  />
                  {m.displayName || m.name || m.remark || m.wxid}
                </label>
              ))}
            </div>
          </div>
        )}

        <div className="composer-box">
          <textarea
            value={text}
            placeholder="写点什么…"
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                void sendText()
              }
            }}
          />
          <div className="composer-foot">
            <span className="hint">Enter 发送 · Shift+Enter 换行</span>
            <button
              type="button"
              className="btn primary"
              disabled={sending || !text.trim()}
              onClick={() => void sendText()}
            >
              发送
            </button>
          </div>
        </div>
      </footer>
      {toast && <div className="toast">{toast}</div>}
    </>
  )
}
