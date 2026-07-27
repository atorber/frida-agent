import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api/endpoints'
import {
  appsApi,
  getStoredLlmParams,
  setStoredLlmParams,
  type AppsMessage,
  type ConversationInsight,
  type LlmParams,
  type ReplySuggestion,
} from '../api/apps'
import { useAgent } from '../context/AgentContext'

type Props = {
  onUseReply: (text: string) => void
}

type TabId = 'insight' | 'suggest' | 'chat'

const tabs: { id: TabId; label: string }[] = [
  { id: 'insight', label: '情境' },
  { id: 'suggest', label: '建议' },
  { id: 'chat', label: '对话' },
]

const toneLabel: Record<ReplySuggestion['tone'], string> = {
  friendly: '友好',
  formal: '正式',
  brief: '简短',
}

// 省 token：把会话摘录压缩到较小规模（用于情境/建议/对话上下文）
const ANALYZE_SNIPPET_LIMIT = 12
const ANALYZE_SNIPPET_CHARS = 100
const CHAT_SNIPPET_LIMIT = 8
const CHAT_SNIPPET_CHARS = 80

async function loadWxSnippet(
  baseUrl: string,
  talker: string,
  limit = ANALYZE_SNIPPET_LIMIT,
  maxChars = ANALYZE_SNIPPET_CHARS,
): Promise<string> {
  try {
    const data = await api.history(baseUrl, { talker, limit, order: 'desc' })
    const items = [...(data.items || [])].reverse()
    return items
      .map((m) => {
        const who = m.isSender ? '我' : '对方'
        const body = (m.displayContent || m.content || `[类型${m.type}]`).replace(/\s+/g, ' ').trim()
        return `${who}: ${body.slice(0, maxChars)}`
      })
      .join('\n')
  } catch {
    return ''
  }
}

/** 助手：情境/建议 LLM + 流式对话 + 存速记（不自动发微信） */
export function AssistantPanel({ onUseReply }: Props) {
  const { activeTalker, sessions, baseUrl } = useAgent()
  const session = sessions.find((s) => s.id === activeTalker)
  const talkerName = session?.name || activeTalker || '未选择会话'
  const [tab, setTab] = useState<TabId>('suggest')
  const [prompt, setPrompt] = useState('')
  const [busy, setBusy] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [llmReady, setLlmReady] = useState<boolean | null>(null)
  const [messages, setMessages] = useState<AppsMessage[]>([])
  const [suggestions, setSuggestions] = useState<ReplySuggestion[]>([])
  const [insights, setInsights] = useState<ConversationInsight[]>([])
  const [streaming, setStreaming] = useState('')
  const [llmParams, setLlmParams] = useState<LlmParams>(() => getStoredLlmParams())
  const [showParams, setShowParams] = useState(false)
  const endRef = useRef<HTMLDivElement>(null)
  const lastFp = useRef<string>('')
  const chatContextSentRef = useRef(false)

  const refreshAnalysis = useCallback(
    async (force = false, mode?: Exclude<TabId, 'chat'>) => {
      if (!activeTalker) return
      const actualMode = mode || (tab === 'insight' ? 'insight' : 'suggest')
      setAnalyzing(true)
      setErr(null)
      try {
        const context = await loadWxSnippet(baseUrl, activeTalker)
        const data = await appsApi.assistantAnalyze(activeTalker, {
          name: talkerName,
          context,
          force,
          mode: actualMode,
        })
        if (actualMode === 'insight') {
          setInsights(data.insights || [])
          if ((data.suggestions || []).length) setSuggestions(data.suggestions || [])
        } else {
          setSuggestions(data.suggestions || [])
          if ((data.insights || []).length) setInsights(data.insights || [])
        }
        lastFp.current = data.fingerprint || lastFp.current
      } catch (e) {
        setErr((e as Error).message)
      } finally {
        setAnalyzing(false)
      }
    },
    [activeTalker, baseUrl, talkerName, tab],
  )

  useEffect(() => {
    if (!activeTalker) {
      setMessages([])
      setSuggestions([])
      setInsights([])
      setPrompt('')
      setErr(null)
      setLlmReady(null)
      lastFp.current = ''
      return
    }
    let cancelled = false
    setLoading(true)
    setErr(null)
    setTab('suggest')
    void appsApi
      .assistantContext(activeTalker, talkerName)
      .then(async (ctx) => {
        if (cancelled) return
        setMessages(ctx.messages || [])
        setLlmReady(ctx.llm?.configured ?? null)
        setInsights(ctx.insights || [])
        setSuggestions(ctx.suggestions || [])
        lastFp.current = ctx.analysisFingerprint || ''
        chatContextSentRef.current = false

        // 省 token：首次进入默认 tab=建议，只有在缓存为空时才请求 LLM。
        if (ctx.llm?.configured) {
          if (!ctx.suggestions?.length) {
            await refreshAnalysis(false, 'suggest')
          }
        }
      })
      .catch((e) => {
        if (!cancelled) setErr((e as Error).message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [activeTalker, talkerName, baseUrl, refreshAnalysis])

  useEffect(() => {
    if (tab !== 'chat') return
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages.length, busy, streaming, tab])

  // 切到「情境/建议」时，如果对应缓存为空，再拉一次 LLM。
  useEffect(() => {
    if (tab !== 'insight' && tab !== 'suggest') return
    if (!llmReady) return
    if (analyzing || busy) return
    if (tab === 'insight' && insights.length === 0) void refreshAnalysis(false, 'insight')
    if (tab === 'suggest' && suggestions.length === 0) void refreshAnalysis(false, 'suggest')
  }, [tab, llmReady, analyzing, busy, insights.length, suggestions.length, refreshAnalysis])

  const saveNote = async (text: string, tags: string[] = ['其他']) => {
    if (!activeTalker || !text.trim()) return
    try {
      await appsApi.addNote(activeTalker, text.trim(), { tags })
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  const ask = async (text: string) => {
    const q = text.trim()
    if (!q || busy || !activeTalker) return
    setTab('chat')
    setBusy(true)
    setPrompt('')
    setErr(null)
    setStreaming('')
    const params = getStoredLlmParams()
    // 省 token：对话 maxTokens 做保守上限
    const maxCap = 520
    const nextParams = {
      ...params,
      maxTokens: typeof params.maxTokens === 'number' ? Math.min(params.maxTokens, maxCap) : maxCap,
    }
    try {
      // 省 token：对话仅在「第一次发起」时附带聊天摘录；后续轮次只用历史（由服务端截断）。
      const context = chatContextSentRef.current
        ? undefined
        : await loadWxSnippet(baseUrl, activeTalker, CHAT_SNIPPET_LIMIT, CHAT_SNIPPET_CHARS)
      await appsApi.assistantChatStream(
        activeTalker,
        q,
        { name: talkerName, context: context || undefined, ...nextParams },
        {
          onUser: (u) => setMessages((prev) => [...prev, u]),
          onDelta: (d) => setStreaming((s) => s + d),
          onDone: (data) => {
            setStreaming('')
            setMessages(data.messages || [])
          },
          onError: (msg) => {
            setErr(msg)
            setStreaming('')
          },
        },
      )
      chatContextSentRef.current = true
    } catch (e) {
      // 流式失败时回退非流式
      try {
        const context = chatContextSentRef.current
          ? undefined
          : await loadWxSnippet(baseUrl, activeTalker, CHAT_SNIPPET_LIMIT, CHAT_SNIPPET_CHARS)
        const data = await appsApi.assistantChat(activeTalker, q, {
          name: talkerName,
          context: context || undefined,
          ...nextParams,
        })
        setMessages(data.messages || [])
        chatContextSentRef.current = true
      } catch (e2) {
        setErr((e2 as Error).message || (e as Error).message)
      }
    } finally {
      setBusy(false)
      setStreaming('')
    }
  }

  const clearHistory = async () => {
    if (!activeTalker) return
    setBusy(true)
    try {
      await appsApi.clearAssistantMessages(activeTalker)
      const ctx = await appsApi.assistantContext(activeTalker, talkerName)
      setMessages(ctx.messages || [])
      chatContextSentRef.current = false
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (!activeTalker) {
    return <div className="assistant-empty">选中会话后，可在此生成回复草案。</div>
  }

  return (
    <div className="assistant-app">
      {llmReady === false && (
        <div className="banner error" style={{ margin: '8px 12px 0' }}>
          未配置大模型：请在 server/.env 填写 API Key 后重启 Apps Server
        </div>
      )}
      {err && (
        <div className="banner error" style={{ margin: '8px 12px 0' }}>
          {err}
        </div>
      )}
      <div className="assistant-toolbar">
        <button
          type="button"
          className="btn soft"
          disabled={analyzing || busy || llmReady === false}
          onClick={() => void refreshAnalysis(true, tab === 'insight' ? 'insight' : 'suggest')}
        >
          {analyzing ? '分析中…' : tab === 'insight' ? '刷新情境' : '刷新建议'}
        </button>
        <button type="button" className="btn ghost" onClick={() => setShowParams((v) => !v)}>
          模型参数
        </button>
      </div>
      {showParams && (
        <div className="assistant-params">
          <label>
            temperature
            <input
              type="number"
              min={0}
              max={2}
              step={0.1}
              value={llmParams.temperature ?? 0.7}
              onChange={(e) => {
                const next = { ...llmParams, temperature: Number(e.target.value) }
                setLlmParams(next)
                setStoredLlmParams(next)
              }}
            />
          </label>
          <label>
            maxTokens
            <input
              type="number"
              min={64}
              max={4096}
              step={64}
              value={llmParams.maxTokens ?? 1024}
              onChange={(e) => {
                const next = { ...llmParams, maxTokens: Number(e.target.value) }
                setLlmParams(next)
                setStoredLlmParams(next)
              }}
            />
          </label>
        </div>
      )}
      <nav className="assistant-tabs" aria-label="助手功能">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            className={tab === t.id ? 'on' : ''}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <div className="assistant-body">
        {(loading || analyzing) && tab !== 'chat' && (
          <div className="assistant-empty">{analyzing ? '正在分析会话…' : '加载中…'}</div>
        )}

        {!loading && tab === 'insight' && (
          <ul className="assistant-insight">
            {insights.length === 0 ? (
              <li>
                <strong>暂无</strong>
                <span>点击上方「刷新情境/建议」生成。</span>
              </li>
            ) : (
              insights.map((it) => (
                <li key={it.id}>
                  <strong>{it.title}</strong>
                  <span>{it.detail}</span>
                </li>
              ))
            )}
          </ul>
        )}

        {!loading && tab === 'suggest' && (
          <div className="assistant-suggest">
            {suggestions.length === 0 ? (
              <div className="assistant-empty">暂无建议，请先刷新分析。</div>
            ) : (
              suggestions.map((s) => (
                <div key={s.id} className="suggest-card">
                  <div className="suggest-top">
                    <span>{s.label}</span>
                    <em>{toneLabel[s.tone] || s.tone}</em>
                  </div>
                  <p>{s.text}</p>
                  <div className="suggest-actions">
                    <button type="button" className="btn soft" onClick={() => onUseReply(s.text)}>
                      填入输入框
                    </button>
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() => void ask(`请基于「${s.text}」再写一版更自然的回复`)}
                    >
                      再改一版
                    </button>
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() => void saveNote(s.text, ['其他'])}
                    >
                      存为速记
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {tab === 'chat' && (
          <div className="assistant-chat">
            <div className="assistant-quick">
              {['总结对话', '润色上一条', '生成英文回复'].map((q) => (
                <button key={q} type="button" className="chip" disabled={busy} onClick={() => void ask(q)}>
                  {q}
                </button>
              ))}
              <button type="button" className="chip" disabled={busy} onClick={() => void clearHistory()}>
                清空历史
              </button>
            </div>
            <div className="assistant-thread">
              {messages.map((m) => (
                <div key={m.id} className={`assistant-msg ${m.role}`}>
                  {m.content}
                  {m.role === 'assistant' && (
                    <span className="assistant-msg-actions">
                      <button type="button" className="link" onClick={() => onUseReply(m.content)}>
                        用到输入框
                      </button>
                      <button type="button" className="link" onClick={() => void saveNote(m.content)}>
                        存为速记
                      </button>
                    </span>
                  )}
                </div>
              ))}
              {streaming && (
                <div className="assistant-msg assistant">
                  {streaming}
                  <span className="typing-caret">▍</span>
                </div>
              )}
              {busy && !streaming && <div className="assistant-msg assistant typing">正在起草…</div>}
              <div ref={endRef} />
            </div>
            <div className="assistant-compose">
              <textarea
                value={prompt}
                placeholder="问问助手…（不会自动发微信）"
                rows={2}
                disabled={busy}
                onChange={(e) => setPrompt(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault()
                    void ask(prompt)
                  }
                }}
              />
              <button
                type="button"
                className="btn primary"
                disabled={busy || !prompt.trim()}
                onClick={() => void ask(prompt)}
              >
                发送
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
