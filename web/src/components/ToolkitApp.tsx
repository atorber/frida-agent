import { useEffect, useState } from 'react'
import { api } from '../api/endpoints'
import { appsApi, getStoredLlmParams, type ToolkitRun, type ToolkitTool } from '../api/apps'
import { useAgent } from '../context/AgentContext'

type Props = {
  onUseReply: (text: string) => void
  composerDraft?: string
}

// 省 token：工具侧摘录同样压缩规模
const TOOL_SNIPPET_LIMIT = 12
const TOOL_SNIPPET_CHARS = 100

async function loadWxSnippet(
  baseUrl: string,
  talker: string,
  limit = TOOL_SNIPPET_LIMIT,
  maxChars = TOOL_SNIPPET_CHARS,
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

/** 工具四件套：回复草案 / 摘要 / 润色 / 翻译（均走 LLM，不自动发微信） */
export function ToolkitApp({ onUseReply, composerDraft = '' }: Props) {
  const { activeTalker, sessions, baseUrl } = useAgent()
  const session = sessions.find((s) => s.id === activeTalker)
  const [tools, setTools] = useState<ToolkitTool[]>([])
  const [history, setHistory] = useState<ToolkitRun[]>([])
  const [draft, setDraft] = useState('')
  const [direction, setDirection] = useState<'zh2en' | 'en2zh'>('zh2en')
  const [lastResult, setLastResult] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    void appsApi
      .listTools()
      .then((list) => setTools(list || []))
      .catch((e) => setErr((e as Error).message))
  }, [])

  useEffect(() => {
    setDraft(composerDraft || '')
  }, [composerDraft])

  useEffect(() => {
    setLastResult(null)
    setErr(null)
    if (!activeTalker) {
      setHistory([])
      return
    }
    void appsApi
      .toolHistory(activeTalker, 15)
      .then(setHistory)
      .catch(() => setHistory([]))
  }, [activeTalker])

  const run = async (toolId: string, fill: boolean) => {
    if (!activeTalker || busy) return
    setBusy(true)
    setErr(null)
    try {
      const effectiveDraft = (draft || composerDraft || '').trim()

      // 省 token：只有在“必须依赖会话摘录”的工具/场景才传 context
      const needContext =
        toolId === 'reply_draft' ||
        toolId === 'summarize' ||
        ((toolId === 'polish' || toolId === 'translate') && !effectiveDraft)

      const context = needContext ? await loadWxSnippet(baseUrl, activeTalker) : undefined
      const params = getStoredLlmParams()
      // 省 token：按工具类型对 maxTokens 做保守上限
      const maxCap = toolId === 'translate' ? 320 : toolId === 'polish' ? 380 : 520
      const nextParams = {
        ...params,
        maxTokens: typeof params.maxTokens === 'number' ? Math.min(params.maxTokens, maxCap) : maxCap,
      }
      const data = await appsApi.runTool(activeTalker, toolId, {
        name: session?.name,
        draft: effectiveDraft,
        context,
        direction,
        ...nextParams,
      })
      setLastResult(data.result)
      setHistory((prev) => [data, ...prev].slice(0, 15))
      if (fill) onUseReply(data.result)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const saveSummaryNote = async () => {
    if (!activeTalker || !lastResult) return
    try {
      await appsApi.addNote(activeTalker, lastResult, { tags: ['待办'] })
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  if (!activeTalker) {
    return <div className="assistant-empty">选中会话后，可使用快捷工具。</div>
  }

  return (
    <div className="toolkit-app">
      {err && <div className="banner error">{err}</div>}
      <div className="field" style={{ marginBottom: 8 }}>
        <span>草稿（润色/翻译用，可同步自输入框）</span>
        <textarea
          value={draft}
          rows={3}
          placeholder="粘贴或编辑待处理文本…"
          onChange={(e) => setDraft(e.target.value)}
        />
      </div>
      <div className="notes-filters" style={{ marginBottom: 8 }}>
        <span className="svc-meta">翻译方向</span>
        <button
          type="button"
          className={`chip ${direction === 'zh2en' ? 'on' : ''}`}
          onClick={() => setDirection('zh2en')}
        >
          中→英
        </button>
        <button
          type="button"
          className={`chip ${direction === 'en2zh' ? 'on' : ''}`}
          onClick={() => setDirection('en2zh')}
        >
          英→中
        </button>
      </div>
      <div className="toolkit-grid">
        {tools.map((t) => (
          <div key={t.id} className="toolkit-card">
            <strong>{t.title}</strong>
            <span>{t.desc}</span>
            <div className="toolkit-actions">
              <button
                type="button"
                className="btn soft"
                disabled={busy}
                onClick={() => void run(t.id, true)}
              >
                填入输入框
              </button>
              <button
                type="button"
                className="btn ghost"
                disabled={busy}
                onClick={() => void run(t.id, false)}
              >
                预览
              </button>
            </div>
          </div>
        ))}
      </div>
      {lastResult && (
        <div className="toolkit-preview">
          <div className="toolkit-preview-title">最近结果</div>
          <pre>{lastResult}</pre>
          <div className="toolkit-actions">
            <button type="button" className="btn soft" onClick={() => onUseReply(lastResult)}>
              再次填入
            </button>
            <button type="button" className="btn ghost" onClick={() => void saveSummaryNote()}>
              存为速记
            </button>
          </div>
        </div>
      )}
      <div className="toolkit-history">
        <div className="toolkit-preview-title">运行历史</div>
        {history.length === 0 ? (
          <div className="assistant-empty">暂无记录</div>
        ) : (
          <ul>
            {history.map((h) => (
              <li key={h.id}>
                <div className="suggest-top">
                  <span>{h.toolId}</span>
                  <em>{new Date(h.at).toLocaleString('zh-CN', { hour12: false })}</em>
                </div>
                <p>{h.result.slice(0, 180)}{h.result.length > 180 ? '…' : ''}</p>
                <button type="button" className="link" onClick={() => onUseReply(h.result)}>
                  填入
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
