import type { ApiResponse } from './types'

export interface AppsMessage {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  at: number
}

export interface ReplySuggestion {
  id: string
  label: string
  text: string
  tone: 'friendly' | 'formal' | 'brief'
}

export interface ConversationInsight {
  id: string
  title: string
  detail: string
}

export interface NoteItem {
  id: string
  text: string
  at: number
  updatedAt?: number
  pinned?: boolean
  tags?: string[]
}

export interface ToolkitTool {
  id: string
  title: string
  desc: string
}

export interface ToolkitRun {
  id: string
  toolId: string
  result: string
  at: number
}

export interface AssistantContext {
  talker: string
  name: string
  suggestions: ReplySuggestion[]
  insights: ConversationInsight[]
  messages: AppsMessage[]
  analysisUpdatedAt?: number | null
  analysisFingerprint?: string | null
  noteTags?: string[]
  llm?: { configured: boolean; model: string; baseUrl: string }
}

export interface LlmParams {
  temperature?: number
  maxTokens?: number
}

const APPS_ROOT = ''
const LLM_PARAMS_KEY = 'wx391027.llmParams'

export function getStoredLlmParams(): LlmParams {
  try {
    const raw = localStorage.getItem(LLM_PARAMS_KEY)
    if (!raw) return { temperature: 0.7, maxTokens: 512 }
    return { temperature: 0.7, maxTokens: 512, ...JSON.parse(raw) }
  } catch {
    return { temperature: 0.7, maxTokens: 512 }
  }
}

export function setStoredLlmParams(p: LlmParams) {
  localStorage.setItem(LLM_PARAMS_KEY, JSON.stringify(p))
}

async function appsRequest<T>(
  method: string,
  path: string,
  body?: unknown,
  query?: Record<string, string | number | undefined | null>,
): Promise<T> {
  const qs = new URLSearchParams()
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null || v === '') continue
      qs.set(k, String(v))
    }
  }
  const q = qs.toString()
  const url = `${APPS_ROOT}${path}${q ? `?${q}` : ''}`
  let res: Response
  try {
    res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body !== undefined && method !== 'GET' ? JSON.stringify(body) : undefined,
    })
  } catch (e) {
    throw new Error(`应用服务连接失败: ${(e as Error).message || String(e)}`)
  }
  let data: ApiResponse<T>
  try {
    data = (await res.json()) as ApiResponse<T>
  } catch {
    throw new Error(`应用服务响应解析失败 HTTP ${res.status}`)
  }
  if (data.code !== 1) {
    throw new Error(data.msg || '应用服务请求失败')
  }
  return data.data
}

export type StreamHandlers = {
  onUser?: (msg: AppsMessage) => void
  onDelta?: (chunk: string) => void
  onDone?: (data: { assistant: AppsMessage; messages: AppsMessage[] }) => void
  onError?: (msg: string) => void
}

export const appsApi = {
  health: () =>
    appsRequest<{ status: string; llm?: { configured: boolean } }>('GET', '/apps/health'),

  assistantContext: (talker: string, name?: string) =>
    appsRequest<AssistantContext>('GET', '/apps/assistant/context', undefined, { talker, name }),

  assistantAnalyze: (
    talker: string,
    opts?: { name?: string; context?: string; force?: boolean; mode?: 'insight' | 'suggest' | 'both' },
  ) =>
    appsRequest<{
      insights: ConversationInsight[]
      suggestions: ReplySuggestion[]
      fingerprint: string
      updatedAt?: number
      cached?: boolean
    }>('POST', '/apps/assistant/analyze', {
      talker,
      name: opts?.name,
      context: opts?.context,
      force: opts?.force,
      mode: opts?.mode,
    }),

  assistantChat: (
    talker: string,
    prompt: string,
    opts?: { name?: string; context?: string } & LlmParams,
  ) =>
    appsRequest<{
      user: AppsMessage
      assistant: AppsMessage
      messages: AppsMessage[]
    }>('POST', '/apps/assistant/chat', {
      talker,
      prompt,
      name: opts?.name,
      context: opts?.context,
      temperature: opts?.temperature,
      maxTokens: opts?.maxTokens,
    }),

  assistantChatStream: async (
    talker: string,
    prompt: string,
    opts: ({ name?: string; context?: string } & LlmParams) | undefined,
    handlers: StreamHandlers,
  ) => {
    const res = await fetch(`${APPS_ROOT}/apps/assistant/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        talker,
        prompt,
        name: opts?.name,
        context: opts?.context,
        temperature: opts?.temperature,
        maxTokens: opts?.maxTokens,
      }),
    })
    if (!res.ok || !res.body) {
      let msg = `流式请求失败 HTTP ${res.status}`
      try {
        const j = (await res.json()) as ApiResponse<unknown>
        if (j.msg) msg = j.msg
      } catch {
        /* ignore */
      }
      throw new Error(msg)
    }

    const reader = res.body.getReader()
    const decoder = new TextDecoder('utf-8')
    let buffer = ''
    let eventName = 'message'

    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const chunks = buffer.split('\n')
      buffer = chunks.pop() || ''
      for (const line of chunks) {
        if (line.startsWith('event:')) {
          eventName = line.slice(6).trim()
          continue
        }
        if (!line.startsWith('data:')) continue
        const raw = line.slice(5).trim()
        if (!raw) continue
        let data: any
        try {
          data = JSON.parse(raw)
        } catch {
          continue
        }
        if (eventName === 'user') handlers.onUser?.(data)
        else if (eventName === 'delta') handlers.onDelta?.(data.content || '')
        else if (eventName === 'done') handlers.onDone?.(data)
        else if (eventName === 'error') handlers.onError?.(data.msg || '流式错误')
      }
    }
  },

  clearAssistantMessages: (talker: string) =>
    appsRequest<{ cleared: boolean }>('DELETE', '/apps/assistant/messages', undefined, { talker }),

  listNotes: (talker: string, tag?: string) =>
    appsRequest<NoteItem[]>('GET', '/apps/notes', undefined, { talker, tag }),

  addNote: (talker: string, text: string, opts?: { tags?: string[]; pinned?: boolean }) =>
    appsRequest<NoteItem>('POST', '/apps/notes', {
      talker,
      text,
      tags: opts?.tags,
      pinned: opts?.pinned,
    }),

  updateNote: (
    id: string,
    patch: { text?: string; tags?: string[]; pinned?: boolean },
  ) => appsRequest<NoteItem>('PATCH', `/apps/notes/${encodeURIComponent(id)}`, patch),

  deleteNote: (id: string) =>
    appsRequest<{ deleted: boolean }>('DELETE', `/apps/notes/${encodeURIComponent(id)}`),

  listTools: () => appsRequest<ToolkitTool[]>('GET', '/apps/toolkit/tools'),

  runTool: (
    talker: string,
    toolId: string,
    opts?: {
      name?: string
      draft?: string
      context?: string
      direction?: string
    } & LlmParams,
  ) =>
    appsRequest<{ id: string; toolId: string; result: string; at: number }>(
      'POST',
      '/apps/toolkit/run',
      {
        talker,
        toolId,
        name: opts?.name,
        draft: opts?.draft,
        context: opts?.context,
        direction: opts?.direction,
        temperature: opts?.temperature,
        maxTokens: opts?.maxTokens,
      },
    ),

  toolHistory: (talker: string, limit = 20) =>
    appsRequest<ToolkitRun[]>('GET', '/apps/toolkit/history', undefined, { talker, limit }),
}
