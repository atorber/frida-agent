/**
 * OpenAI 兼容 Chat Completions（含流式）
 *
 * 环境变量（两组等价，优先 LLM_*）：
 *   LLM_API_KEY / OPENAI_API_KEY
 *   LLM_BASE_URL / OPENAI_API_URL / OPENAI_BASE_URL
 *   LLM_MODEL / OPENAI_MODEL
 *   LLM_TIMEOUT_MS
 */

function trimSlash(s) {
  return String(s || '').replace(/\/+$/, '')
}

function firstEnv(...keys) {
  for (const k of keys) {
    const v = String(process.env[k] || '').trim()
    if (v) return v
  }
  return ''
}

export function llmConfig() {
  const apiKey = firstEnv('LLM_API_KEY', 'OPENAI_API_KEY')
  const baseUrl = trimSlash(
    firstEnv('LLM_BASE_URL', 'OPENAI_API_URL', 'OPENAI_BASE_URL') ||
      'https://api.openai.com/v1',
  )
  const model = firstEnv('LLM_MODEL', 'OPENAI_MODEL') || 'gpt-4o-mini'
  const timeoutMs = Number(process.env.LLM_TIMEOUT_MS || 60000)
  return {
    configured: !!apiKey,
    apiKey,
    baseUrl,
    model,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 60000,
  }
}

function buildBody(messages, opts, stream) {
  const cfg = llmConfig()
  return {
    model: opts.model || cfg.model,
    messages,
    temperature: opts.temperature ?? 0.7,
    max_tokens: opts.maxTokens ?? 1024,
    stream: !!stream,
  }
}

/**
 * @param {{ role: string, content: string }[]} messages
 * @param {{ temperature?: number, maxTokens?: number, model?: string }} [opts]
 */
export async function chatCompletion(messages, opts = {}) {
  const cfg = llmConfig()
  if (!cfg.apiKey) {
    throw new Error('未配置 LLM_API_KEY，请在 server/.env 中设置')
  }

  const url = `${cfg.baseUrl}/chat/completions`
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs)

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${cfg.apiKey}`,
      },
      body: JSON.stringify(buildBody(messages, opts, false)),
      signal: controller.signal,
    })

    const raw = await res.text()
    let data
    try {
      data = JSON.parse(raw)
    } catch {
      throw new Error(`大模型响应非 JSON (HTTP ${res.status}): ${raw.slice(0, 200)}`)
    }

    if (!res.ok) {
      const msg = data?.error?.message || data?.msg || raw.slice(0, 300)
      throw new Error(`大模型调用失败 (HTTP ${res.status}): ${msg}`)
    }

    const text = data?.choices?.[0]?.message?.content
    if (!text || !String(text).trim()) {
      throw new Error('大模型返回空内容')
    }
    return String(text).trim()
  } catch (e) {
    if (e?.name === 'AbortError') {
      throw new Error(`大模型请求超时（>${cfg.timeoutMs}ms）`)
    }
    throw e
  } finally {
    clearTimeout(timer)
  }
}

/**
 * 流式补全：对每个增量调用 onDelta(textChunk)，最终返回完整文本
 */
export async function chatCompletionStream(messages, opts = {}, onDelta) {
  const cfg = llmConfig()
  if (!cfg.apiKey) {
    throw new Error('未配置 LLM_API_KEY，请在 server/.env 中设置')
  }

  const url = `${cfg.baseUrl}/chat/completions`
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs)

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${cfg.apiKey}`,
      },
      body: JSON.stringify(buildBody(messages, opts, true)),
      signal: controller.signal,
    })

    if (!res.ok) {
      const raw = await res.text()
      let msg = raw.slice(0, 300)
      try {
        msg = JSON.parse(raw)?.error?.message || msg
      } catch {
        /* ignore */
      }
      throw new Error(`大模型调用失败 (HTTP ${res.status}): ${msg}`)
    }

    if (!res.body) {
      // 部分网关不支持 stream，回退非流式
      const text = await chatCompletion(messages, opts)
      if (onDelta) onDelta(text)
      return text
    }

    const reader = res.body.getReader()
    const decoder = new TextDecoder('utf-8')
    let buffer = ''
    let full = ''

    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const parts = buffer.split('\n')
      buffer = parts.pop() || ''
      for (const line of parts) {
        const trimmed = line.trim()
        if (!trimmed.startsWith('data:')) continue
        const payload = trimmed.slice(5).trim()
        if (payload === '[DONE]') continue
        try {
          const json = JSON.parse(payload)
          const delta = json?.choices?.[0]?.delta?.content
          if (delta) {
            full += delta
            if (onDelta) onDelta(delta)
          }
        } catch {
          /* ignore bad chunk */
        }
      }
    }

    if (!full.trim()) {
      throw new Error('大模型流式返回空内容')
    }
    return full.trim()
  } catch (e) {
    if (e?.name === 'AbortError') {
      throw new Error(`大模型请求超时（>${cfg.timeoutMs}ms）`)
    }
    throw e
  } finally {
    clearTimeout(timer)
  }
}

/** 从模型输出中尽量解析 JSON */
export function extractJson(text) {
  const raw = String(text || '').trim()
  try {
    return JSON.parse(raw)
  } catch {
    /* continue */
  }
  const fence = raw.match(/```(?:json)?\s*([\s\S]*?)```/i)
  if (fence) {
    try {
      return JSON.parse(fence[1].trim())
    } catch {
      /* continue */
    }
  }
  const start = raw.indexOf('{')
  const end = raw.lastIndexOf('}')
  if (start >= 0 && end > start) {
    try {
      return JSON.parse(raw.slice(start, end + 1))
    } catch {
      /* continue */
    }
  }
  throw new Error('无法解析模型 JSON 输出')
}

export function buildAssistantSystemPrompt({ talkerName, talkerId }) {
  return [
    '你是微信会话助手：只输出可直接发送的草案（不要解释/前缀）。',
    '不编造事实；信息不足可先说明假设或追问。',
    '语气匹配私聊/群聊场景，避免公文腔。',
    `会话对象：${talkerName || talkerId || '未知'}`,
  ].join('\n')
}
