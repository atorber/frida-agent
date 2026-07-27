import type { ApiResponse } from './types'

export class ApiError extends Error {
  code: number
  constructor(msg: string, code = 0) {
    super(msg)
    this.code = code
    this.name = 'ApiError'
  }
}

const STORAGE_KEY = 'wx391027.baseUrl'

function isLoopbackHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase()
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0'
}

/** 当前页面是否通过 localhost / 127.0.0.1 打开 */
export function pageIsLoopback(): boolean {
  if (typeof window === 'undefined') return true
  return isLoopbackHost(window.location.hostname)
}

/** 直连 Agent 的推荐地址（跟页面同主机名） */
export function suggestDirectBaseUrl(port = 19088): string {
  if (typeof window === 'undefined') return `http://127.0.0.1:${port}`
  const host = window.location.hostname
  return `http://${host}:${port}`
}

/**
 * 解析实际请求用的 Base URL。
 * - 空字符串：同源 `/api`（开发态 Vite 代理，局域网访问也正确）
 * - 若页面用局域网 IP 打开，却配置了 127.0.0.1，则自动改写，避免打到访客本机
 */
export function resolveApiBase(stored: string): string {
  const raw = (stored || '').trim().replace(/\/$/, '')
  const host = typeof window !== 'undefined' ? window.location.hostname : 'localhost'
  const onLoopback = isLoopbackHost(host)

  if (!raw) {
    if (import.meta.env.DEV) return ''
    return onLoopback ? 'http://127.0.0.1:19088' : `http://${host}:19088`
  }

  try {
    const u = new URL(raw.includes('://') ? raw : `http://${raw}`)
    if (isLoopbackHost(u.hostname) && !onLoopback) {
      // 局域网打开页面时，127.0.0.1 指向访客电脑 → 开发走代理，生产走页面主机
      if (import.meta.env.DEV) return ''
      return `http://${host}:${u.port || '19088'}`
    }
    return `${u.protocol}//${u.host}`.replace(/\/$/, '')
  } catch {
    return raw
  }
}

export function getStoredBaseUrl(): string {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v != null) return v.replace(/\/$/, '')
  } catch {
    /* ignore */
  }
  return ''
}

export function setStoredBaseUrl(url: string) {
  const next = url.replace(/\/$/, '')
  try {
    if (!next) localStorage.removeItem(STORAGE_KEY)
    else localStorage.setItem(STORAGE_KEY, next)
  } catch {
    /* ignore */
  }
}

export async function request<T>(
  baseUrl: string,
  method: string,
  path: string,
  body?: unknown,
  query?: Record<string, string | number | undefined | null>,
): Promise<ApiResponse<T>> {
  const root = resolveApiBase(baseUrl)
  const qs = new URLSearchParams()
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null || v === '') continue
      qs.set(k, String(v))
    }
  }
  const q = qs.toString()
  const url = `${root}${path}${q ? `?${q}` : ''}`

  const init: RequestInit = {
    method,
    headers: { 'Content-Type': 'application/json' },
  }
  if (body !== undefined && method !== 'GET') {
    init.body = JSON.stringify(body)
  }

  let res: Response
  try {
    res = await fetch(url, init)
  } catch (e) {
    throw new ApiError(`连接失败: ${(e as Error).message || String(e)}`)
  }

  let data: ApiResponse<T>
  try {
    data = (await res.json()) as ApiResponse<T>
  } catch {
    throw new ApiError(`响应解析失败 HTTP ${res.status}`)
  }
  return data
}

export async function requestOk<T>(
  baseUrl: string,
  method: string,
  path: string,
  body?: unknown,
  query?: Record<string, string | number | undefined | null>,
): Promise<T> {
  const res = await request<T>(baseUrl, method, path, body, query)
  if (res.code !== 1) {
    throw new ApiError(res.msg || '请求失败', res.code)
  }
  return res.data
}

export interface UploadResult {
  path: string
  filename: string
  size: number
  category: string
}

/** 上传文件到 Agent 本机，返回绝对路径 */
export async function uploadBinary(
  baseUrl: string,
  file: Blob,
  filename: string,
  category: 'image' | 'file' | 'emotion' = 'file',
): Promise<UploadResult> {
  const root = resolveApiBase(baseUrl)
  const url = `${root}/api/upload`
  let res: Response
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Filename': encodeURIComponent(filename),
        'X-Category': category,
      },
      body: file,
    })
  } catch (e) {
    throw new ApiError(`上传失败: ${(e as Error).message || String(e)}`)
  }
  let data: ApiResponse<UploadResult>
  try {
    data = (await res.json()) as ApiResponse<UploadResult>
  } catch {
    throw new ApiError(`上传响应解析失败 HTTP ${res.status}`)
  }
  if (data.code !== 1 || !data.data?.path) {
    throw new ApiError(data.msg || '上传失败', data.code)
  }
  return data.data
}
