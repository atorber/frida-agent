/**
 * 基于 Frida Socket.listen 的轻量 HTTP 服务。
 * 保留原始 body 字节，支持文件上传。
 */
import { uint8ArrayToString, stringToUint8Array } from './utils.js'

export interface ParsedHttpRequest {
  method: string
  url: string
  query: Record<string, string>
  headers: Record<string, string>
  /** UTF-8 文本 body（JSON 等）；二进制请求可能为空或不完整，请用 bodyBytes */
  body: string
  /** 原始 body 字节 */
  bodyBytes: Uint8Array
}

export interface HttpJsonResponse {
  code: number
  data: any
  msg: string
}

type RequestHandler = (req: ParsedHttpRequest) => HttpJsonResponse | Promise<HttpJsonResponse>

const CORS_HEADERS =
  `Access-Control-Allow-Origin: *\r\n` +
  `Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n` +
  `Access-Control-Allow-Headers: Content-Type, X-Filename, X-Category\r\n` +
  `Access-Control-Max-Age: 86400\r\n`

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

function parseRequestFromBytes(buf: Uint8Array): ParsedHttpRequest {
  let headerEnd = -1
  for (let i = 0; i <= buf.length - 4; i++) {
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a && buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
      headerEnd = i
      break
    }
  }
  const headBytes = headerEnd >= 0 ? buf.subarray(0, headerEnd) : buf
  const bodyBytes = headerEnd >= 0 ? buf.subarray(headerEnd + 4) : new Uint8Array(0)
  const head = uint8ArrayToString(headBytes)
  const lines = head.split('\r\n')
  const first = lines[0] || ''
  const m = first.match(/^(GET|POST|PUT|DELETE|OPTIONS|HEAD)\s+(\S+)/i)
  let method = m ? m[1].toUpperCase() : 'GET'
  let fullUrl = m ? m[2] : '/'
  const qIdx = fullUrl.indexOf('?')
  let url = qIdx >= 0 ? fullUrl.substring(0, qIdx) : fullUrl
  const query: Record<string, string> = {}
  if (qIdx >= 0) {
    const qs = fullUrl.substring(qIdx + 1)
    for (const part of qs.split('&')) {
      if (!part) continue
      const eq = part.indexOf('=')
      const k = eq >= 0 ? decodeURIComponent(part.substring(0, eq)) : decodeURIComponent(part)
      const v = eq >= 0 ? decodeURIComponent(part.substring(eq + 1)) : ''
      query[k] = v
    }
  }
  const headers: Record<string, string> = {}
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]
    const c = line.indexOf(':')
    if (c > 0) {
      headers[line.substring(0, c).trim().toLowerCase()] = line.substring(c + 1).trim()
    }
  }
  const ct = (headers['content-type'] || '').toLowerCase()
  let body = ''
  // 仅对文本/JSON 解码；二进制保持 body 为空，避免破坏 UTF-8 解码
  if (
    bodyBytes.length > 0 &&
    (ct.includes('application/json') ||
      ct.includes('text/') ||
      ct.includes('application/x-www-form-urlencoded') ||
      ct === '')
  ) {
    try {
      body = uint8ArrayToString(bodyBytes)
    } catch {
      body = ''
    }
  }
  return { method, url, query, headers, body, bodyBytes }
}

async function readHttpRequest(conn: SocketConnection): Promise<ParsedHttpRequest | null> {
  let buf = new Uint8Array(0)
  let headerEnd = -1
  let contentLength = -1
  const deadline = Date.now() + 120000
  const maxBody = 42 * 1024 * 1024

  while (Date.now() < deadline) {
    const chunk = await conn.input.read(65536)
    if (!chunk || chunk.byteLength === 0) {
      if (buf.length === 0) return null
      break
    }
    const arr: Uint8Array =
      chunk && (chunk as any).byteLength !== undefined
        ? new Uint8Array(chunk as ArrayBufferLike)
        : new Uint8Array(0)
    buf = concatBytes(buf, arr)

    if (headerEnd < 0) {
      for (let i = 0; i <= buf.length - 4; i++) {
        if (buf[i] === 0x0d && buf[i + 1] === 0x0a && buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
          headerEnd = i
          const headerText = uint8ArrayToString(buf.subarray(0, i))
          const m = headerText.match(/content-length:\s*(\d+)/i)
          contentLength = m ? parseInt(m[1], 10) : 0
          if (contentLength > maxBody) {
            throw new Error(`请求体过大: ${contentLength}`)
          }
          break
        }
      }
    }

    if (headerEnd >= 0) {
      const need = headerEnd + 4 + Math.max(0, contentLength)
      if (buf.length >= need) {
        return parseRequestFromBytes(buf.subarray(0, need))
      }
    }
  }

  if (buf.length > 0) {
    return parseRequestFromBytes(buf)
  }
  return null
}

async function writeHttpResponse(conn: SocketConnection, response: HttpJsonResponse, statusCode = 200) {
  const body = JSON.stringify(response)
  const bodyBytes = stringToUint8Array(body)
  const head =
    `HTTP/1.1 ${statusCode} ${statusCode === 200 ? 'OK' : 'Error'}\r\n` +
    `Content-Type: application/json; charset=utf-8\r\n` +
    `Content-Length: ${bodyBytes.byteLength}\r\n` +
    `Connection: close\r\n` +
    CORS_HEADERS +
    `\r\n`
  const headBytes = stringToUint8Array(head)
  const all = concatBytes(headBytes, bodyBytes)
  const ab = all.buffer.slice(all.byteOffset, all.byteOffset + all.byteLength) as ArrayBuffer
  await conn.output.writeAll(ab)
}

async function writeOptionsResponse(conn: SocketConnection) {
  const head =
    `HTTP/1.1 204 No Content\r\n` +
    `Content-Length: 0\r\n` +
    `Connection: close\r\n` +
    CORS_HEADERS +
    `\r\n`
  const headBytes = stringToUint8Array(head)
  const ab = headBytes.buffer.slice(
    headBytes.byteOffset,
    headBytes.byteOffset + headBytes.byteLength,
  ) as ArrayBuffer
  await conn.output.writeAll(ab)
}

export interface HttpServerHandle {
  close: () => void
  start: () => void
  isClosed: () => boolean
}

export function startHttpServer(port: number, handler: RequestHandler): HttpServerHandle {
  let listener: SocketListener | null = null
  let closed = false
  let restartTimer: any = null
  let accepting = false
  let bindFailStreak = 0

  const closeListener = () => {
    const l = listener
    listener = null
    accepting = false
    if (l) {
      try {
        l.close()
      } catch (e) {}
    }
  }

  const scheduleRestart = (reason: string) => {
    if (closed) return
    if (restartTimer) return

    const isAddrInUse = /只允许使用一次|address already in use|EADDRINUSE/i.test(reason)
    if (isAddrInUse) {
      bindFailStreak++
      if (bindFailStreak > 8) {
        console.error(
          `[HTTP] [${new Date().toISOString()}] 端口 ${port} 持续占用，停止自动重启。可先释放端口再 POST /api/server/start`,
        )
        return
      }
      const delay = Math.min(30000, 1000 * Math.pow(2, Math.min(bindFailStreak - 1, 4)))
      console.error(
        `[HTTP] [${new Date().toISOString()}] 端口占用，${delay}ms 后重试 (${bindFailStreak}/8): ${reason}`,
      )
      restartTimer = setTimeout(() => {
        restartTimer = null
        listenAndAccept()
      }, delay)
      return
    }

    bindFailStreak = 0
    console.error(`[HTTP] [${new Date().toISOString()}] 准备重启监听 (${reason})，500ms 后...`)
    closeListener()
    restartTimer = setTimeout(() => {
      restartTimer = null
      listenAndAccept()
    }, 500)
  }

  const handleConn = (conn: SocketConnection) => {
    ;(async () => {
      try {
        const req = await readHttpRequest(conn)
        if (!req) {
          try {
            await conn.close()
          } catch (e) {}
          return
        }
        console.log(`[HTTP] [${new Date().toISOString()}] ${req.method} ${req.url}`)
        if (req.method === 'OPTIONS') {
          await writeOptionsResponse(conn)
          return
        }
        const res = await new Promise<HttpJsonResponse>((resolve) => {
          setImmediate(() => {
            try {
              Promise.resolve(handler(req))
                .then(resolve)
                .catch((e: any) => {
                  resolve({
                    code: 0,
                    data: null,
                    msg: `处理失败: ${e && e.message ? e.message : String(e)}`,
                  })
                })
            } catch (e: any) {
              resolve({
                code: 0,
                data: null,
                msg: `处理失败: ${e && e.message ? e.message : String(e)}`,
              })
            }
          })
        })
        await writeHttpResponse(conn, res, 200)
      } catch (e: any) {
        console.error(
          `[HTTP] [${new Date().toISOString()}] 连接处理错误:`,
          e && e.message ? e.message : e,
        )
        try {
          await writeHttpResponse(
            conn,
            {
              code: 0,
              data: null,
              msg: `服务器错误: ${e && e.message ? e.message : String(e)}`,
            },
            500,
          )
        } catch (e2) {}
      } finally {
        try {
          await conn.close()
        } catch (e) {}
      }
    })()
  }

  const acceptLoop = () => {
    if (closed || !listener || accepting) return
    accepting = true
    const l = listener
    l.accept()
      .then((conn) => {
        accepting = false
        if (closed || listener !== l) {
          try {
            conn.close()
          } catch (e) {}
          return
        }
        setImmediate(acceptLoop)
        handleConn(conn)
      })
      .catch((err: any) => {
        accepting = false
        if (closed) return
        const msg = err && err.message ? err.message : String(err)
        console.error(`[HTTP] [${new Date().toISOString()}] accept 失败:`, msg)
        scheduleRestart(msg)
      })
  }

  const listenAndAccept = () => {
    if (closed) return
    closeListener()
    console.log(`[HTTP] [${new Date().toISOString()}] 准备启动 HTTP 服务器，端口: ${port}`)
    Socket.listen({
      family: 'ipv4',
      host: '0.0.0.0',
      port,
    })
      .then((l) => {
        if (closed) {
          try {
            l.close()
          } catch (e) {}
          return
        }
        listener = l
        bindFailStreak = 0
        console.log(`[HTTP] [${new Date().toISOString()}] ✓ 服务器已成功启动，监听端口 ${port}`)
        console.log(`[HTTP] [${new Date().toISOString()}] ✓ 访问 http://localhost:${port}/api/health`)
        console.log(`[HTTP] [${new Date().toISOString()}] ✓ 优雅退出: POST /api/server/stop`)
        acceptLoop()
      })
      .catch((err: any) => {
        const msg = err && err.message ? err.message : String(err)
        console.error(`[HTTP] [${new Date().toISOString()}] listen 失败:`, msg)
        scheduleRestart(msg)
      })
  }

  listenAndAccept()

  return {
    close: () => {
      closed = true
      bindFailStreak = 0
      if (restartTimer) {
        clearTimeout(restartTimer)
        restartTimer = null
      }
      closeListener()
      console.log(`[HTTP] [${new Date().toISOString()}] ✓ HTTP 监听已关闭，端口 ${port} 已释放`)
    },
    start: () => {
      if (restartTimer) {
        clearTimeout(restartTimer)
        restartTimer = null
      }
      closed = false
      bindFailStreak = 0
      listenAndAccept()
    },
    isClosed: () => closed,
  }
}
