// @ts-ignore
import net from '@frida/net'

const INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

interface ParsedHttpUrl {
    protocol: 'http' | 'https'
    host: string
    port: number
    path: string
}

function parseHttpUrl(url: string): ParsedHttpUrl {
    const match = url.match(/^(https?):\/\/([^/?#]+)(\/[^?#]*)?(\?[^#]*)?/)
    if (!match) {
        throw new Error(`无效 URL: ${url}`)
    }

    const protocol = match[1] as 'http' | 'https'
    const hostPort = match[2]
    const pathname = match[3] || '/'
    const query = match[4] || ''
    const path = pathname + query
    const [host, portStr] = hostPort.split(':')
    const port = portStr
        ? parseInt(portStr, 10)
        : (protocol === 'https' ? 443 : 80)

    return { protocol, host, port, path }
}

function pathExists(targetPath: string): boolean {
    const GetFileAttributesW = new NativeFunction(
        Module.getExportByName('kernel32.dll', 'GetFileAttributesW'),
        'uint32',
        ['pointer']
    )
    const pathPtr = Memory.allocUtf16String(targetPath)
    const attrs = GetFileAttributesW(pathPtr)
    return attrs !== INVALID_FILE_ATTRIBUTES
}

function ensureParentDir(filePath: string) {
    const lastSep = Math.max(filePath.lastIndexOf('\\'), filePath.lastIndexOf('/'))
    if (lastSep <= 0) {
        return
    }

    const dir = filePath.substring(0, lastSep)
    if (pathExists(dir)) {
        return
    }

    const CreateDirectoryW = new NativeFunction(
        Module.getExportByName('kernel32.dll', 'CreateDirectoryW'),
        'int',
        ['pointer', 'pointer']
    )

    const parts = dir.split(/[\\/]/).filter(Boolean)
    let current = ''
    if (parts[0] && parts[0].endsWith(':')) {
        current = `${parts[0]}\\`
        parts.shift()
    }

    for (const part of parts) {
        current = current.endsWith('\\') ? `${current}${part}` : `${current}\\${part}`
        if (!pathExists(current)) {
            const pathPtr = Memory.allocUtf16String(current)
            CreateDirectoryW(pathPtr, ptr(0))
        }
    }
}

function writeBinaryFile(savePath: string, body: Uint8Array) {
    const buffer = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength)
    // @ts-ignore Frida File API
    File.writeAllBytes(savePath, buffer)
}

function parseContentLength(headers: string): number | null {
    const match = headers.match(/content-length:\s*(\d+)/i)
    return match ? parseInt(match[1], 10) : null
}

function findHeaderEnd(buf: Uint8Array): number {
    for (let i = 0; i < buf.length - 3; i++) {
        if (buf[i] === 0x0d && buf[i + 1] === 0x0a && buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
            return i + 4
        }
    }
    return -1
}

function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((sum, item) => sum + item.length, 0)
    const result = new Uint8Array(total)
    let offset = 0
    for (const item of arrays) {
        result.set(item, offset)
        offset += item.length
    }
    return result
}

export function buildFinderVideoSavePath(msgId: string, baseDir?: string): string {
    const dir = baseDir || 'C:\\GitHub\\frida-agent\\agent\\finder'
    return `${dir}\\${msgId}.mp4`
}

export function downloadHttpFile(url: string, savePath: string, timeoutMs = 120000): Promise<string> {
    return new Promise((resolve, reject) => {
        let parsed: ParsedHttpUrl
        try {
            parsed = parseHttpUrl(url)
        } catch (e: any) {
            reject(e)
            return
        }

        if (parsed.protocol === 'https') {
            reject(new Error('Agent 暂不支持 HTTPS 直链下载，请使用 http 视频地址'))
            return
        }

        try {
            ensureParentDir(savePath)
        } catch (e: any) {
            reject(new Error(`创建目录失败: ${e.message || e}`))
            return
        }

        if (pathExists(savePath)) {
            console.log('[DOWNLOAD] 文件已存在，跳过:', savePath)
            resolve(savePath)
            return
        }

        const socket = net.connect({ host: parsed.host, port: parsed.port })
        const rawChunks: Uint8Array[] = []
        let finished = false
        let timer: any = null

        const finish = (err?: Error, resultPath?: string) => {
            if (finished) {
                return
            }
            finished = true
            if (timer) {
                clearTimeout(timer)
            }
            try {
                socket.destroy()
            } catch (_) {
                // ignore
            }
            if (err) {
                reject(err)
            } else {
                resolve(resultPath!)
            }
        }

        timer = setTimeout(() => {
            finish(new Error(`下载超时 (${timeoutMs}ms): ${url}`))
        }, timeoutMs)

        socket.on('connect', () => {
            const hostHeader = parsed.port === 80
                ? parsed.host
                : `${parsed.host}:${parsed.port}`
            socket.write(
                `GET ${parsed.path} HTTP/1.1\r\n` +
                `Host: ${hostHeader}\r\n` +
                `User-Agent: MicroMessenger Client\r\n` +
                `Connection: close\r\n` +
                `\r\n`
            )
        })

        socket.on('data', (data: ArrayBuffer | Uint8Array) => {
            rawChunks.push(data instanceof Uint8Array ? data : new Uint8Array(data))
        })

        socket.on('error', (err: any) => {
            finish(new Error(`下载连接错误: ${err.message || err}`))
        })

        socket.on('close', () => {
            if (finished) {
                return
            }

            try {
                const raw = concatUint8Arrays(rawChunks)
                const headerEnd = findHeaderEnd(raw)
                if (headerEnd < 0) {
                    finish(new Error('HTTP 响应头解析失败'))
                    return
                }

                const headerText = Array.from(raw.subarray(0, headerEnd - 4))
                    .map(byte => String.fromCharCode(byte))
                    .join('')

                const statusMatch = headerText.match(/^HTTP\/\d\.\d\s+(\d+)/)
                if (!statusMatch || statusMatch[1][0] !== '2') {
                    finish(new Error(`HTTP 下载失败: ${headerText.split('\r\n')[0]}`))
                    return
                }

                let body = raw.subarray(headerEnd)
                const contentLength = parseContentLength(headerText)
                if (contentLength !== null && body.length >= contentLength) {
                    body = body.subarray(0, contentLength)
                }

                writeBinaryFile(savePath, body)
                console.log('[DOWNLOAD] 下载完成:', savePath, `(${body.length} bytes)`)
                finish(undefined, savePath)
            } catch (e: any) {
                finish(new Error(`保存文件失败: ${e.message || e}`))
            }
        })
    })
}

export function downloadFinderFeedVideo(msgId: string, videoUrl: string, savePath?: string): Promise<string> {
    return downloadHttpFile(videoUrl, savePath || buildFinderVideoSavePath(msgId))
}
