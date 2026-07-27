import { writeFileBytes, stringToUint8Array } from './utils.js'

function safeFileName(name: string): string {
  const base = (name || 'file.bin').replace(/^.*[\\/]/, '')
  return base.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').slice(0, 180) || 'file.bin'
}

function uploadRoot(homePath: string): string {
  const home = (homePath || '').replace(/\//g, '\\').replace(/\\+$/, '')
  if (home) return `${home}\\FridaAgent\\uploads`
  return 'C:\\Users\\Public\\FridaAgent\\uploads'
}

/**
 * 将上传字节写入本机，返回绝对路径供 messageSendImage/File/Emotion 使用。
 */
export function saveUploadedFile(
  homePath: string,
  filename: string,
  data: Uint8Array,
  category?: string,
): { path: string; filename: string; size: number; category: string } {
  const cat = (category || 'file').toLowerCase()
  const safe = safeFileName(filename)
  const dir = `${uploadRoot(homePath)}\\${cat}`
  const stamp = Date.now()
  const path = `${dir}\\${stamp}_${safe}`
  if (!data || data.byteLength === 0) {
    throw new Error('上传内容为空')
  }
  if (data.byteLength > 40 * 1024 * 1024) {
    throw new Error('文件过大（限制 40MB）')
  }
  if (!writeFileBytes(path, data)) {
    throw new Error(`写入失败: ${path}`)
  }
  return { path, filename: safe, size: data.byteLength, category: cat }
}

function indexOfBytes(hay: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer
    }
    return i
  }
  return -1
}

function headerValue(headersLatin1: string, name: string): string {
  const re = new RegExp('^' + name + ':\\s*(.+)$', 'im')
  const m = re.exec(headersLatin1)
  return m ? m[1].trim() : ''
}

/** 从 multipart/form-data 中提取第一个带 filename 的字段 */
export function extractMultipartFile(
  body: Uint8Array,
  contentType: string,
): { filename: string; data: Uint8Array } | null {
  const bm = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(contentType || '')
  if (!bm) return null
  const boundary = bm[1] || bm[2]
  if (!boundary) return null

  const delim = stringToUint8Array(`\r\n--${boundary}`)
  const first = stringToUint8Array(`--${boundary}`)
  let start = indexOfBytes(body, first, 0)
  if (start < 0) return null
  start += first.length
  if (start + 1 < body.length && body[start] === 0x0d && body[start + 1] === 0x0a) {
    start += 2
  }

  while (start < body.length) {
    const next = indexOfBytes(body, delim, start)
    const end = next >= 0 ? next : body.length
    const part = body.subarray(start, end)
    const headerEnd = indexOfBytes(part, stringToUint8Array('\r\n\r\n'), 0)
    if (headerEnd >= 0) {
      let head = ''
      for (let i = 0; i < headerEnd; i++) head += String.fromCharCode(part[i])
      const disp = headerValue(head, 'Content-Disposition')
      if (/filename=/i.test(disp)) {
        const fm =
          /filename\*=UTF-8''([^;\r\n]+)|filename="([^"]*)"|filename=([^;\r\n]+)/i.exec(disp)
        let filename = (fm && (fm[1] || fm[2] || fm[3])) || 'file.bin'
        try {
          filename = decodeURIComponent(filename.trim())
        } catch {
          /* keep */
        }
        let dataStart = headerEnd + 4
        let dataEnd = part.length
        // 去掉 part 末尾可能残留的 \r\n
        if (dataEnd >= 2 && part[dataEnd - 2] === 0x0d && part[dataEnd - 1] === 0x0a) {
          dataEnd -= 2
        }
        return { filename, data: part.subarray(dataStart, dataEnd) }
      }
    }
    if (next < 0) break
    start = next + delim.length
    if (start + 1 < body.length && body[start] === 0x0d && body[start + 1] === 0x0a) {
      start += 2
    }
    // 结束边界 --boundary--
    if (start < body.length && body[start] === 0x2d) break
  }
  return null
}

/** JSON body: { filename, dataBase64, category? } */
export function extractJsonBase64Upload(
  bodyText: string,
): { filename: string; data: Uint8Array; category?: string } | null {
  try {
    const obj = JSON.parse(bodyText || '{}')
    if (!obj || !obj.dataBase64) return null
    const b64 = String(obj.dataBase64).replace(/\s/g, '')
    if (typeof atob !== 'function') throw new Error('atob 不可用')
    const binary = atob(b64)
    const out = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i) & 0xff
    return {
      filename: String(obj.filename || 'file.bin'),
      data: out,
      category: obj.category ? String(obj.category) : undefined,
    }
  } catch {
    return null
  }
}
