/**
 * 接收媒体后自动下载；图片下载完成后自动解密 .dat
 * 注意：不可在 DoAddMsg Hook 栈内同步调原生下载，需延迟执行。
 */
import { Message } from './types.js'
import { downloadAttach, decryptImage, getAudio } from './message.js'
import { getLocalIdAndDbIdx } from './sqlite.js'
import { pathExistsNative, getFileSizeNative, ensureParentDirNative } from './utils.js'
import { getFileNameFromAppMsg } from './appMsgParser.js'

export interface MediaAutoOptions {
    homePath: string
    selfId: string
    /** 语音导出目录，默认 homePath\FridaAgent\audio */
    audioDir?: string
    enabled?: boolean
    /** 相对收消息延迟 ms，避开 Hook 重入 */
    deferMs?: number
    /** 文件消息额外延迟（入库较慢） */
    fileDeferMs?: number
}

let opts: MediaAutoOptions = {
    homePath: '',
    selfId: '',
    enabled: true,
    deferMs: 800,
    fileDeferMs: 2500,
}

const pendingDecrypt = new Set<string>()
const pendingMsg = new Set<string>()

export function configureMediaAuto(next: Partial<MediaAutoOptions>) {
    opts = { ...opts, ...next }
}

function absPath(p: string): string {
    if (!p) return ''
    const n = p.replace(/\//g, '\\')
    if (/^[a-zA-Z]:\\/.test(n) || n.startsWith('\\\\')) {
        return n
    }
    const home = (opts.homePath || '').replace(/\//g, '\\')
    if (!home) {
        return n
    }
    const base = home.endsWith('\\') ? home : home + '\\'
    return base + n.replace(/^[\\/]+/, '')
}

function parseImagePaths(msg: Message): { thumb: string; extra: string } {
    let thumb = msg.mediaThumb || ''
    let extra = msg.mediaExtra || msg.filename || ''
    if ((!thumb || !extra) && msg.text) {
        try {
            const arr = JSON.parse(msg.text)
            if (Array.isArray(arr) && arr.length >= 3) {
                thumb = thumb || String(arr[1] || arr[0] || '')
                extra = extra || String(arr[2] || arr[3] || '')
            }
        } catch (e) {}
    }
    return { thumb: absPath(thumb), extra: absPath(extra) }
}

function pollDecryptImage(datPath: string, tries = 60, intervalMs = 1000) {
    if (!datPath || pendingDecrypt.has(datPath)) {
        return
    }
    pendingDecrypt.add(datPath)
    let left = tries
    let lastSize = -1
    let stable = 0

    const tick = () => {
        left -= 1
        try {
            if (!pathExistsNative(datPath)) {
                if (left > 0) {
                    setTimeout(tick, intervalMs)
                } else {
                    pendingDecrypt.delete(datPath)
                    console.warn('[MediaAuto] 等待图片超时:', datPath)
                }
                return
            }
            const size = getFileSizeNative(datPath)
            if (size > 0 && size === lastSize) {
                stable += 1
            } else {
                stable = 0
                lastSize = size
            }
            if (size > 64 && stable >= 1) {
                const out = decryptImage(datPath, '')
                pendingDecrypt.delete(datPath)
                if (out) {
                    console.log('[MediaAuto] 图片已解密:', out)
                } else {
                    console.warn('[MediaAuto] 图片解密失败:', datPath)
                }
                return
            }
        } catch (e) {
            console.error('[MediaAuto] 解密轮询异常:', e)
        }
        if (left > 0) {
            setTimeout(tick, intervalMs)
        } else {
            pendingDecrypt.delete(datPath)
            console.warn('[MediaAuto] 等待图片稳定超时:', datPath)
        }
    }
    setTimeout(tick, 1500)
}

function resolveFileSavePath(msg: Message): string {
    const selfId = opts.selfId || ''
    // 优先按 appMsg 标题 + 正确 wxid 重建，避免 selfInfo.id=undefined
    if (msg.text && selfId) {
        const rebuilt = getFileNameFromAppMsg(msg.text, selfId)
        if (rebuilt) {
            return absPath(rebuilt)
        }
    }
    let rel = msg.filename || ''
    if (rel.includes('\\undefined\\') || rel.startsWith('undefined\\')) {
        if (selfId) {
            rel = rel.replace(/^undefined\\/, `${selfId}\\`).replace(/\\undefined\\/g, `\\${selfId}\\`)
        }
    }
    return absPath(rel)
}

/** 等待消息写入 MSG 库后再 downloadAttach */
function downloadAttachWhenReady(
    msgId: string,
    thumb: string,
    extra: string,
    retries = 8,
    intervalMs = 800,
): void {
    let left = retries
    const tryOnce = () => {
        const loc = getLocalIdAndDbIdx(msgId)
        if (!loc) {
            left -= 1
            if (left > 0) {
                console.log(`[MediaAuto] 等待消息入库 msgId=${msgId} 剩余重试=${left}`)
                setTimeout(tryOnce, intervalMs)
                return
            }
            console.warn('[MediaAuto] 消息一直未入库，放弃下载:', msgId)
            return
        }
        const st = downloadAttach(msgId, thumb, extra)
        console.log('[MediaAuto] downloadAttach=', st, 'extra=', extra)
    }
    tryOnce()
}

function handleMediaNow(msg: Message): void {
    const msgId = String(msg.id)
    const type = msg.type

    try {
        if (type === 3) {
            const { thumb, extra } = parseImagePaths(msg)
            if (!extra) {
                console.warn('[MediaAuto] 图片路径为空, msgId=', msgId)
                return
            }
            try {
                ensureParentDirNative(extra)
            } catch (e) {}
            console.log('[MediaAuto] 下载图片:', msgId, extra)
            downloadAttachWhenReady(msgId, thumb, extra, 5, 600)
            pollDecryptImage(extra)
            return
        }

        if (type === 43 || type === 62) {
            const thumb = absPath(msg.mediaThumb || msg.filename || '')
            const extra = absPath(msg.mediaExtra || '')
            if (!thumb && !extra) {
                console.warn('[MediaAuto] 视频路径为空, msgId=', msgId)
                return
            }
            const t = thumb || extra
            try {
                ensureParentDirNative(t)
            } catch (e) {}
            console.log('[MediaAuto] 下载视频:', msgId, t)
            downloadAttachWhenReady(msgId, t, extra || t, 6, 800)
            return
        }

        if (type === 49 && msg.appMsg?.subType === 6) {
            const extra = resolveFileSavePath(msg)
            if (!extra || extra.includes('\\undefined\\')) {
                console.warn('[MediaAuto] 文件路径无效, msgId=', msgId, 'path=', extra, 'selfId=', opts.selfId)
                return
            }
            try {
                ensureParentDirNative(extra)
            } catch (e) {}
            console.log('[MediaAuto] 下载文件:', msgId, extra)
            // 文件入库更慢，多等几轮
            downloadAttachWhenReady(msgId, '', extra, 12, 1000)
            return
        }

        if (type === 34) {
            const home = (opts.homePath || '').replace(/\//g, '\\')
            const dir = opts.audioDir
                || ((home.endsWith('\\') ? home : home + '\\') + 'FridaAgent\\audio')
            ensureParentDirNative(dir + '\\x')
            const path = getAudio(msgId, dir)
            if (path) {
                console.log('[MediaAuto] 语音已处理:', path)
            }
        }
    } catch (e) {
        console.error('[MediaAuto] 处理失败:', e)
    } finally {
        pendingMsg.delete(msgId)
    }
}

/**
 * 收到消息后触发（延迟执行，避免 DoAddMsg 重入崩溃）
 */
export function autoHandleMedia(msg: Message): void {
    if (opts.enabled === false) {
        return
    }
    if (!msg || !msg.id) {
        return
    }

    const msgId = String(msg.id)
    const type = msg.type
    if (![3, 34, 43, 49, 62].includes(type)) {
        return
    }
    if (type === 49 && msg.appMsg?.subType !== 6) {
        return
    }
    if (pendingMsg.has(msgId)) {
        return
    }
    pendingMsg.add(msgId)

    const isFile = type === 49 && msg.appMsg?.subType === 6
    const delay = isFile
        ? (opts.fileDeferMs ?? 2500)
        : (opts.deferMs ?? 800)
    const snapshot: Message = { ...msg, appMsg: msg.appMsg ? { ...msg.appMsg } : undefined }
    console.log(`[MediaAuto] 已调度 ${delay}ms 后处理 type=${type} id=${msgId}`)
    setTimeout(() => handleMediaNow(snapshot), delay)
}
