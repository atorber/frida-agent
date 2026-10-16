/**
 * 4.1.10.27 收消息 Hook
 *
 * DoAddMsg 特征来自 wx-basic-bridge 4.1.9.23：
 *   指令 `48 89 85 F8 01 00 00` (mov [rbp+0x1f8], rax)
 *   消息指针在 RSI+0x18
 *
 * 在 4.1.10.27 上用 send_message 邻域 + 同特征扫描重定位。
 * MsgStruct 字段布局对齐 4.1.9.23 bridge（与 4.1.7.30 docs 不同）。
 */
import { offsets, WX_DLL } from './offset.js'
import { Message } from './types.js'
import { log } from './utils.js'

export type MsgHandler = (msg: Message) => void

export type MsgStructDump = {
  at: number
  ptr: string
  strings: { off: number; len: number; text: string; wxidish: boolean }[]
  ints: { off: number; u32: number; u64?: string; flags: string[] }[]
  parsed?: Message | null
}

let msgListener: InvocationListener | null = null
let msgHandler: MsgHandler | null = null
let isListeningMsg = false
let hookedRva = 0
const structDumps: MsgStructDump[] = []
const STRUCT_DUMP_MAX = 20
let dumpRemaining = 15 // 前 N 条入站做全量字段扫描

const EXPECTED_SITE = [0x48, 0x89, 0x85, 0xf8, 0x01, 0x00, 0x00]

function base(): NativePointer {
  return Process.getModuleByName(WX_DLL).base
}

function readStdString(addr: NativePointer): string | null {
  try {
    const len = addr.add(0x10).readU64().toNumber()
    const cap = addr.add(0x18).readU64().toNumber()
    if (len > 0x10000 || cap > 0x10000 || len === 0) return null
    const dataPtr = cap <= 15 ? addr : addr.readPointer()
    return dataPtr.readUtf8String(Math.min(len, 4000))
  } catch {
    return null
  }
}

function siteMatches(rva: number): boolean {
  try {
    const p = base().add(rva)
    for (let i = 0; i < EXPECTED_SITE.length; i++) {
      if (p.add(i).readU8() !== EXPECTED_SITE[i]) return false
    }
    return true
  } catch {
    return false
  }
}

/** Frida Interceptor 已挂上时原指令会被改成 E9 jmp */
function siteIsTrampoline(rva: number): boolean {
  try {
    return base().add(rva).readU8() === 0xe9
  } catch {
    return false
  }
}

/** 在候选区扫描 DoAddMsg 特征指令 */
export function resolveDoAddMsgRva(): number {
  const preferred = offsets.do_add_msg
  // 磁盘已校验的首选：完整特征 或 已被 hook 的 trampoline 都算有效
  if (preferred && (siteMatches(preferred) || siteIsTrampoline(preferred))) {
    return preferred
  }

  const mod = Process.getModuleByName(WX_DLL)
  const scanStart = offsets.do_add_msg_scan_lo
  const scanEnd = Math.min(offsets.do_add_msg_scan_hi, mod.size)
  const pattern = '48 89 85 F8 01 00 00'
  let scanned: number[] = []
  try {
    const matches = Memory.scanSync(mod.base.add(scanStart), scanEnd - scanStart, pattern)
    scanned = matches.map((m) => m.address.sub(mod.base).toInt32() >>> 0)
  } catch (e) {
    console.error('[RECV] scan failed', e)
  }

  // 次选：静态候选（按列表顺序，且必须仍是完整特征）
  for (const rva of offsets.do_add_msg_candidates) {
    if (siteMatches(rva) || siteIsTrampoline(rva)) {
      log('RECV', `DoAddMsg candidate match -> 0x${rva.toString(16)}`)
      return rva
    }
  }

  // 扫描命中里选离 preferred 最近的，避免误用区间首个假阳性
  if (scanned.length > 0 && preferred) {
    scanned.sort((a, b) => Math.abs(a - preferred) - Math.abs(b - preferred))
    const rva = scanned[0]
    log(
      'RECV',
      `DoAddMsg resolved by nearest scan -> 0x${rva.toString(16)} (of ${scanned.length}, prefer 0x${preferred.toString(16)})`,
    )
    return rva
  }
  if (scanned.length > 0) {
    log('RECV', `DoAddMsg resolved by scan -> 0x${scanned[0].toString(16)}`)
    return scanned[0]
  }

  if (preferred) {
    log('RECV', `DoAddMsg fallback preferred 0x${preferred.toString(16)} (bytes mismatch)`)
    return preferred
  }
  return 0
}

function extractGroupSender(content: string): string {
  // 群消息常见 "wxid_xxx:\n正文"
  const i = content.indexOf(':\n')
  if (i > 0 && i < 80) {
    const head = content.substring(0, i)
    if (head.indexOf('@') >= 0 || head.indexOf('wxid_') >= 0 || head.length < 40) return head
  }
  return ''
}

function looksWxid(s: string): boolean {
  if (!s) return false
  if (s.indexOf('@chatroom') >= 0) return true
  if (s.indexOf('wxid_') === 0) return true
  if (s === 'filehelper' || s === 'fmessage' || s === 'newsapp') return true
  if (/^[a-zA-Z][\w\-]{4,32}$/.test(s) && s.indexOf(' ') < 0) return true
  return false
}

function tryReadStdAt(addr: NativePointer): { len: number; text: string } | null {
  try {
    const len = addr.add(0x10).readU64().toNumber()
    const cap = addr.add(0x18).readU64().toNumber()
    // 放宽：允许 cap==0xf SSO；允许 len==cap；拒绝明显垃圾
    if (len <= 0 || len > 0x20000) return null
    if (cap > 0x20000) return null
    if (cap < 15 && len > 15) return null
    if (len > cap + 1 && cap > 15) return null
    const dataPtr = cap <= 15 ? addr : addr.readPointer()
    if (!dataPtr || dataPtr.isNull()) return null
    // 先试 UTF-8，再试 UTF-16
    let text: string | null = null
    try {
      text = dataPtr.readUtf8String(Math.min(len, 800))
    } catch {
      text = null
    }
    if (!text) {
      try {
        text = dataPtr.readUtf16String(Math.min(len, 400))
      } catch {
        text = null
      }
    }
    if (!text) return null
    let printable = 0
    const n = Math.min(text.length, 48)
    for (let i = 0; i < n; i++) {
      const c = text.charCodeAt(i)
      if (c >= 0x20 || c === 10 || c === 13 || c === 9) printable++
    }
    if (n > 0 && printable < n * 0.5) return null
    return { len, text }
  } catch {
    return null
  }
}

/** 扫描 MsgStruct 内 std::string / 整型候选，用于对齐字段 */
export function dumpMsgStructLayout(msgBase: NativePointer): MsgStructDump {
  const strings: MsgStructDump['strings'] = []
  const size = 0x300
  const seen = new Set<number>()
  for (let off = 0; off + 0x20 <= size; off += 8) {
    const got = tryReadStdAt(msgBase.add(off))
    if (!got) continue
    // 避免同一 SSO 缓冲被相邻 off 重复命中：若文本相同且 off 差 < 0x20 则跳过
    let dup = false
    for (const prev of seen) {
      if (Math.abs(prev - off) < 0x20) {
        const p = strings.find((s) => s.off === prev)
        if (p && p.text === got.text.slice(0, 240)) {
          dup = true
          break
        }
      }
    }
    if (dup) continue
    seen.add(off)
    strings.push({
      off,
      len: got.len,
      text: got.text.slice(0, 240),
      wxidish: looksWxid(got.text),
    })
  }

  const now = Math.floor(Date.now() / 1000)
  const typeish = [1, 3, 34, 37, 42, 43, 47, 48, 49, 10000, 10002]
  const ints: MsgStructDump['ints'] = []
  for (let off = 0; off + 4 <= size; off += 4) {
    try {
      const u32 = msgBase.add(off).readU32()
      const flags: string[] = []
      if (typeish.indexOf(u32) >= 0) flags.push('typeish')
      if (u32 > now - 86400 * 14 && u32 < now + 3600) flags.push('timeish')
      let u64: string | undefined
      if (off % 8 === 0) {
        try {
          u64 = msgBase.add(off).readU64().toString()
          if (u64 !== '0' && u64.length >= 10) flags.push('idish')
        } catch {
          /* ignore */
        }
      }
      if (flags.length) ints.push({ off, u32, u64, flags })
    } catch {
      /* skip */
    }
  }

  return {
    at: Date.now(),
    ptr: msgBase.toString(),
    strings,
    ints: ints.slice(0, 50),
  }
}

export function getMsgStructDumps(): MsgStructDump[] {
  return structDumps.slice()
}

export function clearMsgStructDumps(): void {
  structDumps.length = 0
  dumpRemaining = 15
}

export function armMsgStructDump(count = 15): void {
  dumpRemaining = count
}

function isMsgsourceOrMeta(s: string): boolean {
  const t = s.trim()
  if (!t) return true
  if (t.indexOf('<msgsource') >= 0) return true
  if (t.indexOf('<msg>') === 0 && t.indexOf('<img ') < 0) return true
  return false
}

function contentScore(s: string): number {
  if (!s || looksWxid(s) || isMsgsourceOrMeta(s)) return -1
  let score = 0
  if (s.indexOf(':\n') >= 0) score += 50
  if (s.indexOf('\n') >= 0) score += 10
  // 可打印比例
  let ok = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0x20 || c === 10 || c === 13) ok++
  }
  score += Math.floor((ok / Math.max(s.length, 1)) * 20)
  score += Math.min(s.length, 40)
  // 拒绝大量罕见码点（误把指针当 UTF-8）
  let weird = 0
  for (let i = 0; i < Math.min(s.length, 32); i++) {
    const c = s.charCodeAt(i)
    if (c > 0xFFFF || (c >= 0x2000 && c <= 0x2FFF && c !== 0x3000)) weird++
  }
  if (weird >= 3 && s.indexOf(':\n') < 0) score -= 40
  return score
}

/** 正文：优先固定 0x180，再在窗口内按评分选取 */
function readContentScanned(msgBase: NativePointer): string {
  const o = offsets.msg
  const pick = (off: number): string => {
    const got = tryReadStdAt(msgBase.add(off))
    return got ? got.text : ''
  }
  const fixed = pick(o.content)
  if (contentScore(fixed) >= 20) return fixed

  let best = ''
  let bestSc = -1
  for (let off = o.content_scan_lo; off + 0x20 <= o.content_scan_hi; off += 8) {
    const s = pick(off)
    const sc = contentScore(s)
    if (sc > bestSc) {
      bestSc = sc
      best = s
    }
  }
  return bestSc >= 10 ? best : fixed || best
}

function buildChatMessage(msgBase: NativePointer): Message | null {
  const o = offsets.msg
  const from = readStdString(msgBase.add(o.from)) || ''
  const to = readStdString(msgBase.add(o.to)) || ''
  const sender = readStdString(msgBase.add(o.sender)) || ''
  let content = readContentScanned(msgBase)
  let msgType = 0
  let createTime = 0
  let msgId = '0'
  let isSelf = false
  try {
    msgType = msgBase.add(o.type).readS32()
  } catch {
    /* ignore */
  }
  try {
    createTime = msgBase.add(o.create_time).readU32()
    // 拒绝明显非时间戳
    const now = Math.floor(Date.now() / 1000)
    if (createTime < now - 86400 * 365 * 5 || createTime > now + 86400) {
      createTime = msgBase.add(o.create_time_alt).readU32()
    }
  } catch {
    try {
      createTime = msgBase.add(o.create_time_alt).readU32()
    } catch {
      /* ignore */
    }
  }
  try {
    msgId = msgBase.add(o.msg_id).readU64().toString()
    if (msgId === '0') {
      msgId = msgBase.add(o.local_id).readU64().toString()
    }
  } catch {
    /* ignore */
  }

  // 兼容 docs/4.1.7.30 布局：若新布局字段全空则回退
  if (!from && !to && !content && !sender) {
    const talker = readStdString(msgBase) || ''
    const contentOld = readStdString(msgBase.add(0x48)) || ''
    if (!talker && !contentOld) return null
    let status = 0
    try {
      status = msgBase.add(0x98).readU32()
      msgType = msgBase.add(0x9c).readU32()
      createTime = msgBase.add(0x90).readU32()
      msgId = msgBase.add(0x28).readU64().toString()
    } catch {
      /* ignore */
    }
    const room = talker.indexOf('@chatroom') >= 0 ? talker : ''
    isSelf = status === 1
    return {
      id: msgId,
      text: contentOld,
      timestamp: createTime,
      type: msgType,
      talkerId: isSelf ? '' : talker,
      roomId: room,
      listenerId: isSelf ? talker : '',
      mentionIds: [],
      isSelf,
    }
  }

  let roomId = ''
  let talkerId = ''
  let listenerId = ''
  if (from.indexOf('@chatroom') >= 0) {
    roomId = from
    talkerId = sender || extractGroupSender(content) || ''
    if (talkerId && content.startsWith(talkerId + ':\n')) {
      content = content.substring(talkerId.length + 2)
    }
    // to 常为自己
    if (to && looksWxid(to)) listenerId = to
  } else if (to.indexOf('@chatroom') >= 0) {
    roomId = to
    talkerId = sender || from
  } else {
    // 私聊
    talkerId = from
    listenerId = to
    if (sender && sender !== from && sender !== to) {
      // 少数路径 sender 更准
      talkerId = sender
    }
  }

  return {
    id: msgId,
    text: content,
    timestamp: createTime,
    type: msgType,
    talkerId,
    roomId,
    listenerId,
    mentionIds: [],
    isSelf,
  }
}

export function isRecvMsgEnabled(): boolean {
  return isListeningMsg
}

export function setMsgHandler(handler: MsgHandler | null) {
  msgHandler = handler
}

export function getHookedRecvRva(): number {
  return hookedRva
}

export function enableRecvMsg(handler?: MsgHandler): boolean {
  try {
    if (handler) msgHandler = handler
    if (isListeningMsg && msgListener) return true

    const rva = resolveDoAddMsgRva()
    if (!rva) {
      console.error('[RECV] DoAddMsg RVA 未解析')
      return false
    }

    msgListener = Interceptor.attach(base().add(rva), {
      onEnter() {
        try {
          const ctx = this.context as any
          const rsi = ctx.rsi as NativePointer
          // 对齐 wx-basic-bridge: mov rax, [rsi+0x18]；同时尝试其它寄存器以防约定变化
          const candidates: { tag: string; ptr: NativePointer }[] = []
          const pushCand = (tag: string, p: NativePointer | null | undefined) => {
            if (p && !p.isNull()) candidates.push({ tag, ptr: p })
          }
          try {
            if (rsi && !rsi.isNull()) {
              pushCand('rsi+0x18', rsi.add(0x18).readPointer())
              pushCand('rsi+0x10', rsi.add(0x10).readPointer())
              pushCand('rsi+0x20', rsi.add(0x20).readPointer())
              pushCand('rsi', rsi)
            }
          } catch {
            /* ignore */
          }
          pushCand('rax', ctx.rax)
          pushCand('rcx', ctx.rcx)
          pushCand('rdx', ctx.rdx)
          pushCand('r8', ctx.r8)

          let bestPtr: NativePointer | null = null
          let bestTag = ''
          let bestDump: MsgStructDump | null = null
          let bestScore = -1
          for (const c of candidates) {
            try {
              const d = dumpMsgStructLayout(c.ptr)
              const score =
                d.strings.filter((s) => s.wxidish).length * 10 +
                d.strings.length +
                (d.strings.some((s) => s.text.indexOf('struct_dump_') >= 0) ? 50 : 0)
              if (score > bestScore) {
                bestScore = score
                bestPtr = c.ptr
                bestTag = c.tag
                bestDump = d
              }
            } catch {
              /* ignore */
            }
          }

          if (dumpRemaining > 0 && bestDump) {
            dumpRemaining--
            bestDump.parsed = bestPtr ? buildChatMessage(bestPtr) : null
            ;(bestDump as any).tag = bestTag
            ;(bestDump as any).score = bestScore
            structDumps.push(bestDump)
            while (structDumps.length > STRUCT_DUMP_MAX) structDumps.shift()
            const brief = bestDump.strings
              .slice(0, 6)
              .map((s) => `0x${s.off.toString(16)}:${JSON.stringify(s.text.slice(0, 40))}`)
              .join(' | ')
            log('RECV-DUMP', `tag=${bestTag} score=${bestScore} left=${dumpRemaining} ${brief}`)
          }

          // 运行时仍优先 bridge 约定 rsi+0x18；若其无字符串则回退到评分最高指针
          let msgPtr: NativePointer | null = null
          try {
            if (rsi && !rsi.isNull()) msgPtr = rsi.add(0x18).readPointer()
          } catch {
            msgPtr = null
          }
          if (!msgPtr || msgPtr.isNull()) msgPtr = bestPtr
          else {
            const primary = dumpMsgStructLayout(msgPtr)
            if (primary.strings.length === 0 && bestPtr && bestScore > 0) msgPtr = bestPtr
          }
          if (!msgPtr || msgPtr.isNull()) return

          const message = buildChatMessage(msgPtr)
          if (!message) return
          if (msgHandler) msgHandler(message)
        } catch (e) {
          console.error('[RECV] 回调失败', e)
        }
      },
    })
    hookedRva = rva
    isListeningMsg = true
    log('RECV', `hook on DoAddMsg 0x${rva.toString(16)}`)
    return true
  } catch (e) {
    console.error('[RECV] enable 失败', e)
    msgListener = null
    isListeningMsg = false
    hookedRva = 0
    return false
  }
}

export function disableRecvMsg(): boolean {
  try {
    if (msgListener) {
      msgListener.detach()
      msgListener = null
    }
    isListeningMsg = false
    hookedRva = 0
    log('RECV', 'hook detached')
    return true
  } catch (e) {
    console.error('[RECV] disable 失败', e)
    return false
  }
}
