/**
 * 微信 4.1.10.27 消息发送（对齐 aixed wx_send.cpp）
 */
import { offsets, WX_DLL } from './offset.js'
import { setWeixinString, setWeixinStringU, log, heapAlloc, pathExists, fileSize } from './utils.js'
import { forwardXmlNative, xmlOffsetsLookValid, detectXmlKind } from './forwardXml.js'

const UNKNOWN_BLOCK_QWORDS = 64
const BUF_QWORDS = 16

let _base: NativePointer | null = null
let _fns: { createParam2: any; sendMessage: any; txtCtr: any; decodePic: any } | null = null
let _pumpHooked = false
let _mainTid = 0
let _sending = false

type JobKind = 'text' | 'image' | 'media' | 'decode' | 'xml' | 'xmlTyped'
type SendJob = {
  kind: JobKind
  contactId: string
  text: string
  path: string
  dstPath: string
  xml: string
  mediaType: number
  done: boolean
  result: number
  error: string | null
}

let _queue: SendJob[] = []

function base(): NativePointer {
  if (!_base) _base = Process.getModuleByName(WX_DLL).base
  return _base
}

function getFns() {
  if (_fns) return _fns
  const b = base()
  _fns = {
    createParam2: new NativeFunction(
      b.add(offsets.create_param2),
      'pointer',
      ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'uint64'],
    ),
    sendMessage: new NativeFunction(b.add(offsets.send_message), 'void', ['pointer', 'pointer']),
    txtCtr: new NativeFunction(b.add(offsets.txt_message_ctr), 'void', ['pointer']),
    decodePic: new NativeFunction(b.add(offsets.dec_pic_call), 'void', [
      'pointer',
      'pointer',
      'int',
    ]),
  }
  return _fns
}

function genGuid(): string {
  const hex = '0123456789abcdef'
  let s = ''
  for (let i = 0; i < 32; i++) s += hex[(Math.random() * 16) | 0]
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`
}

function calcWxCapacity(len: number): number {
  const need = len + 1
  const cap = (need + 0xf) & ~0xf
  return cap - 1
}

function allocUnknownBlock(vtableRva: number): NativePointer {
  const p = heapAlloc(UNKNOWN_BLOCK_QWORDS * 8)
  p.writePointer(base().add(vtableRva))
  p.add(0x38).writePointer(p)
  return p
}

function buildSendParam2(out: NativePointer): void {
  const b = base()
  const fns = getFns()
  const buf = heapAlloc(BUF_QWORDS * 8)
  const p1 = allocUnknownBlock(offsets.param2_1)
  const p2 = allocUnknownBlock(offsets.param2_2)
  const p3 = allocUnknownBlock(offsets.param2_3)
  fns.createParam2(out, p1, p2, p3, buf, b.add(offsets.param2).readU64())
}

function buildArg1(msgBuf: NativePointer): NativePointer {
  const b = base()
  const data = heapAlloc(0x20)
  data.writePointer(msgBuf.add(0x10))
  data.add(8).writePointer(msgBuf)
  data.add(0x10).writeU64(uint64(0))

  const arg1 = heapAlloc(0x28)
  arg1.writePointer(b.add(offsets.param1_vtable))
  arg1.add(8).writePointer(data)
  arg1.add(0x10).writePointer(data.add(0x10))
  arg1.add(0x18).writePointer(data.add(0x10))
  arg1.add(0x20).writeU64(uint64(1))
  return arg1
}

function sendTextNative(contactId: string, text: string): number {
  const b = base()
  const fns = getFns()
  const msgBuf = heapAlloc(offsets.msg_buf_size_text)

  msgBuf.writePointer(b.add(offsets.txt_message_vtbl))
  msgBuf.add(8).writeU64(uint64(offsets.txt_ctrl_const))
  const msg = msgBuf.add(0x10)
  fns.txtCtr(msg)
  setWeixinString(msg.add(offsets.tm_receiver), contactId)
  setWeixinString(msg.add(offsets.tm_content), text)
  msg.add(offsets.tm_type).writeU64(uint64(1))
  msg.add(offsets.tm_msg_len).writeU64(uint64(text.length))

  const arg1 = buildArg1(msgBuf)
  const arg2 = heapAlloc(0xe8)
  buildSendParam2(arg2)
  fns.sendMessage(arg1, arg2)
  return 1
}

/**
 * 对齐 aixed BuildSendParam1_sub + SendImage / 统一发送文件类接口
 * mediaType: 3=image, 43=video, 47=gif/emotion, 49=file
 */
function sendMediaNative(contactId: string, filePath: string, mediaType: number): number {
  const b = base()
  const fns = getFns()
  if (!pathExists(filePath)) throw new Error('filepath does not exist: ' + filePath)
  const size = fileSize(filePath)
  if (size <= 0) throw new Error('file size is 0')

  const msgBuf = heapAlloc(offsets.msg_buf_size_image)
  msgBuf.writePointer(b.add(offsets.img_msg_vtbl))
  msgBuf.add(8).writeU64(uint64(offsets.img_ctrl_const))
  msgBuf.add(0x10).writePointer(b.add(offsets.img_msg_vtb2))

  msgBuf.add(0x40).writeU64(uint64(0xf))
  msgBuf.add(0x60).writeU64(uint64(0xf))
  msgBuf.add(0x80).writeU64(uint64(0xf))
  msgBuf.add(0xa0).writeU64(uint64(0xf))
  msgBuf.add(0xa8).writeU64(uint64('0x100000000'))
  msgBuf.add(0xb0).writeU64(uint64('0x700000000'))

  setWeixinString(msgBuf.add(0xc0), contactId)
  msgBuf.add(0xd0).writeU64(uint64(contactId.length))
  msgBuf.add(0xd8).writeU64(uint64(calcWxCapacity(contactId.length)))
  msgBuf.add(0xe8).writeU64(uint64(mediaType >>> 0))

  setWeixinStringU(msgBuf.add(0xf0), filePath)
  msgBuf.add(0x100).writeU64(uint64(filePath.length))
  msgBuf.add(0x108).writeU64(uint64(calcWxCapacity(filePath.length)))

  msgBuf.add(0x130).writeU64(uint64(0xf))
  msgBuf.add(0x150).writeU64(uint64(7))
  msgBuf.add(0x170).writeU64(uint64(0xf))
  msgBuf.add(0x198).writeU64(uint64(size))
  msgBuf.add(0x1b8).writeU64(uint64(0xf))

  msgBuf.add(0x668).writeU64(uint64(0xf))
  msgBuf.add(0x688).writeU64(uint64(0xf))
  msgBuf.add(0x6b0).writeU64(uint64(0xf))
  const guid = genGuid()
  setWeixinString(msgBuf.add(0x6b8), guid)
  msgBuf.add(0x6c8).writeU64(uint64(guid.length))
  msgBuf.add(0x6d0).writeU64(uint64(calcWxCapacity(guid.length)))

  for (const off of [0x6f0, 0x710, 0x738, 0x760, 0x780, 0x7a0]) {
    msgBuf.add(off).writeU64(uint64(0xf))
  }

  const arg1 = buildArg1(msgBuf)
  const arg2 = heapAlloc(0xe8)
  buildSendParam2(arg2)
  fns.sendMessage(arg1, arg2)
  return 1
}

function sendImageNative(contactId: string, imgPath: string): number {
  return sendMediaNative(contactId, imgPath, offsets.media_type_image)
}

/** 扩展名 → mediaType（对齐 aixed 统一发送文件类） */
export function guessMediaType(filePath: string): number {
  const lower = filePath.toLowerCase()
  const dot = lower.lastIndexOf('.')
  const ext = dot >= 0 ? lower.substring(dot + 1) : ''
  if (['gif', 'wxgf'].indexOf(ext) >= 0) return offsets.media_type_emotion
  if (['mp4', 'mov', 'avi', 'mkv'].indexOf(ext) >= 0) return offsets.media_type_video
  if (['png', 'jpg', 'jpeg', 'bmp', 'webp', 'tif', 'tiff'].indexOf(ext) >= 0) {
    return offsets.media_type_image
  }
  return offsets.media_type_file
}

function decodePicNative(src: string, dst: string): number {
  const fns = getFns()
  const arg1 = heapAlloc(0x28)
  const arg2 = heapAlloc(0x28)
  setWeixinString(arg1, src)
  setWeixinString(arg2, dst)
  fns.decodePic(arg1, arg2, 1)
  return 1
}

function resolveMainTid(): number {
  if (_mainTid) return _mainTid
  try {
    const user32 = Process.getModuleByName('user32.dll')
    const EnumWindows = new NativeFunction(user32.getExportByName('EnumWindows'), 'int', [
      'pointer',
      'pointer',
    ])
    const GetWindowThreadProcessId = new NativeFunction(
      user32.getExportByName('GetWindowThreadProcessId'),
      'uint32',
      ['pointer', 'pointer'],
    )
    const IsWindowVisible = new NativeFunction(user32.getExportByName('IsWindowVisible'), 'int', [
      'pointer',
    ])
    const myPid = Process.id
    const found = Memory.alloc(4)
    found.writeU32(0)
    const cb = new NativeCallback(
      (hwnd: NativePointer): number => {
        try {
          if (!IsWindowVisible(hwnd)) return 1
          const pidBuf = Memory.alloc(4)
          const tid = GetWindowThreadProcessId(hwnd, pidBuf) as number
          if (pidBuf.readU32() === myPid && tid && found.readU32() === 0) found.writeU32(tid)
        } catch (e) {}
        return 1
      },
      'int',
      ['pointer', 'pointer'],
    )
    EnumWindows(cb, ptr(0))
    _mainTid = found.readU32()
  } catch (e) {
    log('MSG', 'resolveMainTid failed', e)
  }
  if (!_mainTid) _mainTid = Process.getCurrentThreadId()
  log('MSG', 'mainTid=', _mainTid)
  return _mainTid
}

function ensurePumpHook(): void {
  if (_pumpHooked) return
  const modAny = Module as any
  const peek: NativePointer | null =
    (modAny.getGlobalExportByName && modAny.getGlobalExportByName('PeekMessageW')) ||
    Module.getExportByName(null as any, 'PeekMessageW') ||
    null
  if (!peek || peek.isNull()) throw new Error('PeekMessageW not found')
  resolveMainTid()

  Interceptor.attach(peek, {
    onLeave() {
      if (_sending || _queue.length === 0) return
      if (resolveMainTid() && Process.getCurrentThreadId() !== _mainTid) return
      const job = _queue[0]
      _sending = true
      try {
        if (job.kind === 'text') job.result = sendTextNative(job.contactId, job.text)
        else if (job.kind === 'image') job.result = sendImageNative(job.contactId, job.path)
        else if (job.kind === 'media')
          job.result = sendMediaNative(job.contactId, job.path, job.mediaType)
        else if (job.kind === 'xml') job.result = forwardXmlNative(job.contactId, job.xml)
        else if (job.kind === 'xmlTyped')
          job.result = forwardXmlAsTypedContent(job.contactId, job.xml)
        else job.result = decodePicNative(job.path, job.dstPath)
      } catch (e: any) {
        job.result = -1
        job.error = e && e.message ? e.message : String(e)
      } finally {
        _sending = false
        _queue.shift()
        job.done = true
      }
    },
  })
  _pumpHooked = true
  log('MSG', 'PeekMessageW pump hook installed')
}

function enqueue(job: SendJob): number {
  ensurePumpHook()
  _queue.push(job)
  const deadline = Date.now() + 15000
  while (!job.done && Date.now() < deadline) Thread.sleep(0.05)
  if (!job.done) {
    const idx = _queue.indexOf(job)
    if (idx >= 0) _queue.splice(idx, 1)
    return -1
  }
  if (job.error) {
    console.error('[MSG]', job.error)
    return -1
  }
  return job.result
}

function emptyJob(partial: Partial<SendJob> & Pick<SendJob, 'kind'>): SendJob {
  return {
    kind: partial.kind,
    contactId: partial.contactId || '',
    text: partial.text || '',
    path: partial.path || '',
    dstPath: partial.dstPath || '',
    xml: partial.xml || '',
    mediaType: partial.mediaType || 0,
    done: false,
    result: 0,
    error: null,
  }
}

export const messageSendText = (contactId: string, text: string, atWxids?: string[]): number => {
  const start = Date.now()
  try {
    let msgText = text
    if (contactId.includes('@chatroom') && atWxids && atWxids.length > 0) {
      for (const wxid of atWxids) {
        if (wxid === 'notify@all') {
          if (!msgText.includes('@所有人')) msgText = '@所有人 ' + msgText
        } else {
          const atText = `@${wxid}`
          if (!msgText.includes(atText)) msgText = `${atText} ${msgText}`
        }
      }
    }
    const r = enqueue(emptyJob({ kind: 'text', contactId, text: msgText }))
    log('MSG', `messageSendText ok, ${Date.now() - start}ms -> ${contactId}`)
    return r
  } catch (e: any) {
    console.error('[MSG] messageSendText 异常:', e)
    return -1
  }
}

export const messageSendImage = (contactId: string, path: string): number => {
  try {
    return enqueue(emptyJob({ kind: 'image', contactId, path }))
  } catch (e: any) {
    console.error('[MSG] messageSendImage 异常:', e)
    return -1
  }
}

export const decryptImage = (src: string, dst: string): number => {
  try {
    return enqueue(emptyJob({ kind: 'decode', path: src, dstPath: dst }))
  } catch (e: any) {
    console.error('[MSG] decryptImage 异常:', e)
    return -1
  }
}

/** 按 XML type 选 mediaType，经文本消息管线发送 XML 正文（原生 ForwardXML 偏移无效时的回退） */
function forwardXmlAsTypedContent(toWxid: string, xml: string): number {
  const kind = detectXmlKind(xml)
  let msgType = offsets.media_type_file
  if (kind === 'image') msgType = offsets.media_type_image
  else if (kind === 'video') msgType = offsets.media_type_video
  else if (kind === 'animation') msgType = offsets.media_type_emotion

  const b = base()
  const fns = getFns()
  const msgBuf = heapAlloc(offsets.msg_buf_size_text)
  msgBuf.writePointer(b.add(offsets.txt_message_vtbl))
  msgBuf.add(8).writeU64(uint64(offsets.txt_ctrl_const))
  const msg = msgBuf.add(0x10)
  fns.txtCtr(msg)
  setWeixinString(msg.add(offsets.tm_receiver), toWxid)
  setWeixinString(msg.add(offsets.tm_content), xml)
  msg.add(offsets.tm_type).writeU64(uint64(msgType))
  msg.add(offsets.tm_msg_len).writeU64(uint64(xml.length))
  const arg1 = buildArg1(msgBuf)
  const arg2 = heapAlloc(0xe8)
  buildSendParam2(arg2)
  fns.sendMessage(arg1, arg2)
  return 1
}

/** aixed ForwardXMLMsg：优先原生；虚表非法则回退为按类型发送 XML 内容 */
export const messageForwardXml = (toWxid: string, xml: string): number => {
  try {
    if (!toWxid || !xml) throw new Error('toWxid/xml empty')
    if (!detectXmlKind(xml)) throw new Error('unsupported xml type (need img/videomsg/emoji)')
    if (xmlOffsetsLookValid()) {
      return enqueue(emptyJob({ kind: 'xml', contactId: toWxid, xml }))
    }
    log('MSG', 'ForwardXML native offsets invalid; fallback typed XML content')
    return enqueue(emptyJob({ kind: 'xmlTyped', contactId: toWxid, xml }))
  } catch (e: any) {
    console.error('[MSG] messageForwardXml 异常:', e && e.message ? e.message : e)
    return -1
  }
}

export const messageSendFile = (contactId: string, path: string): number => {
  try {
    if (!contactId || !path) return -1
    return enqueue(
      emptyJob({
        kind: 'media',
        contactId,
        path,
        mediaType: offsets.media_type_file,
      }),
    )
  } catch (e: any) {
    console.error('[MSG] messageSendFile 异常:', e)
    return -1
  }
}

export const messageSendEmotion = (contactId: string, path: string): number => {
  try {
    if (!contactId || !path) return -1
    return enqueue(
      emptyJob({
        kind: 'media',
        contactId,
        path,
        mediaType: offsets.media_type_emotion,
      }),
    )
  } catch (e: any) {
    console.error('[MSG] messageSendEmotion 异常:', e)
    return -1
  }
}

export const messageSendPat = (_room: string, _wxid: string): number => -2
/** 按 msgId 转发未实现；请用 messageForwardXml / POST content */
export const messageForward = (_msgId: string, _to: string): number => -2
export const messageSendRichText = (_msg: any): number => -2
export const downloadAttach = (_msgId: string, _extra?: string): any => null
export const getAudio = (_msgId: string, _dir?: string): any => null
export const refreshPyq = (_id?: number): number => -2
export const getMsgTypes = (): Record<string, number> => ({
  text: 1,
  image: offsets.media_type_image,
  video: offsets.media_type_video,
  file: offsets.media_type_file,
  emotion: offsets.media_type_emotion,
})
