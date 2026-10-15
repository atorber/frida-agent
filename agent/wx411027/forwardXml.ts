/**
 * XML 转发（对齐 aixed wx_send_xml.cpp ForwardXmlMessage）
 * 支持 img / videomsg / emoji
 */
import { offsets, WX_DLL } from './offset.js'
import { heapAlloc } from './utils.js'

export type XmlKind = 'image' | 'video' | 'animation'

export type XmlFields = {
  cdnbigurl: string
  cdnurl: string
  aeskey: string
  md5: string
  hdlength: number
  length: number
  hevc_mid_size: number
  cdnthumblength: number
  cdnthumbwidth: number
  cdnthumbheight: number
  playlength: number
  type: number
  width: number
  height: number
  productid: string
}

function base(): NativePointer {
  return Process.getModuleByName(WX_DLL).base
}

function extractBetween(source: string, start: string, end: string): string {
  const i = source.indexOf(start)
  if (i < 0) return ''
  const from = i + start.length
  const j = source.indexOf(end, from)
  if (j < 0) return ''
  return source.substring(from, j)
}

function parseIntSafe(s: string): number {
  if (!s) return 0
  const n = parseInt(s, 10)
  return Number.isFinite(n) ? n : 0
}

function allocCString(s: string): NativePointer | null {
  if (!s) return null
  const p = heapAlloc(s.length + 1)
  p.writeUtf8String(s)
  return p
}

function writeStdLike(dst: NativePointer, strPtr: NativePointer | null, len: number): void {
  if (!strPtr) return
  dst.writePointer(strPtr)
  dst.add(0x10).writeU64(uint64(len))
  dst.add(0x18).writeU64(uint64(len))
}

export function detectXmlKind(xml: string): XmlKind | null {
  if (xml.indexOf('<img ') >= 0) return 'image'
  if (xml.indexOf('<videomsg ') >= 0) return 'video'
  if (xml.indexOf('<emoji ') >= 0) return 'animation'
  return null
}

export function extractXmlFields(xml: string, kind: XmlKind): XmlFields {
  const empty: XmlFields = {
    cdnbigurl: '',
    cdnurl: '',
    aeskey: '',
    md5: '',
    hdlength: 0,
    length: 0,
    hevc_mid_size: 0,
    cdnthumblength: 0,
    cdnthumbwidth: 0,
    cdnthumbheight: 0,
    playlength: 0,
    type: 0,
    width: 0,
    height: 0,
    productid: '',
  }
  if (kind === 'image') {
    return {
      ...empty,
      cdnbigurl: extractBetween(xml, 'cdnbigimgurl="', '"'),
      cdnurl: extractBetween(xml, 'cdnthumburl="', '"'),
      aeskey: extractBetween(xml, 'aeskey="', '"'),
      md5: extractBetween(xml, 'md5="', '"'),
      hdlength: parseIntSafe(extractBetween(xml, 'hdlength="', '"')),
      length: parseIntSafe(extractBetween(xml, 'length="', '"')),
      hevc_mid_size: parseIntSafe(extractBetween(xml, 'hevc_mid_size="', '"')),
      cdnthumblength: parseIntSafe(extractBetween(xml, 'cdnthumblength="', '"')),
      cdnthumbwidth: parseIntSafe(extractBetween(xml, 'cdnthumbwidth="', '"')),
      cdnthumbheight: parseIntSafe(extractBetween(xml, 'cdnthumbheight="', '"')),
    }
  }
  if (kind === 'video') {
    return {
      ...empty,
      cdnurl: extractBetween(xml, 'cdnthumburl="', '"'),
      aeskey: extractBetween(xml, 'aeskey="', '"'),
      md5: extractBetween(xml, 'md5="', '"'),
      playlength: parseIntSafe(extractBetween(xml, 'playlength="', '"')),
      length: parseIntSafe(extractBetween(xml, 'length="', '"')),
      cdnthumblength: parseIntSafe(extractBetween(xml, 'cdnthumblength="', '"')),
      cdnthumbwidth: parseIntSafe(extractBetween(xml, 'cdnthumbwidth="', '"')),
      cdnthumbheight: parseIntSafe(extractBetween(xml, 'cdnthumbheight="', '"')),
    }
  }
  return {
    ...empty,
    md5: extractBetween(xml, 'md5="', '"'),
    length: parseIntSafe(extractBetween(xml, 'len="', '"')),
    type: parseIntSafe(extractBetween(xml, 'type="', '"')),
    width: parseIntSafe(extractBetween(xml, 'width="', '"')),
    height: parseIntSafe(extractBetween(xml, 'height="', '"')),
    productid: extractBetween(xml, 'productid="', '"'),
  }
}

/** aixed BuildLinkedList：10 个 0xA0 节点的循环双向链表 */
function buildLinkedList(count = 10): NativePointer {
  const nodeSize = 0xa0
  const total = nodeSize * count
  const memory = heapAlloc(total)
  const header = memory
  const first = memory.add(nodeSize)
  const last = first.add(nodeSize * (count - 1))
  header.writePointer(first)
  header.add(8).writePointer(last)
  header.add(0x10).writeU64(uint64('0xABABABABABABABAB'))

  for (let i = 0; i < count; i++) {
    const cur = first.add(nodeSize * i)
    let prev: NativePointer
    let next: NativePointer
    if (i === 0) {
      prev = header
      next = cur.add(nodeSize)
    } else if (i === count - 1) {
      prev = cur.sub(nodeSize)
      next = header
    } else {
      prev = cur.sub(nodeSize)
      next = cur.add(nodeSize)
    }
    cur.writePointer(next)
    cur.add(8).writePointer(prev)
    if (i === 4) {
      // "svrid" little-endian packed
      cur.add(0x10).writeU64(uint64(0x6469727673))
      cur.add(0x20).writeU64(uint64(5))
      cur.add(0x28).writeU64(uint64(0xf))
    }
  }
  return memory
}

function writeFieldHeader(field: NativePointer, vtbl1: number, vtbl2: number): void {
  const b = base()
  field.writePointer(b.add(vtbl1))
  field.add(8).writeU64(uint64('0x100000006'))
  field.add(0x10).writePointer(b.add(vtbl2))
  field.add(0x18).writeU64(uint64(1))
  field.add(0x20).writeU64(uint64(0))
  field.add(0x28).writeU64(uint64(0x3f800000))
  field.add(0x38).writeU64(uint64(0xa))
  const list = buildLinkedList()
  field.add(0x30).writePointer(list)
}

function buildImageStructure(fields: XmlFields): NativePointer {
  const field = heapAlloc(0x400)
  const aes1 = allocCString(fields.aeskey)
  const aes2 = allocCString(fields.aeskey)
  const md5 = allocCString(fields.md5)
  const big = allocCString(fields.cdnbigurl)
  const url1 = allocCString(fields.cdnurl)
  const url2 = allocCString(fields.cdnurl)

  writeStdLike(field.add(0x170), aes1, fields.aeskey.length)
  writeStdLike(field.add(0x1b0), md5, fields.md5.length)
  if (big && fields.cdnbigurl) {
    writeStdLike(field.add(0x1d0), big, fields.cdnbigurl.length)
    field.add(0x1f0).writeU64(uint64(fields.hdlength))
  }
  writeStdLike(field.add(0x1f8), url1, fields.cdnurl.length)
  field.add(0x218).writeU32(fields.length >>> 0)
  field.add(0x21c).writeU32(fields.hevc_mid_size >>> 0)
  writeStdLike(field.add(0x220), url2, fields.cdnurl.length)
  writeStdLike(field.add(0x240), aes2, fields.aeskey.length)
  field.add(0x260).writeU32(fields.cdnthumblength >>> 0)
  field.add(0x264).writeU32(fields.cdnthumbwidth >>> 0)
  field.add(0x268).writeU32(fields.cdnthumbheight >>> 0)

  writeFieldHeader(field, offsets.IMAGE_FIELD_VTABLE, offsets.IMAGE_FIELD_VTABLE2)
  return field
}

function buildVideoStructure(fields: XmlFields): NativePointer {
  const field = heapAlloc(0x400)
  const aes1 = allocCString(fields.aeskey)
  const aes2 = allocCString(fields.aeskey)
  const md5 = allocCString(fields.md5)
  const url1 = allocCString(fields.cdnurl)
  const url2 = allocCString(fields.cdnurl)

  writeStdLike(field.add(0x170), aes1, fields.aeskey.length)
  writeStdLike(field.add(0x1a0), md5, fields.md5.length)
  field.add(0x190).writeU32(fields.playlength >>> 0)
  field.add(0x198).writeU32(1)
  field.add(0x1e0).writeU32(fields.length >>> 0)
  writeStdLike(field.add(0x1e8), url1, fields.cdnurl.length)
  writeStdLike(field.add(0x270), url2, fields.cdnurl.length)
  writeStdLike(field.add(0x290), aes2, fields.aeskey.length)
  field.add(0x2b0).writeU32(fields.cdnthumblength >>> 0)
  field.add(0x2b4).writeU32(fields.cdnthumbwidth >>> 0)
  field.add(0x2b8).writeU32(fields.cdnthumbheight >>> 0)

  writeFieldHeader(field, offsets.VIDEO_FIELD_VTABLE, offsets.VIDEO_FIELD_VTABLE2)
  return field
}

function buildAnimationStructure(fields: XmlFields): NativePointer {
  const field = heapAlloc(0x400)
  const md5 = allocCString(fields.md5)
  const product = allocCString(fields.productid)

  field.add(0x190).writeU32(fields.length >>> 0)
  writeStdLike(field.add(0x198), md5, fields.md5.length)
  writeStdLike(field.add(0x1b8), product, fields.productid.length)
  field.add(0x258).writeU32(fields.type >>> 0)
  field.add(0x25c).writeU32(fields.width >>> 0)
  field.add(0x260).writeU32(fields.height >>> 0)

  writeFieldHeader(field, offsets.ANIMATION_FIELD_VTABLE, offsets.ANIMATION_FIELD_VTABLE2)
  return field
}

function buildXmlDataStructure(kind: XmlKind): NativePointer {
  const b = base()
  const p = heapAlloc(0x100)
  p.writePointer(b.add(offsets.IMAGE_DATA_VTABLE))
  p.add(8).writeU64(uint64('0x100000005'))
  p.add(0x10).writePointer(b.add(offsets.IMAGE_DATA_VTABLE2))
  if (kind === 'image') p.add(0x18).writeU64(uint64('0x300000064'))
  else if (kind === 'video') p.add(0x18).writeU64(uint64('0x2B00000064'))
  else p.add(0x18).writeU64(uint64('0x2F00000000'))
  return p
}

/** aixed global.h 中 Offsets 标注为 4.1.5.30；在 4.1.10.27 上需像 vtable 一样指向模块内代码 */
export function xmlOffsetsLookValid(): boolean {
  const b = base()
  const candidates = [
    offsets.IMAGE_FIELD_VTABLE,
    offsets.IMAGE_FIELD_VTABLE2,
    offsets.MESSAGE_STRUCT_VTABLE,
    offsets.MESSAGE_STRUCT_VTABLE2,
    offsets.MESSAGE_PARAM_VTABLE,
    offsets.ANIMATION_FIELD_VTABLE,
    offsets.VIDEO_FIELD_VTABLE,
  ]
  const modEnd = b.add(Process.getModuleByName(WX_DLL).size)
  for (const rva of candidates) {
    try {
      const slot = b.add(rva)
      let ok = 0
      for (let i = 0; i < 3; i++) {
        const q = slot.add(i * 8).readPointer()
        if (!q.isNull() && q.compare(b) >= 0 && q.compare(modEnd) < 0) ok++
      }
      if (ok < 2) return false
    } catch {
      return false
    }
  }
  return true
}

/** 在主线程调用；对齐 aixed ForwardXmlMessage */
export function forwardXmlNative(toWxid: string, xml: string): number {
  if (!toWxid || !xml) throw new Error('toWxid/xml empty')
  const kind = detectXmlKind(xml)
  if (!kind) throw new Error('unsupported xml type (need img/videomsg/emoji)')
  if (!xmlOffsetsLookValid()) {
    throw new Error(
      'XML Offsets invalid on this Weixin.dll (aixed labeled 4.1.5.30; need refresh for 4.1.10.27)',
    )
  }

  const fields = extractXmlFields(xml, kind)
  let xmlField: NativePointer
  let xmlData: NativePointer | null = null
  if (kind === 'image') {
    xmlField = buildImageStructure(fields)
  } else if (kind === 'video') {
    xmlField = buildVideoStructure(fields)
    xmlData = buildXmlDataStructure(kind)
  } else {
    xmlField = buildAnimationStructure(fields)
    xmlData = buildXmlDataStructure(kind)
  }

  const b = base()
  const messageStruct = heapAlloc(0x400)
  const wxidPtr = allocCString(toWxid)!

  messageStruct.writePointer(b.add(offsets.MESSAGE_STRUCT_VTABLE))
  messageStruct.add(8).writeU64(uint64('0x100000003'))
  messageStruct.add(0x10).writePointer(b.add(offsets.MESSAGE_STRUCT_VTABLE2))

  let msgType = 0x31
  if (kind === 'image') msgType = 0x3
  else if (kind === 'video') msgType = 0x2b
  else if (kind === 'animation') msgType = 0x2f
  messageStruct.add(0xd8).writeU64(uint64(msgType))

  messageStruct.add(0xa8).writePointer(wxidPtr)
  messageStruct.add(0xb8).writeU64(uint64(toWxid.length))
  messageStruct.add(0xc0).writeU64(uint64(toWxid.length))

  messageStruct.add(0x318).writePointer(xmlField.add(0x10))
  messageStruct.add(0x320).writePointer(xmlField)
  if (xmlData) {
    messageStruct.add(0x340).writePointer(xmlData.add(0x10))
    messageStruct.add(0x348).writePointer(xmlData)
  }

  const listPtr = heapAlloc(0x20)
  listPtr.writePointer(messageStruct.add(0x10))
  listPtr.add(8).writePointer(messageStruct)

  const paramPtr = heapAlloc(0x28)
  paramPtr.writePointer(b.add(offsets.MESSAGE_PARAM_VTABLE))
  paramPtr.add(8).writePointer(listPtr)
  paramPtr.add(0x10).writePointer(listPtr.add(0x10))
  paramPtr.add(0x18).writePointer(listPtr.add(0x10))

  const rcx = heapAlloc(0x40)
  const rdx = heapAlloc(0x100)
  rcx.add(0x38).writePointer(paramPtr)
  rdx.add(0x20).writePointer(b.add(0x367849))

  const forwardCall = new NativeFunction(b.add(offsets.FORWARD_XML_CALL), 'void', [
    'pointer',
    'pointer',
    'pointer',
  ])
  forwardCall(rcx, rdx, rdx.add(0xc0))
  return 1
}
