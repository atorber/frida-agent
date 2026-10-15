/** MSVC x64 std::string (WeixinString) helpers for Weixin.dll 4.x */

export const log = (type: string, ...args: any[]) => {
  console.log(`${new Date().toLocaleString()} [${type}] `, ...args)
}

export const WX_STRING_SIZE = 0x20

const HEAP_ZERO_MEMORY = 0x00000008

let _heapAlloc: any = null
let _getProcessHeap: any = null

function ensureHeapFns() {
  if (_heapAlloc) return
  const k32 = Process.getModuleByName('kernel32.dll')
  _getProcessHeap = new NativeFunction(k32.getExportByName('GetProcessHeap'), 'pointer', [])
  _heapAlloc = new NativeFunction(k32.getExportByName('HeapAlloc'), 'pointer', [
    'pointer',
    'uint32',
    'ulong',
  ])
}

/** 对齐 aixed：用进程堆分配，便于微信侧后续释放 */
export function heapAlloc(size: number): NativePointer {
  ensureHeapFns()
  const p = _heapAlloc(_getProcessHeap(), HEAP_ZERO_MEMORY, size) as NativePointer
  if (p.isNull()) throw new Error('HeapAlloc failed size=' + size)
  return p
}

export function calcWxCapacity(len: number): number {
  const need = len + 1
  const cap = (need + 0xf) & ~0xf
  return cap - 1
}

/** 写入 MSVC x64 SSO std::string（UTF-8）到已有 0x20 缓冲区 */
export function setWeixinString(dst: NativePointer, src: string): void {
  for (let i = 0; i < WX_STRING_SIZE; i++) {
    dst.add(i).writeU8(0)
  }
  const bytes = Memory.allocUtf8String(src)
  const utf8Len = byteLengthUtf8(src)
  dst.add(0x10).writeU64(uint64(utf8Len))

  if (utf8Len < 16) {
    Memory.copy(dst, bytes, utf8Len)
    dst.add(0x18).writeU64(uint64(0xf))
  } else {
    const heap = heapAlloc(utf8Len + 1)
    Memory.copy(heap, bytes, utf8Len)
    heap.add(utf8Len).writeU8(0)
    dst.writePointer(heap)
    dst.add(0x18).writeU64(uint64(calcWxCapacity(utf8Len)))
  }
}

function byteLengthUtf8(s: string): number {
  // Frida 无 TextEncoder 时用手动估算
  let n = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x80) n += 1
    else if (c < 0x800) n += 2
    else if (c >= 0xd800 && c <= 0xdbff) {
      // surrogate pair
      n += 4
      i++
    } else n += 3
  }
  return n
}

export function readStdString(addr: NativePointer): string | null {
  try {
    const len = addr.add(0x10).readU64().toNumber()
    const cap = addr.add(0x18).readU64().toNumber()
    if (len > 0x10000 || cap > 0x10000) return null
    if (len === 0) return ''
    const dataPtr = cap <= 15 ? addr : addr.readPointer()
    return dataPtr.readUtf8String(len)
  } catch {
    return null
  }
}

export function uint8ArrayToString(bytes: Uint8Array): string {
  const out: string[] = []
  for (let i = 0; i < bytes.length; i++) {
    out.push(String.fromCharCode(bytes[i]))
  }
  try {
    // @ts-ignore
    return decodeURIComponent(escape(out.join('')))
  } catch {
    return out.join('')
  }
}

export function stringToUint8Array(str: string): Uint8Array {
  const utf8: number[] = []
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i)
    if (c < 0x80) utf8.push(c)
    else if (c < 0x800) {
      utf8.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f))
    } else if (c >= 0xd800 && c <= 0xdbff) {
      i++
      const c2 = str.charCodeAt(i)
      const cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff)
      utf8.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f),
      )
    } else {
      utf8.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
    }
  }
  return new Uint8Array(utf8)
}

export function zeroMemory(p: NativePointer, size: number): void {
  for (let i = 0; i < size; i++) p.add(i).writeU8(0)
}

/** MSVC x64 SSO std::wstring（wchar，inline 容量 7+NUL → cap=0xF） */
export function setWeixinStringU(dst: NativePointer, src: string): void {
  for (let i = 0; i < 0x20; i++) dst.add(i).writeU8(0)
  const w = Memory.allocUtf16String(src)
  const len = src.length
  dst.add(0x10).writeU64(uint64(len))
  if (len < 8) {
    Memory.copy(dst, w, (len + 1) * 2)
    dst.add(0x18).writeU64(uint64(0xf))
  } else {
    const heap = heapAlloc((len + 1) * 2)
    Memory.copy(heap, w, (len + 1) * 2)
    dst.writePointer(heap)
    dst.add(0x18).writeU64(uint64(calcWxCapacity(len)))
  }
}

export function pathExists(path: string): boolean {
  try {
    const k32 = Process.getModuleByName('kernel32.dll')
    const GetFileAttributesW = new NativeFunction(
      k32.getExportByName('GetFileAttributesW'),
      'uint32',
      ['pointer'],
    )
    const INVALID = 0xffffffff
    const p = Memory.allocUtf16String(path)
    return (GetFileAttributesW(p) as number) !== INVALID
  } catch {
    return false
  }
}

/** MD5 via Windows CryptoAPI，用于 4.x Msg_{md5(username)} 表名 */
export function md5Hex(input: string): string {
  const adv = Process.getModuleByName('advapi32.dll')
  const CryptAcquireContextW = new NativeFunction(
    adv.getExportByName('CryptAcquireContextW'),
    'int',
    ['pointer', 'pointer', 'pointer', 'uint32', 'uint32'],
  )
  const CryptCreateHash = new NativeFunction(adv.getExportByName('CryptCreateHash'), 'int', [
    'pointer',
    'uint32',
    'pointer',
    'uint32',
    'pointer',
  ])
  const CryptHashData = new NativeFunction(adv.getExportByName('CryptHashData'), 'int', [
    'pointer',
    'pointer',
    'uint32',
    'uint32',
  ])
  const CryptGetHashParam = new NativeFunction(adv.getExportByName('CryptGetHashParam'), 'int', [
    'pointer',
    'uint32',
    'pointer',
    'pointer',
    'uint32',
  ])
  const CryptDestroyHash = new NativeFunction(adv.getExportByName('CryptDestroyHash'), 'int', [
    'pointer',
  ])
  const CryptReleaseContext = new NativeFunction(
    adv.getExportByName('CryptReleaseContext'),
    'int',
    ['pointer', 'uint32'],
  )

  const PROV_RSA_FULL = 1
  const CRYPT_VERIFYCONTEXT = 0xf0000000
  const CALG_MD5 = 0x00008003
  const HP_HASHVAL = 2

  const hProv = Memory.alloc(Process.pointerSize)
  hProv.writePointer(ptr(0))
  if (!CryptAcquireContextW(hProv, ptr(0), ptr(0), PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    throw new Error('CryptAcquireContextW failed')
  }
  const prov = hProv.readPointer()
  const hHash = Memory.alloc(Process.pointerSize)
  hHash.writePointer(ptr(0))
  try {
    if (!CryptCreateHash(prov, CALG_MD5, ptr(0), 0, hHash)) {
      throw new Error('CryptCreateHash failed')
    }
    const hash = hHash.readPointer()
    const data = Memory.allocUtf8String(input)
    const len = stringToUint8Array(input).length
    if (!CryptHashData(hash, data, len, 0)) throw new Error('CryptHashData failed')
    const outLen = Memory.alloc(4)
    outLen.writeU32(16)
    const out = Memory.alloc(16)
    if (!CryptGetHashParam(hash, HP_HASHVAL, out, outLen, 0)) {
      throw new Error('CryptGetHashParam failed')
    }
    const bytes = new Uint8Array(out.readByteArray(16)!)
    let s = ''
    for (let i = 0; i < 16; i++) s += ('0' + bytes[i].toString(16)).slice(-2)
    CryptDestroyHash(hash)
    return s
  } finally {
    CryptReleaseContext(prov, 0)
  }
}

export function fileSize(path: string): number {
  try {
    const k32 = Process.getModuleByName('kernel32.dll')
    const CreateFileW = new NativeFunction(k32.getExportByName('CreateFileW'), 'pointer', [
      'pointer',
      'uint32',
      'uint32',
      'pointer',
      'uint32',
      'uint32',
      'pointer',
    ])
    const GetFileSizeEx = new NativeFunction(k32.getExportByName('GetFileSizeEx'), 'int', [
      'pointer',
      'pointer',
    ])
    const CloseHandle = new NativeFunction(k32.getExportByName('CloseHandle'), 'int', ['pointer'])
    const GENERIC_READ = 0x80000000
    const OPEN_EXISTING = 3
    const FILE_SHARE_READ = 1
    const h = CreateFileW(
      Memory.allocUtf16String(path),
      GENERIC_READ,
      FILE_SHARE_READ,
      ptr(0),
      OPEN_EXISTING,
      0,
      ptr(0),
    ) as NativePointer
    if (h.equals(ptr(-1))) return 0
    const sizeBuf = Memory.alloc(8)
    const ok = GetFileSizeEx(h, sizeBuf) as number
    CloseHandle(h)
    if (!ok) return 0
    return sizeBuf.readU64().toNumber()
  } catch {
    return 0
  }
}
