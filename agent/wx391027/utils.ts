export const log = (type: string, ...args: any[]) => {
  console.log(`${new Date().toLocaleString()} [${type}] `, ...args)
}

/* -----------------base------------------------- */
let retidPtr: any = null
let retidStruct: any = null
export const initidStruct = ((str: string | any[]) => {

  retidPtr = Memory.alloc(str.length * 2 + 1)
  retidPtr.writeUtf16String(str)

  retidStruct = Memory.alloc(0x14) // returns a NativePointer

  retidStruct
    .writePointer(retidPtr).add(0x04)
    .writeU32(str.length * 2).add(0x04)
    .writeU32(str.length * 2).add(0x04)
    .writeU32(0).add(0x04)
    .writeU32(0)

  return retidStruct
})

let retPtr: any = null
let retStruct: any = null
export const initStruct = ((str: any) => {
  retPtr = Memory.alloc(str.length * 2 + 1)
  retPtr.writeUtf16String(str)

  retStruct = Memory.alloc(0x14) // returns a NativePointer

  retStruct
    .writePointer(retPtr).add(0x04)
    .writeU32(str.length * 2).add(0x04)
    .writeU32(str.length * 2).add(0x04)
    .writeU32(0).add(0x04)
    .writeU32(0)

  return retStruct
})

let msgstrPtr: any = null
let msgStruct: any = null
export const initmsgStruct = (str: any) => {
  msgstrPtr = Memory.alloc(str.length * 2 + 1)
  msgstrPtr.writeUtf16String(str)

  msgStruct = Memory.alloc(0x14) // returns a NativePointer

  msgStruct
    .writePointer(msgstrPtr).add(0x04)
    .writeU32(str.length * 2).add(0x04)
    .writeU32(str.length * 2).add(0x04)
    .writeU32(0).add(0x04)
    .writeU32(0)

  return msgStruct
}

let atStruct: any = null
export const initAtMsgStruct = (wxidStruct: any) => {
  atStruct = Memory.alloc(0x10)

  atStruct.writePointer(wxidStruct).add(0x04)
    .writeU32(wxidStruct.toInt32() + 0x14).add(0x04)// 0x14 = sizeof(wxid structure)
    .writeU32(wxidStruct.toInt32() + 0x14).add(0x04)
    .writeU32(0)
  return atStruct
}

export const readStringPtr = (address: any) => {
  const addr: any = ptr(address)
  const size = addr.add(16).readU32()
  const capacity = addr.add(20).readU32()
  addr.ptr = addr
  addr.size = size
  addr.capacity = capacity
  if (capacity > 15 && !addr.readPointer().isNull()) {
    addr.ptr = addr.readPointer()
  }
  addr.ptr._readCString = addr.ptr.readCString
  addr.ptr._readAnsiString = addr.ptr.readAnsiString
  addr.ptr._readUtf8String = addr.ptr.readUtf8String
  addr.readCString = () => {
    return addr.size ? addr.ptr._readCString(addr.size) : ''
  }
  addr.readAnsiString = () => {
    return addr.size ? addr.ptr._readAnsiString(addr.size) : ''
  }
  addr.readUtf8String = () => {
    return addr.size ? addr.ptr._readUtf8String(addr.size) : ''
  }

  // console.log('readStringPtr() address:',address,' -> str ptr:', addr.ptr, 'size:', addr.size, 'capacity:', addr.capacity)
  // console.log('readStringPtr() str:' , addr.readUtf8String())
  // console.log('readStringPtr() address:', addr,'dump:', addr.readByteArray(24))

  return addr
}

export const readString = (address: any) => {
  return readStringPtr(address).readUtf8String()
}

export const readWideString = (address: any) => {
  return readWStringPtr(address).readUtf16String()
}

export const writeWStringPtr = (str: string) => {
    // console.log(`输入字符串内容: ${str}`);
    const strLength = str.length;
    // console.log(`字符串长度: ${strLength}`);

    // 计算UTF-16编码的字节长度（每个字符2个字节）
    const utf16Length = strLength * 2;

    // 计算我们需要为字符串对象结构分配的总内存空间，结构包含：指针 (Process.pointerSize) + 长度 (4 bytes) + 容量 (4 bytes)
    const structureSize = Process.pointerSize + 4 + 4;

    // 为字符串数据和结构体分配连续的内存空间
    const totalSize = utf16Length + 2 + structureSize; // +2 用于 null 终止符
    const basePointer = Memory.alloc(totalSize);

    // 将结构体指针定位到分配的内存起始位置
    const structurePointer = basePointer;
    // console.log(`字符串分配空间内存指针: ${structurePointer}`);

    // 将字符串数据指针定位到结构体之后的位置
    const stringDataPointer = basePointer.add(structureSize);
    // console.log(`字符串保存地址指针: ${stringDataPointer}`);

    // 将 JavaScript 字符串转换成 UTF-16 编码格式，并写入分配的内存空间
    stringDataPointer.writeUtf16String(str);
    // console.log(`写入字符串到地址: ${stringDataPointer.readUtf16String()}`);

    // 检查分配的内存内容
    const allocatedMemoryContent = stringDataPointer.readUtf16String();
    // console.log(`检查分配的内存内容: ${allocatedMemoryContent}`);

    // 在分配的内存空间中写入字符串对象的信息
    // 写入字符串数据指针
    structurePointer.writePointer(stringDataPointer);
    // console.log(`写入字符串地址存放指针: ${structurePointer.readPointer()}`);
    // console.log(`写入字符串内容确认: ${structurePointer.readPointer().readUtf16String()}`);

    // 写入字符串长度（字节数，UTF-16 每个字符2个字节，不包含 null 终止符）
    // 注意：WeChat 的字符串结构期望长度字段存储字节数，而不是字符数
    structurePointer.add(Process.pointerSize).writeU32(utf16Length);
    // console.log(`写入字符串长度指针: ${structurePointer.add(Process.pointerSize)}`);

    // 写入字符串容量（字节数），这里我们假设容量和长度是相同的
    structurePointer.add(Process.pointerSize + 4).writeU32(utf16Length);
    // console.log(`写入字符串容量指针: ${structurePointer.add(Process.pointerSize + 4)}`);

    // console.log(`写入字符串内容再次确认: ${structurePointer.readPointer().readUtf16String()}`);
    // console.log(`写入字符地址再次确认: ${structurePointer.readPointer()}`);
    // console.log(`读取32位测试: ${structurePointer.readPointer().readS32()}`);
    // console.log(`return写入字符串结构体: ${structurePointer}`);

    // 返回分配的结构体表面的起始地址
    return structurePointer;
};

export const readWStringPtr = (addr: any) => {
    // console.log(`input读取字符串地址指针4: ${addr}`);
    // console.log(`读取字符串内容指针4: ${addr.readPointer().readUtf16String()}`);
    const stringPointer = addr.readPointer();
    // console.log(`读取数据指针地址1: ${stringPointer}`);
    // console.log(`读取数据指针内容1: ${stringPointer.readUtf16String()}`);

    const size = addr.add(Process.pointerSize).readU32();
    // console.log(`读取字符串长度: ${size}`);

    const capacity = addr.add(Process.pointerSize + 4).readU32();
    // console.log(`读取字符串容量: ${capacity}`);

    return {
        ptr: stringPointer,
        size: size,
        capacity: capacity,
        readUtf16String: () => {
            if (!stringPointer || stringPointer.isNull()) {
                return '';
            }
            
            // WeChat 内存中的字符串结构，长度字段可能存储的是字符数，也可能是字节数
            // 为了兼容两种情况，我们使用不传参数的方式读取，让 Frida 自动读取到 null 终止符
            // 这是最安全的方式，不依赖于长度字段的值
            try {
                const content = stringPointer.readUtf16String()?.replace(/\0+$/, '') || '';
                return content;
            } catch (e) {
                // 如果读取失败，尝试使用 size 作为字符数（假设 size 是字符数）
                try {
                    if (size > 0 && size < 10000) {
                        return stringPointer.readUtf16String(size)?.replace(/\0+$/, '') || '';
                    }
                } catch (e2) {
                    // 如果还是失败，尝试将 size/2 作为字符数（假设 size 是字节数）
                    try {
                        const charCount = Math.floor(size / 2);
                        if (charCount > 0 && charCount < 10000) {
                            return stringPointer.readUtf16String(charCount)?.replace(/\0+$/, '') || '';
                        }
                    } catch (e3) {
                        // 所有方法都失败
                    }
                }
                return '';
            }
        }
    };
};

//   string GetStringByStrAddr(UINT64 addr)
// {
//     size_t strLength = GET_DWORD(addr + 8);
//     return strLength ? string(GET_STRING(addr), strLength) : string();
// }
export const getStringByStrAddr = (addr:any)=>{
  const strLength = addr.add(8).readU32();
  // console.log('strLength:', strLength)
 return strLength ? addr.readPointer().readUtf16String(strLength) : '';
}

export interface WeChatMessage {
    // 发送者的用户标识
    fromUser: string;

    // 接收者的用户标识
    toUser?: string;

    room?:string;

    // 消息内容，这里提供的是 XML 格式的数据
    content: string;

    // 消息签名，包含了一些描述和验证信息
    signature: string;

    // 消息的唯一识别码
    msgId: string;

    // 消息的序列号
    msgSequence: number;

    // 消息的创建时间戳
    createTime: number;

    // 全文展示的标记，这里为空字符串，具体情况需要根据实际的业务逻辑确定
    displayFullContent: string;

    // 消息的类型，这里为 3，具体指代意义在业务中确定
    type: number;

    base64Img?: string;
    isSelf: boolean;
}

export function ReadWeChatStr(addr: any) {
    // console.log("addr: " + addr);
    addr = ptr(addr);
    var len = addr.add(0x10).readS64(); // 使用 ptr的`.readS64`方法
    // console.log("len: " + len);

    if (len == 0) return "";

    var max_len = addr.add(0x18).readS64();
    // console.log("max_len: " + max_len);
    let res = ''
    if ((max_len.or(0xF)).equals(0xF)) {
        res = addr.readUtf8String(len);

    } else {
        var char_from_user = addr.readPointer();
        res = char_from_user.readUtf8String(len);
    }
    // console.log("res: " + res);
    return res;
}

export function ReadSKBuiltinString(addr: { add: (arg0: number) => string | number; }) {
    console.log("addr: " + addr);
    var inner_string = ptr(addr.add(0x8)).readS64();
    console.log("inner_string: " + inner_string);

    // if (inner_string.isNull()) return "";
    return ReadWeChatStr(inner_string);
}

export const findIamgePathAddr = (param2: any) => {
    const len = 0x180
    console.log('param2:', param2)
    console.log('len:', len)
    let path = ''
    let isPath = false
    for (let i = 0; i < len; i++) {
        const offset = (i + 1) + 0x280 * 0
        console.log('offset:', offset)
        try {
            path = ReadSKBuiltinString(param2.add(offset).readS64()) // 发送者
            isPath = hasPath(path)
            if (isPath) {
                console.log('ReadSKBuiltinString offset:', offset)
                console.log('path:', path)
                break
            }
        } catch (error) {
            // console.error('error:', error)
        }
        try {
            path = ReadWeChatStr(param2.add(offset).readS64()) // 消息签名
            isPath = hasPath(path)
            if (isPath) {
                console.log('ReadWeChatStr offset:', offset)
                console.log('path:', path)
                break
            }
        } catch (error) {
            // console.error('error:', error)
        }
    }
}

const INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
/** WxString 结构大小（x64，对齐 WCF spy_types.h） */
export const WX_STRING_SIZE = 0x20

export const pathExistsNative = (targetPath: string): boolean => {
  try {
    const GetFileAttributesW = new NativeFunction(
      Module.getExportByName('kernel32.dll', 'GetFileAttributesW'),
      'uint32',
      ['pointer']
    )
    const pathPtr = Memory.allocUtf16String(targetPath)
    return GetFileAttributesW(pathPtr) !== INVALID_FILE_ATTRIBUTES
  } catch (e) {
    return false
  }
}

/** 查找可用的 python.exe（WeChat 进程 PATH 可能不含用户环境） */
export const findPythonExe = (): string => {
  const candidates = [
    'C:\\ProgramData\\anaconda3\\python.exe',
    'C:\\Python312\\python.exe',
    'C:\\Python314\\python.exe',
    'C:\\Python311\\python.exe',
    'C:\\Python310\\python.exe',
  ]
  const userProfile = (() => {
    try {
      const GetEnvironmentVariableW = new NativeFunction(
        Module.getExportByName('kernel32.dll', 'GetEnvironmentVariableW'),
        'uint32',
        ['pointer', 'pointer', 'uint32']
      )
      const name = Memory.allocUtf16String('USERPROFILE')
      const buf = Memory.alloc(512 * 2)
      const n = GetEnvironmentVariableW(name, buf, 512)
      return n > 0 ? (buf.readUtf16String() || '') : ''
    } catch (e) {
      return ''
    }
  })()
  if (userProfile) {
    candidates.push(
      `${userProfile}\\anaconda3\\python.exe`,
      `${userProfile}\\miniconda3\\python.exe`,
      `${userProfile}\\AppData\\Local\\Programs\\Python\\Python312\\python.exe`,
      `${userProfile}\\AppData\\Local\\Programs\\Python\\Python311\\python.exe`,
    )
  }
  for (const c of candidates) {
    if (pathExistsNative(c)) {
      return c
    }
  }
  return 'python'
}

/** 同步执行命令行（CreateProcessW + WaitForSingleObject），返回 exit code；失败 -1 */
export const runCmdBlocking = (commandLine: string, timeoutMs = 60000): number => {
  try {
    const CreateProcessW = new NativeFunction(
      Module.getExportByName('kernel32.dll', 'CreateProcessW'),
      'int',
      ['pointer', 'pointer', 'pointer', 'pointer', 'int', 'uint32', 'pointer', 'pointer', 'pointer', 'pointer']
    )
    const WaitForSingleObject = new NativeFunction(
      Module.getExportByName('kernel32.dll', 'WaitForSingleObject'),
      'uint32',
      ['pointer', 'uint32']
    )
    const GetExitCodeProcess = new NativeFunction(
      Module.getExportByName('kernel32.dll', 'GetExitCodeProcess'),
      'int',
      ['pointer', 'pointer']
    )
    const CloseHandle = new NativeFunction(
      Module.getExportByName('kernel32.dll', 'CloseHandle'),
      'int',
      ['pointer']
    )

    // STARTUPINFOW 68/104 bytes on x64; PROCESS_INFORMATION 24 bytes
    const si = Memory.alloc(104)
    for (let i = 0; i < 104; i++) si.add(i).writeU8(0)
    si.writeU32(104) // cb
    const pi = Memory.alloc(24)
    for (let i = 0; i < 24; i++) pi.add(i).writeU8(0)

    // lpCommandLine must be writable
    const cmdBuf = Memory.allocUtf16String(commandLine)
    const CREATE_NO_WINDOW = 0x08000000
    const ok = CreateProcessW(
      ptr(0),
      cmdBuf,
      ptr(0),
      ptr(0),
      0,
      CREATE_NO_WINDOW,
      ptr(0),
      ptr(0),
      si,
      pi
    )
    if (!ok) {
      console.error('CreateProcessW failed for:', commandLine)
      return -1
    }
    const hProcess = pi.readPointer()
    const hThread = pi.add(Process.pointerSize).readPointer()
    WaitForSingleObject(hProcess, timeoutMs >>> 0)
    const codeBuf = Memory.alloc(4)
    GetExitCodeProcess(hProcess, codeBuf)
    const code = codeBuf.readU32()
    CloseHandle(hThread)
    CloseHandle(hProcess)
    return code
  } catch (e) {
    console.error('runCmdBlocking failed:', e)
    return -1
  }
}

/** silk -> mp3（外部 python pysilk + ffmpeg） */
export const convertSilkToMp3 = (silkPath: string, mp3Path: string, sampleRate = 24000): boolean => {
  try {
    if (!pathExistsNative(silkPath)) {
      console.error('convertSilkToMp3: silk 不存在', silkPath)
      return false
    }
    if (pathExistsNative(mp3Path) && getFileSizeNative(mp3Path) > 0) {
      return true
    }

    const scriptCandidates = [
      'C:\\GitHub\\frida-agent\\agent\\wx391027\\tools\\silk2mp3.py',
    ]
    let script = ''
    for (const s of scriptCandidates) {
      if (pathExistsNative(s)) {
        script = s
        break
      }
    }
    if (!script) {
      console.error('convertSilkToMp3: 找不到 silk2mp3.py')
      return false
    }

    const py = findPythonExe()
    const ffmpeg = pathExistsNative('C:\\ffmpeg\\bin\\ffmpeg.exe')
      ? 'C:\\ffmpeg\\bin\\ffmpeg.exe'
      : 'ffmpeg'
    // 参数：silk mp3 sr [ffmpeg]
    const cmd =
      `cmd.exe /C ""${py}" "${script}" "${silkPath}" "${mp3Path}" ${sampleRate} "${ffmpeg}""`
    console.log('convertSilkToMp3:', cmd)
    const code = runCmdBlocking(cmd, 120000)
    if (code !== 0) {
      console.error('convertSilkToMp3 exit=', code)
      return false
    }
    return pathExistsNative(mp3Path) && getFileSizeNative(mp3Path) > 0
  } catch (e) {
    console.error('convertSilkToMp3 failed:', e)
    return false
  }
}

/** 获取本地文件大小（字节）；失败返回 -1 */
export const getFileSizeNative = (targetPath: string): number => {
  try {
    const CreateFileW = new NativeFunction(
      Module.getExportByName('kernel32.dll', 'CreateFileW'),
      'pointer',
      ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer']
    )
    const GetFileSizeEx = new NativeFunction(
      Module.getExportByName('kernel32.dll', 'GetFileSizeEx'),
      'int',
      ['pointer', 'pointer']
    )
    const CloseHandle = new NativeFunction(
      Module.getExportByName('kernel32.dll', 'CloseHandle'),
      'int',
      ['pointer']
    )
    const GENERIC_READ = 0x80000000
    const FILE_SHARE_READ = 0x1
    const OPEN_EXISTING = 3
    const FILE_ATTRIBUTE_NORMAL = 0x80
    const INVALID_HANDLE_VALUE = ptr(-1)
    const pathPtr = Memory.allocUtf16String(targetPath)
    const h = CreateFileW(
      pathPtr,
      GENERIC_READ,
      FILE_SHARE_READ,
      ptr(0),
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      ptr(0)
    )
    if (!h || h.equals(INVALID_HANDLE_VALUE)) {
      return -1
    }
    const sizeBuf = Memory.alloc(8)
    const ok = GetFileSizeEx(h, sizeBuf)
    CloseHandle(h)
    if (!ok) {
      return -1
    }
    // LARGE_INTEGER：低 32 + 高 32；GIF 一般远小于 4GB
    return sizeBuf.readU32()
  } catch (e) {
    return -1
  }
}

export const hasPath = (path: string | undefined) => {
  console.log('hasPath:', path)
  if (!path || path.length === 0) {
    return false
  }
  return pathExistsNative(path)
}

/** 防止 Frida GC 回收导致原生调用期间字符串悬空 */
const wxStringKeepAlive: NativePointer[] = []

/** ProcessHeap 分配（微信侧可能 HeapFree，勿用 Frida Memory.alloc 传给会接管内存的 API） */
export const heapAlloc = (size: number): NativePointer => {
  const GetProcessHeap = new NativeFunction(
    Module.getExportByName('kernel32.dll', 'GetProcessHeap'),
    'pointer',
    []
  )
  const HeapAllocFn = new NativeFunction(
    Module.getExportByName('kernel32.dll', 'HeapAlloc'),
    'pointer',
    ['pointer', 'uint32', 'ulong']
  )
  const HEAP_ZERO_MEMORY = 0x8
  const p = HeapAllocFn(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
  if (!p || p.isNull()) {
    throw new Error(`HeapAlloc(${size}) failed`)
  }
  return p
}

/** 对齐 WCF NewWxStringFromWstr：ProcessHeap + 宽字符个数 */
export const createWxStringHeap = (str: string): NativePointer => {
  const dataPtr = heapAlloc((str.length + 1) * 2)
  dataPtr.writeUtf16String(str)
  const structPtr = heapAlloc(WX_STRING_SIZE)
  structPtr.writePointer(dataPtr)
  structPtr.add(8).writeU32(str.length)
  structPtr.add(12).writeU32(str.length)
  return structPtr
}

/**
 * 创建微信字符串结构（WCF WxString：ptr + DWORD size + DWORD capacity + ansi + clen）
 * 使用 Memory.allocUtf16String，避免自管缓冲区写入异常。
 */
export const createWxString = (str: string, lengthInBytes = true): NativePointer => {
  const dataPtr = Memory.allocUtf16String(str)
  wxStringKeepAlive.push(dataPtr)
  const structPtr = Memory.alloc(WX_STRING_SIZE)
  for (let i = 0; i < WX_STRING_SIZE; i++) {
    structPtr.add(i).writeU8(0)
  }
  const len = lengthInBytes ? str.length * 2 : str.length
  const cap = Math.max(len, lengthInBytes ? 16 : 8)
  structPtr.writePointer(dataPtr)
  structPtr.add(8).writeU32(len >>> 0)
  structPtr.add(12).writeU32(cap >>> 0)
  wxStringKeepAlive.push(structPtr)
  return structPtr
}

/**
 * 将 WxString 字段直接写入目标地址（用于 vector 内联元素，避免 Memory.copy 异常）
 */
export const writeWxStringTo = (
  dest: NativePointer,
  str: string,
  lengthInBytes = false,
): void => {
  const dataPtr = Memory.allocUtf16String(str)
  wxStringKeepAlive.push(dataPtr)
  for (let i = 0; i < WX_STRING_SIZE; i++) {
    dest.add(i).writeU8(0)
  }
  const len = lengthInBytes ? str.length * 2 : str.length
  const cap = Math.max(len, lengthInBytes ? 16 : 8)
  dest.writePointer(dataPtr)
  dest.add(8).writeU32(len >>> 0)
  dest.add(12).writeU32(cap >>> 0)
}

/**
 * MSVC x64 std::wstring 布局：ptr(8) + reserved(8) + size(8) + capacity(8)
 */
export const createMsvcWString = (str: string): NativePointer => {
  const dataPtr = Memory.allocUtf16String(str)
  wxStringKeepAlive.push(dataPtr)
  const structPtr = Memory.alloc(0x20)
  for (let i = 0; i < 0x20; i++) {
    structPtr.add(i).writeU8(0)
  }
  structPtr.writePointer(dataPtr)
  structPtr.add(16).writeU64(str.length)
  structPtr.add(24).writeU64(Math.max(str.length, 8))
  wxStringKeepAlive.push(structPtr)
  return structPtr
}

export const createMsvcWStringVector = (ids: string[]): NativePointer => {
  const cleaned = ids.map(s => s.trim()).filter(Boolean)
  if (cleaned.length === 0) {
    throw new Error('createMsvcWStringVector: empty ids')
  }
  const stride = 0x20
  const count = cleaned.length
  const arrayPtr = Memory.alloc(stride * count)
  for (let i = 0; i < stride * count; i++) {
    arrayPtr.add(i).writeU8(0)
  }
  for (let i = 0; i < count; i++) {
    const slot = arrayPtr.add(i * stride)
    const dataPtr = Memory.allocUtf16String(cleaned[i])
    wxStringKeepAlive.push(dataPtr)
    slot.writePointer(dataPtr)
    slot.add(16).writeU64(cleaned[i].length)
    slot.add(24).writeU64(Math.max(cleaned[i].length, 8))
  }
  const rawVector = Memory.alloc(Process.pointerSize * 3)
  const finish = arrayPtr.add(stride * count)
  rawVector.writePointer(arrayPtr)
  rawVector.add(Process.pointerSize).writePointer(finish)
  rawVector.add(Process.pointerSize * 2).writePointer(finish)
  wxStringKeepAlive.push(arrayPtr, rawVector)
  return rawVector
}

/** 对齐 WCF NewWxString：size/capacity 为宽字符个数 */
export const createWxStringChars = (str: string): NativePointer => createWxString(str, false)

/**
 * 创建 std::vector<WxString> 的 Release 布局：{ start, finish, end }
 * 元素为内联 WxString（步长 0x20），与 WCF chatroom_mgmt 一致。
 */
export const createWxStringVector = (ids: string[], lengthInBytes = false): NativePointer => {
  const cleaned = ids.map(s => s.trim()).filter(Boolean)
  if (cleaned.length === 0) {
    throw new Error('createWxStringVector: empty ids')
  }

  const count = cleaned.length
  const arrayPtr = Memory.alloc(WX_STRING_SIZE * count)
  for (let i = 0; i < WX_STRING_SIZE * count; i++) {
    arrayPtr.add(i).writeU8(0)
  }

  for (let i = 0; i < count; i++) {
    writeWxStringTo(arrayPtr.add(i * WX_STRING_SIZE), cleaned[i], lengthInBytes)
  }

  const rawVector = Memory.alloc(Process.pointerSize * 3)
  const finish = arrayPtr.add(WX_STRING_SIZE * count)
  rawVector.writePointer(arrayPtr)
  rawVector.add(Process.pointerSize).writePointer(finish)
  rawVector.add(Process.pointerSize * 2).writePointer(finish)
  wxStringKeepAlive.push(arrayPtr, rawVector)
  return rawVector
}

/**
 * 按指定步长创建内联 WxString 向量（用于排查不同微信字符串布局）
 */
export const createWxStringVectorStride = (
  ids: string[],
  stride: number,
  lengthInBytes = true
): NativePointer => {
  const cleaned = ids.map(s => s.trim()).filter(Boolean)
  if (cleaned.length === 0) {
    throw new Error('createWxStringVectorStride: empty ids')
  }
  const count = cleaned.length
  const arrayPtr = Memory.alloc(stride * count)
  arrayPtr.writeByteArray(Array(stride * count).fill(0))

  for (let i = 0; i < count; i++) {
    const wx = lengthInBytes ? writeWStringPtr(cleaned[i]) : createWxStringChars(cleaned[i])
    const copyLen = Math.min(stride, WX_STRING_SIZE)
    Memory.copy(arrayPtr.add(i * stride), wx, copyLen)
  }

  const rawVector = Memory.alloc(Process.pointerSize * 3)
  const finish = arrayPtr.add(stride * count)
  rawVector.writePointer(arrayPtr)
  rawVector.add(Process.pointerSize).writePointer(finish)
  rawVector.add(Process.pointerSize * 2).writePointer(finish)
  return rawVector
}

/**
 * 64 位长度字段布局：ptr(8) + size(8) + cap(8)，常见于部分微信内部 string
 */
export const createWxStringU64 = (str: string, lengthInBytes = false): NativePointer => {
  const structPtr = Memory.alloc(0x20)
  structPtr.writeByteArray(Array(0x20).fill(0))
  const dataPtr = Memory.alloc((str.length + 1) * 2)
  dataPtr.writeUtf16String(str)
  const len = lengthInBytes ? str.length * 2 : str.length
  structPtr.writePointer(dataPtr)
  structPtr.add(8).writeU64(len)
  structPtr.add(16).writeU64(len)
  return structPtr
}

export const createWxStringVectorU64 = (ids: string[], lengthInBytes = false): NativePointer => {
  const cleaned = ids.map(s => s.trim()).filter(Boolean)
  if (cleaned.length === 0) {
    throw new Error('createWxStringVectorU64: empty ids')
  }
  const stride = 0x18
  const count = cleaned.length
  const arrayPtr = Memory.alloc(stride * count)
  arrayPtr.writeByteArray(Array(stride * count).fill(0))
  for (let i = 0; i < count; i++) {
    const wx = createWxStringU64(cleaned[i], lengthInBytes)
    Memory.copy(arrayPtr.add(i * stride), wx, stride)
  }
  const rawVector = Memory.alloc(Process.pointerSize * 3)
  const finish = arrayPtr.add(stride * count)
  rawVector.writePointer(arrayPtr)
  rawVector.add(Process.pointerSize).writePointer(finish)
  rawVector.add(Process.pointerSize * 2).writePointer(finish)
  return rawVector
}

/**
 * 备用：WxString* 指针数组向量
 */
export const createWxStringPtrVector = (ids: string[], lengthInBytes = true): NativePointer => {
  const cleaned = ids.map(s => s.trim()).filter(Boolean)
  if (cleaned.length === 0) {
    throw new Error('createWxStringPtrVector: empty ids')
  }
  const ptrSize = Process.pointerSize
  const start = Memory.alloc(ptrSize * cleaned.length)
  for (let i = 0; i < cleaned.length; i++) {
    const wx = lengthInBytes ? writeWStringPtr(cleaned[i]) : createWxStringChars(cleaned[i])
    start.add(i * ptrSize).writePointer(wx)
  }
  const rawVector = Memory.alloc(ptrSize * 3)
  const finish = start.add(ptrSize * cleaned.length)
  rawVector.writePointer(start)
  rawVector.add(ptrSize).writePointer(finish)
  rawVector.add(ptrSize * 2).writePointer(finish)
  return rawVector
}

export const readFileBytes = (filePath: string): Uint8Array | null => {
  try {
    // @ts-ignore Frida File API
    const buf = File.readAllBytes(filePath)
    if (!buf) {
      return null
    }
    if (buf instanceof ArrayBuffer) {
      return new Uint8Array(buf)
    }
    // 部分环境返回带 buffer 的对象
    if ((buf as any).buffer) {
      const anyBuf = buf as any
      return new Uint8Array(anyBuf.buffer, anyBuf.byteOffset || 0, anyBuf.byteLength || anyBuf.length)
    }
    return new Uint8Array(buf as any)
  } catch (e) {
    console.error('readFileBytes failed:', e)
    return null
  }
}

export const writeFileBytes = (filePath: string, data: Uint8Array): boolean => {
  try {
    ensureParentDirNative(filePath)
    const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
    // @ts-ignore Frida File API
    File.writeAllBytes(filePath, buffer)
    return true
  } catch (e) {
    console.error('writeFileBytes failed:', e)
    return false
  }
}

export const ensureParentDirNative = (filePath: string) => {
  const lastSep = Math.max(filePath.lastIndexOf('\\'), filePath.lastIndexOf('/'))
  if (lastSep <= 0) {
    return
  }
  const dir = filePath.substring(0, lastSep)
  if (pathExistsNative(dir)) {
    return
  }
  try {
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
      if (!pathExistsNative(current)) {
        CreateDirectoryW(Memory.allocUtf16String(current), ptr(0))
      }
    }
  } catch (e) {
    console.error('ensureParentDirNative failed:', e)
  }
}

// 接收消息
export function uint8ArrayToString(arr: Uint8Array) {
    const utf8 = Array.from(arr).map(byte => String.fromCharCode(byte as number)).join('');
    return decodeURIComponent(escape(utf8));
}

// 将字符串转换为 Uint8Array
export function stringToUint8Array(str: string) {
    const utf8 = unescape(encodeURIComponent(str));
    const arr = new Uint8Array(utf8.length);
    for (let i = 0; i < utf8.length; i++) {
        arr[i] = utf8.charCodeAt(i);
    }
    return arr;
}

// 读取流数据
export const readAll = async (input: InputStream): Promise<any> => {
    const chunks: any[] = [];
    const size = 1024;
    let chunk: any;
    let i = 0;
    let isEnd = false;
    while (!isEnd) {
        try {
            chunk = await input.read(size)
            // console.log('chunk:', chunk);
            // console.log('chunk.byteLength:', chunk.byteLength);

            // 示例接收数据
            const receivedData = new Uint8Array(chunk);

            const message = uint8ArrayToString(receivedData);
            chunks.push(message);

            if (chunk.byteLength < size) {
                isEnd = true;
                break;
            }
            // console.log('isEnd:', isEnd);
        } catch (error) {
            console.error('Failed to read chunk:', error);
        }
    }

    return chunks.join('');
};

// 解析联系人信息，信息不准确
export function parseContact(start: any) {
  // console.log('contactPtr:', contactPtr)

  /* Get Contacts:
  call1, call2, wxId, Code, Remark,Name, Gender, Country, Province, City*/
  // { 0x75A4A0, 0xC089F0, 0x10, 0x24, 0x58, 0x6C, 0x0E, 0x00, 0x00, 0x00 },

  const temp: any = {
      wxid: readWideString(start.add(0x10)),
      custom_account: readWideString(start.add(0x30)),
      encrypt_name: readWideString(start.add(0x50)),
      remark: readWideString(start.add(0x80)),
      remark_pinyin: readWideString(start.add(0x148)),
      remark_pinyin_all: readWideString(start.add(0x168)),
      label_ids: readWideString(start.add(0xc0)),
      nickname: readWideString(start.add(0xA0)),
      pinyin: readWideString(start.add(0x108)),
      pinyin_all: readWideString(start.add(0x128)),
      verify_flag: start.add(0x70).readS32(),
      type: start.add(0x74).readS32(),
      reserved1: start.add(0x1F0).readS32(),
      reserved2: start.add(0x1F4).readS32(),
  };
  // console.log('temp:', JSON.stringify(temp, null, 2))

  const info: any = {}
  try {
    info.BigHeadImgUrl = readWideString(start.add(0x188)) || ''
  } catch (e) {
    info.BigHeadImgUrl = ''
  }
  try {
    info.SmallHeadImgUrl = readWideString(start.add(0x1A8)) || ''
  } catch (e) {
    info.SmallHeadImgUrl = ''
  }

  const contact = {
      id: temp.wxid,
      gender: 1,
      type: temp.type,
      name: (temp.remark && String(temp.remark).trim()) || temp.nickname,
      friend: isFriendContactId(temp.wxid, temp.type, temp.verify_flag),
      star: false,
      coworker: temp.wxid.indexOf('@openim') > -1,
      avatar: info.SmallHeadImgUrl || info.BigHeadImgUrl || '',
      address: info.Province + info.City,
      alias: temp.remark || info.Alias,
      city: info.City,
      province: info.Province,
      weixin: temp.custom_account,
      corporation: '',
      title: '',
      description: '',
      phone: [],
  };
  return contact;

}

/** Contact.Type：通讯录联系人标记 */
const MM_CONTACTFLAG_CONTACT = 0x1

/** 系统号 / 非个人好友（保留 filehelper） */
const NON_FRIEND_SYSTEM_IDS = new Set([
  'fmessage',
  'medianote',
  'floatbottle',
  'weibo',
  'mphelper',
  'newsapp',
  'qmessage',
  'tmessage',
  'officialaccounts',
  'notification_messages',
  'helper_entry',
  'blogapp',
  'facebookapp',
  'feedsapp',
  'qqfriend',
  'qqmail',
  'brandsessionholder',
  'weixin',
  'brandcustomer',
])

/**
 * 是否应出现在「好友/人脉」列表中。
 *
 * 注意：DB/内存里好友的 EncryptUserName 也常为 `v3_…@stranger`，
 * 不能据此判非好友。该串对应的典型非好友是公众号（如 gh_* + VerifyFlag≠0）。
 */
export function isFriendContactId(
  id: string,
  type?: number,
  verifyFlag?: number,
): boolean {
  if (!id || typeof id !== 'string') return false
  const wxid = id.trim()
  if (!wxid) return false
  if (wxid.endsWith('@chatroom')) return false
  if (wxid.endsWith('@openim')) return false
  if (wxid.includes('@im.chatroom')) return false
  // UserName 本身是临时陌生人
  if (wxid.endsWith('@stranger')) return false
  if (/^v\d+_/i.test(wxid) && wxid.includes('@')) return false
  // 公众号
  if (wxid.startsWith('gh_')) return false
  if (NON_FRIEND_SYSTEM_IDS.has(wxid)) return false
  // 须带通讯录 CONTACT 位（排除仅群聊出现过的 Type=4、仅聊天 Type=2 等）
  if (typeof type === 'number' && (type & MM_CONTACTFLAG_CONTACT) === 0) {
    return false
  }
  // VerifyFlag≠0：公众号/品牌号等（EncryptUserName 常带 @stranger）
  if (typeof verifyFlag === 'number' && verifyFlag !== 0) {
    return false
  }
  return true
}
