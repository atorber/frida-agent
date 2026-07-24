import {
    writeWStringPtr,
    readWStringPtr,
    ReadSKBuiltinString,
    ReadWeChatStr,
    WeChatMessage,
    hasPath,
    pathExistsNative,
    getFileSizeNative,
    uint8ArrayToString,
    stringToUint8Array,
    readAll,
    findIamgePathAddr,
    readString,
    readWideString,
    readStringPtr,
    getStringByStrAddr,
    initStruct,
    initidStruct,
    initmsgStruct,
    parseContact,
    createWxString,
    createWxStringChars,
    createWxStringHeap,
    createWxStringVector,
    heapAlloc,
    WX_STRING_SIZE,
    readFileBytes,
    writeFileBytes,
    ensureParentDirNative,
    convertSilkToMp3,
} from './utils.js'

import {
    getLocalIdAndDbIdx,
    getAudioData,
} from './sqlite.js'

import { RichTextMsg } from './types.js'
import { offsets } from './offset.js'

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

/*
发送文本消息 3.9.10.27
*/ 
// 缓存 NativeFunction，避免每次发送都新建（减轻 GumJS / Socket 侧压力）
let _sendTextFns: {
    mgr: any
    send: any
    free: any
} | null = null

function getSendTextFns() {
    if (_sendTextFns) return _sendTextFns
    _sendTextFns = {
        mgr: new NativeFunction(moduleBaseAddress.add(offsets.kSendMessageMgr), 'void', []),
        send: new NativeFunction(
            moduleBaseAddress.add(offsets.kSendTextMsg),
            'uint64',
            ['pointer', 'pointer', 'pointer', 'pointer', 'int32', 'int32', 'int32', 'int32']
        ),
        free: new NativeFunction(moduleBaseAddress.add(offsets.kFreeChatMsg), 'void', ['pointer']),
    }
    return _sendTextFns
}

export const messageSendText = (contactId: string, text: string, atWxids?: string[]): number => {
    const startTime = Date.now();
    try {
        // 对齐 WCF：WxString.size/capacity 为 wchar 个数；结构体 0x20
        let msgText = text;
        if (contactId.includes('@chatroom') && atWxids && atWxids.length > 0) {
            for (const wxid of atWxids) {
                if (wxid === 'notify@all') {
                    if (!msgText.includes('@所有人')) {
                        msgText = '@所有人 ' + msgText;
                    }
                } else {
                    const atText = `@${wxid}`;
                    if (!msgText.includes(atText)) {
                        msgText = `${atText} ${msgText}`;
                    }
                }
            }
        }

        const chat_msg = Memory.alloc(0x460);
        chat_msg.writeByteArray(Array(0x460).fill(0));
        const to_user = createWxStringChars(contactId);
        const text_msg = createWxStringChars(msgText);

        // RawVector<WxString>：与 WCF vector 布局一致（start/finish/end）
        // 无 @ 时仍 push 一个空 WxString（对齐 WCF）
        let wxAters: NativePointer;
        const pinned: NativePointer[] = [chat_msg, to_user, text_msg];
        if (atWxids && atWxids.length > 0) {
            wxAters = createWxStringVector(atWxids, false);
        } else {
            const emptyWx = createWxStringChars('');
            const finish = emptyWx.add(WX_STRING_SIZE);
            wxAters = Memory.alloc(Process.pointerSize * 3);
            wxAters.writePointer(emptyWx);
            wxAters.add(Process.pointerSize).writePointer(finish);
            wxAters.add(Process.pointerSize * 2).writePointer(finish);
            pinned.push(emptyWx);
        }
        pinned.push(wxAters);

        const { mgr, send, free } = getSendTextFns();
        mgr();
        const success = send(chat_msg, to_user, text_msg, wxAters, 1, 1, 0, 0);
        free(chat_msg);
        // 保持引用，避免发送返回前被 GC
        void pinned.length;

        const result = Number(success) > 0 ? 1 : 0;
        console.log(`[MSG] messageSendText ok, ${Date.now() - startTime}ms, result=${result}`);
        return result;
    } catch (error: any) {
        console.error(`[MSG] messageSendText 异常:`, error);
        return -1;
    }
}

// 发送图片消息
export const messageSendImage = (contactId: string, path: string): number => {
    try {
        const new_chat_msg_addr = moduleBaseAddress.add(offsets.kNewChatMsg);
        const free_chat_msg_addr = moduleBaseAddress.add(offsets.kFreeChatMsg);
        const send_message_mgr_addr = moduleBaseAddress.add(offsets.kSendMessageMgr);
        const send_image_msg_addr = moduleBaseAddress.add(offsets.kSendImageMsg);

        // 分配内存并初始化
        const msg = Memory.alloc(0x460);
        const msgTmp = Memory.alloc(0x460);
        msg.writeByteArray(Array(0x460).fill(0));
        msgTmp.writeByteArray(Array(0x460).fill(0));

        // 构造字符串参数
        const to_user = writeWStringPtr(contactId);
        const path_msg = writeWStringPtr(path);

        // 分配和初始化flag数组
        const flag = Memory.alloc(Process.pointerSize * 10);
        flag.writeByteArray(Array(Process.pointerSize * 10).fill(0)); // 初始化flag数组

        const tmp1 = Memory.alloc(Process.pointerSize);
        const tmp2 = Memory.alloc(Process.pointerSize);
        const tmp3 = Memory.alloc(Process.pointerSize);
        
        tmp1.writePointer(ptr(0));
        tmp2.writePointer(ptr(0));
        tmp3.writePointer(ptr(1));

        // 设置flag数组中的指针
        flag.writePointer(tmp3);
        flag.add(Process.pointerSize * 8).writePointer(tmp1);
        flag.add(Process.pointerSize * 9).writePointer(tmp2);
        flag.add(Process.pointerSize).writePointer(msgTmp);

        // 创建NativeFunction对象
        const constructor = new NativeFunction(new_chat_msg_addr, 'pointer', ['pointer']);
        const destructor = new NativeFunction(free_chat_msg_addr, 'void', ['pointer']);
        const mgr = new NativeFunction(send_message_mgr_addr, 'pointer', []);
        const send = new NativeFunction(send_image_msg_addr, 'int64', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

        // 构造消息对象
        const pMsg = constructor(msg);
        const pMsgTmp = constructor(msgTmp);
        const instance = mgr();

        if (!pMsg || !pMsgTmp || !instance) {
            throw new Error('Failed to initialize message objects');
        }

        // 发送图片消息
        const success = send(instance, pMsg, to_user, path_msg, flag);

        // 清理内存
        destructor(pMsgTmp);
        destructor(pMsg);

        return Number(success) > 0 ? 1 : 0;
    } catch (error) {
        console.error('Error in messageSendImage:', error);
        return -1;
    }
}

// 发送文件消息
export const messageSendFile = (contactId: string, path: string): number => {
    const new_chat_msg_addr = moduleBaseAddress.add(offsets.kNewChatMsg);
    const free_chat_msg_addr = moduleBaseAddress.add(offsets.kFreeChatMsg);
    const get_app_msg_mgr_addr = moduleBaseAddress.add(offsets.kAppMsgMgr);
    const send_file_msg_addr = moduleBaseAddress.add(offsets.kSendFileMsg);

    const msg = Memory.alloc(0x460);
    msg.writeByteArray(Array(0x460).fill(0));

    const to_user = writeWStringPtr(contactId);
    const path_msg = writeWStringPtr(path);

    const tmp1 = Memory.alloc(Process.pointerSize * 4);
    const tmp2 = Memory.alloc(Process.pointerSize * 4);
    const tmp3 = Memory.alloc(Process.pointerSize * 4);

    const constructor = new NativeFunction(new_chat_msg_addr, 'pointer', ['pointer']);
    const destructor = new NativeFunction(free_chat_msg_addr, 'void', ['pointer']);
    const getAppMsgMgr = new NativeFunction(get_app_msg_mgr_addr, 'pointer', []);
    const send = new NativeFunction(send_file_msg_addr, 'int64', ['pointer', 'pointer', 'pointer', 'pointer', 'int32', 'pointer', 'int32', 'pointer', 'int32', 'pointer', 'int32', 'int32']);

    const pMsg = constructor(msg);
    const appMgr = getAppMsgMgr();

    const success = send(appMgr, pMsg, to_user, path_msg, 1, tmp1, 0, tmp2, 0, tmp3, 0, 0);

    destructor(pMsg);

    return Number(success) > 0 ? 1 : 0;
}

// 发送拍一拍消息
export const messageSendPat = (roomId: string, contactId: string): number => {
    try {
        // 获取函数地址
        const send_pat_msg_addr = moduleBaseAddress.add(offsets.OS_SEND_PAT_MSG);

        // 查看C++中WxString的结构:
        // struct WxString {
        //     const wchar_t *wptr;    // 宽字符串指针
        //     DWORD size;             // 字符串长度
        //     DWORD capacity;         // 容量
        //     const char *ptr;        // 窄字符串指针
        //     DWORD clen;             // 窄字符串长度
        // }
        
        // 为群ID创建WxString结构
        const roomIdWStr = Memory.allocUtf16String(roomId);
        const roomIdWxString = Memory.alloc(5 * Process.pointerSize); // WxString结构大小
        roomIdWxString.writePointer(roomIdWStr);         // wptr
        roomIdWxString.add(Process.pointerSize).writeU32(roomId.length);  // size
        roomIdWxString.add(Process.pointerSize + 4).writeU32(roomId.length);  // capacity
        roomIdWxString.add(Process.pointerSize + 8).writePointer(ptr(0));  // ptr = NULL
        roomIdWxString.add(Process.pointerSize + 12).writeU32(0);  // clen = 0
        
        // 为用户ID创建WxString结构
        const contactIdWStr = Memory.allocUtf16String(contactId);
        const contactIdWxString = Memory.alloc(5 * Process.pointerSize); // WxString结构大小
        contactIdWxString.writePointer(contactIdWStr);         // wptr
        contactIdWxString.add(Process.pointerSize).writeU32(contactId.length);  // size
        contactIdWxString.add(Process.pointerSize + 4).writeU32(contactId.length);  // capacity
        contactIdWxString.add(Process.pointerSize + 8).writePointer(ptr(0));  // ptr = NULL
        contactIdWxString.add(Process.pointerSize + 12).writeU32(0);  // clen = 0

        // 创建NativeFunction对象 - 根据C++定义，函数只接收两个指针参数
        const send = new NativeFunction(send_pat_msg_addr, 'int64', ['pointer', 'pointer']);

        // 调用函数 - 传递结构体的指针，而不是字符串指针
        const success = send(roomIdWxString, contactIdWxString);
        console.log("发送拍一拍消息结果: ", success);

        return Number(success) > 0 ? 1 : 0;
    } catch (error) {
        console.error("发送拍一拍消息失败: ", error);
        return -1;
    }
}

// 转发消息（对齐 WCF ForwardMessage；msgId 建议传字符串避免 JS 精度丢失）
export const messageForward = (msgId: number | string, receiver: string): number => {
    try {
        if (!receiver) {
            console.error('messageForward: receiver 为空')
            return -1
        }

        const result = getLocalIdAndDbIdx(msgId);
        if (!result) {
            console.error('messageForward: 未找到 localId/dbIdx, msgId=', msgId)
            return -1;
        }

        const { localId, dbIdx } = result;
        // WCF: NewWxStringFromStr + LARGE_INTEGER{ HighPart=dbIdx, LowPart=localId }
        const receiverStr = createWxStringChars(receiver);

        const l = Memory.alloc(0x8);
        l.writeU32(localId >>> 0);       // LowPart
        l.add(0x4).writeU32(dbIdx >>> 0); // HighPart
        const quad = l.readU64()

        const forward = new NativeFunction(
            moduleBaseAddress.add(offsets.kForwardMsg),
            'int',
            ['pointer', 'uint64', 'int', 'int']
        );

        const raw = forward(receiverStr, quad, 0x4, 0x0) as number
        const status = raw & 0xff
        console.log(`messageForward msgId=${msgId} localId=${localId} dbIdx=${dbIdx} raw=${raw} status=${status}`)
        return status;
    } catch (e) {
        console.error('messageForward failed:', e)
        return -1
    }
}

/** 发送链接卡片消息（对齐 WCF SendRichTextMessage） */
export const messageSendRichText = (rt: RichTextMsg): number => {
    try {
        if (!rt || !rt.receiver) {
            console.error('messageSendRichText: receiver 为空')
            return -1
        }

        const SRTM_SIZE = 0x3F0
        const funcNew = new NativeFunction(moduleBaseAddress.add(offsets.OS_RTM_NEW), 'pointer', ['pointer'])
        const funcFree = new NativeFunction(moduleBaseAddress.add(offsets.OS_RTM_FREE), 'void', ['pointer'])
        const getAppMsgMgr = new NativeFunction(moduleBaseAddress.add(offsets.OS_GET_APP_MSG_MGR), 'pointer', [])
        const sendRichText = new NativeFunction(
            moduleBaseAddress.add(offsets.OS_SEND_RICH_TEXT),
            'int64',
            ['pointer', 'pointer', 'pointer']
        )

        const buff = Memory.alloc(SRTM_SIZE)
        buff.writeByteArray(Array(SRTM_SIZE).fill(0))
        funcNew(buff)

        const pReceiver = createWxString(rt.receiver || '')
        const pTitle = createWxString(rt.title || '')
        const pUrl = createWxString(rt.url || '')
        const pThumburl = createWxString(rt.thumburl || '')
        const pDigest = createWxString(rt.digest || '')
        const pAccount = createWxString(rt.account || '')
        const pName = createWxString(rt.name || '')

        Memory.copy(buff.add(0x8), pTitle, WX_STRING_SIZE)
        Memory.copy(buff.add(0x48), pUrl, WX_STRING_SIZE)
        Memory.copy(buff.add(0xB0), pThumburl, WX_STRING_SIZE)
        Memory.copy(buff.add(0xF0), pDigest, WX_STRING_SIZE)
        Memory.copy(buff.add(0x2C0), pAccount, WX_STRING_SIZE)
        Memory.copy(buff.add(0x2E0), pName, WX_STRING_SIZE)

        const mgr = getAppMsgMgr()
        const status = sendRichText(mgr, pReceiver, buff)
        funcFree(buff)
        return Number(status)
    } catch (error) {
        console.error('messageSendRichText failed:', error)
        return -1
    }
}

let emotionHookInstalled = false
let emotionCallFromUs = false

function readWxStringArg(p: NativePointer): { size: number; str: string } {
    try {
        if (!p || p.isNull()) {
            return { size: 0, str: '' }
        }
        const wptr = p.readPointer()
        const size = p.add(8).readU32()
        let str = ''
        if (wptr && !wptr.isNull()) {
            str = (size > 0 && size < 0x1000 ? wptr.readUtf16String(size) : wptr.readUtf16String()) || ''
        }
        return { size, str }
    } catch (e) {
        return { size: -1, str: '' }
    }
}

function dumpPtrHex(tag: string, label: string, p: NativePointer, n = 0x40): void {
    try {
        if (!p || p.isNull()) {
            console.log(`${tag} ${label}=null`)
            return
        }
        const buf = p.readByteArray(n)
        if (!buf) {
            console.log(`${tag} ${label} read failed`)
            return
        }
        const arr = Array.from(new Uint8Array(buf))
        console.log(`${tag} ${label}@${p} ${arr.map(b => b.toString(16).padStart(2, '0')).join(' ')}`)
    } catch (e) {
        console.log(`${tag} ${label} dump err:`, e)
    }
}

function describeWxLike(tag: string, label: string, p: NativePointer): void {
    try {
        if (!p || p.isNull()) {
            return
        }
        const wptr = p.readPointer()
        const size = p.add(8).readU32()
        const cap = p.add(12).readU32()
        let str = ''
        if (wptr && !wptr.isNull()) {
            try {
                str = wptr.readUtf16String() || ''
            } catch (e) {}
        }
        console.log(`${tag} ${label} wptr=${wptr} size=${size} cap=${cap} str="${str}"`)
        dumpPtrHex(tag, label + 'raw', p, 0x20)
    } catch (e) {
        console.log(`${tag} ${label} describe err:`, e)
    }
}

function toModuleRva(addr: NativePointer): string {
    try {
        const base = moduleBaseAddress
        const off = addr.sub(base)
        if (off.compare(0) >= 0 && off.compare(0x10000000) < 0) {
            return `WeChatWin.dll+0x${off.toString(16)}`
        }
    } catch (e) {}
    return `${addr}`
}

/** 拦截 SendEmotion / EmotionMgr：对照 UI 与 API 入参差异 */
export function installEmotionHook(): void {
    if (emotionHookInstalled) {
        return
    }
    emotionHookInstalled = true

    let mgrUiLogLeft = 2
    Interceptor.attach(moduleBaseAddress.add(offsets.OS_GET_EMOTION_MGR), {
        onLeave(retval) {
            if (emotionCallFromUs) {
                console.log(`EmotionMgr[api] ret=${retval}`)
                return
            }
            if (mgrUiLogLeft <= 0) {
                return
            }
            mgrUiLogLeft -= 1
            console.log(`EmotionMgr[ui] ret=${retval} (剩余采样 ${mgrUiLogLeft})`)
        },
    })

    Interceptor.attach(moduleBaseAddress.add(offsets.OS_SEND_EMOTION), {
        onEnter(args) {
            const tag = emotionCallFromUs ? 'Emotion[api]' : 'Emotion[ui]'
            this.tag = tag
            console.log(
                `${tag} mgr=${args[0]} path=${args[1]} a3=${args[2]} wxid=${args[3]}` +
                ` a5=${args[4]} a6=${args[5]} a7=${args[6]} a8=${args[7]}`
            )
            describeWxLike(tag, 'path', args[1])
            describeWxLike(tag, 'wxid', args[3])
            dumpPtrHex(tag, 'a3', args[2], 0x40)
            dumpPtrHex(tag, 'a6', args[5], 0x40)
            // UI 的 a8 与 a3/a6 不同，可能是表情对象
            dumpPtrHex(tag, 'a8', args[7], 0x60)
            try {
                describeWxLike(tag, 'a8asWx', args[7])
            } catch (e) {}
            try {
                const bt = Thread.backtrace(this.context, Backtracer.FUZZY)
                    .slice(0, 8)
                    .map(a => toModuleRva(a))
                    .join('\n  ')
                console.log(`${tag} backtrace:\n  ${bt}`)
            } catch (e) {}
        },
        onLeave(retval) {
            const tag = (this as any).tag || (emotionCallFromUs ? 'Emotion[api]' : 'Emotion[ui]')
            console.log(`${tag} retval=${retval} low8=${retval.toInt32() & 0xff}`)
        },
    })

    console.log(
        '已安装 Emotion 钩子：请分别用 UI 自定义 GIF 与 API 各发一次，对比 path/a3/a6/a8'
    )
}

/** 微信自定义表情常见上限；超过时 UI 会改为文件发送 */
const EMOTION_MAX_BYTES = 500 * 1024

/**
 * 发送表情/GIF（对齐 WCF SendEmotionMessage）。
 * 文件过大时对齐 UI：自动改走文件发送。
 * @returns 1=表情成功，2=过大已改文件发送，-1=失败
 */
export const messageSendEmotion = (contactId: string, path: string): number => {
    try {
        if (!contactId || !path) {
            console.error('messageSendEmotion: 参数为空')
            return -1
        }

        if (!hasPath(path)) {
            console.error('messageSendEmotion: 文件不存在', path)
            return -1
        }

        const fileSize = getFileSizeNative(path)
        if (fileSize > EMOTION_MAX_BYTES) {
            console.log(
                `messageSendEmotion: size=${fileSize} > ${EMOTION_MAX_BYTES}，对齐 UI 改为文件发送`
            )
            const fileRet = messageSendFile(contactId, path)
            return fileRet > 0 ? 2 : -1
        }

        installEmotionHook()

        const getEmotionMgr = new NativeFunction(
            moduleBaseAddress.add(offsets.OS_GET_EMOTION_MGR),
            'pointer',
            []
        )

        // NativeFunction 传 >4 个参数时，Windows x64 栈参可能未正确落栈；
        // SendEmotion 会读第 6 参并解引用，若为 0 即崩（system error）。
        // 用单指针结构体绕过 Frida 多参传栈问题，由 C 编译器生成正确调用。
        const cm = new CModule(`
            #include <stdint.h>
            typedef uint64_t (*fn8_t)(uint64_t, uint64_t, uint64_t, uint64_t,
                                      uint64_t, uint64_t, uint64_t, uint64_t);
            typedef struct {
                uint64_t fn, a1, a2, a3, a4, a5, a6, a7, a8;
            } call8_t;
            uint64_t invoke8(call8_t *p) {
                return ((fn8_t)p->fn)(p->a1, p->a2, p->a3, p->a4, p->a5, p->a6, p->a7, p->a8);
            }
        `)
        const invoke8 = new NativeFunction(cm.invoke8, 'uint64', ['pointer'])

        const pWxPath = createWxStringHeap(path)
        const pWxWxid = createWxStringHeap(contactId)
        const buff = heapAlloc(0x40)

        const mgr = getEmotionMgr()
        if (!mgr || mgr.isNull()) {
            console.error('messageSendEmotion: EmotionMgr 为空')
            return -1
        }

        const sendAddr = moduleBaseAddress.add(offsets.OS_SEND_EMOTION)
        const args = Memory.alloc(8 * 9)
        args.writePointer(sendAddr)
        args.add(8).writePointer(mgr)
        args.add(16).writePointer(pWxPath)
        args.add(24).writePointer(buff)
        args.add(32).writePointer(pWxWxid)
        args.add(40).writeU64(2)
        args.add(48).writePointer(buff)
        args.add(56).writeU64(0)
        args.add(64).writePointer(buff)

        console.log(
            `messageSendEmotion: contactId=${contactId} path=${path} size=${fileSize}` +
            ` mgr=${mgr} pathW=${pWxPath.readPointer().readUtf16String()}`
        )
        emotionCallFromUs = true
        let ret: NativePointer | number | UInt64
        try {
            ret = invoke8(args) as NativePointer | number | UInt64
        } finally {
            emotionCallFromUs = false
        }
        console.log(`messageSendEmotion: ret=${ret}`)
        return 1
    } catch (error) {
        emotionCallFromUs = false
        console.error('messageSendEmotion failed:', error)
        return -1
    }
}

/** 消息类型表（对齐 WCF GetMsgTypes） */
export const getMsgTypes = (): { [key: number]: string } => {
    return {
        0x00: '朋友圈消息',
        0x01: '文字',
        0x03: '图片',
        0x22: '语音',
        0x25: '好友确认',
        0x28: 'POSSIBLEFRIEND_MSG',
        0x2A: '名片',
        0x2B: '视频',
        0x2F: '石头剪刀布 | 表情图片',
        0x30: '位置',
        0x31: '共享实时位置、文件、转账、链接',
        0x32: 'VOIPMSG',
        0x33: '微信初始化',
        0x34: 'VOIPNOTIFY',
        0x35: 'VOIPINVITE',
        0x3E: '小视频',
        0x42: '微信红包',
        0x270F: 'SYSNOTICE',
        0x2710: '红包、系统消息',
        0x2712: '撤回消息',
        0x100031: '搜狗表情',
        0x1000031: '链接',
        0x1A000031: '微信红包',
        0x20010031: '红包封面',
        0x2D000031: '视频号视频',
        0x2E000031: '视频号名片',
        0x31000031: '引用消息',
        0x37000031: '拍一拍',
        0x3A000031: '视频号直播',
        0x3A100031: '商品链接',
        0x3A200031: '视频号直播',
        0x3E000031: '音乐链接',
        0x41000031: '文件',
    }
}

/**
 * 刷新朋友圈
 * @param id 朋友圈ID，0表示刷新第一页，非0表示获取下一页
 * @returns 成功返回1，失败返回-1
 */
export const refreshPyq = (id: number): number => {
    try {
        // 判断是刷新第一页还是获取下一页
        if (id === 0) {
            return getFirstPage();
        } else {
            return getNextPage(id);
        }
    } catch (error) {
        console.error('刷新朋友圈失败:', error);
        return -1;
    }
}

/**
 * 获取朋友圈第一页
 * @returns 成功返回1，失败返回-1
 */
export function getFirstPage(): number {
    try {
        const getSNSDataMgrAddr = moduleBaseAddress.add(offsets.OS_GET_SNS_DATA_MGR);
        const getSNSFirstPageAddr = moduleBaseAddress.add(offsets.OS_GET_SNS_FIRST_PAGE);
        
        // 创建函数对象
        const getSNSDataMgr = new NativeFunction(getSNSDataMgrAddr, 'pointer', []);
        const getSNSFirstPage = new NativeFunction(getSNSFirstPageAddr, 'pointer', ['pointer', 'pointer', 'int32']);
        
        // 分配缓冲区
        const buff = Memory.alloc(Process.pointerSize * 16);
        buff.writeByteArray(Array(Process.pointerSize * 16).fill(0));
        
        // 获取SNS数据管理器
        const mgr = getSNSDataMgr();
        if (!mgr || mgr.isNull()) {
            console.error('获取SNS数据管理器失败');
            return -1;
        }
        
        // 调用获取第一页函数
        const status = getSNSFirstPage(mgr, buff, 1);
        
        return Number(status) > 0 ? 1 : -1;
    } catch (error) {
        console.error('获取朋友圈第一页失败:', error);
        return -1;
    }
}

/**
 * 获取朋友圈下一页
 * @param id 朋友圈ID
 * @returns 成功返回1，失败返回-1
 */
export function getNextPage(id: number): number {
    try {
        const getSnsTimeLineMgrAddr = moduleBaseAddress.add(offsets.OS_GET_SNS_TIMELINE_MGR);
        const getSNSNextPageSceneAddr = moduleBaseAddress.add(offsets.OS_GET_SNS_NEXT_PAGE);
        
        // 创建函数对象
        const getSnsTimeLineMgr = new NativeFunction(getSnsTimeLineMgrAddr, 'pointer', []);
        const getSNSNextPageScene = new NativeFunction(getSNSNextPageSceneAddr, 'pointer', ['pointer', 'pointer']);
        
        // 获取SNS时间线管理器
        const mgr = getSnsTimeLineMgr();
        if (!mgr || mgr.isNull()) {
            console.error('获取SNS时间线管理器失败');
            return -1;
        }
        
        // 调用获取下一页函数
        const status = getSNSNextPageScene(mgr, ptr(id));
        
        return Number(status) > 0 ? 1 : -1;
    } catch (error) {
        console.error('获取朋友圈下一页失败:', error);
        return -1;
    }
}

/**
 * 下载附件（对齐 WCF DownloadAttach）
 * @param id 消息 MsgSvrID（建议字符串，避免 JS 精度丢失）
 * @param thumb 缩略图路径（视频需要）
 * @param extra 图片或文件保存路径
 * @returns 成功返回1或0，失败返回-1
 */
export const downloadAttach = (id: number | string, thumb: string, extra: string): number => {
    console.log('downloadAttach:', id, thumb, extra)
    let pChatMsg: NativePointer | null = null
    let freeChatMsg: NativeFunction<any, any> | null = null
    try {
        if (extra && pathExistsNative(extra)) {
            console.log('downloadAttach: 目标已存在，跳过', extra)
            return 0
        }

        const result = getLocalIdAndDbIdx(id)
        if (!result) {
            console.error('获取消息localId失败，请检查消息ID:', id)
            return -1
        }

        const { localId, dbIdx } = result
        console.log('downloadAttach localId=', localId, 'dbIdx=', dbIdx)

        const newChatMsg = new NativeFunction(moduleBaseAddress.add(offsets.OS_NEW), 'pointer', ['pointer'])
        freeChatMsg = new NativeFunction(moduleBaseAddress.add(offsets.OS_FREE), 'void', ['pointer'])
        const getChatMgr = new NativeFunction(moduleBaseAddress.add(offsets.OS_GET_CHAT_MGR), 'pointer', [])
        const getPreDownloadMgr = new NativeFunction(
            moduleBaseAddress.add(offsets.OS_GET_PRE_DOWNLOAD_MGR),
            'pointer',
            []
        )
        const getMgrByPrefixLocalId = new NativeFunction(
            moduleBaseAddress.add(offsets.OS_GET_MGR_BY_PREFIX_LOCAL_ID),
            'void',
            ['uint64', 'pointer']
        )

        // LARGE_INTEGER: LowPart=localId, HighPart=dbIdx
        const l = Memory.alloc(0x8)
        l.writeU32(localId >>> 0)
        l.add(0x4).writeU32(dbIdx >>> 0)
        const quadPart = l.readU64()

        const buff = Memory.alloc(0x460)
        buff.writeByteArray(Array(0x460).fill(0))

        pChatMsg = newChatMsg(buff)
        getChatMgr()
        getMgrByPrefixLocalId(quadPart, pChatMsg)

        const type = buff.add(0x38).readU32()
        console.log('downloadAttach msgType=', type.toString(16))

        let savePath = ''
        let thumbPath = ''

        switch (type) {
            case 0x03:
                savePath = extra
                thumbPath = thumb || ''
                break
            case 0x3E:
            case 0x2B:
                thumbPath = thumb
                if (thumb) {
                    const lastDotIndex = thumb.lastIndexOf('.')
                    savePath = lastDotIndex !== -1
                        ? thumb.substring(0, lastDotIndex) + '.mp4'
                        : thumb + '.mp4'
                } else {
                    savePath = extra
                }
                break
            case 0x31:
                savePath = extra
                break
            default:
                console.log('downloadAttach: 未知/不支持类型', type.toString(16))
                freeChatMsg(pChatMsg)
                return -1
        }

        if (!savePath) {
            console.error('downloadAttach: savePath 为空')
            freeChatMsg(pChatMsg)
            return -1
        }

        if (pathExistsNative(savePath)) {
            console.log('downloadAttach: savePath 已存在', savePath)
            freeChatMsg(pChatMsg)
            return 0
        }

        try {
            ensureParentDirNative(savePath)
        } catch (e) {
            console.warn('downloadAttach ensureParentDir skipped:', e)
        }
        console.log('downloadAttach path=', savePath, 'thumb=', thumbPath)

        // WCF: HeapAlloc WxString + memcpy 到 buff+0x280/0x2A0
        const pThumb = createWxStringHeap(thumbPath || '')
        const pSave = createWxStringHeap(savePath)
        Memory.copy(buff.add(0x280), pThumb, WX_STRING_SIZE)
        Memory.copy(buff.add(0x2A0), pSave, WX_STRING_SIZE)
        buff.add(0x40C).writeU32(1)

        const mgr = getPreDownloadMgr()
        if (!mgr || mgr.isNull()) {
            console.error('downloadAttach: PreDownloadMgr 为空')
            freeChatMsg(pChatMsg)
            return -1
        }

        // 经 CModule 调用，避免个别 Frida/ABI 问题
        const cm = new CModule(`
            #include <stdint.h>
            typedef uint64_t (*fn4_t)(uint64_t, uint64_t, uint64_t, uint64_t);
            typedef struct { uint64_t fn, a1, a2, a3, a4; } call4_t;
            uint64_t invoke4(call4_t *p) {
                return ((fn4_t)p->fn)(p->a1, p->a2, p->a3, p->a4);
            }
        `)
        const invoke4 = new NativeFunction(cm.invoke4, 'uint64', ['pointer'])
        const args = Memory.alloc(8 * 5)
        args.writePointer(moduleBaseAddress.add(offsets.OS_PUSH_ATTACH_TASK))
        args.add(8).writePointer(mgr)
        args.add(16).writePointer(pChatMsg)
        args.add(24).writeU64(0)
        args.add(32).writeU64(1)

        console.log('downloadAttach: push...')
        const status = Number(invoke4(args))
        console.log('downloadAttach push status=', status)
        freeChatMsg(pChatMsg)
        pChatMsg = null
        return status > 0 ? 1 : (status === 0 ? 0 : -1)
    } catch (error) {
        console.error('下载附件失败:', error)
        try {
            if (pChatMsg && freeChatMsg) {
                freeChatMsg(pChatMsg)
            }
        } catch (e2) {}
        return -1
    }
}

/**
 * 解密图片（对齐 WCF DecryptImage：XOR 解 .dat）
 * @param src 源文件路径
 * @param dir 目标目录（空则同目录换扩展名）
 * @returns 解密后的文件路径
 */
export const decryptImage = (src: string, dir: string): string => {
    try {
        const HEADER_PNG1 = 0x89;
        const HEADER_PNG2 = 0x50;
        const HEADER_JPG1 = 0xFF;
        const HEADER_JPG2 = 0xD8;
        const HEADER_GIF1 = 0x47;
        const HEADER_GIF2 = 0x49;

        if (!hasPath(src)) {
            console.error('文件不存在:', src);
            return '';
        }

        const fileData = readFileBytes(src);
        if (!fileData || fileData.length < 2) {
            console.error('读取文件失败:', src);
            return '';
        }

        let key = 0;
        let ext = '';

        key = HEADER_PNG1 ^ fileData[0];
        if ((HEADER_PNG2 ^ key) === fileData[1]) {
            ext = '.png';
        } else {
            key = HEADER_JPG1 ^ fileData[0];
            if ((HEADER_JPG2 ^ key) === fileData[1]) {
                ext = '.jpg';
            } else {
                key = HEADER_GIF1 ^ fileData[0];
                if ((HEADER_GIF2 ^ key) === fileData[1]) {
                    ext = '.gif';
                } else {
                    console.error('无法确定图片类型');
                    return '';
                }
            }
        }

        const decryptedData = new Uint8Array(fileData.length);
        for (let i = 0; i < fileData.length; i++) {
            decryptedData[i] = fileData[i] ^ key;
        }

        const normalize = (p: string) => p.replace(/\//g, '\\');
        const srcNorm = normalize(src);
        const lastSlash = Math.max(srcNorm.lastIndexOf('\\'), srcNorm.lastIndexOf('/'));
        const lastDot = srcNorm.lastIndexOf('.');
        const fileName = lastDot > lastSlash
            ? srcNorm.substring(lastSlash + 1, lastDot)
            : srcNorm.substring(lastSlash + 1);

        let dst = '';
        if (!dir) {
            dst = (lastDot > lastSlash ? srcNorm.substring(0, lastDot) : srcNorm) + ext;
        } else {
            const base = dir.endsWith('\\') || dir.endsWith('/') ? dir : (dir + '\\');
            dst = normalize(base) + fileName + ext;
        }

        if (!writeFileBytes(dst, decryptedData)) {
            console.error('写入解密文件失败:', dst);
            return '';
        }
        return dst;
    } catch (error) {
        console.error('解密图片失败:', error);
        return '';
    }
}

/**
 * 获取语音消息并转 mp3（对齐 WCF GetAudio / Silk2Mp3）
 * 流程：MediaMSG 取 Buf → 写 .silk → pysilk+ffmpeg → .mp3
 * @returns 优先返回 .mp3；转码失败则回退 .silk
 */
export const getAudio = (id: number | string, dir: string): string => {
    try {
        const idStr = String(id)
        const baseDir = (dir.endsWith('/') || dir.endsWith('\\')) ? dir : (dir + '\\');
        const mp3path = (baseDir + idStr + '.mp3').replace(/\//g, '\\');
        const silkPath = (baseDir + idStr + '.silk').replace(/\//g, '\\');

        if (hasPath(mp3path)) {
            return mp3path;
        }

        let haveSilk = hasPath(silkPath)
        if (!haveSilk) {
            const silk = getAudioData(id);
            if (!silk || silk.length === 0) {
                console.error('Empty audio data.');
                return '';
            }
            ensureParentDirNative(silkPath);
            if (!writeFileBytes(silkPath, silk)) {
                console.error('写入 silk 失败:', silkPath);
                return '';
            }
            haveSilk = true
            console.log('语音已导出 silk:', silkPath);
        }

        if (haveSilk && convertSilkToMp3(silkPath, mp3path, 24000)) {
            console.log('语音已转 mp3:', mp3path);
            return mp3path;
        }

        console.warn('silk→mp3 失败，回退返回 silk:', silkPath);
        return silkPath;
    } catch (error) {
        console.error('获取语音失败:', error);
        return '';
    }
}

/**
 * 撤回消息（与 WCF 同样暂不可用）
 */
export const revokeMsg = (id: number): number => {
    try {
        const result = getLocalIdAndDbIdx(id);
        if (!result) {
            console.error('获取消息localId失败，请检查消息ID:', id);
            return -1;
        }
        console.warn('撤回消息功能尚未完全实现（与 WCF 一致）');
        return -1;
    } catch (error) {
        console.error('撤回消息失败:', error);
        return -1;
    }
}