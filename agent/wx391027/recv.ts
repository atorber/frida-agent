/**
 * 消息 / 朋友圈接收控制（对齐 WCF receive_msg）
 */
import {
    getStringByStrAddr,
    readWideString,
    ReadWeChatStr,
} from './utils.js'
import { Message } from './types.js'
import { offsets } from './offset.js'

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

export type MsgHandler = (msg: Message) => void

let msgListener: InvocationListener | null = null
let pyqListener: InvocationListener | null = null
let msgHandler: MsgHandler | null = null
let pyqHandler: MsgHandler | null = null
let isListeningMsg = false
let isListeningPyq = false

export function isRecvMsgEnabled(): boolean {
    return isListeningMsg
}

export function isRecvPyqEnabled(): boolean {
    return isListeningPyq
}

export function setMsgHandler(handler: MsgHandler | null) {
    msgHandler = handler
}

export function setPyqHandler(handler: MsgHandler | null) {
    pyqHandler = handler
}

function buildChatMessage(param2: NativePointer): Message {
    const msgId = param2.add(0x30).readS64().toString()
    const msgType = param2.add(0x38).readS32()
    const isSelf = param2.add(0x3C).readS32() === 1
    const createTime = param2.add(0x44).readS32()
    const content = readWideString(param2.add(0x88)) || ''
    const toUser = readWideString(param2.add(0x240)) || ''
    const fromUser = readWideString(param2.add(0x48)) || ''
    const signature = ReadWeChatStr(param2.add(0x260)) || ''

    let room = ''
    let talkerId = ''
    let listenerId = ''
    let text = content
    let filename = ''

    if (fromUser.indexOf('@') !== -1) {
        room = fromUser
    } else if (toUser && toUser.indexOf('@') !== -1) {
        room = toUser
        talkerId = fromUser
    }

    if (room && toUser) {
        talkerId = toUser
    } else if (room && !toUser) {
        talkerId = ''
    } else {
        if (isSelf) {
            talkerId = ''
            listenerId = fromUser
        } else {
            talkerId = fromUser
        }
    }

    let mediaThumb = ''
    let mediaExtra = ''
    if (msgType === 3 || msgType === 43 || msgType === 62) {
        mediaThumb = getStringByStrAddr(param2.add(0x280)) || ''
        mediaExtra = getStringByStrAddr(param2.add(0x2A0)) || ''
        if (msgType === 3) {
            text = JSON.stringify([mediaThumb, mediaThumb, mediaExtra, mediaExtra])
            filename = mediaThumb || mediaExtra
        } else {
            filename = mediaThumb || mediaExtra
        }
    }

    return {
        id: msgId,
        filename,
        text,
        timestamp: createTime,
        type: msgType,
        talkerId,
        roomId: room,
        mentionIds: [],
        listenerId,
        isSelf,
        mediaThumb: mediaThumb || undefined,
        mediaExtra: mediaExtra || undefined,
    }
}

/**
 * 开启聊天消息接收（对齐 ListenMessage）
 */
export function enableRecvMsg(handler?: MsgHandler): boolean {
    try {
        if (handler) {
            msgHandler = handler
        }
        if (isListeningMsg && msgListener) {
            return true
        }

        msgListener = Interceptor.attach(moduleBaseAddress.add(offsets.kDoAddMsg), {
            onEnter(args) {
                try {
                    const message = buildChatMessage(args[1])
                    if (msgHandler) {
                        msgHandler(message)
                    }
                } catch (e) {
                    console.error('接收消息回调失败：', e)
                }
            },
        })
        isListeningMsg = true
        console.log('消息 Hook 已开启')
        return true
    } catch (e) {
        console.error('开启消息接收失败：', e)
        msgListener = null
        isListeningMsg = false
        return false
    }
}

/**
 * 关闭聊天消息接收（对齐 UnListenMessage）
 */
export function disableRecvMsg(): boolean {
    try {
        if (msgListener) {
            msgListener.detach()
            msgListener = null
        }
        isListeningMsg = false
        console.log('消息 Hook 已关闭')
        return true
    } catch (e) {
        console.error('关闭消息接收失败：', e)
        return false
    }
}

/**
 * 开启朋友圈消息接收（对齐 ListenPyq）
 */
export function listenPyq(handler?: MsgHandler): boolean {
    try {
        if (handler) {
            pyqHandler = handler
        }
        if (isListeningPyq && pyqListener) {
            return true
        }

        pyqListener = Interceptor.attach(moduleBaseAddress.add(offsets.OS_PYQ_MSG_CALL), {
            onEnter(args) {
                try {
                    const arg2 = args[1]
                    const startAddr = arg2.add(offsets.OS_PYQ_MSG_START).readPointer()
                    const endAddr = arg2.add(offsets.OS_PYQ_MSG_END).readPointer()
                    if (startAddr.isNull()) {
                        return
                    }

                    let cur = startAddr
                    while (cur.compare(endAddr) < 0) {
                        const id = cur.readS64().toString()
                        const ts = cur.add(offsets.OS_PYQ_MSG_TS).readU32()
                        const xml = getStringByStrAddr(cur.add(offsets.OS_PYQ_MSG_XML)) || ''
                        const sender = getStringByStrAddr(cur.add(offsets.OS_PYQ_MSG_SENDER)) || ''
                        const content = getStringByStrAddr(cur.add(offsets.OS_PYQ_MSG_CONTENT)) || ''

                        const message: Message = {
                            id,
                            text: content || xml,
                            timestamp: ts,
                            type: 0x00,
                            talkerId: sender,
                            roomId: '',
                            mentionIds: [],
                            isSelf: false,
                        }

                        if (pyqHandler) {
                            pyqHandler(message)
                        } else if (msgHandler) {
                            msgHandler(message)
                        }

                        cur = cur.add(offsets.OS_PYQ_MSG_STEP)
                    }
                } catch (e) {
                    console.error('朋友圈消息回调失败：', e)
                }
            },
        })
        isListeningPyq = true
        console.log('朋友圈 Hook 已开启')
        return true
    } catch (e) {
        console.error('开启朋友圈接收失败：', e)
        pyqListener = null
        isListeningPyq = false
        return false
    }
}

/**
 * 关闭朋友圈消息接收（对齐 UnListenPyq）
 */
export function unListenPyq(): boolean {
    try {
        if (pyqListener) {
            pyqListener.detach()
            pyqListener = null
        }
        isListeningPyq = false
        console.log('朋友圈 Hook 已关闭')
        return true
    } catch (e) {
        console.error('关闭朋友圈接收失败：', e)
        return false
    }
}
