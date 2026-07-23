import {
    writeWStringPtr,
    readWStringPtr,
    ReadSKBuiltinString,
    ReadWeChatStr,
    WeChatMessage,
    hasPath,
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
    createWxStringVector,
    WX_STRING_SIZE,
    readFileBytes,
    writeFileBytes,
    ensureParentDirNative,
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
export const messageSendText = (contactId: string, text: string, atWxids?: string[]): number => {
    const startTime = Date.now();
    console.log(`[MSG] [${new Date().toISOString()}] messageSendText 开始执行:`, { 
        contactId, 
        textLength: text.length,
        textPreview: text.length > 50 ? text.substring(0, 50) + '...' : text,
        atWxids 
    });
    
    try {
        const step1Time = Date.now();
        const send_message_mgr_addr = moduleBaseAddress.add(offsets.kSendMessageMgr);
        const send_text_msg_addr = moduleBaseAddress.add(offsets.kSendTextMsg);
        const free_chat_msg_addr = moduleBaseAddress.add(offsets.kFreeChatMsg);

        console.log(`[MSG] [${new Date().toISOString()}] 步骤1: 获取函数地址完成，耗时: ${Date.now() - step1Time}ms`, {
            send_message_mgr_addr,
            send_text_msg_addr,
            free_chat_msg_addr
        });

        const step2Time = Date.now();
        // 分配内存并初始化
        const chat_msg = Memory.alloc(0x460);
        chat_msg.writeByteArray(Array(0x460).fill(0));
        console.log(`[MSG] [${new Date().toISOString()}] 步骤2: 分配消息缓冲区完成，耗时: ${Date.now() - step2Time}ms，地址:`, chat_msg);

        // 检查是否需要@人，如果需要且在群聊中，需要在文本前添加@用户
        let msgText = text;
        if (contactId.includes('@chatroom') && atWxids && atWxids.length > 0) {
            console.log('处理@消息，群聊ID:', contactId);
            for (const wxid of atWxids) {
                if (wxid === 'notify@all') {
                    // 特殊处理@所有人
                    if (!msgText.includes('@所有人')) {
                        msgText = '@所有人 ' + msgText;
                    }
                } else {
                    // 普通@用户，只有当文本中还没有@该用户时才添加
                    const atText = `@${wxid}`;
                    if (!msgText.includes(atText)) {
                        msgText = `${atText} ${msgText}`;
                    }
                }
            }
            console.log('添加@后的消息:', msgText);
        }

        const step3Time = Date.now();
        // 构造字符串参数
        console.log(`[MSG] [${new Date().toISOString()}] 步骤3: 开始构造字符串参数...`);
        const to_user = writeWStringPtr(contactId);
        console.log(`[MSG] [${new Date().toISOString()}] to_user 指针创建完成:`, to_user);
        const text_msg = writeWStringPtr(msgText);
        console.log(`[MSG] [${new Date().toISOString()}] text_msg 指针创建完成:`, text_msg);

        if (!to_user || !text_msg) {
            throw new Error('Failed to create string pointers');
        }

        console.log(`[MSG] [${new Date().toISOString()}] 步骤3: 字符串参数构造完成，耗时: ${Date.now() - step3Time}ms`, {
            to_user,
            text_msg
        });

        // 处理@消息
        let wxAters: NativePointer;
        if (atWxids && atWxids.length > 0) {
            console.log('处理@列表:', atWxids);
            // 创建WxString数组
            const wxStrings: NativePointer[] = [];
            for (const wxid of atWxids) {
                const wxStringPtr = writeWStringPtr(wxid);
                if (wxStringPtr && !wxStringPtr.isNull()) {
                    wxStrings.push(wxStringPtr);
                    console.log('添加@用户:', wxid, '指针:', wxStringPtr);
                }
            }

            // 分配RawVector结构的内存
            const rawVectorSize = Process.pointerSize * 3; // start, finish, end
            const rawVector = Memory.alloc(rawVectorSize);
            rawVector.writeByteArray(Array(rawVectorSize).fill(0));

            // 设置RawVector的指针
            const start = Memory.alloc(Process.pointerSize * wxStrings.length);
            start.writeByteArray(Array(Process.pointerSize * wxStrings.length).fill(0));

            // 写入WxString指针
            for (let i = 0; i < wxStrings.length; i++) {
                start.add(Process.pointerSize * i).writePointer(wxStrings[i]);
                console.log('写入@用户指针:', i, wxStrings[i]);
            }

            // 设置RawVector的字段
            rawVector.writePointer(start); // start
            rawVector.add(Process.pointerSize).writePointer(start.add(Process.pointerSize * wxStrings.length)); // finish
            rawVector.add(Process.pointerSize * 2).writePointer(start.add(Process.pointerSize * wxStrings.length)); // end

            wxAters = rawVector;
            console.log('RawVector结构:', {
                start: rawVector.readPointer(),
                finish: rawVector.add(Process.pointerSize).readPointer(),
                end: rawVector.add(Process.pointerSize * 2).readPointer()
            });
        } else {
            // 创建空的WxString
            const emptyWxString = writeWStringPtr('');
            const rawVectorSize = Process.pointerSize * 4;
            const rawVector = Memory.alloc(rawVectorSize);
            rawVector.writeByteArray(Array(rawVectorSize).fill(0));

            const start = Memory.alloc(Process.pointerSize);
            start.writePointer(emptyWxString);

            rawVector.writePointer(start);
            rawVector.add(Process.pointerSize).writePointer(start.add(Process.pointerSize));
            rawVector.add(Process.pointerSize * 2).writePointer(start.add(Process.pointerSize));
            rawVector.add(Process.pointerSize * 3).writePointer(start.add(Process.pointerSize));

            wxAters = rawVector;
            console.log('创建空的RawVector结构');
        }

        if (!wxAters || wxAters.isNull()) {
            throw new Error('Failed to create wxAters');
        }

        const step4Time = Date.now();
        // 创建NativeFunction对象
        console.log(`[MSG] [${new Date().toISOString()}] 步骤4: 创建 NativeFunction 对象...`);
        const mgr = new NativeFunction(send_message_mgr_addr, 'void', []);
        const send = new NativeFunction(send_text_msg_addr, 'uint64', ['pointer', 'pointer', 'pointer', 'pointer', 'int32', 'int32', 'int32', 'int32']);
        const free = new NativeFunction(free_chat_msg_addr, 'void', ['pointer']);
        console.log(`[MSG] [${new Date().toISOString()}] 步骤4: NativeFunction 对象创建完成，耗时: ${Date.now() - step4Time}ms`);

        const step5Time = Date.now();
        console.log(`[MSG] [${new Date().toISOString()}] 步骤5: 调用发送消息管理器初始化...`);
        mgr();
        console.log(`[MSG] [${new Date().toISOString()}] 步骤5: 发送消息管理器初始化完成，耗时: ${Date.now() - step5Time}ms`);

        const step6Time = Date.now();
        console.log(`[MSG] [${new Date().toISOString()}] 步骤6: 准备发送文本消息，参数:`, {
            chat_msg,
            to_user,
            text_msg,
            wxAters,
            wxAters_start: wxAters.readPointer()
        });

        // 发送文本消息
        // 注意：wxAters 是 RawVector 结构的指针，应该直接传递，而不是 readPointer()
        console.log(`[MSG] [${new Date().toISOString()}] 步骤6: 开始调用 send 函数...`);
        const success = send(chat_msg, to_user, text_msg, wxAters, 1, 1, 0, 0);
        console.log(`[MSG] [${new Date().toISOString()}] 步骤6: send 函数调用完成，耗时: ${Date.now() - step6Time}ms，返回值:`, success);

        const step7Time = Date.now();
        // 释放内存
        console.log(`[MSG] [${new Date().toISOString()}] 步骤7: 释放内存...`);
        free(chat_msg);
        console.log(`[MSG] [${new Date().toISOString()}] 步骤7: 内存释放完成，耗时: ${Date.now() - step7Time}ms`);

        const totalTime = Date.now() - startTime;
        const result = Number(success) > 0 ? 1 : 0;
        console.log(`[MSG] [${new Date().toISOString()}] messageSendText 执行完成，总耗时: ${totalTime}ms，结果:`, result);
        
        return result;
    } catch (error: any) {
        const totalTime = Date.now() - startTime;
        console.error(`[MSG] [${new Date().toISOString()}] messageSendText 执行异常，总耗时: ${totalTime}ms`);
        console.error(`[MSG] [${new Date().toISOString()}] 错误信息:`, error);
        console.error(`[MSG] [${new Date().toISOString()}] 错误堆栈:`, error.stack);
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

// 转发消息
export const messageForward = (msgId: number, receiver: string): number => {
    const forward_msg_addr = moduleBaseAddress.add(offsets.kForwardMsg);

    const result = getLocalIdAndDbIdx(msgId);
    if (!result) {
        return -1;
    }

    const { localId, dbIdx } = result;
    const receiverStr = writeWStringPtr(receiver);

    const l = Memory.alloc(0x8);
    l.writeU32(dbIdx);
    l.add(0x4).writeU32(localId);

    const forward = new NativeFunction(forward_msg_addr, 'int32', ['pointer', 'int64', 'int32', 'int32']);

    const success = forward(receiverStr, l.readInt(), 0x4, 0x0);

    return success;
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

/** 发送表情/GIF（对齐 WCF SendEmotionMessage） */
export const messageSendEmotion = (contactId: string, path: string): number => {
    try {
        if (!contactId || !path) {
            console.error('messageSendEmotion: 参数为空')
            return -1
        }

        const getEmotionMgr = new NativeFunction(
            moduleBaseAddress.add(offsets.OS_GET_EMOTION_MGR),
            'pointer',
            []
        )
        const sendEmotion = new NativeFunction(
            moduleBaseAddress.add(offsets.OS_SEND_EMOTION),
            'int64',
            ['pointer', 'pointer', 'pointer', 'pointer', 'int32', 'pointer', 'int32', 'pointer']
        )

        const pWxPath = createWxString(path)
        const pWxWxid = createWxString(contactId)
        const buff = Memory.alloc(0x20)
        buff.writeByteArray(Array(0x20).fill(0))

        const mgr = getEmotionMgr()
        const status = sendEmotion(mgr, pWxPath, buff, pWxWxid, 2, buff, 0, buff)
        return Number(status) >= 0 ? 1 : -1
    } catch (error) {
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
 * 下载附件（图片、视频、文件）
 * @param id 消息ID
 * @param thumb 缩略图路径（视频需要）
 * @param extra 图片或文件路径
 * @returns 成功返回1或0，失败返回-1
 */
export const downloadAttach = (id: number, thumb: string, extra: string): number => {
    console.log('downloadAttach:', id, thumb, extra)
    try {
        // 检查文件是否已存在，避免重复下载
        // if (hasPath(extra)) {
        //     console.log('文件已存在:', extra)
        //     return 0;
        // }

        // 获取localId和dbIdx
        console.log('getLocalIdAndDbIdx:', id)
        const result = getLocalIdAndDbIdx(id);
        console.log('result:', result)
        if (!result) {
            console.error('获取消息localId失败，请检查消息ID:', id);
            return -1;
        }

        const { localId, dbIdx } = result;
        console.log('localId:', localId, 'dbIdx:', dbIdx);

        // 获取相关函数地址
        const newChatMsgAddr = moduleBaseAddress.add(offsets.OS_NEW);
        const freeChatMsgAddr = moduleBaseAddress.add(offsets.OS_FREE);
        const getChatMgrAddr = moduleBaseAddress.add(offsets.OS_GET_CHAT_MGR);
        const getPreDownloadMgrAddr = moduleBaseAddress.add(offsets.OS_GET_PRE_DOWNLOAD_MGR);
        const pushAttachTaskAddr = moduleBaseAddress.add(offsets.OS_PUSH_ATTACH_TASK);
        const getMgrByPrefixLocalIdAddr = moduleBaseAddress.add(offsets.OS_GET_MGR_BY_PREFIX_LOCAL_ID);

        // 创建NativeFunction对象
        const newChatMsg = new NativeFunction(newChatMsgAddr, 'pointer', ['pointer']);
        const freeChatMsg = new NativeFunction(freeChatMsgAddr, 'void', ['pointer']);
        const getChatMgr = new NativeFunction(getChatMgrAddr, 'pointer', []);
        const getPreDownloadMgr = new NativeFunction(getPreDownloadMgrAddr, 'pointer', []);
        const pushAttachTask = new NativeFunction(pushAttachTaskAddr, 'int64', ['pointer', 'pointer', 'int32', 'int32']);
        const getMgrByPrefixLocalId = new NativeFunction(getMgrByPrefixLocalIdAddr, 'void', ['int64', 'pointer']);

        // 创建LARGE_INTEGER结构 - 这里使用int64代替
        const l = Memory.alloc(0x8);
        l.writeU32(dbIdx); // HighPart
        l.add(0x4).writeU32(localId); // LowPart
        
        // 打印QuadPart值进行调试
        const quadPart = l.readS64();
        console.log('QuadPart值:', quadPart);

        // 分配内存
        const buff = Memory.alloc(0x460);
        buff.writeByteArray(Array(0x460).fill(0));

        // 创建聊天消息对象
        const pChatMsg = newChatMsg(buff);
        getChatMgr();
        
        // 这里使用int64
        getMgrByPrefixLocalId(quadPart, pChatMsg);

        // 获取消息类型
        const type = buff.add(0x38).readU32();
        console.log('消息类型:', type.toString(16));

        let savePath = "";
        let thumbPath = "";

        // 根据消息类型设置保存路径
        switch (type) {
            case 0x03: // 图片
                savePath = extra;
                break;
            case 0x3E:
            case 0x2B: // 视频
                thumbPath = thumb;
                // 简化路径处理，避免使用URL对象
                const lastDotIndex = thumb.lastIndexOf('.');
                if (lastDotIndex !== -1) {
                    savePath = thumb.substring(0, lastDotIndex) + '.mp4';
                } else {
                    savePath = thumb + '.mp4';
                }
                break;
            case 0x31: // 文件
                savePath = extra;
                break;
            default:
                console.log('未知消息类型:', type.toString(16));
                freeChatMsg(pChatMsg);
                return -1;
        }

        // 检查文件是否已存在
        // if (hasPath(savePath)) {
        //    freeChatMsg(pChatMsg);
        //    return 0;
        // }

        console.log('下载路径:', savePath);

        // 为保存路径创建父目录 - 简化处理
        // 这里应该是创建目录的代码，但在Frida中直接省略

        // 创建WxString对象
        const savePathPtr = writeWStringPtr(savePath);
        const thumbPathPtr = writeWStringPtr(thumbPath);
        console.log('savePathPtr:', savePathPtr, 'thumbPathPtr:', thumbPathPtr);

        // 设置缓冲区参数
        buff.add(0x280).writePointer(thumbPathPtr);
        buff.add(0x2A0).writePointer(savePathPtr);
        buff.add(0x40C).writeU32(1);

        // 执行下载任务
        const mgr = getPreDownloadMgr();
        console.log('预下载管理器:', mgr);
        const status = pushAttachTask(mgr, pChatMsg, 0, 1);
        console.log('下载任务状态:', status);

        // 释放资源
        freeChatMsg(pChatMsg);

        return Number(status) > 0 ? 1 : -1;
    } catch (error) {
        console.error('下载附件失败:', error);
        return -1;
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
 * 获取语音消息数据并落盘（对齐 WCF GetAudio）
 * Frida 环境无 Codec.lib，先导出 silk；若目录下已有同名 mp3 则直接返回。
 * @param id 消息ID
 * @param dir 保存目录
 * @returns 文件路径（优先 .mp3，否则 .silk）
 */
export const getAudio = (id: number, dir: string): string => {
    try {
        const baseDir = (dir.endsWith('/') || dir.endsWith('\\')) ? dir : (dir + '\\');
        const mp3path = (baseDir + id.toString() + '.mp3').replace(/\//g, '\\');
        const silkPath = (baseDir + id.toString() + '.silk').replace(/\//g, '\\');

        if (hasPath(mp3path)) {
            return mp3path;
        }
        if (hasPath(silkPath)) {
            return silkPath;
        }

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

        console.log('语音已导出为 silk（无内置 silk→mp3，可外部转码）:', silkPath);
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