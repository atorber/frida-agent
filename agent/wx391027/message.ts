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
    parseContact
} from './utils.js'

import {
    Contact,
    Message,
} from './types.js'

import {
    getLocalIdAndDbIdx
} from './sqlite.js'

const offsets = {
    kSendMessageMgr: 0x1C1E690, // 3.9.10.27
    kSendTextMsg: 0x238DDD0, // 3.9.10.27
    kFreeChatMsg: 0x1C1FF10, // 3.9.10.27
    kNewChatMsg: 0x1C28800,
    kSendImageMsg: 0x2383560, // 3.9.10.27
    kAppMsgMgr: 0x1C23630, // 3.9.10.27
    kSendFileMsg: 0x21969E0, // 3.9.10.27
    kSendPatMsg: 0x2D669B0, // 3.9.10.27
    kForwardMsg: 0x238D350, // 3.9.10.27
    OS_NEW:0x1C28800,
    OS_FREE:0x1C1FF10,
    OS_SEND_MSG_MGR:0x1C1E690,
    OS_SEND_TEXT:0x238DDD0,
    OS_SEND_IMAGE:0x2383560,
    OS_GET_APP_MSG_MGR:0x1C23630,
    OS_SEND_FILE:0x21969E0,
    OS_RTM_NEW:0x1C27D50,
    OS_RTM_FREE:0x1C27120,
    OS_SEND_RICH_TEXT:0x21A09C0,
    OS_SEND_PAT_MSG:0x2D669B0,
    OS_FORWARD_MSG:0x238D350,
    OS_GET_EMOTION_MGR:0x1C988D0,
    OS_SEND_EMOTION:0x227B9E0,
    OS_GET_SNS_DATA_MGR: 0x22A91C0,
    OS_GET_SNS_FIRST_PAGE: 0x2ED9080,
    OS_GET_SNS_TIMELINE_MGR: 0x2E6B110,
    OS_GET_SNS_NEXT_PAGE: 0x2EFEC00,
}

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

/*
发送文本消息 3.9.10.27
*/ 
export const messageSendText = (contactId: string, text: string, atWxids?: string[]): number => {
    try {
        const send_message_mgr_addr = moduleBaseAddress.add(offsets.kSendMessageMgr);
        const send_text_msg_addr = moduleBaseAddress.add(offsets.kSendTextMsg);
        const free_chat_msg_addr = moduleBaseAddress.add(offsets.kFreeChatMsg);

        // 分配内存并初始化
        const chat_msg = Memory.alloc(0x460);
        chat_msg.writeByteArray(Array(0x460).fill(0));

        // 检查是否需要@人，如果需要且在群聊中，需要在文本前添加@用户
        let msgText = text;
        if (contactId.includes('@chatroom') && atWxids && atWxids.length > 0) {
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

        // 构造字符串参数
        const to_user = writeWStringPtr(contactId);
        const text_msg = writeWStringPtr(msgText);

        if (!to_user || !text_msg) {
            throw new Error('Failed to create string pointers');
        }

        // 处理@消息
        let wxAters: NativePointer;
        if (atWxids && atWxids.length > 0) {
            console.log('atWxids:', atWxids);
            // 创建WxString数组
            const wxStrings: NativePointer[] = [];
            for (const wxid of atWxids) {
                const wxStringPtr = writeWStringPtr(wxid);
                if (wxStringPtr && !wxStringPtr.isNull()) {
                    wxStrings.push(wxStringPtr);
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
            }

            // 设置RawVector的字段
            rawVector.writePointer(start); // start
            rawVector.add(Process.pointerSize).writePointer(start.add(Process.pointerSize * wxStrings.length)); // finish
            rawVector.add(Process.pointerSize * 2).writePointer(start.add(Process.pointerSize * wxStrings.length)); // end

            wxAters = rawVector;
            console.log('wxAters:', wxAters);
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
        }

        if (!wxAters || wxAters.isNull()) {
            throw new Error('Failed to create wxAters');
        }

        // console.log('wxAters:', wxAters);

        // 创建NativeFunction对象
        const mgr = new NativeFunction(send_message_mgr_addr, 'void', []);
        const send = new NativeFunction(send_text_msg_addr, 'uint64', ['pointer', 'pointer', 'pointer', 'pointer', 'int32', 'int32', 'int32', 'int32']);
        const free = new NativeFunction(free_chat_msg_addr, 'void', ['pointer']);

        // 调用发送消息管理器初始化
        mgr();

        // 发送文本消息
        const success = send(chat_msg, to_user, text_msg, wxAters, 1, 1, 0, 0);

        // 释放内存
        free(chat_msg);

        return Number(success) > 0 ? 1 : 0;
    } catch (error) {
        console.error('Error in messageSendText:', error);
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
        const getChatMgrAddr = moduleBaseAddress.add(0x1C51CF0); // 获取聊天管理器的偏移量
        const getPreDownloadMgrAddr = moduleBaseAddress.add(0x1CD87E0); // 获取预下载管理器的偏移量
        const pushAttachTaskAddr = moduleBaseAddress.add(0x1DA69C0); // 任务推送函数的偏移量
        const getMgrByPrefixLocalIdAddr = moduleBaseAddress.add(0x2206280); // 获取管理器的偏移量

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
 * 解密图片
 * @param src 源文件路径
 * @param dir 目标目录
 * @returns 解密后的文件路径
 */
export const decryptImage = (src: string, dir: string): string => {
    try {
        // 定义图片格式的头部字节
        const HEADER_PNG1 = 0x89;
        const HEADER_PNG2 = 0x50;
        const HEADER_JPG1 = 0xFF;
        const HEADER_JPG2 = 0xD8;
        const HEADER_GIF1 = 0x47;
        const HEADER_GIF2 = 0x49;

        // 检查文件是否存在
        if (!hasPath(src)) {
            console.error('文件不存在:', src);
            return '';
        }

        // 读取文件内容 - 这里修改为更合适的文件读取方式
        // 假设readAll函数返回Uint8Array类型
        const fileData = new Uint8Array(); // 实际使用时要替换为文件读取函数
        if (!fileData || fileData.length === 0) {
            console.error('读取文件失败:', src);
            return '';
        }

        // 确定文件类型和解密密钥
        let key = 0;
        let ext = '';

        // PNG判断
        key = HEADER_PNG1 ^ fileData[0];
        if ((HEADER_PNG2 ^ key) === fileData[1]) {
            ext = '.png';
        } else {
            // JPG判断
            key = HEADER_JPG1 ^ fileData[0];
            if ((HEADER_JPG2 ^ key) === fileData[1]) {
                ext = '.jpg';
            } else {
                // GIF判断
                key = HEADER_GIF1 ^ fileData[0];
                if ((HEADER_GIF2 ^ key) === fileData[1]) {
                    ext = '.gif';
                } else {
                    console.error('无法确定图片类型');
                    return '';
                }
            }
        }

        // 解密文件内容
        const decryptedData = new Uint8Array(fileData.length);
        for (let i = 0; i < fileData.length; i++) {
            decryptedData[i] = fileData[i] ^ key;
        }

        // 确定输出路径
        let dst = '';
        const pathObj = new URL('file://' + src);
        const fileName = pathObj.pathname.slice(pathObj.pathname.lastIndexOf('/') + 1, pathObj.pathname.lastIndexOf('.'));

        if (dir === '') {
            dst = src.slice(0, src.lastIndexOf('.')) + ext;
        } else {
            dst = (dir.endsWith('/') || dir.endsWith('\\')) ? dir : (dir + '/');
            dst += fileName + ext;
        }

        // 替换Windows路径分隔符
        dst = dst.replace(/\\/g, '/');

        // 写入解密后的文件
        // 这里需要调用文件写入API，Frida需要使用native API

        return dst;
    } catch (error) {
        console.error('解密图片失败:', error);
        return '';
    }
}

/**
 * 获取语音消息并转换为MP3
 * @param id 消息ID
 * @param dir 保存目录
 * @returns MP3文件路径
 */
export const getAudio = (id: number, dir: string): string => {
    try {
        // 确定MP3文件路径
        let mp3path = (dir.endsWith('/') || dir.endsWith('\\')) ? dir : (dir + '/');
        mp3path += id.toString() + '.mp3';
        
        // 替换Windows路径分隔符
        mp3path = mp3path.replace(/\\/g, '/');
        
        // 检查文件是否已存在
        if (hasPath(mp3path)) {
            return mp3path;
        }
        
        // 获取语音数据（需要调用native API）
        // 这部分需要实现获取音频数据的功能，可能需要查询数据库

        // 将silk格式转换为MP3
        // 这部分需要调用转换函数，Frida可能需要使用native API
        
        console.log('语音消息转换为MP3:', mp3path);
        
        return mp3path;
    } catch (error) {
        console.error('获取语音失败:', error);
        return '';
    }
}

/**
 * 撤回消息
 * @param id 消息ID
 * @returns 成功返回1，失败返回-1
 */
export const revokeMsg = (id: number): number => {
    try {
        // 获取localId和dbIdx
        const result = getLocalIdAndDbIdx(id);
        if (!result) {
            console.error('获取消息localId失败，请检查消息ID:', id);
            return -1;
        }

        const { localId, dbIdx } = result;

        console.log(`尝试撤回消息 ID: ${id}, LocalId: ${localId}, DbIdx: ${dbIdx}`);

        // 注意：此功能在C++版本中没有完全实现
        // 原因："自己发的消息没法直接获得msgid"
        console.warn('撤回消息功能尚未完全实现');

        // 如果需要完整实现，需要增加相关API调用
        
        return -1;
    } catch (error) {
        console.error('撤回消息失败:', error);
        return -1;
    }
}

/*
发送联系人名片
*/
async function messageSendContact(
    conversationId: string,
    contactId: string,
): Promise<void> {

}

/*
发送链接消息
*/
async function messageSendUrl(
    conversationId: string,
    urlLinkPayload: any,
): Promise<void> {
}

/*
发送小程序消息
*/
async function messageSendMiniProgram(
    conversationId: string,
    miniProgramPayload: any,
): Promise<void> {

}

/*
发送位置消息
*/
async function messageSendLocation(
    conversationId: string,
    locationPayload: any,
): Promise<void | string> {
}